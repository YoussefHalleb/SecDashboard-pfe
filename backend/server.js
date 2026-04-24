const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const pool = require("./db");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { callGeminiWithGrounding } = require("./vertexClient");
const { parseZapHtmlFile } = require("./zapParser");
function safeParseJSON(raw) {
  try {
    let cleaned = raw.replace(/```json|```/gi, "").trim();

    const first = cleaned.indexOf("{");
    const last = cleaned.lastIndexOf("}");

    if (first === -1 || last === -1) {
      throw new Error("No valid JSON found");
    }

    cleaned = cleaned.slice(first, last + 1);

    // 🔥 FIX : supprimer code cassé
    cleaned = cleaned.replace(
      /"code_fix_example":\s*"[^"]*$/g,
      `"code_fix_example": ""`
    );

    return JSON.parse(cleaned);
  } catch (e) {
    console.error("❌ JSON PARSE FAILED");
    console.error(raw);
    return { items: [] };
  }
}
const ZAP_DIR = path.join(__dirname, "uploads", "zap");

fs.mkdirSync(ZAP_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, ZAP_DIR),
  filename: (req, file, cb) => {
    const repoName = (req.body?.repo_name || "unknown").replace(
      /[^a-zA-Z0-9-_]/g,
      "_",
    );
    cb(null, `${repoName}-zap.html`);
  },
});

const upload = multer({ storage });
const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: [
      "http://localhost:5173", // dev
      "http://localhost", // docker
      "http://localhost:80", // docker explicite
      process.env.CLIENT_ORIGIN,
    ],
    credentials: true,
  }),
);

const DEFECTDOJO_URL = process.env.DEFECTDOJO_URL;
const DEFECTDOJO_TOKEN = process.env.DEFECTDOJO_API_KEY;

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // {sub,email,iat,exp}
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

const headers = {
  Authorization: `Token ${DEFECTDOJO_TOKEN}`,
};

// REGISTER
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    if (password.length < 8)
      return res.status(400).json({ error: "Password too short (min 8)" });

    const password_hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email, password_hash],
    );

    const user = result.rows[0];
    const token = signToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",
      secure: false, // mets true en HTTPS (prod)
      maxAge: 7 * 24 * 3600 * 1000,
    });

    res.json(user);
  } catch (err) {
    console.error("REGISTER ERROR:", err.message);
    return res.status(400).json({ error: err.message });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const result = await pool.query(
      `SELECT id, email, password_hash
       FROM users
       WHERE email = $1`,
      [email],
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 7 * 24 * 3600 * 1000,
    });

    res.json({ id: user.id, email: user.email });
  } catch (err) {
    return res.status(500).json({ error: "Login failed" });
  }
});

// ME (qui est connecté ?)
app.get("/auth/me", authMiddleware, async (req, res) => {
  res.json({ id: req.user.sub, email: req.user.email });
});

// LOGOUT
app.post("/auth/logout", (req, res) => {
  res.clearCookie("token", { httpOnly: true, sameSite: "lax", secure: false });
  res.json({ ok: true });
});

///////////////////////////////////////////////////////
// FUNCTION: FETCH ALL PAGES FROM DEFECTDOJO API
///////////////////////////////////////////////////////
async function fetchAllPages(url) {
  let results = [];
  let nextUrl = url;

  while (nextUrl) {
    const response = await axios.get(nextUrl, { headers });
    results.push(...response.data.results);
    nextUrl = response.data.next;
  }

  return results;
}

app.post("/api/pipeline/run", async (req, res) => {
  try {
    const { repo_url, repo_branch, app_port } = req.body;

    if (!repo_branch) {
      return res.status(400).json({ error: "repo_branch is required" });
    }

    const githubUrl = `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/actions/workflows/${process.env.GITHUB_WORKFLOW_FILE}/dispatches`;

    // ← Répondre immédiatement au frontend
    res.json({ success: true, message: "Pipeline triggered successfully" });

    // ← Envoyer à GitHub en arrière-plan
    axios
      .post(
        githubUrl,
        {
          ref: "main",
          inputs: {
            repo_url: repo_url || "",
            repo_branch: repo_branch || "main",
            app_port: String(app_port || "80"),
          },
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github+json",
          },
          timeout: 30000,
        },
      )
      .catch((e) => {
        console.error("Pipeline trigger error:", e.response?.data || e.message);
      });
  } catch (error) {
    console.error(
      "Pipeline trigger error:",
      error.response?.data || error.message,
    );
    if (!res.headersSent) {
      return res.status(500).json({ error: "Failed to trigger pipeline" });
    }
  }
});

///////////////////////////////////////////////////////
// GET ALL REPOSITORIES (Products + ALL Findings)
// + STORE IN POSTGRESQL
///////////////////////////////////////////////////////
app.get("/api/repositories", async (req, res) => {
  try {
    // Fetch products
    const products = await fetchAllPages(
      `${DEFECTDOJO_URL}/api/v2/products/?limit=1000`,
    );

    // STORE PRODUCTS
    for (const product of products) {
      await pool.query(
        `
        INSERT INTO products (id, name)
        VALUES ($1, $2)
        ON CONFLICT (id) DO NOTHING
        `,
        [product.id, product.name],
      );
    }

    const repositories = await Promise.all(
      products.map(async (product) => {
        const engagements = await fetchAllPages(
          `${DEFECTDOJO_URL}/api/v2/engagements/?product=${product.id}&limit=1000`,
        );

        let allFindings = [];

        for (const engagement of engagements) {
          const tests = await fetchAllPages(
            `${DEFECTDOJO_URL}/api/v2/tests/?engagement=${engagement.id}&limit=1000`,
          );

          for (const test of tests) {
            const findings = await fetchAllPages(
              `${DEFECTDOJO_URL}/api/v2/findings/?test=${test.id}&active=true&limit=1000`,
            );

            const testDetails = await axios.get(
              `${DEFECTDOJO_URL}/api/v2/tests/${test.id}/`,
              { headers },
            );

            const scannerName =
              testDetails.data.title ||
              testDetails.data.test_type_name ||
              "Unknown Scanner";

            const findingsWithScanner = findings.map((finding) => ({
              ...finding,
              scanner: scannerName,
            }));

            // STORE FINDINGS
            for (const finding of findingsWithScanner) {
              await pool.query(
                `
                INSERT INTO findings (
                  id,
                  product_id,
                  title,
                  description,
                  severity,
                  scanner
                )
                VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT (id) DO NOTHING
                `,
                [
                  finding.id,
                  product.id,
                  finding.title,
                  finding.description,
                  finding.severity,
                  finding.scanner,
                ],
              );
            }

            allFindings.push(...findingsWithScanner);
          }
        }

        console.log(
          `Product ${product.name}: ${allFindings.length} findings stored`,
        );

        return {
          id: product.id,
          name: product.name,
          vulnerabilities: allFindings,
        };
      }),
    );

    res.json(repositories);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({
      error: "Failed to fetch repositories",
    });
  }
});

///////////////////////////////////////////////////////
// GET FINDINGS FROM DATABASE (FAST)
///////////////////////////////////////////////////////
app.get("/api/findings", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM findings
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error.message);

    res.status(500).json({
      error: "Failed to fetch findings from database",
    });
  }
});

///////////////////////////////////////////////////////
// GET FINDINGS BY PRODUCT ID (FROM DATABASE)
///////////////////////////////////////////////////////
app.get("/api/repositories/:id/findings", async (req, res) => {
  try {
    const productId = req.params.id;

    const result = await pool.query(
      `
      SELECT *
      FROM findings
      WHERE product_id = $1
      ORDER BY created_at DESC
      `,
      [productId],
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error.message);

    res.status(500).json({
      error: "Failed to fetch findings",
    });
  }
});

app.get("/api/products/:id/zap-findings", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, zap_report_path
       FROM products
       WHERE id = $1`,
      [req.params.id],
    );

    const product = rows[0];
    if (!product?.zap_report_path) {
      return res.status(404).json({ error: "No ZAP report found" });
    }

    const fullPath = path.resolve(__dirname, product.zap_report_path);
    const findings = parseZapHtmlFile(fullPath);

    res.json({
      product_id: product.id,
      product_name: product.name,
      count: findings.length,
      findings,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to parse ZAP report" });
  }
});
app.delete("/api/products/:id", async (req, res) => {
  const productId = req.params.id;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `DELETE FROM finding_recommendations WHERE finding_id IN (SELECT id FROM findings WHERE product_id = $1)`,
      [productId],
    );
    await client.query(
      `DELETE FROM finding_ai_analysis WHERE finding_id IN (SELECT id FROM findings WHERE product_id = $1)`,
      [productId],
    );
    await client.query(
      `DELETE FROM performance_results WHERE product_id = $1`,
      [productId],
    );
    await client.query(`DELETE FROM findings WHERE product_id = $1`, [
      productId,
    ]);
    await client.query(`DELETE FROM products WHERE id = $1`, [productId]);
    await client.query("COMMIT");
    res.json({ success: true });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Delete failed", details: e.message });
  } finally {
    client.release();
  }
});
app.post("/api/products/:id/ai-from-zap", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, zap_report_path
       FROM products
       WHERE id = $1`,
      [req.params.id],
    );

    const product = rows[0];
    if (!product?.zap_report_path) {
      return res.status(404).json({ error: "No ZAP report found" });
    }

    const fullPath = path.resolve(__dirname, product.zap_report_path);
    const findings = parseZapHtmlFile(fullPath);

    if (!findings.length) {
      return res.json({ items: [], stats: {}, summary: "No findings parsed" });
    }

    const selected = findings.slice(0, 10);

    const prompt = `
You are a senior Application Security Engineer analyzing vulnerabilities from an OWASP ZAP report.

Return ONLY valid JSON in this exact format:

{
  "items": [
    {
      "title": string,
      "owasp_category": string,
      "risk_analysis": string,
      "impact": string,
      "remediation": string,
      "recommended_priority": "Low|Medium|High|Critical",
      "risk_score": number
    }
  ],
  "stats": {
    "total_findings": number,
    "high_priority_count": number,
    "top_categories": [string]
  },
  "executive_summary": string
}

Rules:
- risk_score must be between 0 and 100
- be concise and practical
- use the finding fields exactly as provided
- prioritize exploitation risk and business impact

Product: ${product.name}

Findings:
${JSON.stringify(selected, null, 2)}
`;

    const { raw } = await callGeminiWithGrounding(prompt);

   
   const parsed = safeParseJSON(raw);

if (!parsed) {
  throw new Error("Invalid JSON from AI");
}

    return res.json({
      parsed_findings_count: findings.length,
      ai_result: parsed,
    });
  } catch (error) {
    console.error("AI from ZAP error:", error.response?.data || error.message);
    return res.status(500).json({ error: "AI from ZAP failed" });
  }
});
///////////////////////////////////////////////////////
// AI RECOMMENDATIONS (Groq) + STORE SOLUTION IN DB
///////////////////////////////////////////////////////
app.post("/api/ai/recommendations", async (req, res) => {
  try {
    const { product, vulnerabilities } = req.body;

    if (!vulnerabilities?.length) {
      return res.json({ items: [] });
    }

    const MAX_ITEMS = 5;
    const selected = vulnerabilities.slice(0, MAX_ITEMS);
    const findingIds = selected.map((v) => v.id);

    // 1) Vérifier si les recommendations existent déjà
    const existing = await pool.query(
      `SELECT
    id,
    finding_id,
    content,
    status,
    created_at,
    cvss_score,
    cvss_vector,
    ai_risk_score,
    confidence,
    false_positive_likelihood,
    priority,
    attack_complexity,
    privileges_required,
    user_interaction,
    owasp_category,
    code_fix_example
   FROM finding_recommendations
   WHERE finding_id = ANY($1::int[])
     AND status = 'proposed'
   ORDER BY created_at DESC`,
      [findingIds],
    );

    if (existing.rows.length > 0) {
      const items = existing.rows.map((row) => {
        const vuln = selected.find(
          (v) => Number(v.id) === Number(row.finding_id),
        );
        return {
          ...row,
          title: vuln?.title || "Vulnerability",
        };
      });

      return res.json({
        items,
        source: "database",
      });
    }
    // On veut 1 recommendation proposed par finding
    const existingMap = new Map();
    for (const row of existing.rows) {
      if (!existingMap.has(row.finding_id)) {
        existingMap.set(row.finding_id, row);
      }
    }

    // Si toutes existent déjà, on les retourne directement
    if (existingMap.size === findingIds.length) {
      const items = selected
        .map((v) => {
          const rec = existingMap.get(v.id);
          if (!rec) return null;
          return {
            ...rec,
            title: v.title,
          };
        })
        .filter(Boolean);

      return res.json({ items, source: "database" });
    }
    const productRow = await pool.query(
      `SELECT zap_report_path FROM products WHERE name = $1`,
      [product],
    );
    const zapPath = productRow.rows[0]?.zap_report_path;
    let zapMap = new Map();

    if (zapPath) {
      const fullPath = path.resolve(__dirname, zapPath);
      const zapFindings = parseZapHtmlFile(fullPath);
      zapFindings.forEach((z) => zapMap.set(z.title?.trim(), z));
    }
    // 2) Sinon on génère avec Groq
    const summary = selected.map((v) => {
      const zap = zapMap.get(v.title?.trim()) || {};
      return {
        finding_id: v.id,
        title: v.title,
        severity: v.severity,
        scanner: v.scanner,
        description: v.description || zap.description || "",
        url: zap.url || "",
        method: zap.method || "",
        parameter: zap.parameter || "",
        attack: zap.attack || "",
        evidence: zap.evidence || "",
        solution: zap.solution || "",
        reference: zap.reference || "",
        cwe: zap.cwe || "",
      };
    });

    // APRÈS - par ça :
    const prompt = `
You are a senior Application Security Engineer analyzing vulnerabilities from a security scan.

Return ONLY valid JSON in this exact format:

{
  "items": [
    {
      "finding_id": number,
      "title": string,
      "owasp_category": string,
      "cvss_score": number,
      "cvss_vector": string,
      "exploit_scenario": string,
      "impact": string,
      "remediation": string,
      "priority": "Critical|High|Medium|Low",
      "ai_risk_score": number,
      "code_fix_example": string,
      "confidence": number,
      "false_positive_likelihood": "Low|Medium|High",
      "attack_complexity": "Low|High",
      "privileges_required": "None|Low|High",
      "user_interaction": "None|Required"
    }
  ]
}

Rules:
- cvss_score: between 0.0 and 10.0, based on url, method, parameter, attack, evidence
- cvss_vector: CVSS v3.1 vector string (ex: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- ai_risk_score: between 0 and 100, your own contextual risk assessment
- confidence: between 0 and 100, how confident you are this is a real vulnerability
- false_positive_likelihood: based on evidence and attack fields
- exploit_scenario: concrete real-world attack scenario using the url, method, parameter and attack fields
- impact: business and technical impact
- remediation: explain the fix clearly with OWASP reference
- priority: based on cvss_score + context
- be concise, practical, and specific to the actual finding data

- code_fix_example: return ONE short secure fix command/config line only
- code_fix_example: maximum 180 characters
- code_fix_example: no raw newlines
- code_fix_example: no markdown
- code_fix_example: escape quotes
- NEVER generate long code
- NEVER break JSON
- ALWAYS close strings

Product: ${product}

Findings JSON:
${JSON.stringify(summary, null, 2)}
`;

   const { raw } = await callGeminiWithGrounding(prompt);

   

    const parsed = safeParseJSON(raw);

if (!parsed) {
  throw new Error("Invalid JSON from AI");
}

    const items = Array.isArray(parsed.items) ? parsed.items : [];
    const saved = [];

    for (const it of items) {
      if (!it?.finding_id) continue;

      const content = `
**Exploit Scenario:** ${it.exploit_scenario || ""}

**Impact:** ${it.impact || ""}

**Remediation:** ${it.remediation || ""}

**OWASP:** ${it.owasp_category || ""}
  `.trim();

      const r = await pool.query(
        `INSERT INTO finding_recommendations (
      finding_id, content, status,
      cvss_score, cvss_vector, ai_risk_score, confidence,
      false_positive_likelihood, priority, attack_complexity,
      privileges_required, user_interaction, owasp_category, code_fix_example
    )
    VALUES ($1,$2,'proposed',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT ON CONSTRAINT unique_proposed_per_finding
    DO UPDATE SET
      content = EXCLUDED.content,
      code_fix_example = EXCLUDED.code_fix_example,
      cvss_score = EXCLUDED.cvss_score,
      cvss_vector = EXCLUDED.cvss_vector,
      ai_risk_score = EXCLUDED.ai_risk_score,
      confidence = EXCLUDED.confidence,
      false_positive_likelihood = EXCLUDED.false_positive_likelihood,
      priority = EXCLUDED.priority,
      attack_complexity = EXCLUDED.attack_complexity,
      privileges_required = EXCLUDED.privileges_required,
      user_interaction = EXCLUDED.user_interaction,
      owasp_category = EXCLUDED.owasp_category
    RETURNING *`,
        [
          it.finding_id,
          content,
          it.cvss_score || null,
          it.cvss_vector || null,
          it.ai_risk_score || null,
          it.confidence || null,
          it.false_positive_likelihood || null,
          it.priority || null,
          it.attack_complexity || null,
          it.privileges_required || null,
          it.user_interaction || null,
          it.owasp_category || null,
          it.code_fix_example || null,
        ],
      );

      saved.push({ ...r.rows[0], title: it.title });
    }

    return res.json({ items: saved, source: "generated" });
  } catch (error) {
    console.error(
      "AI recommendations error:",
      error.response?.data || error.message,
    );
    return res.status(500).json({ error: "AI recommendations failed" });
  }
});

app.post("/api/ai/analyze", async (req, res) => {
  const client = await pool.connect();
  let txStarted = false;

  try {
    const { product, vulnerabilities } = req.body;

    if (!vulnerabilities?.length) {
      return res.json({ items: [] });
    }

    const MAX_ITEMS = 5;
    const selected = vulnerabilities.slice(0, MAX_ITEMS);
    const findingIds = selected.map((v) => v.id);

    const existing = await client.query(
      `SELECT *
       FROM finding_ai_analysis
       WHERE finding_id = ANY($1::int[])
       ORDER BY created_at DESC`,
      [findingIds],
    );

    if (existing.rows.length === findingIds.length) {
      return res.json({ items: existing.rows });
    }

    const summary = selected.map((v) => ({
      finding_id: v.id,
      title: v.title,
      severity: v.severity,
      scanner: v.scanner,
      description: v.description || "",
      url: v.url || "",
      method: v.method || "",
      parameter: v.parameter || "",
      attack: v.attack || "",
      evidence: v.evidence || "",
      solution: v.solution || "",
      reference: v.reference || "",
      cwe: v.cwe || "",
      plugin_id: v.plugin_id || "",
    }));

    const prompt = `
You are a senior Application Security Engineer analyzing vulnerabilities from a security scan.

Return ONLY valid JSON in this exact format:

{
  "items": [
    {
      "finding_id": number,
      "title": string,
      "owasp_category": string,
      "cvss_score": number,
      "cvss_vector": string,
      "exploit_scenario": string,
      "impact": string,
      "remediation": string,
      "code_fix_example": string,
      "priority": "Critical|High|Medium|Low",
      "ai_risk_score": number,
      "confidence": number,
      "false_positive_likelihood": "Low|Medium|High",
      "attack_complexity": "Low|High",
      "privileges_required": "None|Low|High",
      "user_interaction": "None|Required"
    }
  ]
}

Rules:
- remediation: explain the fix
- code_fix_example: provide REAL secure code example (Node.js, Java, or generic depending on context)
- include headers, middleware or config if needed
- be concise and practical

Product: ${product}

Findings JSON:
${JSON.stringify(summary, null, 2)}
`;

    const { raw } = await callGeminiWithGrounding(prompt);

    
  const parsed = safeParseJSON(raw);

if (!parsed) {
  throw new Error("Invalid JSON from AI");
}

    const items = Array.isArray(parsed.items) ? parsed.items : [];

    await client.query("BEGIN");
    txStarted = true;

    const saved = [];

    for (const it of items) {
      if (!it?.finding_id) continue;

      const r = await client.query(
        `INSERT INTO finding_ai_analysis (
          finding_id,
          title,
          risk_analysis,
          exploit_explanation,
          impact,
          remediation,
          secure_code_example,
          owasp_reference,
          attack_complexity,
          exploitability,
          business_risk,
          recommended_priority,
          risk_score,
          updated_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
        ON CONFLICT (finding_id)
        DO UPDATE SET
          title = EXCLUDED.title,
          risk_analysis = EXCLUDED.risk_analysis,
          exploit_explanation = EXCLUDED.exploit_explanation,
          impact = EXCLUDED.impact,
          remediation = EXCLUDED.remediation,
          secure_code_example = EXCLUDED.secure_code_example,
          owasp_reference = EXCLUDED.owasp_reference,
          attack_complexity = EXCLUDED.attack_complexity,
          exploitability = EXCLUDED.exploitability,
          business_risk = EXCLUDED.business_risk,
          recommended_priority = EXCLUDED.recommended_priority,
          risk_score = EXCLUDED.risk_score,
          updated_at = now()
        RETURNING *`,
        [
          it.finding_id,
          it.title || "",
          it.risk_analysis || "",
          it.exploit_explanation || "",
          it.impact || "",
          it.remediation || "",
          it.secure_code_example || "",
          it.owasp_reference || "",
          it.attack_complexity || "",
          it.exploitability || "",
          it.business_risk || "",
          it.recommended_priority || "",
          it.risk_score || 0,
        ],
      );

      saved.push(r.rows[0]);
    }

    await client.query("COMMIT");
    return res.json({ items: saved });
  } catch (error) {
    if (txStarted) await client.query("ROLLBACK");
    console.error("AI analyze error:", error.response?.data || error.message);
    return res.status(500).json({ error: "AI analysis failed" });
  } finally {
    client.release();
  }
});
app.get("/api/findings/:id/ai-analysis", async (req, res) => {
  try {
    const findingId = req.params.id;

    const { rows } = await pool.query(
      `SELECT *
       FROM finding_ai_analysis
       WHERE finding_id = $1`,
      [findingId],
    );

    if (!rows[0]) {
      return res.status(404).json({ error: "AI analysis not found" });
    }

    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch AI analysis" });
  }
});

app.get(
  "/api/repositories/:id/prioritized-findings",

  async (req, res) => {
    try {
      const productId = req.params.id;

      const { rows } = await pool.query(
        `SELECT
         f.*,
         a.risk_analysis,
         a.exploit_explanation,
         a.impact,
         a.remediation,
         a.secure_code_example,
         a.owasp_reference,
         a.attack_complexity,
         a.exploitability,
         a.business_risk,
         a.recommended_priority,
         a.risk_score
       FROM findings f
       LEFT JOIN finding_ai_analysis a ON a.finding_id = f.id
       WHERE f.product_id = $1
       ORDER BY a.risk_score DESC NULLS LAST, f.created_at DESC`,
        [productId],
      );

      res.json(rows);
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: "Failed to fetch prioritized findings" });
    }
  },
);
function computePriorityScore(finding, ai) {
  let score = 0;

  const severityMap = {
    Critical: 40,
    High: 30,
    Medium: 20,
    Low: 10,
    Informational: 0,
  };

  const levelMap = {
    High: 20,
    Medium: 10,
    Low: 5,
  };

  score += severityMap[finding.severity] || 0;
  score += levelMap[ai.exploitability] || 0;
  score += levelMap[ai.business_risk] || 0;

  if ((finding.url || "").includes("/admin")) score += 10;
  if ((finding.url || "").includes("/login")) score += 10;
  if ((finding.title || "").toLowerCase().includes("injection")) score += 10;
  if ((finding.title || "").toLowerCase().includes("broken access"))
    score += 10;

  return Math.min(score, 100);
}

app.post(
  "/api/recommendations/:id/approve",

  async (req, res) => {
    const recId = req.params.id;
    const userId = req.user.sub;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const rec = await client.query(
        `SELECT id, finding_id FROM finding_recommendations WHERE id = $1`,
        [recId],
      );
      if (rec.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Recommendation not found" });
      }

      const findingId = rec.rows[0].finding_id;

      // remettre à proposed l'ancienne approuvée (si existe)
      await client.query(
        `UPDATE finding_recommendations
       SET status='proposed', approved_by=NULL, approved_at=NULL
       WHERE finding_id=$1 AND status='approved'`,
        [findingId],
      );

      const updated = await client.query(
        `UPDATE finding_recommendations
       SET status='approved', approved_by=$2, approved_at=now()
       WHERE id=$1
       RETURNING *`,
        [recId, userId],
      );

      await client.query("COMMIT");
      res.json(updated.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");
      res.status(500).json({ error: "Approve failed", details: e.message });
    } finally {
      client.release();
    }
  },
);

app.post(
  "/api/recommendations/:id/reject",

  async (req, res) => {
    const recId = req.params.id;

    try {
      const { rows } = await pool.query(
        `UPDATE finding_recommendations
       SET status='rejected'
       WHERE id=$1
       RETURNING *`,
        [recId],
      );
      if (!rows[0]) return res.status(404).json({ error: "Not found" });
      res.json(rows[0]);
    } catch (e) {
      res.status(500).json({ error: "Reject failed" });
    }
  },
);

app.get(
  "/api/findings/:id/recommendations",

  async (req, res) => {
    const findingId = req.params.id;
    const { rows } = await pool.query(
      `SELECT *
     FROM finding_recommendations
     WHERE finding_id = $1
     ORDER BY created_at DESC`,
      [findingId],
    );
    res.json(rows);
  },
);

app.post(
  "/api/products/upload-zap",
  upload.single("report"),
  async (req, res) => {
    try {
      const { repo_name } = req.body;

      if (!repo_name)
        return res.status(400).json({ error: "Missing repo_name" });

      const product = await pool.query(
        `SELECT id FROM products WHERE name = $1`,
        [repo_name],
      );

      if (!product.rows[0])
        return res.status(404).json({ error: "Product not found" });

      const productId = product.rows[0].id;

      const normalizedPath = `/app/uploads/zap/${req.body.repo_name.replace(/[^a-zA-Z0-9-_]/g, "_")}-zap.html`;

      await pool.query(
        `UPDATE products
   SET zap_report_path = $1,
       zap_uploaded_at = now()
   WHERE id = $2`,
        [normalizedPath, productId],
      );

      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Upload failed" });
    }
  },
);

///////////////////////////////////////////////////////
// GET ZAP REPORT
///////////////////////////////////////////////////////

app.get("/api/products/:id/zap-report", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT zap_report_path FROM products WHERE id=$1`,
    [req.params.id],
  );

  if (!rows[0]?.zap_report_path)
    return res.status(404).json({ error: "No report found" });

  const filePath = path.resolve(__dirname, rows[0].zap_report_path);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Disposition", "inline"); // ✅ afficher dans le navigateur
  return res.sendFile(filePath);
});
app.get("/test-zap", (req, res) => {
  const file = path.join(__dirname, "uploads/zap/dvwa.html");

  const findings = parseZapHtmlFile(file);

  res.json(findings);
});

// POST /api/performance/results  ← appelé par le pipeline
// POST /api/performance/results  ← appelé par le pipeline
app.post("/api/performance/results", async (req, res) => {
  try {
    const {
      product_name,
      app_url,
      duration_secs,
      vus,
      total_requests,
      failed_requests,
      error_rate,
      avg_response_ms,
      min_response_ms,
      max_response_ms,
      p90_response_ms,
      p95_response_ms,
      throughput,
    } = req.body;

    const product = await pool.query(
      `SELECT id FROM products WHERE name = $1`,
      [product_name],
    );
    const product_id = product.rows[0]?.id || null;

    const result = await pool.query(
      `INSERT INTO performance_results (
        product_name, product_id, app_url,
        duration_secs, vus, total_requests,
        failed_requests, error_rate,
        avg_response_ms, min_response_ms, max_response_ms,
        p90_response_ms, p95_response_ms, throughput
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *`,
      [
        product_name,
        product_id,
        app_url,
        duration_secs,
        vus,
        total_requests,
        failed_requests,
        error_rate,
        avg_response_ms,
        min_response_ms,
        max_response_ms,
        p90_response_ms,
        p95_response_ms,
        throughput,
      ],
    );

    res.json({ success: true, result: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to save performance results" });
  }
});

// GET /api/performance/:productId  ← appelé par le dashboard
app.get("/api/performance/:productId", async (req, res) => {
  try {
    const productId = req.params.productId;

    const prod = await pool.query(`SELECT name FROM products WHERE id = $1`, [
      productId,
    ]);
    const productName = prod.rows[0]?.name;

    const { rows } = await pool.query(
      `SELECT * FROM performance_results
       WHERE product_id = $1 OR product_name = $2
       ORDER BY run_at DESC
       LIMIT 10`,
      [productId, productName || ""],
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: "Failed to fetch performance results" });
  }
});

///////////////////////////////////////////////////////
// START SERVER
///////////////////////////////////////////////////////
app.listen(5000, () => {
  console.log("🚀 Backend running on http://localhost:5000");
});
