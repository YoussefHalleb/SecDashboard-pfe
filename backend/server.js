const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const cookieParser = require("cookie-parser"); 
const pool = require("./db");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const { callGeminiWithGrounding, callGemini } = require("./vertexClient");
const { parseZapHtmlFile } = require("./zapParser");
const { getSecret } = require("./secretManager");
function safeParseJSON(raw) {
  try {
    let cleaned = raw.replace(/```json|```/gi, "").trim();

    // accepte soit { ... } soit [ ... ]
    const firstObj = cleaned.indexOf("{");
    const firstArr = cleaned.indexOf("[");

    let first;
    let last;

    if (firstArr !== -1 && (firstArr < firstObj || firstObj === -1)) {
      first = firstArr;
      last = cleaned.lastIndexOf("]");
    } else {
      first = firstObj;
      last = cleaned.lastIndexOf("}");
    }

    if (first === -1 || last === -1) {
      throw new Error("No valid JSON found");
    }

    cleaned = cleaned.slice(first, last + 1);

    const parsed = JSON.parse(cleaned);

    // si Gemini retourne directement un tableau, on le transforme en { items: [...] }
    if (Array.isArray(parsed)) {
      return { items: parsed };
    }

    return parsed;
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
      "https://35.195.231.227.nip.io",
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
      sameSite: "lax", // ✅ cohérent
      secure: true, // ✅ tu es en HTTPS avec cert-manager
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
      sameSite: "lax", // ✅ cohérent
      secure: true, // ✅ tu es en HTTPS avec cert-manager
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
ON CONFLICT DO NOTHING
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

app.post("/api/products/:id/sync-zap-fields", async (req, res) => {
  try {
    const productId = req.params.id;

    const { rows } = await pool.query(
      `SELECT id, name, zap_report_path
       FROM products
       WHERE id = $1`,
      [productId],
    );

    const product = rows[0];

    if (!product?.zap_report_path) {
      return res.status(404).json({ error: "No ZAP report found" });
    }

    const fullPath = path.resolve(__dirname, product.zap_report_path);
    const zapFindings = parseZapHtmlFile(fullPath);

    let updated = 0;

    for (const z of zapFindings) {
      const result = await pool.query(
        `
        UPDATE findings
        SET
          url = COALESCE($1, url),
          method = COALESCE($2, method),
          parameter = COALESCE($3, parameter),
          attack = COALESCE($4, attack),
          evidence = COALESCE($5, evidence),
          solution = COALESCE($6, solution),
          reference = COALESCE($7, reference),
          cwe = COALESCE($8, cwe),
          plugin_id = COALESCE($9, plugin_id)
        WHERE product_id = $10
          AND LOWER(TRIM(title)) = LOWER(TRIM($11))
          AND scanner ILIKE '%ZAP%'
        `,
        [
          z.url || null,
          z.method || null,
          z.parameter || null,
          z.attack || null,
          z.evidence || null,
          z.solution || null,
          z.reference || null,
          z.cwe ? String(z.cwe) : null,
          z.plugin_id ? String(z.plugin_id) : null,
          productId,
          z.title,
        ],
      );

      updated += result.rowCount;
    }

    res.json({
      success: true,
      parsed: zapFindings.length,
      updated,
    });
  } catch (error) {
    console.error("Sync ZAP fields error:", error.message);
    res.status(500).json({ error: "Failed to sync ZAP fields" });
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

    const selected = findings;

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

app.post("/api/findings/:id/feedback", authMiddleware, async (req, res) => {
  try {
    const findingId = Number(req.params.id);
    const userId = req.user.sub;

    const {
      product_id,
      scanner_severity,
      scanner,
      system_priority,
      system_score,
      developer_priority,
      developer_score,
      developer_reason,
      is_false_positive,
      accepted_risk,
    } = req.body;

    if (!findingId) {
      return res.status(400).json({ error: "Invalid finding id" });
    }

    if (!developer_priority) {
      return res.status(400).json({ error: "developer_priority is required" });
    }

    const scoreMap = {
      Critical: 95,
      High: 75,
      Medium: 50,
      Low: 25,
      "False Positive": 0,
      "Accepted Risk": 10,
    };

    const finalDeveloperScore =
      developer_score !== undefined && developer_score !== null
        ? Number(developer_score)
        : (scoreMap[developer_priority] ?? 0);

    const result = await pool.query(
      `
      INSERT INTO finding_developer_feedback (
        finding_id,
        product_id,
        user_id,
        scanner_severity,
        scanner,
        system_priority,
        system_score,
        developer_priority,
        developer_score,
        developer_action,
        developer_reason,
        is_false_positive,
        accepted_risk
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *
      `,
      [
        findingId,
        product_id || null,
        userId,
        scanner_severity || null,
        scanner || null,
        system_priority || null,
        system_score || null,
        developer_priority,
        finalDeveloperScore,
        "priority_changed",
        developer_reason || "",
        is_false_positive || developer_priority === "False Positive",
        accepted_risk || developer_priority === "Accepted Risk",
      ],
    );

    res.json({
      success: true,
      feedback: result.rows[0],
    });
  } catch (error) {
    console.error("Developer feedback error:", error.message);
    res.status(500).json({ error: "Failed to save developer feedback" });
  }
});

app.get(
  "/api/findings/:id/feedback/latest",
  authMiddleware,
  async (req, res) => {
    try {
      const findingId = Number(req.params.id);

      const { rows } = await pool.query(
        `
      SELECT *
      FROM finding_developer_feedback
      WHERE finding_id = $1
      ORDER BY created_at DESC
      LIMIT 1
      `,
        [findingId],
      );

      res.json(rows[0] || null);
    } catch (error) {
      console.error("Get latest developer feedback error:", error.message);
      res.status(500).json({ error: "Failed to fetch developer feedback" });
    }
  },
);

app.post("/api/ml/predict-priority", async (req, res) => {
  try {
    const finding = req.body;

    const python = spawn("python", ["predict_priority.py"], {
      cwd: __dirname,
    });

    let output = "";
    let errorOutput = "";

    python.stdout.on("data", (data) => {
      output += data.toString();
    });

    python.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    python.stdin.write(JSON.stringify(finding));
    python.stdin.end();

    python.on("close", (code) => {
      if (code !== 0) {
        console.error("ML prediction error:", errorOutput);
        return res.status(500).json({
          error: "ML prediction failed",
          details: errorOutput,
        });
      }

      try {
        const result = JSON.parse(output);
        return res.json(result);
      } catch (e) {
        console.error("Invalid ML output:", output);
        return res.status(500).json({
          error: "Invalid ML output",
          raw: output,
        });
      }
    });
  } catch (error) {
    console.error("Predict priority endpoint error:", error.message);
    res.status(500).json({ error: "Prediction failed" });
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
- The root JSON must be an object with an "items" array, never a raw array.
- code_fix_example: maximum 5 lines of code, concise and focused
- code_fix_example: application-level fix only (Node.js, Express, middleware)
- code_fix_example: NO nginx/server config blocks
- code_fix_example: must be valid JSON string (escape quotes with \\")
- do not use markdown fences

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
  "risk_analysis": string,
  "exploit_explanation": string,
  "impact": string,
  "remediation": string,
  "secure_code_example": string,
  "owasp_reference": string,
  "attack_complexity": "Low|High",
  "exploitability": "Low|Medium|High",
  "business_risk": "Low|Medium|High",
  "recommended_priority": "Critical|High|Medium|Low",
  "risk_score": number
}
  ]
}

Rules:
- remediation: explain the fix
- code_fix_example: provide REAL secure code example (Node.js, Java, or generic depending on context)
- code_fix_example must fix root cause, not just block payload
- include headers, middleware or config if needed
- be concise and practical
- exploitability: High|Medium|Low based on real attack feasibility
- business_risk: High|Medium|Low based on business impact and exposed endpoint
- risk_score: 0-100 based on CVSS, exploitability, business risk and evidence
- recommended_priority must match risk_score
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

function predictPriorityBatchWithML(findings) {
  return new Promise((resolve) => {
    const python = spawn("python", ["predict_priority_batch.py"], {
      cwd: __dirname,
    });

    let output = "";
    let errorOutput = "";

    python.stdout.on("data", (data) => {
      output += data.toString();
    });

    python.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    python.stdin.write(JSON.stringify(findings));
    python.stdin.end();

    python.on("close", (code) => {
      if (code !== 0) {
        console.error("ML batch prediction failed:", errorOutput);
        return resolve([]);
      }

      try {
        return resolve(JSON.parse(output));
      } catch (e) {
        console.error("Invalid ML batch output:", output);
        return resolve([]);
      }
    });
  });
}
function extractCveId(title = "") {
  const match = title.match(/CVE-\d{4}-\d+/i);
  return match ? match[0].toUpperCase() : "";
}

function extractPackageFromTitle(title = "") {
  const parts = title.trim().split(/\s+/);
  if (parts.length >= 2 && parts[0].toUpperCase().startsWith("CVE-")) {
    return parts[1];
  }
  return "";
}

function extractInstalledVersion(title = "") {
  const parts = title.trim().split(/\s+/);
  if (parts.length >= 3 && parts[0].toUpperCase().startsWith("CVE-")) {
    return parts[2];
  }
  return "";
}

function extractFixedVersion(description = "") {
  const match = description.match(/\*\*Fixed version:\*\*\s*([^\n]+)/i);
  return match ? match[1].trim() : "";
}
async function fetchEpssForCves(cveIds) {
  try {
    const uniqueCves = [...new Set(cveIds.filter(Boolean))];

    if (!uniqueCves.length) return new Map();

    const url = `https://api.first.org/data/v1/epss?cve=${uniqueCves.join(",")}`;

    const response = await axios.get(url, { timeout: 15000 });

    const map = new Map();

    for (const item of response.data?.data || []) {
      map.set(item.cve, {
        epss_score: Number(item.epss || 0),
        epss_percentile: Number(item.percentile || 0),
      });
    }

    return map;
  } catch (e) {
    console.error("EPSS fetch failed:", e.message);
    return new Map();
  }
}
async function fetchKevCatalog() {
  try {
    const url =
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    const response = await axios.get(url, { timeout: 15000 });

    const map = new Map();

    for (const item of response.data?.vulnerabilities || []) {
      map.set(item.cveID, {
        is_kev: true,
        kev_due_date: item.dueDate || "",
        kev_vulnerability_name: item.vulnerabilityName || "",
      });
    }

    return map;
  } catch (e) {
    console.error("KEV fetch failed:", e.message);
    return new Map();
  }
}
function normalizeFinding(f, epssMap, kevMap) {
  const scanner = (f.scanner || "").toLowerCase();
  const isTrivy =
  scanner.includes("trivy") ||
  (f.title || "").toUpperCase().startsWith("CVE-");
  const isZap = scanner.includes("zap");

  if (isTrivy) {
    const cveId = extractCveId(f.title);
    const epss = epssMap.get(cveId) || {};
    const kev = kevMap.get(cveId) || {};

    return {
      finding_id: f.id,
      scanner_type: "trivy",
      vulnerability_type: "dependency_cve",

      title: f.title,
      severity: f.severity,
      description_summary: (f.description || "").split("\n").slice(0, 3).join(" "),

      cve_id: cveId,
      package_name: extractPackageFromTitle(f.title),
      installed_version: extractInstalledVersion(f.title),
      fixed_version: extractFixedVersion(f.description || ""),

      epss_score: epss.epss_score || 0,
      epss_percentile: epss.epss_percentile || 0,
      is_kev: kev.is_kev || false,
      kev_due_date: kev.kev_due_date || "",
      kev_vulnerability_name: kev.kev_vulnerability_name || "",
    };
  }

  if (isZap) {
    return {
      finding_id: f.id,
      scanner_type: "zap",
      vulnerability_type: "web_vulnerability",

      title: f.title,
      severity: f.severity,
      description_summary: (f.description || "").slice(0, 200),

      url: f.url || "",
      method: f.method || "",
      parameter: f.parameter || "",
      attack: f.attack || "",
      evidence: f.evidence || "",
      cwe: f.cwe || "",
      plugin_id: f.plugin_id || "",
    };
  }

  return {
    finding_id: f.id,
    scanner_type: "unknown",
    vulnerability_type: "unknown",
    title: f.title,
    severity: f.severity,
    description: f.description || "",
  };
}
function chunkArray(array, size) {
  const chunks = [];

  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }

  return chunks;
}
async function rankFindingsWithVertex(product, findings) {
  const cveIds = findings.map(f => extractCveId(f.title || "")).filter(Boolean);
  const epssMap = await fetchEpssForCves(cveIds);
  const kevMap = await fetchKevCatalog();
  const normalized = findings.map(f => normalizeFinding(f, epssMap, kevMap));

  const trivyFindings   = normalized.filter(f => f.scanner_type === "trivy");
  const zapFindings     = normalized.filter(f => f.scanner_type === "zap");
  const unknownFindings = normalized.filter(f => f.scanner_type === "unknown");

  let allRanking = [];

  if (trivyFindings.length > 0) {
    const ranked = await rankBatch(product, trivyFindings, "trivy");
    allRanking.push(...ranked);
  }
  if (zapFindings.length > 0) {
    const ranked = await rankBatch(product, zapFindings, "zap");
    allRanking.push(...ranked);
  }
  if (unknownFindings.length > 0) {
    const ranked = await rankBatch(product, unknownFindings, "unknown");
    allRanking.push(...ranked);
  }

  return allRanking;
}
async function rankBatch(product, findings, scannerType) {
  const batches = chunkArray(findings, 15);
  let allRanking = [];

  for (const batch of batches) {
    const prompt = buildRankPrompt(product, batch, scannerType);
    const { raw } = await callGemini(prompt);
    const parsed = safeParseJSON(raw);
    const batchRanking = Array.isArray(parsed.ordered_items)
      ? parsed.ordered_items
      : [];
    allRanking.push(...batchRanking);
  }

  // Rank local qui repart de 1 pour chaque scanner_type
  return allRanking.map((item, index) => ({
    ...item,
    rank: index + 1,
    scanner_type: scannerType,
  }));
}

function buildRankPrompt(product, batch, scannerType) {
  const baseRules = `
Return ONLY valid JSON:
{
  "ordered_items": [
    {
      "finding_id": number,
      "rank": number,
      "priority_label": "Critical|High|Medium|Low",
      "reason": string
    }
  ]
}
Rules:
- Include every finding_id exactly once.
- rank starts at 1 inside this batch.
- reason must be 1 short sentence.
- No markdown, no text outside JSON.

Product: ${product.name}
Findings:
${JSON.stringify(batch, null, 2)}
`;

  if (scannerType === "trivy") {
    return `
You are a senior DevSecOps engineer ranking container and dependency CVEs.

Prioritize in this order:
1. KEV (CISA Known Exploited Vulnerabilities) → always Critical
2. EPSS score > 0.4 → very high urgency
3. CVSS base score (higher = more urgent)
4. Fix available (fixed_version not empty) → more urgent to patch
5. Package exposure (network-reachable vs local-only)

Do NOT rank web/HTTP vulnerabilities here.
${baseRules}`;
  }

  if (scannerType === "zap") {
    return `
You are a senior Application Security Engineer ranking OWASP ZAP web vulnerabilities.

Prioritize in this order:
1. Authentication bypass, broken access control (OWASP A01, A07)
2. Injection: SQLi, XSS, SSTI, XXE, command injection
3. Sensitive data exposure on authenticated or admin endpoints
4. Evidence field confirmed + attack payload present → higher urgency
5. Sensitive URL patterns (/admin, /login, /api/payment, /auth)
6. Missing security headers → Low unless combined with other issues

Do NOT rank CVEs or dependency issues here.
${baseRules}`;
  }

  return `You are a security engineer. Rank these findings by urgency.\n${baseRules}`;
}


app.get("/api/repositories/:id/developer-rank-feedback", async (req, res) => {
  try {
    const productId = Number(req.params.id);

   const result = await pool.query(
  `
  SELECT
    f.*,
    r.ai_rank,
    r.ai_priority_label,
    r.ai_ranking_reason,
    d.developer_rank,
    d.developer_reason,
    u.email AS developer_email
  FROM developer_ranking_feedback d
  JOIN findings f ON f.id = d.finding_id
  LEFT JOIN finding_ai_ranking r ON r.finding_id = f.id
  LEFT JOIN users u ON u.id = d.user_id
  WHERE d.product_id = $1
  ORDER BY d.developer_rank ASC
  `,
  [productId]
);
    res.json({
      product_id: productId,
      count: result.rows.length,
      source: "developer-feedback-ranking",
      items: result.rows,
    });
  } catch (error) {
    console.error("Get developer ranking feedback error:", error.message);
    res.status(500).json({ error: "Failed to fetch developer ranking feedback" });
  }
});

app.post("/api/repositories/:id/ai-rank-run", async (req, res) => {
  try {
    const productId = req.params.id;

    const productResult = await pool.query(
      `SELECT id, name FROM products WHERE id = $1`,
      [productId]
    );

    const product = productResult.rows[0];

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    const findingsResult = await pool.query(
      `
      SELECT *
      FROM findings
      WHERE product_id = $1
      ORDER BY created_at DESC
      `,
      [productId]
    );

   const severityOrder = {
  Critical: 1,
  High: 2,
  Medium: 3,
  Low: 4,
};

const findings = findingsResult.rows
  .sort((a, b) => {
    const sa = severityOrder[a.severity] || 99;
    const sb = severityOrder[b.severity] || 99;

    if (sa !== sb) return sa - sb;

    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  })
  .slice(0, 100);

    res.json({
      success: true,
      message: "AI ranking started",
      count: findings.length,
    });

    setImmediate(async () => {
      try {
        const aiRanking = await rankFindingsWithVertex(product, findings);

        for (const item of aiRanking) {
         await pool.query(
  `
  INSERT INTO finding_ai_ranking (
    finding_id,
    product_id,
    ai_rank,
    ai_priority_label,
    ai_ranking_reason,
    scanner_type,
    updated_at
  )
  VALUES ($1,$2,$3,$4,$5,$6,now())
  ON CONFLICT (finding_id)
  DO UPDATE SET
    ai_rank = EXCLUDED.ai_rank,
    ai_priority_label = EXCLUDED.ai_priority_label,
    ai_ranking_reason = EXCLUDED.ai_ranking_reason,
    scanner_type = EXCLUDED.scanner_type,
    updated_at = now()
  `,
  [
    Number(item.finding_id),
    Number(productId),
    Number(item.rank),
    item.priority_label || "Low",
    item.reason || "",
    item.scanner_type || "unknown",
  ]
);
        }

        console.log("AI ranking saved for product", productId);
      } catch (e) {
        console.error("Background AI ranking failed:", e.message);
      }
    });
  } catch (error) {
    console.error("AI rank run error:", error.message);
    res.status(500).json({ error: "Failed to start AI ranking" });
  }
});

app.post("/api/repositories/:id/developer-rank-feedback", authMiddleware, async (req, res) => {
  try {
    const productId = Number(req.params.id);
    const { items } = req.body;

    if (!Array.isArray(items)) {
      return res.status(400).json({ error: "items must be an array" });
    }

    await pool.query(
      `DELETE FROM developer_ranking_feedback WHERE product_id = $1`,
      [productId]
    );

    for (const item of items) {
  await pool.query(
  `INSERT INTO developer_ranking_feedback (
    product_id, finding_id, ai_rank, developer_rank,
    ai_priority_label, developer_reason, user_id
  ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
  [productId, item.finding_id, item.ai_rank, item.developer_rank,
   item.ai_priority_label, item.developer_reason, req.user.sub]
);
    }

    res.json({
      success: true,
      saved: items.length,
    });
  } catch (error) {
    console.error("Save developer ranking feedback error:", error.message);
    res.status(500).json({ error: "Failed to save developer ranking feedback" });
  }
});

app.get("/api/repositories/:id/ai-rank-findings", async (req, res) => {
  try {
    const productId = req.params.id;

    const productResult = await pool.query(
      `SELECT id, name FROM products WHERE id = $1`,
      [productId]
    );

    const product = productResult.rows[0];

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    const result = await pool.query(
      `
      SELECT
        f.*,
        r.ai_rank,
        r.ai_priority_label,
        r.ai_ranking_reason,
        r.scanner_type,
        r.updated_at AS ai_ranking_updated_at
      FROM findings f
      LEFT JOIN finding_ai_ranking r
        ON r.finding_id = f.id
      WHERE f.product_id = $1
      ORDER BY
        CASE WHEN r.ai_rank IS NULL THEN 1 ELSE 0 END,
        r.ai_rank ASC,
        f.created_at DESC
      `,
      [productId]
    );

    res.json({
      product_id: product.id,
      product_name: product.name,
      count: result.rows.length,
      source: "database-ai-ranking",
      items: result.rows.map((row) => ({
        ...row,
        ai_rank: row.ai_rank || 9999,
        ai_priority_label: row.ai_priority_label || "Low",
        ai_ranking_reason: row.ai_ranking_reason || "Not ranked yet",
      })),
    });
  } catch (error) {
    console.error("Get AI ranking error:", error.message);
    res.status(500).json({ error: "Failed to fetch AI ranking" });
  }
});

app.get("/api/repositories/:id/prioritized-findings", async (req, res) => {
  try {
    const productId = req.params.id;

    const { rows } = await pool.query(
      `
      SELECT
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
        a.risk_score,

        r.cvss_score,
        r.ai_risk_score,
        r.confidence,
        r.false_positive_likelihood,
        r.priority,
        r.owasp_category,
        r.code_fix_example,

        df.developer_priority,
        df.developer_score,
        df.developer_reason,
        df.is_false_positive,
        df.accepted_risk,
        df.created_at AS developer_feedback_at

      FROM findings f
      LEFT JOIN finding_ai_analysis a
        ON a.finding_id = f.id
      LEFT JOIN finding_recommendations r
        ON r.finding_id = f.id AND r.status = 'proposed'
      LEFT JOIN LATERAL (
        SELECT *
        FROM finding_developer_feedback d
        WHERE d.finding_id = f.id
        ORDER BY d.created_at DESC
        LIMIT 1
      ) df ON true
      WHERE f.product_id = $1
      `,
      [productId],
    );

    const mlInput = rows.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      scanner: f.scanner,
      cwe: f.cwe || "",
      owasp_category: f.owasp_category || "",
      cvss_score: f.cvss_score || 0,
      epss_score: f.epss_score || 0,
      is_kev: f.is_kev || 0,
      url: f.url || "",
      evidence: f.evidence || "",
      attack: f.attack || "",
    }));

    const mlResults = await predictPriorityBatchWithML(mlInput);

    const mlMap = new Map(
      mlResults.map((item) => [Number(item.id), item])
    );

    const prioritized = rows.map((f) => {
      const ruleResult = computePriorityScore(f, {
        cvss_score: f.cvss_score,
        exploitability: f.exploitability,
        attack_complexity: f.attack_complexity,
        business_risk: f.business_risk,
        owasp_category: f.owasp_category,
      });

      const ml = mlMap.get(Number(f.id));

      const finalScore = ml?.ml_score ?? ruleResult.score;
      const finalLabel = ml?.ml_priority ?? priorityLabel(ruleResult.score);

      const reasons = [];

      if (ml) {
        reasons.push(`ML batch model prediction (${finalScore}pts)`);
      } else {
        reasons.push("Fallback rule-based score");
        reasons.push(...ruleResult.reasons);
      }

      if (f.developer_priority) {
        reasons.push(`Developer feedback: ${f.developer_priority}`);
      }

      return {
        ...f,

        rule_score: ruleResult.score,
        rule_label: priorityLabel(ruleResult.score),
        rule_reasons: ruleResult.reasons,

        ml_score: finalScore,
        ml_priority: finalLabel,

        priority_score: finalScore,
        priority_label: finalLabel,
        priority_reasons: reasons,
      };
    });

    prioritized.sort((a, b) => b.priority_score - a.priority_score);

    const unique = Array.from(
      new Map(
        prioritized.map((f) => [`${f.title}-${f.scanner}`, f])
      ).values(),
    );

    res.json(unique);
  } catch (error) {
    console.error("Prioritized findings error:", error.message);
    res.status(500).json({ error: "Failed to fetch prioritized findings" });
  }
});
function computePriorityScore(finding, ai = {}) {
  let score = 0;
  const reasons = [];

  // ─── 1. CVSS Score (30 pts) ───────────────────────
  const cvss = Number(ai.cvss_score || finding.cvss_score || 0);
  const cvssPoints = Math.round((cvss / 10) * 30);
  score += cvssPoints;
  if (cvss > 0) reasons.push(`CVSS ${cvss} (+${cvssPoints}pts)`);

  // ─── 2. Exploitabilité (20 pts) ──────────────────
  const exploitMap = { High: 20, Medium: 10, Low: 5 };
  const exploitVal = ai.exploitability || ai.attack_complexity || "";
  const exploitPoints = exploitMap[exploitVal] || 0;
  score += exploitPoints;
  if (exploitPoints > 0)
    reasons.push(`Exploitability ${exploitVal} (+${exploitPoints}pts)`);

  // ─── 3. Business Impact (15 pts) ─────────────────
  const businessMap = { High: 15, Medium: 8, Low: 3 };
  const businessPoints = businessMap[ai.business_risk] || 0;
  score += businessPoints;
  if (businessPoints > 0)
    reasons.push(`Business risk ${ai.business_risk} (+${businessPoints}pts)`);

  // ─── 4. Evidence / Attack proof (15 pts) ─────────
  let evidencePoints = 0;
  if (finding.evidence) {
    evidencePoints = 15;
    reasons.push("Evidence confirmed (+15pts)");
  } else if (finding.attack) {
    evidencePoints = 10;
    reasons.push("Attack vector present (+10pts)");
  } else if (finding.description) {
    evidencePoints = 5;
    reasons.push("Description only (+5pts)");
  }
  score += evidencePoints;

  // ─── 5. OWASP Category (10 pts) ──────────────────
  const owasp = (
    ai.owasp_category ||
    finding.owasp_category ||
    ""
  ).toUpperCase();
  let owaspPoints = 0;
  if (owasp.includes("A01") || owasp.includes("A02") || owasp.includes("A03")) {
    owaspPoints = 10;
  } else if (
    owasp.includes("A04") ||
    owasp.includes("A05") ||
    owasp.includes("A06")
  ) {
    owaspPoints = 7;
  } else if (owasp) {
    owaspPoints = 3;
  }
  score += owaspPoints;
  if (owaspPoints > 0)
    reasons.push(`OWASP ${owasp.slice(0, 3)} (+${owaspPoints}pts)`);

  // ─── 6. URL sensible (5 pts) ─────────────────────
  const url = (finding.url || "").toLowerCase();
  let urlPoints = 0;
  if (
    url.includes("admin") ||
    url.includes("login") ||
    url.includes("payment") ||
    url.includes("auth")
  ) {
    urlPoints = 5;
  } else if (url.includes("api") || url.includes("user")) {
    urlPoints = 3;
  }
  score += urlPoints;
  if (urlPoints > 0) reasons.push(`Sensitive URL (+${urlPoints}pts)`);

  // ─── 7. Scanner (5 pts) ──────────────────────────
  const scanner = (finding.scanner || "").toLowerCase();
  let scannerPoints = 0;
  if (scanner.includes("zap")) {
    scannerPoints = 5; // ZAP = confirmed via real HTTP request
    reasons.push("ZAP confirmed (+5pts)");
  } else if (scanner.includes("trivy")) {
    scannerPoints = 2; // Trivy = theoretical CVE
    reasons.push("Trivy theoretical (+2pts)");
  }
  score += scannerPoints;

  return {
    score: Math.min(Math.round(score), 100),
    reasons,
  };
}

function priorityLabel(score) {
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 40) return "Medium";
  return "Low";
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
app.get("/api/test-github-secret", async (req, res) => {
  try {
    const githubToken = await getSecret("github-token");

    res.json({
      ok: true,
      source: "secret-manager",
      secretName: "github-token",
      length: githubToken.length,
    });
  } catch (error) {
    console.error("GitHub Secret Manager test error:", error.message);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});
app.get("/api/test-secret-manager", async (req, res) => {
  try {
    const jwtSecret = await getSecret("jwt-secret");

    res.json({
      ok: true,
      source: "secret-manager",
      secretName: "jwt-secret",
      length: jwtSecret.length,
    });
  } catch (error) {
    console.error("Secret Manager test error:", error.message);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

async function loadRuntimeSecrets() {
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = await getSecret("jwt-secret");
  }

  if (!process.env.GITHUB_TOKEN) {
    process.env.GITHUB_TOKEN = await getSecret("github-token");
  }

  if (!process.env.DEFECTDOJO_API_KEY) {
    process.env.DEFECTDOJO_API_KEY = await getSecret("defectdojo-api-key");
  }

  console.log("✅ Runtime secrets loaded");
  console.log("JWT_SECRET length:", process.env.JWT_SECRET?.length || 0);
  console.log("GITHUB_TOKEN length:", process.env.GITHUB_TOKEN?.length || 0);
  console.log(
    "DEFECTDOJO_API_KEY length:",
    process.env.DEFECTDOJO_API_KEY?.length || 0,
  );
}

async function startServer() {
  await loadRuntimeSecrets();

  app.listen(5000, "0.0.0.0", () => {
    console.log("🚀 Backend running on http://0.0.0.0:5000");
  });
}

startServer().catch((err) => {
  console.error("❌ Failed to start backend:", err);
  process.exit(1);
});
