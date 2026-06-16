const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const pool = require("./db");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { createJiraIssue } = require("./jiraClient");
const { callGeminiWithGrounding, callGemini } = require("./vertexClient");
const { parseZapHtmlFile } = require("./zapParser");
const { getSecret } = require("./secretManager");
const { router: authRouter, authMiddleware } = require("./routes/auth");
const requireRole = require("./middlewares/requireRole.middleware");
const pipelineRoutes = require("./routes/pipeline.routes");
const aiRecommendationsRoutes = require("./routes/aiRecommendations.routes");
const adminRoutes = require("./routes/admin.routes");
const rankingRoutes = require("./routes/ranking.routes");
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
app.use("/auth", authRouter);
app.use("/api/admin", adminRoutes);
app.use("/api/pipeline", pipelineRoutes);
app.use("/api/ai", aiRecommendationsRoutes);
app.use("/api/repositories", rankingRoutes);
const DEFECTDOJO_URL = process.env.DEFECTDOJO_URL;
const DEFECTDOJO_TOKEN = process.env.DEFECTDOJO_API_KEY;

const headers = {
  Authorization: `Token ${DEFECTDOJO_TOKEN}`,
};

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

// GET ALL REPOSITORIES (Products + ALL Findings)
// + STORE IN POSTGRESQL
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

app.delete(
  "/api/products/:id",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
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
  },
);
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

    const mlMap = new Map(mlResults.map((item) => [Number(item.id), item]));

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
      new Map(prioritized.map((f) => [`${f.title}-${f.scanner}`, f])).values(),
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
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const recId = req.params.id;
    const userId = req.user.sub;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const recResult = await client.query(
        `SELECT r.*, f.title, f.severity, f.scanner, f.url
         FROM finding_recommendations r
         JOIN findings f ON f.id = r.finding_id
         WHERE r.id = $1`,
        [recId],
      );

      if (recResult.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Recommendation not found" });
      }

      const rec = recResult.rows[0];

      const finding = {
        title: rec.title,
        severity: rec.severity,
        scanner: rec.scanner,
        url: rec.url,
      };

      await client.query(
        `UPDATE finding_recommendations
         SET status = 'proposed', approved_by = NULL, approved_at = NULL
         WHERE finding_id = $1 AND status = 'approved'`,
        [rec.finding_id],
      );

      const updated = await client.query(
        `UPDATE finding_recommendations
         SET status = 'approved', approved_by = $2, approved_at = now()
         WHERE id = $1
         RETURNING *`,
        [recId, userId],
      );

      await client.query("COMMIT");

      const approvedRec = updated.rows[0];

      res.json({ ...approvedRec, jira_pending: true });
      const { jira_assignee_id } = req.body;

      if (rec.jira_issue_key) return;

      const userResult = await pool.query(
        `SELECT email FROM users WHERE id = $1`,
        [userId],
      );

      setImmediate(async () => {
        try {
          const { issueKey, issueUrl } = await createJiraIssue({
            recommendation: approvedRec,
            finding,
            approvedByEmail: userResult.rows[0]?.email,
            jiraAssigneeId: jira_assignee_id,
          });

          await pool.query(
            `UPDATE finding_recommendations
             SET jira_issue_key = $1,
                 jira_issue_url = $2,
                 jira_created_at = now()
             WHERE id = $3`,
            [issueKey, issueUrl, recId],
          );

          console.log(`✅ Jira ticket created: ${issueKey}`);
        } catch (jiraErr) {
          console.error("Jira ticket creation failed:", {
            message: jiraErr.message,
            status: jiraErr.response?.status,
            data: jiraErr.response?.data,
          });
        }
      });
    } catch (e) {
      await client.query("ROLLBACK");
      res.status(500).json({ error: "Approve failed", details: e.message });
    } finally {
      client.release();
    }
  },
);

app.post(
  "/api/recommendations/:id/create-jira",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    const recId = req.params.id;
    try {
      const { rows } = await pool.query(
        `SELECT r.*, f.title, f.severity, f.scanner, f.url
         FROM finding_recommendations r
         JOIN findings f ON f.id = r.finding_id
         WHERE r.id = $1 AND r.status = 'approved'`,
        [recId],
      );

      if (!rows[0]) {
        return res
          .status(404)
          .json({ error: "Approved recommendation not found" });
      }

      const rec = rows[0];

      if (rec.jira_issue_key) {
        return res.json({
          success: true,
          already_exists: true,
          jira_issue_key: rec.jira_issue_key,
          jira_issue_url: rec.jira_issue_url,
        });
      }

      const userResult = await pool.query(
        `SELECT email FROM users WHERE id = $1`,
        [req.user.sub],
      );

      const { issueKey, issueUrl } = await createJiraIssue({
        recommendation: rec,
        finding: {
          title: rec.title,
          severity: rec.severity,
          scanner: rec.scanner,
          url: rec.url,
        },
        approvedByEmail: userResult.rows[0]?.email,
      });

      await pool.query(
        `UPDATE finding_recommendations
         SET jira_issue_key  = $1,
             jira_issue_url  = $2,
             jira_created_at = now()
         WHERE id = $3`,
        [issueKey, issueUrl, recId],
      );

      res.json({
        success: true,
        jira_issue_key: issueKey,
        jira_issue_url: issueUrl,
      });
    } catch (e) {
      console.error("Manual Jira create error:", {
        message: e.message,
        status: e.response?.status,
        data: e.response?.data,
      });

      res.status(500).json({
        error: "Failed to create Jira ticket",
        details: e.response?.data || e.message,
      });
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
  if (!process.env.JIRA_BASE_URL) {
    process.env.JIRA_BASE_URL = await getSecret("jira-base-url");
  }
  if (!process.env.JIRA_EMAIL) {
    process.env.JIRA_EMAIL = await getSecret("jira-email");
  }
  if (!process.env.JIRA_API_TOKEN) {
    process.env.JIRA_API_TOKEN = await getSecret("jira-api-token");
  }
  if (!process.env.JIRA_PROJECT_KEY) {
    process.env.JIRA_PROJECT_KEY = await getSecret("jira-project-key");
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
