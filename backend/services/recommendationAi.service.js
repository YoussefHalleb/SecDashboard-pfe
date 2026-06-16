const path = require("path");
const { callGeminiWithGrounding, callGemini } = require("../vertexClient");
const { parseZapHtmlFile } = require("../zapParser");
const safeParseJSON = require("../utils/safeParseJSON");
const recommendationRepository = require("../repositories/recommendation.repository");

function resolveZapPath(zapPath) {
  if (!zapPath) return null;

  if (path.isAbsolute(zapPath)) {
    return zapPath;
  }

  return path.resolve(__dirname, "..", zapPath);
}

function normalizeText(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

async function callAiWithFallback(prompt) {
  try {
    const result = await callGeminiWithGrounding(prompt);

    if (result?.raw && result.raw.trim()) {
      return {
        raw: result.raw,
        ai_source: "gemini_grounding",
      };
    }

    console.warn("Gemini with grounding returned empty response");
  } catch (error) {
    console.error(
      "Gemini with grounding failed:",
      error.response?.data || error.message,
    );
  }

  try {
    const result = await callGemini(prompt);

    if (result?.raw && result.raw.trim()) {
      return {
        raw: result.raw,
        ai_source: "gemini_simple",
      };
    }

    console.warn("Gemini simple returned empty response");
  } catch (error) {
    console.error(
      "Gemini simple failed:",
      error.response?.data || error.message,
    );
  }

  return {
    raw: null,
    ai_source: "failed",
    error:
      "Both Gemini with grounding and Gemini simple failed or returned empty response",
  };
}

async function generateRecommendations({ product, vulnerabilities }) {
  if (!product || typeof product !== "string") {
    throw new Error("product is required");
  }

  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return {
      items: [],
      source: "empty",
    };
  }

  const MAX_ITEMS = 5;
  const selected = vulnerabilities.slice(0, MAX_ITEMS);

  const findingIds = selected
    .map((v) => Number(v.id))
    .filter((id) => Number.isInteger(id));

  if (findingIds.length === 0) {
    return {
      items: [],
      source: "invalid_findings",
    };
  }

  const existing =
    await recommendationRepository.findProposedByFindingIds(findingIds);

  const existingFindingIds = new Set(
    existing.map((row) => Number(row.finding_id)),
  );

  const existingItems = existing.map((row) => {
    const vuln = selected.find((v) => Number(v.id) === Number(row.finding_id));

    return {
      ...row,
      title: vuln?.title || "Vulnerability",
    };
  });

  const missing = selected.filter((v) => !existingFindingIds.has(Number(v.id)));

  if (missing.length === 0) {
    return {
      items: existingItems,
      source: "database",
    };
  }

  const zapPath =
    await recommendationRepository.findZapReportPathByProductName(product);

  const zapMap = new Map();

  if (zapPath) {
    const fullPath = resolveZapPath(zapPath);
    const zapFindings = parseZapHtmlFile(fullPath);

    for (const z of zapFindings) {
      const key = normalizeText(z.title);
      if (!key) continue;

      if (!zapMap.has(key)) {
        zapMap.set(key, []);
      }

      zapMap.get(key).push(z);
    }
  }

  const summary = missing.map((v) => {
    const matches = zapMap.get(normalizeText(v.title)) || [];
    const zap = matches[0] || {};

    return {
      finding_id: Number(v.id),
      title: v.title,
      severity: v.severity,
      scanner: v.scanner,
      description: v.description || zap.description || "",
      url: v.url || zap.url || "",
      method: v.method || zap.method || "",
      parameter: v.parameter || zap.parameter || "",
      attack: v.attack || zap.attack || "",
      evidence: v.evidence || zap.evidence || "",
      solution: v.solution || zap.solution || "",
      reference: v.reference || zap.reference || "",
      cwe: v.cwe || zap.cwe || "",
    };
  });

  const parsed = { items: [] };
  let parseErrors = 0;

  for (const vuln of summary) {
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
- cvss_vector: CVSS v3.1 vector string
- ai_risk_score: between 0 and 100
- confidence: between 0 and 100
- false_positive_likelihood: based on evidence and attack fields
- exploit_scenario: concrete real-world attack scenario using the url, method, parameter and attack fields
- impact: business and technical impact
- remediation: explain the fix clearly with OWASP reference
- priority: based on cvss_score + context
- be concise, practical, and specific to the actual finding data
- The root JSON must be an object with an "items" array, never a raw array.
- code_fix_example: maximum 5 lines of code, concise and focused
- code_fix_example: application-level fix only
- code_fix_example: NO nginx/server config blocks
- code_fix_example: must be valid JSON string
- do not use markdown fences

Product: ${product}

Findings JSON:
${JSON.stringify([vuln], null, 2)}
`;

    console.log(`🔎 Analyzing vuln #${vuln.finding_id}: ${vuln.title}`);

    const aiResult = await callAiWithFallback(prompt);

    if (!aiResult.raw) {
      parseErrors += 1;
      console.error(
        `❌ No AI response for finding #${vuln.finding_id}:`,
        aiResult.error,
      );
      continue;
    }

    const p = safeParseJSON(aiResult.raw);

    if (Array.isArray(p?.items) && p.items.length > 0) {
      parsed.items.push(...p.items);
      console.log(
        `✅ AI response for finding #${vuln.finding_id} from ${aiResult.ai_source}`,
      );
    } else {
      parseErrors += 1;
      console.error(`❌ Invalid AI JSON for finding #${vuln.finding_id}`);
    }

    console.log(`✅ Done vuln #${vuln.finding_id}`);
  }

  if (parsed.items.length === 0) {
    return {
      items: existingItems,
      source: existingItems.length
        ? "partial_database_ai_failed"
        : "ai_parse_failed",
      parse_errors: parseErrors,
    };
  }

  const saved = [];

  for (const item of parsed.items) {
    if (!item?.finding_id) continue;

    const recommendation =
      await recommendationRepository.upsertGeneratedRecommendation(item);

    saved.push({
      ...recommendation,
      title: item.title,
    });
  }

  return {
    items: [...existingItems, ...saved],
    source: existingItems.length ? "database_and_generated" : "generated",
  };
}

module.exports = {
  generateRecommendations,
};
