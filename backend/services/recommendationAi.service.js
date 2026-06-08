const path = require("path");
const { callGeminiWithGrounding } = require("../vertexClient");
const { parseZapHtmlFile } = require("../zapParser");
const safeParseJSON = require("../utils/safeParseJSON");
const recommendationRepository = require("../repositories/recommendation.repository");

async function generateRecommendations({ product, vulnerabilities }) {
  if (!vulnerabilities?.length) {
    return {
      items: [],
      source: "empty",
    };
  }

  const MAX_ITEMS = 5;
  const selected = vulnerabilities.slice(0, MAX_ITEMS);
  const findingIds = selected.map((v) => v.id);

  const existing =
    await recommendationRepository.findProposedByFindingIds(findingIds);

  if (existing.length > 0) {
    const items = existing.map((row) => {
      const vuln = selected.find(
        (v) => Number(v.id) === Number(row.finding_id),
      );

      return {
        ...row,
        title: vuln?.title || "Vulnerability",
      };
    });

    return {
      items,
      source: "database",
    };
  }

  const zapPath =
    await recommendationRepository.findZapReportPathByProductName(product);

  const zapMap = new Map();

  if (zapPath) {
    const fullPath = path.resolve(__dirname, "..", zapPath);
    const zapFindings = parseZapHtmlFile(fullPath);
    zapFindings.forEach((z) => zapMap.set(z.title?.trim(), z));
  }

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

  const allRaws = [];

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

    const { raw } = await callGeminiWithGrounding(prompt);
    allRaws.push(raw);

    console.log(`✅ Done vuln #${vuln.finding_id}`);
  }

  const parsed = { items: [] };

  for (const raw of allRaws) {
    const p = safeParseJSON(raw);

    if (p?.items) {
      parsed.items.push(...p.items);
    }
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
    items: saved,
    source: "generated",
  };
}

module.exports = {
  generateRecommendations,
};
