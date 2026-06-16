const axios = require("axios");
const { callGemini } = require("../vertexClient");
const safeParseJSON = require("../utils/safeParseJSON");
const rankingRepository = require("../repositories/ranking.repository");

const {
  extractCveId,
  chunkArray,
  normalizeFinding,
} = require("../utils/ranking.utils");

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

async function rankFindingsWithVertex(product, findings) {
  const cveIds = findings
    .map((f) => extractCveId(f.title || ""))
    .filter(Boolean);

  const epssMap = await fetchEpssForCves(cveIds);
  const kevMap = await fetchKevCatalog();

  const normalized = findings.map((f) => normalizeFinding(f, epssMap, kevMap));

  const trivyFindings = normalized.filter((f) => f.scanner_type === "trivy");
  const zapFindings = normalized.filter((f) => f.scanner_type === "zap");
  const unknownFindings = normalized.filter(
    (f) => f.scanner_type === "unknown",
  );

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

  const developerFeedback =
    await rankingRepository.getDeveloperRankingFeedbackForVertex(
      product.id,
      scannerType,
      findings,
    );

  let datasetExamples = [];

  if (scannerType === "trivy") {
    datasetExamples = await rankingRepository.getTrivyDatasetExamples(
      product.id,
    );
  }

  if (scannerType === "zap") {
    datasetExamples = await rankingRepository.getOwaspDatasetExamples(
      product.id,
    );
  }

  console.log(
    `📚 Dataset examples for ${scannerType}: ${datasetExamples.length}`,
  );

  for (const batch of batches) {
    const prompt = buildRankPrompt(
      product,
      batch,
      scannerType,
      developerFeedback,
      datasetExamples,
    );

    let parsed = { ordered_items: [] };

    try {
      const { raw } = await callGemini(prompt);
      parsed = safeParseJSON(raw);
    } catch (error) {
      console.error("AI ranking batch failed:", error.message);
    }

    const batchRanking = Array.isArray(parsed.ordered_items)
      ? parsed.ordered_items
      : [];

    const rankedIds = new Set(
      batchRanking.map((item) => Number(item.finding_id)),
    );

    const missingItems = batch
      .filter((finding) => !rankedIds.has(Number(finding.id)))
      .map((finding) => ({
        finding_id: finding.id,
        rank: 9999,
        priority_label: finding.severity || "Low",
        reason: "Fallback ranking because AI did not return this finding.",
      }));

    const enrichedRanking = [...batchRanking, ...missingItems].map((item) => {
      const original = batch.find(
        (f) => Number(f.id) === Number(item.finding_id),
      );

      return {
        ...item,

        cve_id: original?.cve_id || "",
        package_name: original?.package_name || "",
        installed_version: original?.installed_version || "",
        fixed_version: original?.fixed_version || "",
        epss_score: original?.epss_score || 0,
        epss_percentile: original?.epss_percentile || 0,
        is_kev: original?.is_kev || false,

        url: original?.url || "",
        method: original?.method || "",
        parameter: original?.parameter || "",
        attack: original?.attack || "",
        evidence: original?.evidence || "",
        cwe: original?.cwe || "",
        plugin_id: original?.plugin_id || "",
        owasp_category: original?.owasp_category || "",
      };
    });

    allRanking.push(...enrichedRanking);
  }

  return allRanking
    .sort((a, b) => Number(a.rank || 9999) - Number(b.rank || 9999))
    .map((item, index) => ({
      ...item,
      rank: index + 1,
      scanner_type: scannerType,
    }));
}

function buildRankPrompt(
  product,
  batch,
  scannerType,
  developerFeedback = [],
  datasetExamples = [],
) {
  const developerFeedbackBlock = developerFeedback.length
    ? `
===== DEVELOPER FEEDBACK (apply these learned rules) =====

${JSON.stringify(
  developerFeedback.map((f) => ({
    title: f.title,
    severity: f.severity,
    evidence_present: !!f.evidence,
    has_attack: !!f.attack,
    url: f.url || "",
    cwe: f.cwe || "",
    ai_rank_was: f.ai_rank,
    developer_corrected_to: f.developer_rank,
    direction: f.developer_rank < f.ai_rank ? "PROMOTED" : "DEMOTED",
    reason: f.developer_reason || "",
  })),
  null,
  2,
)}

Rules to extract from this feedback:
- If developer PROMOTED a finding: similar findings should rank HIGHER.
- If developer DEMOTED a finding: similar findings should rank LOWER.
- developer reason explains WHY → apply that logic to current findings.
- Developer corrections ALWAYS override default ranking rules.
==========================================================
`
    : `No previous developer feedback. Use default ranking rules only.`;

  const datasetExamplesBlock = datasetExamples.length
    ? `
===== SCANNER-SPECIFIC DATASET EXAMPLES =====

These are previous AI rankings corrected by developers.
Use them as examples to improve the current ranking.

${JSON.stringify(
  datasetExamples.map((e) => ({
    previous_product_id: e.product_id,
    title: e.title,
    severity: e.severity,

    trivy_context: {
      cve_id: e.cve_id || "",
      package_name: e.package_name || "",
      fixed_version: e.fixed_version || "",
      epss_score: e.epss_score || 0,
      epss_percentile: e.epss_percentile || 0,
      is_kev: e.is_kev || false,
    },

    owasp_context: {
      url: e.url || "",
      method: e.method || "",
      parameter: e.parameter || "",
      attack_present: !!e.attack,
      evidence_present: !!e.evidence,
      cwe: e.cwe || "",
      plugin_id: e.plugin_id || "",
      owasp_category: e.owasp_category || "",
    },

    ai_rank_was: e.ai_rank,
    ai_priority_was: e.ai_priority_label,
    ai_reason_was: e.ai_reason,
    developer_corrected_rank: e.dev_rank,
    developer_reason: e.dev_reason,
    correction_direction:
      e.dev_rank < e.ai_rank
        ? "PROMOTED"
        : e.dev_rank > e.ai_rank
          ? "DEMOTED"
          : "ACCEPTED",
  })),
  null,
  2,
)}

How to use these examples:
- If developers PROMOTED a similar finding, rank similar current findings higher.
- If developers DEMOTED a similar finding, rank similar current findings lower.
- If developers ACCEPTED the AI rank, use it as confirmation.
- Use developer_reason to understand business/security context.
- Do not copy ranks blindly; generalize the pattern.
- Do not mention dataset examples or developer feedback in the final reason.
================================================
`
    : `
No scanner-specific dataset examples are available yet.
Use default ranking rules only.
`;

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
- reason must explain only the technical/security risk.
- Do NOT mention developer feedback, developer corrections, learned rules, or previous rankings in reason.
- If developer feedback influenced the ranking, apply it silently and justify using security criteria.
- No markdown, no text outside JSON.
- Consider previous developer corrections when available.
- Use scanner-specific dataset examples when available.
- Dataset examples are more important than generic rules when they show repeated developer preferences.

For Trivy findings, prioritize using:
- scanner severity
- CVE identifier
- CISA KEV status
- EPSS score and percentile
- fixed version availability
- affected package context
- previous developer feedback

For ZAP findings, prioritize using:
- scanner severity
- sensitive URL such as admin, login, auth, payment, API
- evidence presence
- attack payload presence
- CWE and OWASP category
- previous developer feedback
- missing security headers are usually lower priority unless strong evidence exists

Product: ${product.name}

${developerFeedbackBlock}

${datasetExamplesBlock}

Current findings to prioritize:
${JSON.stringify(batch, null, 2)}
`;

  if (scannerType === "trivy") {
    return `
You are a senior DevSecOps engineer ranking container and dependency CVEs.

Default ranking rules:
1. CISA KEV vulnerabilities are highest priority.
2. High EPSS score means higher urgency.
3. Higher CVSS means higher urgency.
4. Fix available means higher remediation priority.
5. Runtime/package exposure matters.

Important:
Previous developer corrections override the default rules when relevant.

Do NOT rank web/HTTP vulnerabilities here.

${baseRules}`;
  }

  if (scannerType === "zap") {
    return `
You are a senior Application Security Engineer ranking OWASP ZAP web vulnerabilities.

Default ranking rules:
1. Authentication bypass and broken access control are highest priority.
2. Injection vulnerabilities are very urgent.
3. Sensitive data exposure on admin/auth/payment endpoints is high priority.
4. Evidence and attack payload increase urgency.
5. Sensitive URLs such as /admin, /login, /api/payment, /auth increase urgency.
6. Missing security headers are usually Low unless combined with stronger risk evidence.

Important:
Previous developer corrections override the default rules when relevant.

Do NOT rank CVEs or dependency issues here.

${baseRules}`;
  }

  return `
You are a security engineer. Rank these findings by urgency.

Important:
Previous developer corrections override default rules when relevant.

${baseRules}`;
}

module.exports = {
  rankFindingsWithVertex,
};
