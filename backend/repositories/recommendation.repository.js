const pool = require("../db");

async function findProposedByFindingIds(findingIds) {
  if (!Array.isArray(findingIds) || findingIds.length === 0) {
    return [];
  }

  const { rows } = await pool.query(
    `
    SELECT
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
    ORDER BY created_at DESC
    `,
    [findingIds],
  );

  return rows;
}

async function findZapReportPathByProductName(productName) {
  if (!productName) return null;

  const { rows } = await pool.query(
    `SELECT zap_report_path FROM products WHERE name = $1`,
    [productName],
  );

  return rows[0]?.zap_report_path || null;
}

async function upsertGeneratedRecommendation(item) {
  const content = `
**Exploit Scenario:** ${item.exploit_scenario ?? ""}

**Impact:** ${item.impact ?? ""}

**Remediation:** ${item.remediation ?? ""}

**OWASP:** ${item.owasp_category ?? ""}
  `.trim();

  const { rows } = await pool.query(
    `
    INSERT INTO finding_recommendations (
      finding_id,
      content,
      status,
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
    )
    VALUES ($1,$2,'proposed',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT (finding_id) WHERE status = 'proposed'
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
      owasp_category = EXCLUDED.owasp_category,
      updated_at = now()
    RETURNING *
    `,
    [
      item.finding_id,
      content,
      item.cvss_score ?? null,
      item.cvss_vector ?? null,
      item.ai_risk_score ?? null,
      item.confidence ?? null,
      item.false_positive_likelihood ?? null,
      item.priority ?? null,
      item.attack_complexity ?? null,
      item.privileges_required ?? null,
      item.user_interaction ?? null,
      item.owasp_category ?? null,
      item.code_fix_example ?? null,
    ],
  );

  return rows[0];
}

module.exports = {
  findProposedByFindingIds,
  findZapReportPathByProductName,
  upsertGeneratedRecommendation,
};
