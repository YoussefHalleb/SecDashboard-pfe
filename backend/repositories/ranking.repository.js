const pool = require("../db");

const {
  extractCveId,
  extractPackageFromTitle,
  extractInstalledVersion,
  extractFixedVersion,
} = require("../utils/ranking.utils");

async function findProductById(productId) {
  const { rows } = await pool.query(
    `SELECT id, name FROM products WHERE id = $1`,
    [productId],
  );

  return rows[0];
}

async function findFindingsByProductId(productId) {
  const { rows } = await pool.query(
    `
    SELECT *
    FROM findings
    WHERE product_id = $1
    ORDER BY created_at DESC
    `,
    [productId],
  );

  return rows;
}

async function findDatasetRankFindings(productId) {
  const trivy = await pool.query(
    `
    SELECT
      product_id,
      finding_id AS id,
      title,
      severity,
      scanner,
      cve_id,
      package_name,
      installed_version,
      fixed_version,
      epss_score,
      epss_percentile,
      is_kev,
      ai_rank,
      ai_priority_label,
      ai_reason AS ai_ranking_reason,
      dev_rank,
      dev_reason,
      'trivy' AS scanner_type,
      updated_at
    FROM trivy_ranking_dataset
    WHERE product_id = $1
    ORDER BY ai_rank ASC
    `,
    [productId],
  );

  const owasp = await pool.query(
    `
    SELECT
      product_id,
      finding_id AS id,
      title,
      severity,
      scanner,
      url,
      method,
      parameter,
      attack,
      evidence,
      cwe,
      plugin_id,
      owasp_category,
      ai_rank,
      ai_priority_label,
      ai_reason AS ai_ranking_reason,
      dev_rank,
      dev_reason,
      'zap' AS scanner_type,
      updated_at
    FROM owasp_ranking_dataset
    WHERE product_id = $1
    ORDER BY ai_rank ASC
    `,
    [productId],
  );

  return {
    trivy: trivy.rows,
    owasp: owasp.rows,
  };
}

async function getTrivyDatasetExamples(productId) {
  const { rows } = await pool.query(
    `
    SELECT
      product_id,
      finding_id,
      title,
      severity,
      cve_id,
      package_name,
      installed_version,
      fixed_version,
      epss_score,
      epss_percentile,
      is_kev,
      ai_rank,
      ai_priority_label,
      ai_reason,
      dev_rank,
      dev_reason
    FROM trivy_ranking_dataset
    WHERE dev_rank IS NOT NULL
      AND dev_reason IS NOT NULL
      AND dev_reason <> ''
      AND product_id <> $1
    ORDER BY updated_at DESC
    LIMIT 15
    `,
    [productId],
  );

  return rows;
}

async function getOwaspDatasetExamples(productId) {
  const { rows } = await pool.query(
    `
    SELECT
      product_id,
      finding_id,
      title,
      severity,
      url,
      method,
      parameter,
      attack,
      evidence,
      cwe,
      plugin_id,
      owasp_category,
      ai_rank,
      ai_priority_label,
      ai_reason,
      dev_rank,
      dev_reason
    FROM owasp_ranking_dataset
    WHERE dev_rank IS NOT NULL
      AND dev_reason IS NOT NULL
      AND dev_reason <> ''
      AND product_id <> $1
    ORDER BY updated_at DESC
    LIMIT 15
    `,
    [productId],
  );

  return rows;
}

async function getDeveloperRankingFeedbackForVertex(
  productId,
  scannerType,
  currentFindings = [],
) {
  const titles = currentFindings.map((f) => f.title || "");

  const { rows } = await pool.query(
    `
    SELECT
      f.title,
      f.severity,
      f.scanner,
      f.url,
      f.evidence,
      f.attack,
      f.cwe,
      d.ai_rank,
      d.ai_priority_label,
      d.developer_rank,
      d.developer_reason
    FROM developer_ranking_feedback d
    JOIN findings f ON f.id = d.finding_id
    WHERE (
      $1 = 'unknown'
      OR LOWER(COALESCE(f.scanner, '')) LIKE '%' || LOWER($1) || '%'
    )
    ORDER BY
      CASE WHEN f.title = ANY($2::text[]) THEN 0 ELSE 1 END,
      d.created_at DESC
    LIMIT 20
    `,
    [scannerType, titles],
  );

  return rows;
}

async function saveAiRanking(productId, item) {
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
    ],
  );
}

async function saveTrivyDataset(productId, finding, rankingItem) {
  await pool.query(
    `
    INSERT INTO trivy_ranking_dataset (
      product_id,
      finding_id,
      title,
      severity,
      scanner,
      cve_id,
      package_name,
      installed_version,
      fixed_version,
      epss_score,
      epss_percentile,
      is_kev,
      ai_rank,
      ai_priority_label,
      ai_reason,
      updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now())
    ON CONFLICT (product_id, finding_id)
    DO UPDATE SET
      title = EXCLUDED.title,
      severity = EXCLUDED.severity,
      scanner = EXCLUDED.scanner,
      cve_id = EXCLUDED.cve_id,
      package_name = EXCLUDED.package_name,
      installed_version = EXCLUDED.installed_version,
      fixed_version = EXCLUDED.fixed_version,
      epss_score = EXCLUDED.epss_score,
      epss_percentile = EXCLUDED.epss_percentile,
      is_kev = EXCLUDED.is_kev,
      ai_rank = EXCLUDED.ai_rank,
      ai_priority_label = EXCLUDED.ai_priority_label,
      ai_reason = EXCLUDED.ai_reason,
      updated_at = now()
    `,
    [
      Number(productId),
      Number(finding.id),

      finding.title || "",
      finding.severity || "",
      finding.scanner || "Trivy",

      extractCveId(finding.title || ""),
      extractPackageFromTitle(finding.title || ""),
      extractInstalledVersion(finding.title || ""),
      extractFixedVersion(finding.description || ""),

      Number(finding.epss_score || 0),
      Number(finding.epss_percentile || 0),
      Boolean(finding.is_kev || false),

      Number(rankingItem.rank),
      rankingItem.priority_label || "Low",
      rankingItem.reason || "",
    ],
  );
}

async function saveOwaspDataset(productId, finding, rankingItem) {
  await pool.query(
    `
    INSERT INTO owasp_ranking_dataset (
      product_id,
      finding_id,
      title,
      severity,
      scanner,
      url,
      method,
      parameter,
      attack,
      evidence,
      cwe,
      plugin_id,
      owasp_category,
      ai_rank,
      ai_priority_label,
      ai_reason,
      updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,now())
    ON CONFLICT (product_id, finding_id)
    DO UPDATE SET
      title = EXCLUDED.title,
      severity = EXCLUDED.severity,
      scanner = EXCLUDED.scanner,
      url = EXCLUDED.url,
      method = EXCLUDED.method,
      parameter = EXCLUDED.parameter,
      attack = EXCLUDED.attack,
      evidence = EXCLUDED.evidence,
      cwe = EXCLUDED.cwe,
      plugin_id = EXCLUDED.plugin_id,
      owasp_category = EXCLUDED.owasp_category,
      ai_rank = EXCLUDED.ai_rank,
      ai_priority_label = EXCLUDED.ai_priority_label,
      ai_reason = EXCLUDED.ai_reason,
      updated_at = now()
    `,
    [
      Number(productId),
      Number(finding.id),

      finding.title || "",
      finding.severity || "",
      finding.scanner || "ZAP",

      finding.url || "",
      finding.method || "",
      finding.parameter || "",
      finding.attack || "",
      finding.evidence || "",
      finding.cwe || "",
      finding.plugin_id || "",
      finding.owasp_category || "",

      Number(rankingItem.rank),
      rankingItem.priority_label || "Low",
      rankingItem.reason || "",
    ],
  );
}

async function findAiRankFindings(productId) {
  const product = await findProductById(productId);

  if (!product) {
    return null;
  }

  const { rows } = await pool.query(
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
    [productId],
  );

  return {
    product,
    rows,
  };
}

async function findDeveloperRankFeedback(productId) {
  const { rows } = await pool.query(
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
    [productId],
  );

  return rows;
}

async function saveDeveloperRankFeedback(productId, items, userId) {
  for (const item of items) {
    await pool.query(
      `
      INSERT INTO developer_ranking_feedback (
        product_id,
        finding_id,
        ai_rank,
        developer_rank,
        ai_priority_label,
        developer_reason,
        user_id
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      `,
      [
        productId,
        item.finding_id,
        item.ai_rank,
        item.developer_rank,
        item.ai_priority_label,
        item.developer_reason,
        userId,
      ],
    );
  }
}

async function getAdaptiveRankingStats(productId) {
  const trivy = await pool.query(
    `
    SELECT
      COUNT(*) AS total_examples,
      COUNT(*) FILTER (WHERE dev_rank IS NOT NULL) AS feedback_examples,
      COUNT(*) FILTER (WHERE dev_rank < ai_rank) AS promoted,
      COUNT(*) FILTER (WHERE dev_rank > ai_rank) AS demoted,
      COUNT(*) FILTER (WHERE dev_rank = ai_rank) AS accepted
    FROM trivy_ranking_dataset
    WHERE product_id <> $1
    `,
    [productId],
  );

  const owasp = await pool.query(
    `
    SELECT
      COUNT(*) AS total_examples,
      COUNT(*) FILTER (WHERE dev_rank IS NOT NULL) AS feedback_examples,
      COUNT(*) FILTER (WHERE dev_rank < ai_rank) AS promoted,
      COUNT(*) FILTER (WHERE dev_rank > ai_rank) AS demoted,
      COUNT(*) FILTER (WHERE dev_rank = ai_rank) AS accepted
    FROM owasp_ranking_dataset
    WHERE product_id <> $1
    `,
    [productId],
  );

  return {
    trivy: trivy.rows[0],
    owasp: owasp.rows[0],
  };
}

module.exports = {
  findProductById,
  findFindingsByProductId,
  findDatasetRankFindings,
  getTrivyDatasetExamples,
  getOwaspDatasetExamples,
  getDeveloperRankingFeedbackForVertex,
  saveAiRanking,
  saveTrivyDataset,
  saveOwaspDataset,
  findAiRankFindings,
  findDeveloperRankFeedback,
  saveDeveloperRankFeedback,
  getAdaptiveRankingStats,
};
