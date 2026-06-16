const rankingRepository = require("../repositories/ranking.repository");
const rankingService = require("../services/ranking.service");

async function getDatasetRankFindings(req, res) {
  try {
    const productId = Number(req.params.id);

    const { trivy, owasp } =
      await rankingRepository.findDatasetRankFindings(productId);

    const items = [...trivy, ...owasp];

    res.json({
      product_id: productId,
      count: items.length,
      source: "scanner-specific-ranking-datasets",
      trivy_count: trivy.length,
      owasp_count: owasp.length,
      items,
    });
  } catch (error) {
    console.error("Dataset ranking fetch error:", error.message);
    res.status(500).json({
      error: "Failed to fetch dataset ranking",
    });
  }
}

async function runAiRanking(req, res) {
  try {
    const productId = Number(req.params.id);

    if (!Number.isInteger(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }

    const product = await rankingRepository.findProductById(productId);

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    const rows = await rankingRepository.findFindingsByProductId(productId);

    if (!rows.length) {
      return res.json({
        success: true,
        message: "No findings to rank",
        count: 0,
      });
    }

    const severityOrder = {
      Critical: 1,
      High: 2,
      Medium: 3,
      Low: 4,
    };

    const findings = rows
      .sort((a, b) => {
        const sa = severityOrder[a.severity] || 99;
        const sb = severityOrder[b.severity] || 99;

        if (sa !== sb) return sa - sb;

        return (
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
      })
      .slice(0, 100);

    const aiRanking = await rankingService.rankFindingsWithVertex(
      product,
      findings,
    );

    for (const item of aiRanking) {
      const originalFinding = findings.find(
        (f) => Number(f.id) === Number(item.finding_id),
      );

      if (!originalFinding) continue;

      await rankingRepository.saveAiRanking(productId, item);

      if (item.scanner_type === "trivy") {
        await rankingRepository.saveTrivyDataset(
          productId,
          originalFinding,
          item,
        );
      }

      if (item.scanner_type === "zap") {
        await rankingRepository.saveOwaspDataset(
          productId,
          originalFinding,
          item,
        );
      }
    }

    return res.json({
      success: true,
      message: "AI ranking completed",
      count: aiRanking.length,
    });
  } catch (error) {
    console.error("AI rank run error:", error.message);
    res.status(500).json({ error: "Failed to run AI ranking" });
  }
}

async function getAiRankFindings(req, res) {
  try {
    const productId = req.params.id;

    const result = await rankingRepository.findAiRankFindings(productId);

    if (!result) {
      return res.status(404).json({ error: "Product not found" });
    }

    const { product, rows } = result;

    res.json({
      product_id: product.id,
      product_name: product.name,
      count: rows.length,
      source: "database-ai-ranking",
      items: rows.map((row) => ({
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
}

async function getDeveloperRankFeedback(req, res) {
  try {
    const productId = Number(req.params.id);

    const items = await rankingRepository.findDeveloperRankFeedback(productId);

    res.json({
      product_id: productId,
      count: items.length,
      source: "developer-feedback-ranking",
      items,
    });
  } catch (error) {
    console.error("Get developer ranking feedback error:", error.message);
    res.status(500).json({
      error: "Failed to fetch developer ranking feedback",
    });
  }
}

async function saveDeveloperRankFeedback(req, res) {
  try {
    const productId = Number(req.params.id);
    const { items } = req.body;

    if (!Array.isArray(items)) {
      return res.status(400).json({ error: "items must be an array" });
    }

    await rankingRepository.saveDeveloperRankFeedback(
      productId,
      items,
      req.user.sub,
    );

    res.json({
      success: true,
      saved: items.length,
    });
  } catch (error) {
    console.error("Save developer ranking feedback error:", error.message);
    res.status(500).json({
      error: "Failed to save developer ranking feedback",
    });
  }
}

async function getAdaptiveRankingStats(req, res) {
  try {
    const productId = Number(req.params.id);

    const stats = await rankingRepository.getAdaptiveRankingStats(productId);

    res.json({
      product_id: productId,
      trivy: stats.trivy,
      owasp: stats.owasp,
      message: "Adaptive ranking memory statistics",
    });
  } catch (error) {
    console.error("Adaptive ranking stats error:", error.message);
    res.status(500).json({
      error: "Failed to fetch adaptive ranking stats",
    });
  }
}

module.exports = {
  getDatasetRankFindings,
  runAiRanking,
  getAiRankFindings,
  getDeveloperRankFeedback,
  saveDeveloperRankFeedback,
  getAdaptiveRankingStats,
};
