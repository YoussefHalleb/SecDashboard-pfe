const recommendationAiService = require("../services/recommendationAi.service");

async function generateRecommendations(req, res) {
  try {
    const { product, vulnerabilities } = req.body;

    if (!product || typeof product !== "string") {
      return res.status(400).json({
        error: "product is required",
      });
    }

    if (!Array.isArray(vulnerabilities)) {
      return res.status(400).json({
        error: "vulnerabilities must be an array",
      });
    }

    const result = await recommendationAiService.generateRecommendations({
      product,
      vulnerabilities,
    });

    return res.json(result);
  } catch (error) {
    console.error(
      "AI recommendations error:",
      error.response?.data || error.message,
    );

    return res.status(500).json({
      error: "AI recommendations failed",
      details: error.message,
    });
  }
}

module.exports = {
  generateRecommendations,
};
