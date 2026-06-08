const recommendationAiService = require("../services/recommendationAi.service");

async function generateRecommendations(req, res) {
  try {
    const result = await recommendationAiService.generateRecommendations(
      req.body,
    );

    return res.json(result);
  } catch (error) {
    console.error(
      "AI recommendations error:",
      error.response?.data || error.message,
    );

    return res.status(500).json({
      error: "AI recommendations failed",
    });
  }
}

module.exports = {
  generateRecommendations,
};
