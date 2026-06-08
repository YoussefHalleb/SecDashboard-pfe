const express = require("express");
const rankingController = require("../controllers/ranking.controller");
const { authMiddleware } = require("./auth");

const router = express.Router();

router.get(
  "/:id/dataset-rank-findings",
  rankingController.getDatasetRankFindings,
);

router.post("/:id/ai-rank-run", rankingController.runAiRanking);

router.get("/:id/ai-rank-findings", rankingController.getAiRankFindings);

router.get(
  "/:id/developer-rank-feedback",
  rankingController.getDeveloperRankFeedback,
);

router.post(
  "/:id/developer-rank-feedback",
  authMiddleware,
  rankingController.saveDeveloperRankFeedback,
);

router.get(
  "/:id/adaptive-ranking-stats",
  rankingController.getAdaptiveRankingStats,
);

module.exports = router;
