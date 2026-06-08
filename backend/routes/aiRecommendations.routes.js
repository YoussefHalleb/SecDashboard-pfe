const express = require("express");
const aiRecommendationsController = require("../controllers/aiRecommendations.controller");

const router = express.Router();

router.post(
  "/recommendations",
  aiRecommendationsController.generateRecommendations,
);

module.exports = router;
