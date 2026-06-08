const express = require("express");
const pipelineController = require("../controllers/pipeline.controller");

const router = express.Router();

router.post("/run", pipelineController.runPipeline);

module.exports = router;
