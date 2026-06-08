const githubService = require("../services/github.service");

async function runPipeline(req, res) {
  try {
    const { repo_url, repo_branch, app_port } = req.body;

    if (!repo_branch) {
      return res.status(400).json({ error: "repo_branch is required" });
    }

    res.json({
      success: true,
      message: "Pipeline triggered successfully",
    });

    githubService
      .triggerPipeline({
        repo_url,
        repo_branch,
        app_port,
      })
      .catch((e) => {
        console.error("Pipeline trigger error:", e.response?.data || e.message);
      });
  } catch (error) {
    console.error(
      "Pipeline trigger error:",
      error.response?.data || error.message,
    );

    if (!res.headersSent) {
      return res.status(500).json({ error: "Failed to trigger pipeline" });
    }
  }
}

module.exports = {
  runPipeline,
};
