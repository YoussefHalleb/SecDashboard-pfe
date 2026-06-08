const axios = require("axios");

async function triggerPipeline({ repo_url, repo_branch, app_port }) {
  const githubUrl = `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/actions/workflows/${process.env.GITHUB_WORKFLOW_FILE}/dispatches`;

  await axios.post(
    githubUrl,
    {
      ref: "main",
      inputs: {
        repo_url: repo_url || "",
        repo_branch: repo_branch || "main",
        app_port: String(app_port || "80"),
      },
    },
    {
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
      },
      timeout: 30000,
    },
  );
}

module.exports = {
  triggerPipeline,
};
