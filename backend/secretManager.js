const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");

const client = new SecretManagerServiceClient();

async function getSecret(secretName) {
  const projectId = process.env.GCP_PROJECT_ID || "secdashboard-pfe";

  const [version] = await client.accessSecretVersion({
    name: `projects/${projectId}/secrets/${secretName}/versions/latest`,
  });

  return version.payload.data.toString("utf8");
}

module.exports = { getSecret };
