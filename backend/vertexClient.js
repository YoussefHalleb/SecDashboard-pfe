require("dotenv").config();
const { SearchServiceClient } = require("@google-cloud/discoveryengine").v1beta;
const { GoogleAuth } = require("google-auth-library");
const axios = require("axios");

const PROJECT_ID = process.env.GCP_PROJECT_ID;
const LOCATION = process.env.VERTEX_LOCATION || "global";
const ENGINE_ID = process.env.VERTEX_ENGINE_ID; 

const searchClient = new SearchServiceClient();

async function searchOWASPDocs(query) {
  const servingConfig =
    searchClient.projectLocationCollectionEngineServingConfigPath(
      PROJECT_ID,
      LOCATION,
      "default_collection",
      ENGINE_ID,
      "default_search",
    );

  const [results] = await searchClient.search({
    servingConfig,
    query,
    pageSize: 5,
  });

  return results || [];
}

async function callGeminiWithGrounding(userPrompt) {
  // 1) Chercher les docs OWASP pertinents
  const searchResults = await searchOWASPDocs(userPrompt.slice(0, 300));

  // 2) Extraire le texte avec la bonne structure
  const context = searchResults
    .map((r) => {
      const title =
        r.document?.derivedStructData?.fields?.title?.stringValue || "";
      const snippet =
        r.document?.derivedStructData?.fields?.extractive_answers?.listValue
          ?.values?.[0]?.structValue?.fields?.content?.stringValue || "";
      return `[${title}]: ${snippet}`;
    })
    .filter((s) => s.length > 10)
    .join("\n\n");

  console.log(`✅ ${searchResults.length} docs OWASP trouvés pour le contexte`);

  // 3) Envoyer à Gemini avec le contexte OWASP
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  });
  const authClient = await auth.getClient();
  const tokenResponse = await authClient.getAccessToken();
  const token = tokenResponse.token;

  const MODEL_ID = process.env.VERTEX_MODEL_ID || "gemini-2.5-flash";

const url = `https://aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/global/publishers/google/models/${MODEL_ID}:generateContent`;

  const body = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text: `Using these OWASP reference documents:\n\n${context}\n\n---\n\n${userPrompt}`,
          },
        ],
      },
    ],
    systemInstruction: {
      parts: [
        {
          text: `You are a senior Application Security Engineer.
Use ONLY the provided OWASP documents to generate precise remediations.
Always cite the specific OWASP cheatsheet in your remediation field.
Return ONLY valid JSON, no markdown fences, no explanation outside JSON.`,
        },
      ],
    },
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 8192,
    },
  };

  const response = await axios.post(url, body, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });

  const raw = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "";

  return { raw };
}

module.exports = { callGeminiWithGrounding };
