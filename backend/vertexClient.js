require("dotenv").config();
const { SearchServiceClient } = require("@google-cloud/discoveryengine").v1beta;
const { GoogleAuth } = require("google-auth-library");
const axios = require("axios");

const PROJECT_ID = process.env.GCP_PROJECT_ID;
const LOCATION = process.env.VERTEX_LOCATION || "global";
const ENGINE_ID = process.env.VERTEX_ENGINE_ID;

const searchClient = new SearchServiceClient();

function normalizeQuery(text) {
  const t = text.toLowerCase();

  if (t.includes("clickjacking")) return "owasp clickjacking prevention";
  if (t.includes("content security policy") || t.includes("csp"))
    return "owasp content security policy xss prevention";
  if (t.includes("xss")) return "owasp cross site scripting prevention";
  if (t.includes("csrf")) return "owasp csrf prevention";
  if (t.includes("sql")) return "owasp sql injection prevention";

  return text + " owasp security fix";
}

async function searchOWASPDocs(query) {
  const servingConfig =
    searchClient.projectLocationCollectionEngineServingConfigPath(
      PROJECT_ID,
      LOCATION,
      "default_collection",
      ENGINE_ID,
      "default_search"
    );

  const [results] = await searchClient.search({
    servingConfig,
    query,
    pageSize: 5,
    autoPaginate: false,
  });

  return results || [];
}

async function callGeminiWithGrounding(userPrompt) {
  const searchQuery = normalizeQuery(userPrompt);
  console.log("🔍 SEARCH QUERY:", searchQuery);

  let searchResults = await searchOWASPDocs(searchQuery);

  if (!searchResults.length) {
    console.log("⚠️ Aucun résultat → fallback query");
    searchResults = await searchOWASPDocs("owasp top 10 web vulnerabilities");
  }

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

  console.log(`✅ ${searchResults.length} docs OWASP trouvés`);

  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/cloud-platform"],
  });

  const authClient = await auth.getClient();
  const token = (await authClient.getAccessToken()).token;

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
Use the provided OWASP documents when relevant.
If OWASP context is insufficient, use general secure coding best practices.

Return ONLY valid JSON.
Do not use markdown.
Do not use triple backticks.
All JSON strings must be closed.
code_fix_example must be a single-line JSON string.
code_fix_example must not contain raw line breaks.
Escape all double quotes inside code_fix_example with \\\".
Replace all newlines in code_fix_example with \\n.
Never truncate the JSON.`,
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
