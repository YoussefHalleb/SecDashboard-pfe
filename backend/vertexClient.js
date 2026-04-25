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

  if (t.includes("clickjacking"))
    return "OWASP Clickjacking Prevention Cheat Sheet frame-ancestors X-Frame-Options";

  if (t.includes("csp"))
    return "OWASP Content Security Policy XSS protection header CSP";

  if (t.includes("xss"))
    return "OWASP Cross Site Scripting Prevention Cheat Sheet output encoding";

  if (t.includes("csrf"))
    return "OWASP CSRF prevention token same-site cookies";

  return text + " OWASP security best practice vulnerability fix";
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
  .slice(0, 3) // garde seulement les 3 meilleurs docs
  .map((r) => {
    const title =
      r.document?.derivedStructData?.fields?.title?.stringValue || "";

    const answers =
      r.document?.derivedStructData?.fields?.extractive_answers?.listValue
        ?.values || [];

    const snippets = answers
      .slice(0, 2) // prend 2 passages par document
      .map(
        (a) => a.structValue?.fields?.content?.stringValue || ""
      )
      .filter(Boolean)
      .join(" ");

    return `[${title}]: ${snippets}`;
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

Use OWASP documents when available.
If OWASP context is insufficient, use secure coding best practices.

Return ONLY valid JSON.
Do not use markdown.
Do not use triple backticks.
- exploit_scenario must be complete and detailed (2-3 sentences)
- remediation must always be present and complete
- do not cut sentences
- ensure all fields are filled
CRITICAL JSON RULES:
- JSON must be complete and valid
- NEVER truncate output
- ALWAYS close strings
- code_fix_example must be a single-line JSON string
- code_fix_example must not contain raw line breaks
- Escape all double quotes inside code_fix_example with \\"
- Replace all newlines in code_fix_example with \\n

SECURE CODE RULES:
- code_fix_example must FIX the vulnerability securely
- NEVER return vulnerable code
- ALWAYS validate user input
- ALWAYS enforce correct data types
- NEVER pass raw user input directly into database queries
- For NoSQL injection, reject objects/operators like $ne, $gt, $regex
- For NoSQL injection, use $eq or strict typed values
- For XSS, use output encoding and CSP
- For CSRF, use CSRF tokens and SameSite cookies
- For clickjacking, ALWAYS include both X-Frame-Options and Content-Security-Policy frame-ancestors
- For HTTP-only site, force HTTPS and HSTS

CODE FORMAT:
- code_fix_example maximum 180 characters
- code_fix_example no comments
- code_fix_example no explanations
- code_fix_example must be practical production-style code`,
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
