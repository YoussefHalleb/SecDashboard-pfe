import psycopg2
import json
import os
import requests
from sentence_transformers import SentenceTransformer
from dotenv import dotenv_values

# ======================================================
# CONFIG
# ======================================================
config = dotenv_values(".env")

DB_CONFIG = {
    "host":     config.get("DB_HOST", "localhost"),
    "port":     config.get("DB_PORT", 5432),
    "dbname":   config.get("DB_NAME"),
    "user":     config.get("DB_USER"),
    "password": config.get("DB_PASSWORD"),
}

GROQ_API_KEY = config.get("GROQ_API_KEY")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
MODEL        = "llama-3.1-8b-instant"

print("📦 Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")
print("✅ Model loaded")

# ======================================================
# RETRIEVAL — chercher les documents pertinents
# ======================================================
def retrieve(query: str, top_k: int = 5, sources: list = None) -> list:
    """
    Cherche les top_k documents les plus similaires à la query.
    sources: filtrer par source ['owasp', 'cve', 'recommendation']
    """
    # Convertir la query en vecteur
    query_vector = embedder.encode(query).tolist()
    query_vector_str = "[" + ",".join(map(str, query_vector)) + "]"

    conn = psycopg2.connect(**DB_CONFIG)
    cur  = conn.cursor()

    # Construire la query SQL avec filtre optionnel
    if sources:
        placeholders = ",".join(["%s"] * len(sources))
        sql = f"""
            SELECT
                id,
                source,
                title,
                content,
                metadata,
                1 - (embedding <=> %s::vector) AS similarity
            FROM knowledge_base
            WHERE source IN ({placeholders})
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        cur.execute(sql, [query_vector_str] + sources + [query_vector_str, top_k])
    else:
        sql = """
            SELECT
                id,
                source,
                title,
                content,
                metadata,
                1 - (embedding <=> %s::vector) AS similarity
            FROM knowledge_base
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """
        cur.execute(sql, [query_vector_str, query_vector_str, top_k])

    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id":         row[0],
            "source":     row[1],
            "title":      row[2],
            "content":    row[3],
            "metadata":   row[4],
            "similarity": round(float(row[5]), 4),
        })

    return results

# ======================================================
# BUILD CONTEXT — construire le contexte pour Groq
# ======================================================
def build_context(docs: list) -> str:
    context = ""
    for i, doc in enumerate(docs, 1):
        source_label = {
            "owasp":          "📚 OWASP Reference",
            "cve":            "🔴 CVE Reference",
            "recommendation": "✅ Previously Approved Fix",
            "zap_report":     "⚡ Similar ZAP Finding",
        }.get(doc["source"], "📄 Reference")

        context += f"""
--- [{i}] {source_label} (similarity: {doc['similarity']}) ---
Title: {doc['title']}
{doc['content'][:800]}
"""
    return context.strip()

# ======================================================
# GENERATE — générer la recommendation avec RAG
# ======================================================
def generate_rag_recommendation(finding: dict) -> dict:
    """
    finding: {
        finding_id, title, severity, scanner,
        description, url, method, parameter,
        attack, evidence, solution, cwe
    }
    """

    # 1. Construire la query de recherche
    search_query = f"""
    {finding.get('title', '')}
    {finding.get('description', '')}
    {finding.get('url', '')}
    {finding.get('cwe', '')}
    severity: {finding.get('severity', '')}
    """

    # 2. Retrieval — chercher documents pertinents
    docs = retrieve(search_query, top_k=5)

    if not docs:
        print(f"  ⚠️  No relevant documents found for: {finding.get('title')}")
        context = "No relevant context found."
    else:
        context = build_context(docs)
        print(f"  📎 Found {len(docs)} relevant documents:")
        for doc in docs:
            print(f"     [{doc['source']}] {doc['title']} (similarity: {doc['similarity']})")

    # 3. Augmented prompt
    prompt = f"""
You are a senior Application Security Engineer.
You have access to a knowledge base with OWASP references, CVE data, and previously approved security fixes.

Use the provided context to generate a precise, contextual security recommendation.

=== KNOWLEDGE BASE CONTEXT ===
{context}

=== VULNERABILITY TO ANALYZE ===
Finding ID  : {finding.get('finding_id')}
Title       : {finding.get('title')}
Severity    : {finding.get('severity')}
Scanner     : {finding.get('scanner')}
URL         : {finding.get('url', 'N/A')}
Method      : {finding.get('method', 'N/A')}
Parameter   : {finding.get('parameter', 'N/A')}
Attack      : {finding.get('attack', 'N/A')}
Evidence    : {finding.get('evidence', 'N/A')}
Description : {finding.get('description', 'N/A')}
CWE         : {finding.get('cwe', 'N/A')}

=== INSTRUCTIONS ===
Return ONLY valid JSON:

{{
  "finding_id": number,
  "title": string,
  "owasp_category": string,
  "cvss_score": number,
  "cvss_vector": string,
  "exploit_scenario": string,
  "impact": string,
  "remediation": string,
  "priority": "Critical|High|Medium|Low",
  "ai_risk_score": number,
  "confidence": number,
  "false_positive_likelihood": "Low|Medium|High",
  "attack_complexity": "Low|High",
  "privileges_required": "None|Low|High",
  "user_interaction": "None|Required",
  "rag_sources": [string],
  "similar_fixes": [string]
}}

Rules:
- owasp_category: use EXACTLY the OWASP category from context if found
- cvss_score: 0.0-10.0 based on vulnerability details
- exploit_scenario: concrete attack using url, method, parameter, attack fields
- remediation: specific fix based on previously approved fixes if available
- rag_sources: list the titles of context documents you used
- similar_fixes: list any similar approved fixes found in context
- ai_risk_score: 0-100 contextual risk score
- confidence: 0-100 how confident this is a real vulnerability
"""

    # 4. Appel Groq
    response = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json",
        },
        json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "You are a senior application security engineer. Return only valid JSON."},
                {"role": "user",   "content": prompt},
            ],
            "temperature": 0.1,
        }
    )

    raw     = response.json()["choices"][0]["message"]["content"]
    cleaned = raw.replace("```json", "").replace("```", "").strip()

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        result = {
            "finding_id":               finding.get("finding_id"),
            "title":                    finding.get("title"),
            "owasp_category":           "Unknown",
            "cvss_score":               0,
            "exploit_scenario":         raw,
            "impact":                   "",
            "remediation":              "",
            "priority":                 "Medium",
            "ai_risk_score":            50,
            "confidence":               50,
            "false_positive_likelihood":"Medium",
            "attack_complexity":        "Low",
            "privileges_required":      "None",
            "user_interaction":         "None",
            "rag_sources":              [],
            "similar_fixes":            [],
        }

    result["retrieved_docs"] = docs
    return result

# ======================================================
# PROCESS MULTIPLE FINDINGS
# ======================================================
def process_findings(findings: list) -> list:
    results = []
    for i, finding in enumerate(findings, 1):
        print(f"\n🔍 Processing [{i}/{len(findings)}]: {finding.get('title')}")
        result = generate_rag_recommendation(finding)
        results.append(result)
    return results

# ======================================================
# TEST
# ======================================================
if __name__ == "__main__":
    print("\n🧪 Testing RAG System")
    print("=" * 60)

    test_findings = [
        {
            "finding_id": 1,
            "title":       "SQL Injection",
            "severity":    "High",
            "scanner":     "ZAP Scan",
            "url":         "http://localhost/dvwa/login.php",
            "method":      "POST",
            "parameter":   "username",
            "attack":      "' OR '1'='1",
            "evidence":    "You have an error in your SQL syntax",
            "description": "SQL injection may be possible",
            "cwe":         "CWE-89",
        },
        {
            "finding_id": 2,
            "title":       "Cross Site Scripting (Reflected)",
            "severity":    "Medium",
            "scanner":     "ZAP Scan",
            "url":         "http://localhost/dvwa/xss.php",
            "method":      "GET",
            "parameter":   "name",
            "attack":      "<script>alert(1)</script>",
            "evidence":    "<script>alert(1)</script>",
            "description": "XSS attack possible via reflected input",
            "cwe":         "CWE-79",
        },
    ]

    results = process_findings(test_findings)

    print("\n" + "=" * 60)
    print("📊 RAG RESULTS")
    print("=" * 60)

    for r in results:
        print(f"\n🔎 {r.get('title')} (Finding #{r.get('finding_id')})")
        print(f"   Priority      : {r.get('priority')}")
        print(f"   CVSS Score    : {r.get('cvss_score')}")
        print(f"   AI Risk Score : {r.get('ai_risk_score')}")
        print(f"   Confidence    : {r.get('confidence')}%")
        print(f"   OWASP         : {r.get('owasp_category')}")
        print(f"   False Positive: {r.get('false_positive_likelihood')}")
        print(f"\n   Exploit:")
        print(f"   {r.get('exploit_scenario', '')[:200]}")
        print(f"\n   Remediation:")
        print(f"   {r.get('remediation', '')[:200]}")
        print(f"\n   RAG Sources used:")
        for src in r.get("rag_sources", []):
            print(f"   - {src}")
        print(f"\n   Similar Fixes:")
        for fix in r.get("similar_fixes", []):
            print(f"   - {fix}")
        print("-" * 60)

    print("\n✅ RAG Test Complete!")
    print("👉 Next: integrate rag.py into Node.js backend")