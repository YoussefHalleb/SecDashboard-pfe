import os
import sys
import json
import joblib
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "priority_modell.pkl")


def label_from_score(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def normalize_url_type(url, title):
    text = f"{url or ''} {title or ''}".lower()

    if any(x in text for x in ["admin", "403", "access control", "bypass"]):
        return "admin"
    if any(x in text for x in ["login", "auth", "token", "session"]):
        return "login"
    if "api" in text:
        return "api"
    if any(x in text for x in ["dev", "test"]):
        return "dev"
    if any(x in text for x in ["lib", "openssl", "zlib", "crypto", "ssl"]):
        return "runtime"

    return "public"


def build_row(finding):
    title = finding.get("title", "") or ""
    cwe = finding.get("cwe", "") or ""
    owasp_category = finding.get("owasp_category", "") or ""
    url = finding.get("url", "") or ""

    return {
        "id": finding.get("id"),
        "text": f"{title} {cwe} {owasp_category}",
        "severity": finding.get("severity", "Unknown") or "Unknown",
        "scanner": finding.get("scanner", "Unknown") or "Unknown",
        "url_type": normalize_url_type(url, title),
        "cvss_score": float(finding.get("cvss_score") or 0),
        "epss_score": float(finding.get("epss_score") or 0),
        "is_kev": int(bool(finding.get("is_kev", False))),
        "has_evidence": int(bool(finding.get("evidence"))),
        "has_attack": int(bool(finding.get("attack"))),
    }


def predict_batch(findings):
    model = joblib.load(MODEL_PATH)

    rows = [build_row(f) for f in findings]
    df = pd.DataFrame(rows)

    X = df[
        [
            "text",
            "severity",
            "scanner",
            "url_type",
            "cvss_score",
            "epss_score",
            "is_kev",
            "has_evidence",
            "has_attack",
        ]
    ]

    scores = model.predict(X)

    results = []
    for i, score in enumerate(scores):
        score = max(0, min(100, round(float(score), 2)))

        results.append({
            "id": rows[i]["id"],
            "ml_score": score,
            "ml_priority": label_from_score(score),
        })

    return results


if __name__ == "__main__":
    raw = sys.stdin.read()

    if not raw.strip():
        print(json.dumps({
            "error": "No input JSON provided"
        }))
        sys.exit(1)

    findings = json.loads(raw)

    if not isinstance(findings, list):
        print(json.dumps({
            "error": "Input must be a list of findings"
        }))
        sys.exit(1)

    result = predict_batch(findings)
    print(json.dumps(result))
