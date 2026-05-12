import sys
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import lightgbm as lgb


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "trivy_lambdarank_no_api_model.txt"
METADATA_PATH = BASE_DIR / "trivy_lambdarank_no_api_metadata.json"


def extract_cve(title):
    match = re.search(r"CVE-\d{4}-\d+", str(title), re.IGNORECASE)
    return match.group(0).upper() if match else ""


def extract_package(title):
    clean = re.sub(r"CVE-\d{4}-\d+\s*", "", str(title), flags=re.IGNORECASE).strip()
    parts = clean.split()
    return parts[0].lower() if parts else "unknown"


def package_risk_score(pkg):
    pkg = str(pkg).lower()

    if any(x in pkg for x in ["libssl", "openssl"]):
        return 5
    elif any(x in pkg for x in ["libcrypto"]):
        return 4
    elif any(x in pkg for x in ["zlib"]):
        return 4
    elif any(x in pkg for x in ["linux-libc", "kernel", "linux", "libc6", "glibc", "libc"]):
        return 4
    elif any(x in pkg for x in ["jsonwebtoken", "jws", "jwt"]):
        return 4
    elif any(x in pkg for x in ["multer", "socket", "engine.io", "node", "npm", "express"]):
        return 3
    elif any(x in pkg for x in ["lodash", "minimatch", "micromatch", "tar", "sanitize-html"]):
        return 3
    elif any(x in pkg for x in ["libuuid"]):
        return 3
    elif any(x in pkg for x in ["libpng"]):
        return 2
    else:
        return 1


def priority_label_from_rank(rank):
    if rank <= 3:
        return "Critical"
    if rank <= 10:
        return "High"
    if rank <= 20:
        return "Medium"
    return "Low"


def build_features(items):
    df = pd.DataFrame(items)

    if df.empty:
        return df

    df["id"] = df.get("id", df.get("finding_id", ""))
    df["title"] = df.get("title", "")
    df["severity"] = df.get("severity", "Unknown")
    df["scanner"] = df.get("scanner", "")

    df["ai_rank"] = pd.to_numeric(df.get("ai_rank", np.nan), errors="coerce")
    df["ai_rank"] = df["ai_rank"].fillna(999)

    df["ai_level"] = df.get("ai_level", df["severity"])
    df["ai_level"] = df["ai_level"].fillna("Unknown").astype(str).str.capitalize()

    df["ai_reason"] = df.get("ai_reason", "")
    df["ai_reason"] = df["ai_reason"].fillna("No AI reason provided")

    df["cve_id"] = df["title"].apply(extract_cve)
    df["package_name"] = df["title"].apply(extract_package)

    severity_order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0,
        "Unknown": 0,
    }

    ai_level_order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0,
        "Unknown": 0,
    }

    df["scanner_severity"] = df["severity"].fillna("Unknown").astype(str).str.capitalize()

    df["severity_num"] = df["scanner_severity"].map(severity_order).fillna(0)
    df["ai_level_num"] = df["ai_level"].map(ai_level_order).fillna(0)

    text_auto = (
        df["ai_reason"].fillna("") + " " +
        df["title"].fillna("") + " " +
        df["package_name"].fillna("") + " " +
        df["scanner_severity"].fillna("") + " " +
        df["ai_level"].fillna("")
    ).str.lower()

    df["ai_reason_len"] = df["ai_reason"].str.len()

    df["has_fix"] = text_auto.str.contains(
        r"fix|patch|available fix|fix available|fixed version|patched|upgrade",
        regex=True
    ).astype(int)

    df["mentions_epss"] = text_auto.str.contains(
        r"epss|highest epss|low epss|notable epss",
        regex=True
    ).astype(int)

    df["is_rce"] = text_auto.str.contains(
        r"rce|remote code execution",
        regex=True
    ).astype(int)

    df["has_exploit"] = text_auto.str.contains(
        r"exploit|exploited|poc|proof of concept",
        regex=True
    ).astype(int)

    df["is_dos"] = text_auto.str.contains(
        r"dos|denial of service|resource exhaustion|availability",
        regex=True
    ).astype(int)

    df["is_info_disclosure"] = text_auto.str.contains(
        r"information disclosure|sensitive data|data exposure|leak|disclosure",
        regex=True
    ).astype(int)

    df["is_privilege_escalation"] = text_auto.str.contains(
        r"privilege escalation|toctou|time-of-check|time-of-use",
        regex=True
    ).astype(int)

    df["is_ssl_related"] = text_auto.str.contains(
        r"openssl|ssl|tls|libssl|libcrypto",
        regex=True
    ).astype(int)

    df["is_zlib_related"] = text_auto.str.contains(
        r"zlib|compression",
        regex=True
    ).astype(int)

    df["is_auth_related"] = text_auto.str.contains(
        r"auth|authentication|bypass",
        regex=True
    ).astype(int)

    df["is_exposed"] = text_auto.str.contains(
        r"exposed|internet|public|widely exposed|runtime risk",
        regex=True
    ).astype(int)

    df["package_risk_score"] = df["package_name"].apply(package_risk_score)

    df["same_cve_count"] = df.groupby("cve_id")["id"].transform("count")
    df["package_frequency"] = df.groupby("package_name")["id"].transform("count")

    df["repo_findings_count"] = len(df)
    df["product_findings_count"] = len(df)

    df["same_cve_count"] = df["same_cve_count"].fillna(1)

    df["severity_x_package_risk"] = df["severity_num"] * df["package_risk_score"]
    df["ai_level_x_package_risk"] = df["ai_level_num"] * df["package_risk_score"]
    df["severity_gap"] = (df["severity_num"] - df["ai_level_num"]).abs()

    df["high_ssl"] = (
        (df["severity_num"] >= 3) &
        (df["is_ssl_related"] == 1)
    ).astype(int)

    df["high_package_risk"] = (
        (df["severity_num"] >= 3) &
        (df["package_risk_score"] >= 4)
    ).astype(int)

    df["rce_with_fix"] = (
        (df["is_rce"] == 1) &
        (df["has_fix"] == 1)
    ).astype(int)

    df["medium_ssl_fix"] = (
        (df["severity_num"] == 2) &
        (df["is_ssl_related"] == 1) &
        (df["has_fix"] == 1)
    ).astype(int)

    df["ai_high_but_scanner_low"] = (
        (df["ai_level_num"] >= 3) &
        (df["severity_num"] <= 1)
    ).astype(int)

    df["scanner_high_but_ai_low"] = (
        (df["severity_num"] >= 3) &
        (df["ai_level_num"] <= 1)
    ).astype(int)

    return df


def main():
    raw = sys.stdin.read()
    items = json.loads(raw)

    if isinstance(items, dict):
        items = [items]

    with open(METADATA_PATH, "r") as f:
        metadata = json.load(f)

    features = metadata["features"]

    model = lgb.Booster(model_file=str(MODEL_PATH))

    df = build_features(items)

    if df.empty:
        print(json.dumps([]))
        return

    for col in features:
        if col not in df.columns:
            df[col] = 0

    df[features] = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)

    df["predicted_score"] = model.predict(df[features].values)

    df["predicted_rank"] = (
        df["predicted_score"]
        .rank(ascending=False, method="first")
        .astype(int)
    )

    results = []

    for _, row in df.sort_values("predicted_rank").iterrows():
        rank = int(row["predicted_rank"])

        results.append({
            "id": int(row["id"]),
            "finding_id": int(row["id"]),
            "ml_score": float(row["predicted_score"]),
            "predicted_rank": rank,
            "ml_priority": priority_label_from_rank(rank),
            "ml_reason": f"Trivy ML LambdaRank prediction: rank {rank}"
        })

    print(json.dumps(results))


if __name__ == "__main__":
    main()
