import psycopg2
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, precision_score,
    recall_score, f1_score, accuracy_score
)
import pickle
import os
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

OUTPUT_DIR = "models"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ======================================================
# FETCH REAL DATA FROM DB
# ======================================================
def fetch_real_data():
    conn = psycopg2.connect(**DB_CONFIG)
    query = """
        SELECT
            f.severity,
            f.scanner,
            f.title,
            r.cvss_score,
            r.ai_risk_score,
            r.confidence,
            r.false_positive_likelihood,
            r.attack_complexity,
            r.privileges_required,
            r.user_interaction,
            r.owasp_category,
            r.status
        FROM findings f
        JOIN finding_recommendations r ON r.finding_id = f.id
        WHERE r.status IN ('approved', 'rejected')
          AND r.cvss_score IS NOT NULL
    """
    df = pd.read_sql(query, conn)
    conn.close()
    print(f"✅ Real data fetched: {len(df)} records")
    print(f"   Approved: {(df['status']=='approved').sum()}")
    print(f"   Rejected: {(df['status']=='rejected').sum()}")
    return df

# ======================================================
# GENERATE SYNTHETIC DATA
# ======================================================
def generate_synthetic_data(n=400):
    np.random.seed(42)
    rows = []

    for _ in range(n):
        # Choisir un scénario réaliste
        scenario = np.random.choice([
            "true_positive_high",
            "true_positive_medium",
            "false_positive_static",
            "false_positive_low_confidence",
            "ambiguous",
        ], p=[0.25, 0.25, 0.20, 0.20, 0.10])

        if scenario == "true_positive_high":
            # Vraie vulnérabilité critique → approved
            severity         = np.random.choice(["Critical", "High"], p=[0.4, 0.6])
            cvss_score       = round(np.random.uniform(7.0, 10.0), 1)
            ai_risk_score    = np.random.randint(70, 100)
            confidence       = np.random.randint(75, 100)
            fp_likelihood    = np.random.choice(["Low", "Medium"], p=[0.85, 0.15])
            attack_complexity= np.random.choice(["Low", "High"], p=[0.75, 0.25])
            privileges       = np.random.choice(["None", "Low"], p=[0.7, 0.3])
            user_interaction = np.random.choice(["None", "Required"], p=[0.8, 0.2])
            scanner          = np.random.choice(["ZAP Scan", "Trivy Scan"], p=[0.6, 0.4])
            owasp            = np.random.choice(["Injection", "Broken Access Control", "Cryptographic Failures"])
            status           = "approved"

        elif scenario == "true_positive_medium":
            # Vulnérabilité moyenne mais réelle → approved
            severity         = np.random.choice(["High", "Medium"], p=[0.3, 0.7])
            cvss_score       = round(np.random.uniform(4.0, 7.5), 1)
            ai_risk_score    = np.random.randint(45, 75)
            confidence       = np.random.randint(60, 85)
            fp_likelihood    = np.random.choice(["Low", "Medium"], p=[0.6, 0.4])
            attack_complexity= np.random.choice(["Low", "High"], p=[0.5, 0.5])
            privileges       = np.random.choice(["None", "Low", "High"], p=[0.5, 0.3, 0.2])
            user_interaction = np.random.choice(["None", "Required"], p=[0.6, 0.4])
            scanner          = np.random.choice(["ZAP Scan", "Trivy Scan"], p=[0.5, 0.5])
            owasp            = np.random.choice(["Security Misconfiguration", "Vulnerable Components", "Injection"])
            status           = "approved"

        elif scenario == "false_positive_static":
            # Faux positif sur ressource statique → rejected
            severity         = np.random.choice(["Medium", "Low"], p=[0.5, 0.5])
            cvss_score       = round(np.random.uniform(2.0, 5.5), 1)
            ai_risk_score    = np.random.randint(10, 40)
            confidence       = np.random.randint(20, 55)
            fp_likelihood    = np.random.choice(["Medium", "High"], p=[0.4, 0.6])
            attack_complexity= "High"
            privileges       = np.random.choice(["Low", "High"], p=[0.5, 0.5])
            user_interaction = "Required"
            scanner          = "ZAP Scan"
            owasp            = np.random.choice(["Security Misconfiguration", "Insecure Design"])
            status           = "rejected"

        elif scenario == "false_positive_low_confidence":
            # Faible confiance → rejected
            severity         = np.random.choice(["Medium", "Low", "High"], p=[0.5, 0.3, 0.2])
            cvss_score       = round(np.random.uniform(1.0, 6.0), 1)
            ai_risk_score    = np.random.randint(5, 35)
            confidence       = np.random.randint(10, 45)
            fp_likelihood    = np.random.choice(["Medium", "High"], p=[0.3, 0.7])
            attack_complexity= np.random.choice(["Low", "High"], p=[0.4, 0.6])
            privileges       = np.random.choice(["Low", "High"], p=[0.5, 0.5])
            user_interaction = np.random.choice(["None", "Required"], p=[0.4, 0.6])
            scanner          = np.random.choice(["ZAP Scan", "Trivy Scan"], p=[0.5, 0.5])
            owasp            = np.random.choice(["Security Misconfiguration", "Insecure Design"])
            status           = "rejected"

        else:  # ambiguous
            # Cas ambigus → décision moins certaine
            severity         = np.random.choice(["Medium", "High"], p=[0.6, 0.4])
            cvss_score       = round(np.random.uniform(4.0, 7.0), 1)
            ai_risk_score    = np.random.randint(35, 65)
            confidence       = np.random.randint(45, 70)
            fp_likelihood    = "Medium"
            attack_complexity= np.random.choice(["Low", "High"])
            privileges       = np.random.choice(["None", "Low", "High"])
            user_interaction = np.random.choice(["None", "Required"])
            scanner          = np.random.choice(["ZAP Scan", "Trivy Scan"])
            owasp            = np.random.choice(["Injection", "Security Misconfiguration"])
            status           = np.random.choice(["approved", "rejected"], p=[0.55, 0.45])

        rows.append({
            "severity":                severity,
            "scanner":                 scanner,
            "cvss_score":              cvss_score,
            "ai_risk_score":           ai_risk_score,
            "confidence":              confidence,
            "false_positive_likelihood": fp_likelihood,
            "attack_complexity":       attack_complexity,
            "privileges_required":     privileges,
            "user_interaction":        user_interaction,
            "owasp_category":          owasp,
            "status":                  status,
            "is_synthetic":            True,
        })

    df = pd.DataFrame(rows)
    print(f"✅ Synthetic data generated: {len(df)} records")
    print(f"   Approved: {(df['status']=='approved').sum()}")
    print(f"   Rejected: {(df['status']=='rejected').sum()}")
    return df

# ======================================================
# PREPROCESS
# ======================================================
def preprocess(df):
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    df["severity_num"] = df["severity"].map(severity_map).fillna(1)

    df["scanner_num"] = df["scanner"].apply(
        lambda x: 0 if "ZAP" in str(x) else 1
    )

    df["attack_complexity_num"] = df["attack_complexity"].apply(
        lambda x: 0 if str(x).lower() == "low" else 1
    )

    priv_map = {"None": 0, "Low": 1, "High": 2}
    df["privileges_required_num"] = df["privileges_required"].map(priv_map).fillna(0)

    df["user_interaction_num"] = df["user_interaction"].apply(
        lambda x: 0 if str(x).lower() == "none" else 1
    )

    fp_map = {"Low": 0, "Medium": 1, "High": 2}
    df["fp_likelihood_num"] = df["false_positive_likelihood"].map(fp_map).fillna(1)

    # Target : approved=1, rejected=0
    df["target"] = df["status"].apply(lambda x: 1 if x == "approved" else 0)

    df["cvss_score"]    = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(0)
    df["ai_risk_score"] = pd.to_numeric(df["ai_risk_score"], errors="coerce").fillna(0)
    df["confidence"]    = pd.to_numeric(df["confidence"], errors="coerce").fillna(50)

    return df

# ======================================================
# FEATURES
# ======================================================
FEATURES = [
    "severity_num",
    "scanner_num",
    "cvss_score",
    "ai_risk_score",
    "confidence",
    "attack_complexity_num",
    "privileges_required_num",
    "user_interaction_num",
    "fp_likelihood_num",
]

# ======================================================
# CVSS BASELINE
# ======================================================
def cvss_baseline_predict(cvss_scores, threshold=4.0):
    # CVSS >= 4.0 → approve, sinon reject
    return (cvss_scores >= threshold).astype(int)

# ======================================================
# TRAIN
# ======================================================
def train(df):
    X = df[FEATURES]
    y = df["target"]

    print(f"\n📊 Target distribution:")
    print(f"   Approved (1): {(y==1).sum()} ({(y==1).mean()*100:.1f}%)")
    print(f"   Rejected (0): {(y==0).sum()} ({(y==0).mean()*100:.1f}%)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # ── Random Forest ──────────────────────────────────
    print("\n🌲 Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]

    print_metrics(y_test, rf_preds, "Random Forest")

    # ── XGBoost ───────────────────────────────────────
    print("\n⚡ Training XGBoost...")
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    xgb.fit(X_train, y_train)
    xgb_preds = xgb.predict(X_test)
    xgb_proba = xgb.predict_proba(X_test)[:, 1]

    print_metrics(y_test, xgb_preds, "XGBoost")

    # ── CVSS Baseline ─────────────────────────────────
    print("\n── CVSS Baseline (cvss >= 4.0 → approve) ──")
    cvss_preds = cvss_baseline_predict(df.loc[X_test.index, "cvss_score"])
    print_metrics(y_test, cvss_preds, "CVSS Baseline")

    # ── Compare ───────────────────────────────────────
    compare(y_test, rf_preds, xgb_preds, cvss_preds)

    # ── Feature Importance ────────────────────────────
    print("\n── Feature Importance (Random Forest) ──")
    importances = pd.Series(rf.feature_importances_, index=FEATURES)
    for feat, imp in importances.sort_values(ascending=False).items():
        bar = "█" * int(imp * 50)
        print(f"  {feat:<30} {bar} {imp:.4f}")

    # ── Save ──────────────────────────────────────────
    with open(f"{OUTPUT_DIR}/random_forest.pkl", "wb") as f:
        pickle.dump(rf, f)
    with open(f"{OUTPUT_DIR}/xgboost.pkl", "wb") as f:
        pickle.dump(xgb, f)

    print(f"\n✅ Models saved to {OUTPUT_DIR}/")
    return rf, xgb

# ======================================================
# METRICS
# ======================================================
def print_metrics(y_true, y_pred, model_name):
    print(f"\n── {model_name} ──")
    print(f"  Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
    print(f"  Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"  Recall    : {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"  F1 Score  : {f1_score(y_true, y_pred, zero_division=0):.4f}")
    print(classification_report(
        y_true, y_pred,
        target_names=["Rejected", "Approved"],
        zero_division=0
    ))

# ======================================================
# COMPARE AI vs CVSS
# ======================================================
def compare(y_test, rf_preds, xgb_preds, cvss_preds):
    total = len(y_test)

    # Faux positifs = prédit approved mais vraiment rejected
    fp_cvss = ((cvss_preds == 1) & (y_test == 0)).sum()
    fp_rf   = ((rf_preds   == 1) & (y_test == 0)).sum()
    fp_xgb  = ((xgb_preds  == 1) & (y_test == 0)).sum()

    # Faux négatifs = prédit rejected mais vraiment approved
    fn_cvss = ((cvss_preds == 0) & (y_test == 1)).sum()
    fn_rf   = ((rf_preds   == 0) & (y_test == 1)).sum()
    fn_xgb  = ((xgb_preds  == 0) & (y_test == 1)).sum()

    print(f"\n{'='*55}")
    print(f"  📊 AI vs CVSS Comparison")
    print(f"{'='*55}")
    print(f"  {'Metric':<30} {'CVSS':>6} {'RF':>6} {'XGB':>6}")
    print(f"  {'-'*50}")
    print(f"  {'False Positives':<30} {fp_cvss:>6} {fp_rf:>6} {fp_xgb:>6}")
    print(f"  {'False Negatives':<30} {fn_cvss:>6} {fn_rf:>6} {fn_xgb:>6}")
    print(f"  {'Total samples':<30} {total:>6}")

    gain_rf_fp  = (fp_cvss - fp_rf)  / max(fp_cvss, 1) * 100
    gain_xgb_fp = (fp_cvss - fp_xgb) / max(fp_cvss, 1) * 100

    print(f"\n  🎯 Gain Efficacité (vs CVSS baseline)")
    print(f"  Random Forest  : {gain_rf_fp:+.1f}% faux positifs")
    print(f"  XGBoost        : {gain_xgb_fp:+.1f}% faux positifs")

    # % vulnérabilités auto-triées correctement
    rf_correct  = (rf_preds  == y_test).sum()
    xgb_correct = (xgb_preds == y_test).sum()
    print(f"\n  ⚡ Auto-triage correct")
    print(f"  Random Forest  : {rf_correct}/{total} ({rf_correct/total*100:.1f}%)")
    print(f"  XGBoost        : {xgb_correct}/{total} ({xgb_correct/total*100:.1f}%)")
    print(f"{'='*55}")

# ======================================================
# PREDICT (utilisé par l'API)
# ======================================================
def predict(features: dict, model_name="random_forest") -> dict:
    model_path = f"{OUTPUT_DIR}/{model_name}.pkl"
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    severity_map  = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    priv_map      = {"None": 0, "Low": 1, "High": 2}
    fp_map        = {"Low": 0, "Medium": 1, "High": 2}

    row = pd.DataFrame([{
        "severity_num":            severity_map.get(features.get("severity", "Medium"), 2),
        "scanner_num":             0 if "ZAP" in str(features.get("scanner", "")) else 1,
        "cvss_score":              features.get("cvss_score", 0),
        "ai_risk_score":           features.get("ai_risk_score", 0),
        "confidence":              features.get("confidence", 50),
        "attack_complexity_num":   0 if features.get("attack_complexity", "Low") == "Low" else 1,
        "privileges_required_num": priv_map.get(features.get("privileges_required", "None"), 0),
        "user_interaction_num":    0 if features.get("user_interaction", "None") == "None" else 1,
        "fp_likelihood_num":       fp_map.get(features.get("false_positive_likelihood", "Low"), 0),
    }])

    pred       = model.predict(row)[0]
    proba      = model.predict_proba(row)[0]
    confidence = round(float(max(proba)) * 100, 1)

    return {
        "decision":        "approved" if pred == 1 else "rejected",
        "confidence":      confidence,
        "approve_proba":   round(float(proba[1]) * 100, 1),
        "reject_proba":    round(float(proba[0]) * 100, 1),
    }

# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    # 1. Fetch real data
    real_df = fetch_real_data()
    real_df["is_synthetic"] = False

    # 2. Generate synthetic data
    synthetic_df = generate_synthetic_data(n=400)

    # 3. Combine
    df = pd.concat([real_df, synthetic_df], ignore_index=True)
    print(f"\n📦 Total dataset: {len(df)} records")
    print(f"   Real: {(~df['is_synthetic']).sum()}")
    print(f"   Synthetic: {df['is_synthetic'].sum()}")

    # 4. Preprocess
    df = preprocess(df)

    # 5. Train
    rf, xgb = train(df)

    print("\n✅ Training complete!")
    print("👉 Next: run api.py to serve predictions")