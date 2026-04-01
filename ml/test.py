import pickle
import pandas as pd

OUTPUT_DIR = "models"

# ======================================================
# CHARGER LE MODELE
# ======================================================
def predict(features: dict, model_name="random_forest") -> dict:
    with open(f"{OUTPUT_DIR}/{model_name}.pkl", "rb") as f:
        model = pickle.load(f)

    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    priv_map     = {"None": 0, "Low": 1, "High": 2}
    fp_map       = {"Low": 0, "Medium": 1, "High": 2}

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
        "decision":      "approved" if pred == 1 else "rejected",
        "confidence":    confidence,
        "approve_proba": round(float(proba[1]) * 100, 1),
        "reject_proba":  round(float(proba[0]) * 100, 1),
    }

# ======================================================
# CAS DE TEST
# ======================================================
test_cases = [
    {
        "label": "SQL Injection sur /login → APPROVED attendu",
        "features": {
            "severity":                  "High",
            "scanner":                   "ZAP Scan",
            "cvss_score":                8.5,
            "ai_risk_score":             80,
            "confidence":                90,
            "attack_complexity":         "Low",
            "privileges_required":       "None",
            "user_interaction":          "None",
            "false_positive_likelihood": "Low",
        }
    },
    {
        "label": "Ressource statique /logo.png → REJECTED attendu",
        "features": {
            "severity":                  "Medium",
            "scanner":                   "ZAP Scan",
            "cvss_score":                3.5,
            "ai_risk_score":             15,
            "confidence":                25,
            "attack_complexity":         "High",
            "privileges_required":       "High",
            "user_interaction":          "Required",
            "false_positive_likelihood": "High",
        }
    },
    {
        "label": "XSS Medium confiance → cas ambigu",
        "features": {
            "severity":                  "Medium",
            "scanner":                   "ZAP Scan",
            "cvss_score":                5.5,
            "ai_risk_score":             50,
            "confidence":                55,
            "attack_complexity":         "Low",
            "privileges_required":       "None",
            "user_interaction":          "Required",
            "false_positive_likelihood": "Medium",
        }
    },
    {
        "label": "Broken Access Control /admin → APPROVED attendu",
        "features": {
            "severity":                  "Critical",
            "scanner":                   "ZAP Scan",
            "cvss_score":                9.1,
            "ai_risk_score":             95,
            "confidence":                92,
            "attack_complexity":         "Low",
            "privileges_required":       "None",
            "user_interaction":          "None",
            "false_positive_likelihood": "Low",
        }
    },
    {
        "label": "Info disclosure faible → REJECTED attendu",
        "features": {
            "severity":                  "Low",
            "scanner":                   "ZAP Scan",
            "cvss_score":                2.0,
            "ai_risk_score":             10,
            "confidence":                30,
            "attack_complexity":         "High",
            "privileges_required":       "High",
            "user_interaction":          "Required",
            "false_positive_likelihood": "High",
        }
    },
]

# ======================================================
# LANCER LES TESTS
# ======================================================
if __name__ == "__main__":
    print("\n🧪 TEST DU MODELE ML")
    print("=" * 60)

    for i, case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {case['label']}")
        print("-" * 60)

        # Tester avec les deux modèles
        rf_result  = predict(case["features"], model_name="random_forest")
        xgb_result = predict(case["features"], model_name="xgboost")

        for model_name, result in [("Random Forest", rf_result), ("XGBoost", xgb_result)]:
            emoji = "🟢" if result["decision"] == "approved" else "🔴"
            print(f"  {model_name}:")
            print(f"    {emoji} Decision    : {result['decision'].upper()}")
            print(f"    📊 Confidence  : {result['confidence']}%")
            print(f"    ✅ Approve     : {result['approve_proba']}%")
            print(f"    ❌ Reject      : {result['reject_proba']}%")

        # Vérifier si RF et XGB sont d'accord
        if rf_result["decision"] == xgb_result["decision"]:
            print(f"  ✅ RF et XGBoost sont d'accord")
        else:
            print(f"  ⚠️  RF et XGBoost ne sont pas d'accord !")

    print("\n" + "=" * 60)
    print("✅ Tests terminés")