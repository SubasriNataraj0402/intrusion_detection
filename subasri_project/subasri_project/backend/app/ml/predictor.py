import os
import threading

import joblib
import numpy as np

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    # shap (and the numba/LLVM stack it pulls in) is deliberately excluded
    # from the default install on size-constrained deploys (see
    # requirements-extra.txt) — fall back to RandomForest's built-in
    # feature_importances_ instead of per-prediction SHAP values.
    SHAP_AVAILABLE = False

from app.ml.dataset import FEATURE_COLUMNS

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

_lock = threading.Lock()
_state = {"loaded": False}


def _load():
    with _lock:
        if _state["loaded"]:
            return
        _state["scaler"] = joblib.load(os.path.join(MODELS_DIR, "scaler.joblib"))
        _state["encoder"] = joblib.load(os.path.join(MODELS_DIR, "label_encoder.joblib"))
        _state["clf"] = joblib.load(os.path.join(MODELS_DIR, "random_forest.joblib"))
        _state["iso"] = joblib.load(os.path.join(MODELS_DIR, "isolation_forest.joblib"))
        if SHAP_AVAILABLE:
            _state["explainer"] = shap.TreeExplainer(_state["clf"])
        _state["loaded"] = True


def models_available() -> bool:
    required = ["scaler.joblib", "label_encoder.joblib", "random_forest.joblib", "isolation_forest.joblib"]
    return all(os.path.exists(os.path.join(MODELS_DIR, f)) for f in required)


def predict(features: dict) -> dict:
    _load()
    scaler = _state["scaler"]
    encoder = _state["encoder"]
    clf = _state["clf"]
    iso = _state["iso"]

    x = np.array([[features[c] for c in FEATURE_COLUMNS]], dtype=float)
    x_scaled = scaler.transform(x)

    proba = clf.predict_proba(x_scaled)[0]
    pred_idx = int(np.argmax(proba))
    attack_name = encoder.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])

    anomaly_raw = iso.decision_function(x_scaled)[0]
    is_anomaly = bool(iso.predict(x_scaled)[0] == -1)

    if SHAP_AVAILABLE:
        explainer = _state["explainer"]
        shap_values = explainer.shap_values(x_scaled)
        if isinstance(shap_values, list):
            class_shap = shap_values[pred_idx][0]
        else:
            class_shap = shap_values[0, :, pred_idx] if shap_values.ndim == 3 else shap_values[0]
        contributions = sorted(
            zip(FEATURE_COLUMNS, class_shap.tolist()), key=lambda kv: abs(kv[1]), reverse=True
        )
        explanation = [{"feature": f, "impact": round(v, 4)} for f, v in contributions[:5]]
    else:
        # Global feature_importances_ instead of a per-prediction SHAP value —
        # less precise (doesn't reflect direction/magnitude for this specific
        # input) but needs no extra dependencies.
        contributions = sorted(
            zip(FEATURE_COLUMNS, clf.feature_importances_.tolist()), key=lambda kv: kv[1], reverse=True
        )
        explanation = [{"feature": f, "impact": round(v, 4)} for f, v in contributions[:5]]

    if attack_name == "normal" and is_anomaly:
        attack_name = "unknown_anomaly"
        confidence = max(confidence, float(min(1.0, abs(anomaly_raw) * 4)))

    return {
        "attack_name": attack_name,
        "confidence": confidence,
        "is_anomaly": is_anomaly,
        "anomaly_score": float(anomaly_raw),
        "explanation": explanation,
    }
