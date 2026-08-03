"""
Prediction routes for the NIDS API.

app.py has always imported this blueprint (`from .routes import alerts,
capture, stats, predict`) but the file did not exist - the app would
throw ImportError on startup before this fix. This wires the existing
ml_pipeline.InferenceEngine (which was fully implemented but never
connected to any route) up to /api/predict and /api/model/status.
"""

import logging
from flask import Blueprint, request, jsonify

from ml_pipeline.model_loader import get_inference_engine, ModelNotFoundError
from rules.evaluator import RuleEngine  # noqa: F401 (re-exported for app-level wiring)

logger = logging.getLogger(__name__)

bp = Blueprint("predict", __name__)


@bp.route("/model/status", methods=["GET"])
def model_status():
    try:
        engine = get_inference_engine()
        return jsonify({"success": True, "loaded": True, "stats": engine.get_stats()})
    except ModelNotFoundError as e:
        return jsonify({"success": False, "loaded": False, "error": str(e)}), 503
    except Exception as e:
        logger.exception("Unexpected error checking model status")
        return jsonify({"success": False, "loaded": False, "error": f"{type(e).__name__}: {e}"}), 500


@bp.route("/model/install", methods=["POST"])
def model_install():
    """
    Explicitly trigger model loading/installation (the same dev-fallback
    copy-from-source-tree logic in ml_pipeline/model_loader.py that
    normally only runs lazily on first prediction). Lets the frontend
    show an immediate "installing the trained model..." popup right
    after a tier upgrade, rather than waiting for the first prediction
    to silently trigger it - or discovering days later that it never did.
    """
    try:
        engine = get_inference_engine()
        return jsonify({"success": True, "loaded": True, "stats": engine.get_stats()})
    except ModelNotFoundError as e:
        return jsonify({"success": False, "loaded": False, "error": str(e)}), 503
    except Exception:
        logger.exception("Model install failed")
        return jsonify({"success": False, "loaded": False, "error": "Model installation failed"}), 500


@bp.route("/predict", methods=["POST"])
def predict():
    """
    Run a single prediction on a feature vector.

    Expected JSON body:
        {
          "features": {<78 feature name>: <value>, ...},
          "create_alert": true,           # optional, default true
          "source_ip": "203.0.113.5",     # optional, cosmetic only
          "dest_ip": "192.168.1.50"        # optional, cosmetic only
        }

    Always returns the raw prediction plus a generated human-readable
    explanation. If the prediction is 'Attack' and create_alert isn't
    explicitly false, also stores a real Alert (deduplicated, broadcast
    over websocket) - so calling this endpoint directly (e.g. from
    demo/predict_showcase.py) produces the same dashboard experience a
    live-captured detection would.
    """
    data = request.get_json(silent=True) or {}
    features = data.get("features")

    if not features:
        return jsonify({"success": False, "error": "features object is required"}), 400

    try:
        engine = get_inference_engine()
    except ModelNotFoundError as e:
        return jsonify({"success": False, "error": str(e)}), 503

    try:
        result = engine.predict(features)
    except (ValueError, RuntimeError) as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception:
        logger.exception("Prediction failed")
        return jsonify({"success": False, "error": "Prediction failed"}), 500

    from core.alerting import build_explanation

    dest_port = features.get("Dst_Port")
    protocol_num = features.get("Protocol")
    protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol_num, str(protocol_num))
    source_ip = data.get("source_ip", "unknown")
    dest_ip = data.get("dest_ip", "unknown")

    explanation = build_explanation(
        attack_type="ML-detected anomaly" if result["prediction"] == "Attack" else "Benign traffic",
        source_ip=source_ip,
        dest_ip=dest_ip,
        message=f"Prediction on port {dest_port}/{protocol_name}",
        confidence=result["confidence"],
    )
    result["explanation"] = explanation

    alert = None
    if result["prediction"] == "Attack" and data.get("create_alert", True):
        try:
            from core.alerting import raise_alert, compute_ml_severity
            alert = raise_alert(
                severity=compute_ml_severity("ML-detected anomaly", result["confidence"]),
                attack_type="ML-detected anomaly",
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=None,
                dest_port=dest_port,
                protocol=protocol_name,
                confidence=result["confidence"],
            )
        except Exception:
            logger.exception("Failed to raise alert from /predict")

    return jsonify({"success": True, "result": result, "alert": alert})
