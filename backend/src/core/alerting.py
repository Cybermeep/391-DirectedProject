"""
Shared "turn a detection result into a real Alert" helper.

"""

import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


def build_explanation(
    attack_type: str,
    source_ip: str,
    dest_ip: str,
    message: str,
    confidence: float,
) -> str:
    from explainability.explanation_generator import ExplanationGenerator

    feature_importances = None
    try:
        from ml_pipeline.model_loader import get_inference_engine
        importance_df = get_inference_engine().get_feature_importance()
        if importance_df is not None:
            feature_importances = dict(zip(importance_df.iloc[:, 0], importance_df.iloc[:, 1]))
    except Exception:
        pass

    generator = ExplanationGenerator()
    return generator.generate_explanation(
        {
            "attack_type": attack_type,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "message": message,
            "ml_confidence": confidence,
        },
        feature_importances=feature_importances,
    )


def compute_ml_severity(attack_type: str, confidence: float) -> str:
    from alert_management import SeverityScorer

    return SeverityScorer().calculate_severity({
        "attack_type": attack_type,
        "ml_confidence": confidence,
        "count_occurrences": 1,
    })


def raise_alert(
    *,
    severity: str,
    attack_type: str,
    source_ip: Optional[str],
    dest_ip: Optional[str],
    source_port: Optional[int],
    dest_port: Optional[int],
    protocol: Optional[str],
    confidence: float,
    rule_id: Optional[str] = None,
) -> Dict[str, Any]:
    from alert_management import AlertStore

    message = f"{attack_type} on port {dest_port}/{protocol or '?'}"
    explanation = build_explanation(attack_type, source_ip or "unknown", dest_ip or "unknown", message, confidence)

    store = AlertStore()
    alert = store.create_alert({
        "severity": severity,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "message": message,
        "explanation": explanation,
        "ml_confidence": confidence,
        "rule_id": rule_id,
    })

    alert_dict = alert.to_dict()

    try:
        from api.websocket import emit_new_alert
        emit_new_alert(alert_dict)
    except Exception:
        logger.exception("Failed to broadcast alert over websocket")

    return alert_dict
