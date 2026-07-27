"""
Adapter wiring the external `rule_engine` package (a second team's
packet-level signature detectors) into the live capture pipeline.

Design: prefer this engine over the built-in `rules/rate_signatures.py`
engine automatically, but only once it actually has real rules loaded
(`active_detectors > 0`). Right now `rule_engine/rules.py` is a
deliberate placeholder shipping zero rules (see its docstring and
AUDIT.md) - so `is_active()` returns False and the pipeline transparently
keeps using the built-in engine. The moment the real `rules.py` is
dropped in, this starts returning True and the pipeline switches over -
no other code changes needed.

We deliberately do NOT use `RuleEngine.connect_alert_store()` - it would
persist alerts without generating a websocket broadcast or going through
this project's dedup-by-source/dest-ip fix (see alert_management/alert_store.py).
Instead we call `analyze_packet()` ourselves and route the resulting
alert dicts through `_persist_alert()` below, which reuses everything
this project already built - just without regenerating an explanation,
since these detectors already produce their own.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_engine_instance = None
_import_failed = False


def _get_engine():
    global _engine_instance, _import_failed
    if _import_failed:
        return None
    if _engine_instance is None:
        try:
            from rule_engine import RuleEngine
            _engine_instance = RuleEngine()
        except Exception:
            logger.exception("Could not initialize external rule_engine package")
            _import_failed = True
            return None
    return _engine_instance


def get_engine():
    """Public accessor for the underlying RuleEngine instance (e.g. to call enable_rule/disable_rule)."""
    return _get_engine()


def is_active() -> bool:
    """True once the external engine has real rules loaded (not the empty placeholder)."""
    engine = _get_engine()
    if engine is None:
        return False
    try:
        return engine.get_stats().get("active_detectors", 0) > 0
    except Exception:
        return False


def analyze_packet(packet) -> None:
    """
    Feed one raw scapy packet through the external engine and persist any
    alerts it produces. No-op (and cheap to call) if the engine isn't active.
    """
    engine = _get_engine()
    if engine is None:
        return

    try:
        from core.packet_processor import PacketProcessor
        packet_info = PacketProcessor.extract_packet_info(packet)
    except Exception:
        logger.exception("Failed to extract packet_info for external rule_engine")
        return

    try:
        alerts = engine.analyze_packet(packet_info)
    except Exception:
        logger.exception("external rule_engine.analyze_packet failed")
        return

    for alert in alerts:
        _persist_alert(alert)


def _persist_alert(alert: dict) -> None:
    """
    Persist + broadcast an alert dict already built by an external
    detector (rule_engine/detectors.py's BaseDetector._build_alert).
    Its keys already match AlertStore.create_alert()'s expected shape,
    and it already includes a human-readable explanation, so - unlike
    core.alerting.raise_alert() - we don't regenerate one here.
    """
    from alert_management import AlertStore

    try:
        store = AlertStore()
        record = store.create_alert(alert)
        record_dict = record.to_dict()
    except Exception:
        logger.exception("Failed to persist alert from external rule_engine")
        return

    try:
        from api.websocket import emit_new_alert
        emit_new_alert(record_dict)
    except Exception:
        logger.exception("Failed to broadcast alert over websocket")


def get_stats() -> Optional[dict]:
    engine = _get_engine()
    return engine.get_stats() if engine else None
