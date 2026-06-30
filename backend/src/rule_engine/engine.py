"""
Rule-based detection engine.

RuleEngine loads a set of Rule objects, instantiates the matching detector for
each, and routes incoming packet_info dicts (from PacketProcessor) or flow dicts
(from FlowBuilder) through all enabled detectors.  It returns a list of alert
dicts that are directly compatible with AlertStore.create_alert().

Usage (standalone):
    from rule_engine import RuleEngine

    engine = RuleEngine()
    alerts = engine.analyze_packet(packet_info)

Usage (with AlertStore integration):
    from rule_engine import RuleEngine
    from alert_management import AlertStore

    engine = RuleEngine()
    engine.connect_alert_store(AlertStore())
    engine.analyze_packet(packet_info)   # alerts auto-persisted
"""

import logging
from typing import Any, Dict, List, Optional

from .detectors import (
    BaseDetector,
    BruteForceDetector,
    DNSAmplificationDetector,
    FINScanDetector,
    ICMPFloodDetector,
    ICMPLargePayloadDetector,
    NullScanDetector,
    PingSweepDetector,
    PortScanDetector,
    SYNFloodDetector,
    UDPFloodDetector,
    XMASScanDetector,
)
from .rules import Rule, default_rules

logger = logging.getLogger(__name__)

# Maps rule_id -> detector class
_DETECTOR_REGISTRY: Dict[str, type] = {
    'RULE-001': SYNFloodDetector,
    'RULE-002': PortScanDetector,
    'RULE-003': ICMPFloodDetector,
    'RULE-004': UDPFloodDetector,
    'RULE-005': PingSweepDetector,
    'RULE-006': DNSAmplificationDetector,
    'RULE-007': BruteForceDetector,
    'RULE-008': BruteForceDetector,
    'RULE-009': BruteForceDetector,
    'RULE-010': NullScanDetector,
    'RULE-011': XMASScanDetector,
    'RULE-012': FINScanDetector,
    'RULE-013': ICMPLargePayloadDetector,
}


class RuleEngine:
    """
    Orchestrates rule-based intrusion detection across a live packet stream.

    Each enabled Rule gets its own detector instance so that per-rule state
    (counters, time windows, cooldowns) is completely isolated.
    """

    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self._rules = rules if rules is not None else default_rules()
        self._detectors: List[BaseDetector] = self._build_detectors()
        self._alert_store = None
        self._packets_analyzed = 0
        self._flows_analyzed = 0
        self._alerts_generated = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run all enabled detectors against a single packet_info dict.

        Args:
            packet_info: Dict produced by PacketProcessor.extract_packet_info()

        Returns:
            List of alert dicts.  Each dict is compatible with AlertStore.create_alert().
        """
        self._packets_analyzed += 1
        alerts: List[Dict[str, Any]] = []

        for detector in self._detectors:
            try:
                found = detector.analyze_packet(packet_info)
                alerts.extend(found)
            except Exception as exc:
                logger.warning('Detector %s raised exception: %s', detector.rule.rule_id, exc)

        if alerts:
            self._alerts_generated += len(alerts)
            self._persist(alerts)

        return alerts

    def analyze_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run all enabled detectors against a completed flow dict.

        Args:
            flow: Dict produced by FlowBuilder (flow_id, packets, src_ip, dst_ip, …)

        Returns:
            List of alert dicts compatible with AlertStore.create_alert().
        """
        self._flows_analyzed += 1
        alerts: List[Dict[str, Any]] = []

        for detector in self._detectors:
            try:
                found = detector.analyze_flow(flow)
                alerts.extend(found)
            except Exception as exc:
                logger.warning('Detector %s raised exception: %s', detector.rule.rule_id, exc)

        if alerts:
            self._alerts_generated += len(alerts)
            self._persist(alerts)

        return alerts

    def connect_alert_store(self, alert_store) -> None:
        """
        Attach an AlertStore so that every detected alert is auto-persisted.

        Args:
            alert_store: An instance of alert_management.AlertStore
        """
        self._alert_store = alert_store
        logger.info('RuleEngine connected to AlertStore at %s', getattr(alert_store, 'db_path', '?'))

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID.  Returns True if the rule was found."""
        return self._set_rule_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID.  Returns True if the rule was found."""
        return self._set_rule_enabled(rule_id, False)

    def get_rules(self) -> List[Dict[str, Any]]:
        """Return a summary of all configured rules and their enabled state."""
        return [
            {
                'rule_id': r.rule_id,
                'name': r.name,
                'attack_type': r.attack_type,
                'severity': r.severity,
                'description': r.description,
                'enabled': r.enabled,
                'threshold': r.threshold,
                'time_window': r.time_window,
            }
            for r in self._rules
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Return runtime statistics for the engine."""
        return {
            'packets_analyzed': self._packets_analyzed,
            'flows_analyzed': self._flows_analyzed,
            'alerts_generated': self._alerts_generated,
            'active_detectors': len(self._detectors),
            'total_rules': len(self._rules),
        }

    def reset(self) -> None:
        """Clear all detector state and reset counters."""
        for detector in self._detectors:
            detector.reset()
        self._packets_analyzed = 0
        self._flows_analyzed = 0
        self._alerts_generated = 0
        logger.info('RuleEngine state reset.')

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_detectors(self) -> List[BaseDetector]:
        detectors: List[BaseDetector] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            cls = _DETECTOR_REGISTRY.get(rule.rule_id)
            if cls is None:
                logger.warning('No detector registered for rule %s — skipping.', rule.rule_id)
                continue
            detectors.append(cls(rule))
            logger.debug('Loaded detector %s for rule %s (%s)', cls.__name__, rule.rule_id, rule.name)
        logger.info('RuleEngine initialised with %d active detectors.', len(detectors))
        return detectors

    def _set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = enabled
                # Rebuild detector list to reflect the change
                self._detectors = self._build_detectors()
                logger.info('Rule %s %s.', rule_id, 'enabled' if enabled else 'disabled')
                return True
        logger.warning('Rule %s not found.', rule_id)
        return False

    def _persist(self, alerts: List[Dict[str, Any]]) -> None:
        if self._alert_store is None:
            return
        for alert in alerts:
            try:
                self._alert_store.create_alert(alert)
            except Exception as exc:
                logger.error('Failed to persist alert (rule=%s): %s', alert.get('rule_id'), exc)
