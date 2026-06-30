"""
rule_engine — Rule-based network intrusion detection for the NIDS.

Quick start:
    from rule_engine import RuleEngine

    engine = RuleEngine()                          # loads 13 built-in rules
    alerts = engine.analyze_packet(packet_info)    # packet_info from PacketProcessor

    # Optional: auto-persist alerts to the alert database
    from alert_management import AlertStore
    engine.connect_alert_store(AlertStore())
"""

from .engine import RuleEngine
from .rules import Rule, default_rules

__all__ = ['RuleEngine', 'Rule', 'default_rules']
