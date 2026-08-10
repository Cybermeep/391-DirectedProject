"""
Tests for core.external_rule_engine 
"""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import core.external_rule_engine as ere


class TestRealEngineIsActive(unittest.TestCase):
    def setUp(self):
        ere._engine_instance = None
        ere._import_failed = False

    def test_package_imports_successfully(self):
        engine = ere._get_engine()
        self.assertIsNotNone(engine)

    def test_is_active_true_with_real_rules(self):
        self.assertTrue(ere.is_active())

    def test_get_stats_reports_thirty_detectors(self):
        stats = ere.get_stats()
        self.assertEqual(stats["active_detectors"], 30)
        self.assertEqual(stats["total_rules"], 30)

    def test_analyze_packet_handles_non_scapy_input_safely(self):
        # is_active() is True now, so analyze_packet() will actually try
        # PacketProcessor.extract_packet_info() on whatever it's given.
        # Scapy isn't installed in this sandbox, so this exercises the
        # "extraction failed" branch - confirms it's logged and swallowed,
        # not raised, regardless of *why* extraction failed.
        try:
            ere.analyze_packet(object())
        except Exception as e:
            self.fail(f"analyze_packet() raised unexpectedly: {e}")


class TestEngineDirectly(unittest.TestCase):
    """
    Exercises the real RuleEngine directly (bypassing the scapy-dependent
    packet_info extraction) to confirm the adapter's persistence path
    would receive well-formed alert dicts from it.
    """

    def test_syn_flood_produces_alert_store_compatible_dict(self):
        from rule_engine import RuleEngine
        from rule_engine.rules import Rule

        rule = Rule('RULE-001', 'SYN Flood', 'DoS-SYN-Flood', 'high', '-',
                     threshold=5, time_window=10, cooldown=2)
        engine = RuleEngine(rules=[rule])

        def syn_packet(i):
            return {
                'timestamp': time.time() + i * 0.01,
                'src_ip': '203.0.113.10', 'dst_ip': '192.168.1.50',
                'src_port': 50000, 'dst_port': 8899, 'protocol': 'TCP',
                'has_tcp': True, 'has_udp': False, 'has_icmp': False,
                'tcp_flags': {'syn': True, 'ack': False, 'rst': False, 'fin': False,
                               'psh': False, 'urg': False, 'ece': False, 'cwr': False},
            }

        alerts = []
        for i in range(6):
            alerts.extend(engine.analyze_packet(syn_packet(i)))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        for key in ('rule_id', 'attack_type', 'severity', 'source_ip', 'dest_ip',
                    'source_port', 'dest_port', 'protocol', 'message', 'explanation',
                    'ml_confidence'):
            self.assertIn(key, alert)
        self.assertEqual(alert['rule_id'], 'RULE-001')
        self.assertEqual(alert['source_ip'], '203.0.113.10')


if __name__ == "__main__":
    unittest.main()
