"""
Unit tests for rules.rate_signatures.RateSignatureEngine
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rules.rate_signatures import RateSignatureEngine, BUILTIN_BY_CODE
from ml_pipeline.live_features import PacketRecord


def syn_packet():
    return PacketRecord(timestamp=0, length=60, direction="", syn=True)


class TestSynFloodSignature(unittest.TestCase):
    def setUp(self):
        self.fired = []
        self.engine = RateSignatureEngine(on_fire=lambda sig, key: self.fired.append((sig.code, key)))
        self.engine.set_enabled(["RULE-001"])  # SYN Flood only

    def test_fires_once_threshold_crossed(self):
        sig = BUILTIN_BY_CODE["RULE-001"]  # threshold=100, window=10s
        for i in range(sig.threshold):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0][0], "RULE-001")
        self.assertEqual(self.fired[0][1], "10.0.0.5")

    def test_does_not_fire_below_threshold(self):
        sig = BUILTIN_BY_CODE["RULE-001"]
        for i in range(sig.threshold - 1):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 0)

    def test_events_outside_window_expire(self):
        sig = BUILTIN_BY_CODE["RULE-001"]  # window=10s
        # Half the threshold now, then jump 20s ahead (past the window) and send the other half.
        for i in range(sig.threshold // 2):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        for i in range(sig.threshold // 2):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=20.0 + i * 0.01)
        self.assertEqual(len(self.fired), 0)

    def test_cooldown_prevents_immediate_refire(self):
        sig = BUILTIN_BY_CODE["RULE-001"]
        for i in range(sig.threshold + 20):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 1)

    def test_different_sources_tracked_independently(self):
        sig = BUILTIN_BY_CODE["RULE-001"]
        for i in range(sig.threshold):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        for i in range(sig.threshold - 1):
            self.engine.handle_packet("10.0.0.6", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0][1], "10.0.0.5")

    def test_non_syn_packets_dont_count(self):
        sig = BUILTIN_BY_CODE["RULE-001"]
        ack_packet = PacketRecord(timestamp=0, length=60, direction="", syn=True, ack=True)
        for i in range(sig.threshold + 10):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, ack_packet, now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 0)


class TestPortScanSignature(unittest.TestCase):
    def setUp(self):
        self.fired = []
        self.engine = RateSignatureEngine(on_fire=lambda sig, key: self.fired.append((sig.code, key)))
        self.engine.set_enabled(["RULE-002"])  # Port Scan only

    def test_fires_on_distinct_ports_not_raw_count(self):
        sig = BUILTIN_BY_CODE["RULE-002"]  # threshold=20 distinct ports
        # Same port repeated many times should NOT trip a distinct-count signature.
        for i in range(50):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(self.fired), 0)

    def test_fires_once_enough_distinct_ports_hit(self):
        sig = BUILTIN_BY_CODE["RULE-002"]
        for port in range(sig.threshold):
            self.engine.handle_packet("10.0.0.5", "10.0.0.1", 1000 + port, 6, syn_packet(), now=float(port) * 0.01)
        self.assertEqual(len(self.fired), 1)


class TestDisabledSignaturesDontFire(unittest.TestCase):
    def test_disabled_signature_never_fires(self):
        fired = []
        engine = RateSignatureEngine(on_fire=lambda sig, key: fired.append(sig.code))
        engine.set_enabled([])  # nothing enabled
        sig = BUILTIN_BY_CODE["RULE-001"]
        for i in range(sig.threshold + 50):
            engine.handle_packet("10.0.0.5", "10.0.0.1", 80, 6, syn_packet(), now=float(i) * 0.01)
        self.assertEqual(len(fired), 0)


if __name__ == "__main__":
    unittest.main()
