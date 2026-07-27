"""
Unit tests for ml_pipeline.live_features.compute_flow_features.

Deliberately uses plain PacketRecord objects instead of real scapy
packets, so this suite runs anywhere without scapy/Npcap installed and
still gives real confidence in the flow-math itself (which is the part
actually at risk of being wrong).

Run with:
    cd backend && python -m unittest test_live_features.py -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ml_pipeline.live_features import PacketRecord, compute_flow_features
from rules.ast_nodes import FEATURE_FIELDS


class TestFlowFeatureSchema(unittest.TestCase):
    def test_output_matches_model_schema_exactly(self):
        records = [
            PacketRecord(timestamp=0.0, length=60, direction="fwd", syn=True),
            PacketRecord(timestamp=0.01, length=60, direction="bwd", syn=True, ack=True),
            PacketRecord(timestamp=0.02, length=54, direction="fwd", ack=True),
        ]
        features = compute_flow_features(records, dst_port=443, protocol=6)
        self.assertEqual(set(features.keys()), set(FEATURE_FIELDS))

    def test_empty_flow_returns_empty(self):
        self.assertEqual(compute_flow_features([], dst_port=80, protocol=6), {})


class TestBasicCounts(unittest.TestCase):
    def setUp(self):
        # A simple 3-way handshake + one data packet each way.
        self.records = [
            PacketRecord(timestamp=0.000, length=60, direction="fwd", syn=True, tcp_window=64240),
            PacketRecord(timestamp=0.001, length=60, direction="bwd", syn=True, ack=True, tcp_window=65535),
            PacketRecord(timestamp=0.002, length=54, direction="fwd", ack=True),
            PacketRecord(timestamp=0.010, length=514, direction="fwd", psh=True, ack=True, payload_len=460),
            PacketRecord(timestamp=0.015, length=54, direction="bwd", ack=True),
        ]
        self.features = compute_flow_features(self.records, dst_port=443, protocol=6)

    def test_packet_counts(self):
        self.assertEqual(self.features["Tot_Fwd_Pkts"], 3)
        self.assertEqual(self.features["Tot_Bwd_Pkts"], 2)

    def test_byte_totals(self):
        self.assertEqual(self.features["TotLen_Fwd_Pkts"], 60 + 54 + 514)
        self.assertEqual(self.features["TotLen_Bwd_Pkts"], 60 + 54)

    def test_flag_counts(self):
        self.assertEqual(self.features["SYN_Flag_Cnt"], 2)
        self.assertEqual(self.features["ACK_Flag_Cnt"], 4)
        self.assertEqual(self.features["PSH_Flag_Cnt"], 1)

    def test_duration_is_microseconds(self):
        # Last packet at 0.015s, first at 0.000s -> 15,000 microseconds.
        self.assertAlmostEqual(self.features["Flow_Duration"], 15_000.0, places=3)

    def test_dst_port_and_protocol_passthrough(self):
        self.assertEqual(self.features["Dst_Port"], 443)
        self.assertEqual(self.features["Protocol"], 6)

    def test_init_window_sizes(self):
        self.assertEqual(self.features["Init_Fwd_Win_Byts"], 64240)
        self.assertEqual(self.features["Init_Bwd_Win_Byts"], 65535)

    def test_down_up_ratio(self):
        self.assertAlmostEqual(self.features["Down/Up_Ratio"], 2 / 3)


class TestSynFloodLooksLikeAnAttackToTheRuleEngine(unittest.TestCase):
    """
    Reproduces, from raw synthetic packets, the exact shape of traffic the
    demo's SYN-flood script is designed to generate: many SYNs, one
    direction only, no completed handshakes. Confirms the computed
    features would actually trip the example rule shown in the frontend
    (SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3 AND Flow_Byts/s > 1000).
    """

    def test_high_syn_low_duration_flow(self):
        records = [
            PacketRecord(timestamp=i * 0.001, length=60, direction="fwd", syn=True)
            for i in range(20)
        ]
        # A few RSTs coming back as the target refuses/resets half-open
        # connections it never completed the handshake for.
        records += [
            PacketRecord(timestamp=i * 0.001 + 0.0005, length=54, direction="bwd", rst=True, ack=True)
            for i in range(5)
        ]
        features = compute_flow_features(records, dst_port=80, protocol=6)

        self.assertGreater(features["SYN_Flag_Cnt"], 5)
        self.assertGreater(features["RST_Flag_Cnt"], 3)
        self.assertGreater(features["Flow_Byts/s"], 1000)


class TestActiveIdleSplitting(unittest.TestCase):
    def test_single_burst_no_idle(self):
        records = [
            PacketRecord(timestamp=i * 0.01, length=100, direction="fwd") for i in range(5)
        ]
        features = compute_flow_features(records, dst_port=80, protocol=6)
        self.assertEqual(features["Idle_Mean"], 0.0)
        self.assertGreater(features["Active_Mean"], 0.0)

    def test_two_bursts_separated_by_idle_gap(self):
        # Burst 1: 3 packets close together, then a 2-second gap, then burst 2.
        records = [
            PacketRecord(timestamp=0.0, length=100, direction="fwd"),
            PacketRecord(timestamp=0.01, length=100, direction="fwd"),
            PacketRecord(timestamp=0.02, length=100, direction="fwd"),
            PacketRecord(timestamp=2.02, length=100, direction="fwd"),
            PacketRecord(timestamp=2.03, length=100, direction="fwd"),
        ]
        features = compute_flow_features(records, dst_port=80, protocol=6)
        self.assertGreater(features["Idle_Max"], 1_000_000)  # >1s gap, in microseconds


if __name__ == "__main__":
    unittest.main()
