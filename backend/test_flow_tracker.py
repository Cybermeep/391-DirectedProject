"""
Unit tests for core.flow_tracker.LiveFlowTracker
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.flow_tracker import LiveFlowTracker
from ml_pipeline.live_features import PacketRecord


class TestFlowGrouping(unittest.TestCase):
    def setUp(self):
        self.completed = []
        self.tracker = LiveFlowTracker(on_flow_complete=lambda records, port, proto, src_ip, dst_ip: self.completed.append((records, port, proto, src_ip, dst_ip)))

    def test_both_directions_group_into_one_flow(self):
        # Client -> server SYN
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51000, 443, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        # Server -> client SYN/ACK (reversed src/dst)
        self.tracker.add_packet(
            "10.0.0.1", "10.0.0.5", 443, 51000, 6,
            PacketRecord(timestamp=0.01, length=60, direction="", syn=True, ack=True), now=0.01,
        )
        self.assertEqual(self.tracker.active_flow_count(), 1)

    def test_direction_assigned_relative_to_initiator(self):
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51000, 443, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        rec2 = PacketRecord(timestamp=0.01, length=60, direction="", syn=True, ack=True)
        self.tracker.add_packet("10.0.0.1", "10.0.0.5", 443, 51000, 6, rec2, now=0.01)

        # The second packet came from the server (not the initiator), so
        # it must be tagged 'bwd' even though its raw src/dst is reversed.
        self.assertEqual(rec2.direction, "bwd")

    def test_rst_completes_flow_immediately(self):
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51000, 80, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        self.tracker.add_packet(
            "10.0.0.1", "10.0.0.5", 80, 51000, 6,
            PacketRecord(timestamp=0.01, length=60, direction="", rst=True, ack=True), now=0.01,
        )
        self.assertEqual(len(self.completed), 1)
        self.assertEqual(self.tracker.active_flow_count(), 0)
        records, dst_port, proto, src_ip, dst_ip = self.completed[0]
        self.assertEqual(dst_port, 80)
        self.assertEqual(len(records), 2)
        self.assertEqual(src_ip, "10.0.0.5")
        self.assertEqual(dst_ip, "10.0.0.1")

    def test_idle_reaping_completes_stale_flows(self):
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51000, 80, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        self.assertEqual(len(self.completed), 0)

        # Not idle yet at +5s (default timeout is 15s)
        self.tracker.reap_idle_flows(now=5.0)
        self.assertEqual(len(self.completed), 0)

        # Idle past the timeout
        self.tracker.reap_idle_flows(now=20.0)
        self.assertEqual(len(self.completed), 1)

    def test_different_five_tuples_are_separate_flows(self):
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51000, 80, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        self.tracker.add_packet(
            "10.0.0.5", "10.0.0.1", 51001, 80, 6,
            PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=0.0,
        )
        self.assertEqual(self.tracker.active_flow_count(), 2)

    def test_max_flows_evicts_oldest(self):
        tracker = LiveFlowTracker(on_flow_complete=lambda r, p, pr, s, d: None)
        from core import flow_tracker as ft_module

        original_max = ft_module.MAX_ACTIVE_FLOWS
        ft_module.MAX_ACTIVE_FLOWS = 2
        try:
            for i in range(3):
                tracker.add_packet(
                    "10.0.0.5", "10.0.0.1", 50000 + i, 80, 6,
                    PacketRecord(timestamp=0.0, length=60, direction="", syn=True), now=float(i),
                )
            self.assertLessEqual(tracker.active_flow_count(), 2)
        finally:
            ft_module.MAX_ACTIVE_FLOWS = original_max


if __name__ == "__main__":
    unittest.main()
