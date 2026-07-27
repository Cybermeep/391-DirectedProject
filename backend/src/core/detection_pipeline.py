"""
Wires raw packet capture to actual detection.

Previously, api/routes/capture.py started PacketCapture with no callback
at all - packets went into a ring buffer and nowhere else. Nothing in the
codebase connected live capture to feature extraction, the rule engine,
the ML model, or alert creation. This module is that missing link.

Flow:  scapy packet -> PacketRecord -> LiveFlowTracker -> (on flow done)
       -> compute_flow_features() -> RuleEngine.evaluate_all() AND (if a
       model is loaded) InferenceEngine.predict() -> Alert + explanation
       -> AlertStore + WebSocket broadcast.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from ml_pipeline.live_features import PacketRecord, compute_flow_features
from core.flow_tracker import LiveFlowTracker
from rules.rate_signatures import RateSignatureEngine

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    Owns a LiveFlowTracker (for AST/custom rules + ML, per completed flow)
    and a RateSignatureEngine (for built-in flood/scan signatures, across
    many flows per source IP). Pass `pipeline.handle_packet` as the
    `callback` argument to `PacketCapture.start_capture(...)`.
    """

    def __init__(self, rule_engine=None, alerts_db_path: Optional[str] = None):
        self.rule_engine = rule_engine
        self._alerts_db_path = alerts_db_path
        self.tracker = LiveFlowTracker(on_flow_complete=self._on_flow_complete)
        self.rate_engine = RateSignatureEngine(on_fire=self._on_builtin_signature_fired)
        self._reaper_stop = threading.Event()
        self._reaper_thread: Optional[threading.Thread] = None
        self.flows_processed = 0
        self.alerts_generated = 0

    # -- lifecycle -----------------------------------------------------

    def start_reaper(self, interval_seconds: float = 2.0) -> None:
        """Background thread that periodically flushes idle flows (UDP flows and dead TCP connections never see a clean FIN/RST)."""
        if self._reaper_thread and self._reaper_thread.is_alive():
            return

        def _loop():
            while not self._reaper_stop.is_set():
                try:
                    self.tracker.reap_idle_flows()
                except Exception:
                    logger.exception("Error reaping idle flows")
                self._reaper_stop.wait(interval_seconds)

        self._reaper_stop.clear()
        self._reaper_thread = threading.Thread(target=_loop, daemon=True)
        self._reaper_thread.start()

    def stop_reaper(self) -> None:
        self._reaper_stop.set()

    def load_enabled_builtin_signatures(self, codes) -> None:
        self.rate_engine.set_enabled(codes)

    # -- packet ingestion ------------------------------------------------

    def handle_packet(self, packet) -> None:
        """Callback passed to PacketCapture. Never raises - a bad packet should never kill the capture thread."""
        try:
            from core.packet_stats import record_packet
            record_packet()

            parsed = self._scapy_to_record(packet)
            if parsed is None:
                return
            src_ip, dst_ip, src_port, dst_port, protocol, record = parsed
            now = time.time()
            self.tracker.add_packet(src_ip, dst_ip, src_port, dst_port, protocol, record, now=now)

            # Built-in packet-rate signatures: prefer the external
            # rule_engine package once it's actually populated with real
            # rules (see core/external_rule_engine.py's docstring for why
            # this switches over automatically with no other code
            # changes needed); fall back to the original built-in engine
            # otherwise, so nothing regresses while that integration is
            # incomplete.
            from core import external_rule_engine
            if external_rule_engine.is_active():
                external_rule_engine.analyze_packet(packet)
            else:
                self.rate_engine.handle_packet(src_ip, dst_ip, dst_port, protocol, record, now=now)
        except Exception:
            logger.exception("Error handling packet in detection pipeline")

    def _on_builtin_signature_fired(self, signature, group_key: str) -> None:
        from core.alerting import raise_alert

        # Most signatures group by source_ip (the attacker). DNS
        # Amplification groups by dst_ip instead (the victim receiving
        # reflected traffic) - attribute the tracked IP to the right
        # field rather than always calling it "source_ip".
        if signature.group_by == "dst_ip":
            source_ip, dest_ip = None, group_key
        else:
            source_ip, dest_ip = group_key, None

        alert_dict = raise_alert(
            severity=signature.severity,
            attack_type=signature.name,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=None,
            dest_port=None,
            protocol=None,
            confidence=1.0,
            rule_id=signature.code,
        )
        self.alerts_generated += 1
        logger.info(f"Built-in signature fired: {signature.code} ({signature.name}) - {signature.group_by}={group_key}")

    @staticmethod
    def _scapy_to_record(packet):
        """Translate one scapy packet into (src_ip, dst_ip, src_port, dst_port, protocol, PacketRecord), or None if it's not IP traffic."""
        from scapy.all import IP, TCP, UDP  # imported lazily so this module stays importable without scapy

        if IP not in packet:
            return None

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        protocol = ip_layer.proto  # 6=TCP, 17=UDP, 1=ICMP
        header_len = len(packet) - len(packet.payload.payload) if packet.payload else len(packet)

        src_port = dst_port = 0
        tcp_window = None
        syn = ack = fin = rst = psh = urg = ece = cwe = False
        payload_len = 0

        if TCP in packet:
            tcp = packet[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            tcp_window = int(tcp.window)
            flags = str(tcp.flags)
            syn, ack, fin, rst, psh, urg = ("S" in flags, "A" in flags, "F" in flags, "R" in flags, "P" in flags, "U" in flags)
            ece, cwe = ("E" in flags, "C" in flags)
            payload_len = len(tcp.payload) if tcp.payload else 0
        elif UDP in packet:
            udp = packet[UDP]
            src_port, dst_port = udp.sport, udp.dport
            payload_len = len(udp.payload) if udp.payload else 0

        record = PacketRecord(
            timestamp=time.time(),
            length=len(packet),
            direction="",  # assigned by LiveFlowTracker
            header_len=header_len,
            payload_len=payload_len,
            tcp_window=tcp_window,
            syn=syn, ack=ack, fin=fin, rst=rst, psh=psh, urg=urg, ece=ece, cwe=cwe,
        )
        return src_ip, dst_ip, src_port, dst_port, protocol, record

    # -- flow completion / detection -------------------------------------

    def _on_flow_complete(self, records, dst_port: int, protocol: int, src_ip: str, dst_ip: str) -> None:
        self.flows_processed += 1
        try:
            features = compute_flow_features(records, dst_port, protocol)

            rule_matches = []
            if self.rule_engine is not None:
                rule_matches = self.rule_engine.evaluate_all(features)

            ml_result = None
            try:
                from ml_pipeline.model_loader import get_inference_engine
                engine = get_inference_engine()
                ml_result = engine.predict(features)
            except Exception:
                # Model not installed, or a live-feature edge case the
                # model doesn't like (e.g. all-zero vector) - rule-based
                # detection still works independently of this.
                ml_result = None

            is_ml_attack = bool(ml_result and ml_result.get("prediction") == "Attack")

            if rule_matches or is_ml_attack:
                self._raise_alert(features, src_ip, dst_ip, dst_port, protocol, rule_matches, ml_result)

        except Exception:
            logger.exception("Error processing completed flow")

    def _raise_alert(self, features, src_ip, dst_ip, dst_port, protocol, rule_matches, ml_result):
        from core.alerting import raise_alert

        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, str(protocol))

        if rule_matches:
            top_rule = max(rule_matches, key=lambda m: {"low": 0, "medium": 1, "high": 2, "critical": 3}[m["severity"]])
            severity = top_rule["severity"]
            attack_type = f"Custom rule: {top_rule['name']}"
            rule_id = str(top_rule["rule_id"])
            confidence = 1.0
        else:
            attack_type = "ML-detected anomaly"
            rule_id = None
            confidence = ml_result["confidence"]
            from core.alerting import compute_ml_severity
            severity = compute_ml_severity(attack_type, confidence)

        alert_dict = raise_alert(
            severity=severity,
            attack_type=attack_type,
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=None,
            dest_port=dst_port,
            protocol=protocol_name,
            confidence=confidence,
            rule_id=rule_id,
        )
        self.alerts_generated += 1
        logger.info(f"Alert raised: {attack_type} (severity={severity}, confidence={confidence:.2f})")
