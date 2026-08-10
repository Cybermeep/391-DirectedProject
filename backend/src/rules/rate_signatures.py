"""
Built-in signature catalog + rate/window-based detector
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from ml_pipeline.live_features import PacketRecord

TCP = 6
UDP = 17
ICMP = 1


@dataclass
class BuiltinSignature:
    code: str
    name: str
    attack_type: str
    severity: str
    threshold: int
    window_seconds: int
    description: str

    matcher: Callable[[str, str, int, int, PacketRecord], Optional[object]]
    distinct: bool = False 
    group_by: str = "src_ip"  


def _is_syn_only(r: PacketRecord) -> bool:
    return r.syn and not r.ack


def _is_bare(r: PacketRecord) -> bool:
    return not (r.syn or r.ack or r.fin or r.psh or r.urg or r.rst)


def _is_xmas(r: PacketRecord) -> bool:
    return r.fin and r.psh and r.urg


def _is_fin_only(r: PacketRecord) -> bool:
    return r.fin and not (r.syn or r.ack or r.psh or r.urg or r.rst)


BUILTIN_SIGNATURES = [
    BuiltinSignature(
        "RULE-001", "SYN Flood", "DoS-SYN-Flood", "high", 100, 10,
        "High-rate TCP SYN packets from a single source (handshake never completes).",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_syn_only(r),
    ),
    BuiltinSignature(
        "RULE-002", "Port Scan", "PortScan", "medium", 20, 10,
        "Single source probing many destination ports in a short window.",
        matcher=lambda s, d, dp, proto, r: dp if (proto == TCP and _is_syn_only(r)) else None,
        distinct=True,
    ),
    BuiltinSignature(
        "RULE-003", "ICMP Flood", "DoS-ICMP-Flood", "high", 50, 5,
        "High-rate ICMP packets from a single source.",
        matcher=lambda s, d, dp, proto, r: proto == ICMP,
    ),
    BuiltinSignature(
        "RULE-004", "UDP Flood", "DoS-UDP-Flood", "high", 200, 10,
        "High-rate UDP packets from a single source.",
        matcher=lambda s, d, dp, proto, r: proto == UDP,
    ),
    BuiltinSignature(
        "RULE-005", "Ping Sweep", "Reconnaissance-PingSweep", "low", 10, 30,
        "ICMP echo requests sent to many distinct hosts from one source.",
        matcher=lambda s, d, dp, proto, r: d if proto == ICMP else None,
        distinct=True,
    ),
    BuiltinSignature(
        "RULE-006", "DNS Amplification", "DDoS-DNS-Amplification", "critical", 10, 10,
        "Oversized DNS responses toward a single victim (reflection/amplification).",
        matcher=lambda s, d, dp, proto, r: proto == UDP and dp != 53 and r.length > 512,
        group_by="dst_ip",
    ),
    BuiltinSignature(
        "RULE-007", "SSH Brute Force", "Bruteforce-SSH", "medium", 10, 30,
        "Repeated TCP SYNs toward port 22 from a single source.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_syn_only(r) and dp == 22,
    ),
    BuiltinSignature(
        "RULE-008", "FTP Brute Force", "Bruteforce-FTP", "medium", 10, 30,
        "Repeated TCP SYNs toward port 21 from a single source.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_syn_only(r) and dp == 21,
    ),
    BuiltinSignature(
        "RULE-009", "RDP Brute Force", "Bruteforce-RDP", "high", 5, 30,
        "Repeated TCP SYNs toward port 3389 from a single source.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_syn_only(r) and dp == 3389,
    ),
    BuiltinSignature(
        "RULE-010", "TCP NULL Scan", "PortScan-NullScan", "medium", 5, 10,
        "TCP packets with no flags set at all.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_bare(r),
    ),
    BuiltinSignature(
        "RULE-011", "TCP XMAS Scan", "PortScan-XMASScan", "medium", 5, 10,
        "TCP packets with FIN+PSH+URG flags set together.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_xmas(r),
    ),
    BuiltinSignature(
        "RULE-012", "TCP FIN Scan", "PortScan-FINScan", "low", 5, 10,
        "TCP packets with only the FIN flag set.",
        matcher=lambda s, d, dp, proto, r: proto == TCP and _is_fin_only(r),
    ),
    BuiltinSignature(
        "RULE-013", "Ping of Death", "DoS-PingOfDeath", "high", 1, 60,
        "ICMP packets far larger than a normal echo request.",
        matcher=lambda s, d, dp, proto, r: proto == ICMP and r.length > 1500,
    ),
]

BUILTIN_BY_CODE = {sig.code: sig for sig in BUILTIN_SIGNATURES}


class _SlidingWindowCounter:
    """Per-key sliding window of (timestamp, value) events"""

    def __init__(self):
        self._events: Dict[str, deque] = defaultdict(deque)

    def record(self, key: str, value, now: float) -> None:
        self._events[key].append((now, value))

    def count_in_window(self, key: str, window_seconds: float, now: float, distinct: bool) -> int:
        dq = self._events[key]
        cutoff = now - window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if distinct:
            return len(set(v for _, v in dq))
        return len(dq)


class RateSignatureEngine:
    """
    Evaluates every incoming packet against the enabled built-in
    signatures and fires
    """

    def __init__(self, on_fire: Callable[[BuiltinSignature, str], None]):
        self._counter = _SlidingWindowCounter()
        self._last_fired: Dict[Tuple[str, str], float] = {}  # (code, group_key) -> ts
        self._on_fire = on_fire
        self.enabled_codes = {sig.code for sig in BUILTIN_SIGNATURES}  # overwritten from DB at load time

    def set_enabled(self, codes) -> None:
        self.enabled_codes = set(codes)

    def handle_packet(self, src_ip: str, dst_ip: str, dst_port: int, protocol: int, record: PacketRecord, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()

        for sig in BUILTIN_SIGNATURES:
            if sig.code not in self.enabled_codes:
                continue

            value = sig.matcher(src_ip, dst_ip, dst_port, protocol, record)
            if value is None or value is False:
                continue

            group_key = src_ip if sig.group_by == "src_ip" else dst_ip
            counter_key = f"{sig.code}:{group_key}"
            self._counter.record(counter_key, value if sig.distinct else True, now)

            count = self._counter.count_in_window(counter_key, sig.window_seconds, now, sig.distinct)
            if count < sig.threshold:
                continue

            cooldown_key = (sig.code, group_key)
            last_fired = self._last_fired.get(cooldown_key, float("-inf"))
            if now - last_fired < sig.window_seconds:
                continue  # already alerted for this source recently; don't spam

            self._last_fired[cooldown_key] = now
            self._on_fire(sig, group_key)
