"""
Stateful detector classes for the rule-based detection engine.

Each detector maintains sliding-window state to evaluate a single Rule
against a stream of packet_info dicts (from PacketProcessor) or flow dicts
(from FlowBuilder).  Detectors are instantiated by RuleEngine and should
not be used directly.
"""

import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Dict, List, Optional

from .rules import Rule


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _RateTracker:
    """Counts events per key inside a sliding time window."""

    def __init__(self, time_window: float) -> None:
        self._window = time_window
        self._events: Dict[str, deque] = {}

    def add(self, key: str, timestamp: float) -> int:
        if key not in self._events:
            self._events[key] = deque()
        q = self._events[key]
        q.append(timestamp)
        cutoff = timestamp - self._window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def count(self, key: str, now: float) -> int:
        q = self._events.get(key)
        if not q:
            return 0
        cutoff = now - self._window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def cleanup(self, now: float) -> None:
        stale = now - self._window * 2
        dead = [k for k, q in self._events.items() if not q or q[-1] < stale]
        for k in dead:
            del self._events[k]

    def reset(self) -> None:
        self._events.clear()


class _UniqueSetTracker:
    """Tracks unique values per key inside a sliding time window."""

    def __init__(self, time_window: float) -> None:
        self._window = time_window
        # key -> list of (timestamp, value)
        self._events: Dict[str, list] = {}

    def add(self, key: str, value: Any, timestamp: float) -> int:
        if key not in self._events:
            self._events[key] = []
        events = self._events[key]
        events.append((timestamp, value))
        cutoff = timestamp - self._window
        self._events[key] = [(t, v) for t, v in events if t >= cutoff]
        return len({v for _, v in self._events[key]})

    def cleanup(self, now: float) -> None:
        stale = now - self._window * 2
        dead = [k for k, evts in self._events.items() if not evts or evts[-1][0] < stale]
        for k in dead:
            del self._events[k]

    def reset(self) -> None:
        self._events.clear()


# ---------------------------------------------------------------------------
# Base detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Common behaviour shared by all concrete detectors."""

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self._last_alerted: Dict[str, float] = {}
        self._cleanup_interval = 120.0
        self._last_cleanup = 0.0

    # -- Public interface ---------------------------------------------------

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    def analyze_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    def reset(self) -> None:
        self._last_alerted.clear()

    # -- Helpers for subclasses --------------------------------------------

    def _now(self, packet_info: Dict[str, Any]) -> float:
        return packet_info.get('timestamp') or time.time()

    def _in_cooldown(self, src_ip: str, now: float) -> bool:
        return (now - self._last_alerted.get(src_ip, 0)) < self.rule.cooldown

    def _record_alert(self, src_ip: str, now: float) -> None:
        self._last_alerted[src_ip] = now

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup(now)
            self._last_cleanup = now

    def _cleanup(self, now: float) -> None:
        pass

    def _build_alert(
        self,
        packet_info: Dict[str, Any],
        message: str,
        explanation: str,
        count: Optional[int] = None,
    ) -> Dict[str, Any]:
        alert = {
            'rule_id': self.rule.rule_id,
            'attack_type': self.rule.attack_type,
            'severity': self.rule.severity,
            'source_ip': packet_info.get('src_ip'),
            'dest_ip': packet_info.get('dst_ip'),
            'source_port': packet_info.get('src_port'),
            'dest_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol', 'unknown'),
            'message': message,
            'explanation': explanation,
            'ml_confidence': 0.0,
        }
        if count is not None:
            alert['count'] = count
        return alert


# ---------------------------------------------------------------------------
# Concrete detectors
# ---------------------------------------------------------------------------

class SYNFloodDetector(BaseDetector):
    """RULE-001: Detects TCP SYN floods by counting bare SYN packets per source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        if not (flags.get('syn') and not flags.get('ack')):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'SYN Flood: {count} SYN packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP SYN packets in {tw} seconds '
                 f'without completing handshakes, consistent with a SYN flood DoS attack.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class PortScanDetector(BaseDetector):
    """RULE-002: Detects port scans by tracking unique destination ports per source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _UniqueSetTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        if not src_ip or dst_port is None:
            return []
        if not (packet_info.get('has_tcp') or packet_info.get('has_udp')):
            return []

        now = self._now(packet_info)
        unique_ports = self._tracker.add(src_ip, dst_port, now)
        self._maybe_cleanup(now)

        if unique_ports >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'Port Scan: {unique_ports} unique ports probed in {tw}s from {src_ip}',
                (f'{src_ip} contacted {unique_ports} distinct destination ports in {tw} seconds, '
                 f'consistent with automated port scanning.'),
                count=unique_ports,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPFloodDetector(BaseDetector):
    """RULE-003: Detects ICMP floods by counting ICMP packets per source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'ICMP Flood: {count} ICMP packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} ICMP packets in {tw} seconds, '
                 f'consistent with an ICMP flood denial-of-service attack.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class UDPFloodDetector(BaseDetector):
    """RULE-004: Detects UDP floods by counting UDP packets per source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_udp'):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'UDP Flood: {count} UDP packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} UDP datagrams in {tw} seconds, '
                 f'consistent with a UDP flood denial-of-service attack.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class PingSweepDetector(BaseDetector):
    """RULE-005: Detects ping sweeps by tracking unique ICMP echo targets per source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _UniqueSetTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []
        # Only ICMP echo request (type 8)
        if packet_info.get('icmp_type') != 8:
            return []

        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        if not src_ip or not dst_ip:
            return []

        now = self._now(packet_info)
        unique_hosts = self._tracker.add(src_ip, dst_ip, now)
        self._maybe_cleanup(now)

        if unique_hosts >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'Ping Sweep: {unique_hosts} hosts pinged in {tw}s from {src_ip}',
                (f'{src_ip} sent ICMP echo requests to {unique_hosts} distinct hosts in '
                 f'{tw} seconds, consistent with network reconnaissance via ping sweep.'),
                count=unique_hosts,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class DNSAmplificationDetector(BaseDetector):
    """RULE-006: Detects DNS amplification by flagging large DNS responses."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._min_size = rule.params.get('min_response_size', 512)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_dns'):
            return []
        if packet_info.get('dns_qr') != 'response':
            return []
        # Source must be port 53 (DNS server)
        if packet_info.get('src_port') != 53:
            return []

        payload_len = packet_info.get('payload_length', 0) or packet_info.get('length', 0)
        if payload_len < self._min_size:
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'DNS Amplification: {count} large DNS responses ({payload_len}B) in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} DNS responses larger than {self._min_size} bytes '
                 f'in {tw} seconds.  Large responses to spoofed requests are the hallmark '
                 f'of DNS amplification DDoS attacks.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class BruteForceDetector(BaseDetector):
    """RULE-007/008/009: Detects brute-force login attempts against a specific service port."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._target_port: int = rule.params['target_port']
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        if packet_info.get('dst_port') != self._target_port:
            return []
        flags = packet_info.get('tcp_flags', {})
        # Count connection-initiation attempts (SYN-only packets)
        if not (flags.get('syn') and not flags.get('ack')):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            service = self.rule.attack_type.split('-')[-1]
            return [self._build_alert(
                packet_info,
                f'{service} Brute Force: {count} connection attempts in {tw}s from {src_ip}',
                (f'{src_ip} made {count} TCP connection attempts to port {self._target_port} '
                 f'({service}) in {tw} seconds, consistent with automated credential brute forcing.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class NullScanDetector(BaseDetector):
    """RULE-010: Detects TCP NULL scans (packets with no flags set)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        # NULL scan: no flags set at all
        if any(flags.get(f) for f in ('syn', 'ack', 'rst', 'fin', 'psh', 'urg')):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'TCP NULL Scan: {count} null-flag packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP packets with no flags set in {tw} seconds. '
                 f'NULL scans are used to probe open ports by bypassing stateless firewalls.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class XMASScanDetector(BaseDetector):
    """RULE-011: Detects TCP XMAS scans (FIN+PSH+URG all set)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        if not (flags.get('fin') and flags.get('psh') and flags.get('urg')):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'TCP XMAS Scan: {count} FIN+PSH+URG packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP packets with FIN, PSH, and URG flags set in {tw} seconds. '
                 f'This Christmas tree pattern is used by Nmap and similar tools for stealth port scanning.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class FINScanDetector(BaseDetector):
    """RULE-012: Detects TCP FIN scans (only FIN flag set, no ACK)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        # FIN-only: fin=True, ack=False (all others irrelevant but typically off too)
        if not (flags.get('fin') and not flags.get('ack') and not flags.get('syn')):
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        count = self._tracker.add(src_ip, now)
        self._maybe_cleanup(now)

        if count >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'TCP FIN Scan: {count} FIN-only packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP FIN packets (without ACK) in {tw} seconds. '
                 f'FIN scans exploit RFC 793 behaviour to identify open ports behind stateless firewalls.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPLargePayloadDetector(BaseDetector):
    """RULE-013: Detects Ping-of-Death style oversized ICMP payloads."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._max_safe = rule.params.get('max_safe_icmp_payload', 1472)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []

        payload_len = packet_info.get('payload_length', 0) or 0
        if payload_len <= self._max_safe:
            return []

        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return []

        now = self._now(packet_info)
        if self._in_cooldown(src_ip, now):
            return []

        self._record_alert(src_ip, now)
        return [self._build_alert(
            packet_info,
            f'Ping of Death: ICMP payload {payload_len}B from {src_ip} (limit {self._max_safe}B)',
            (f'{src_ip} sent an ICMP packet with a {payload_len}-byte payload, '
             f'exceeding the safe limit of {self._max_safe} bytes. '
             f'Oversized ICMP packets can crash or destabilise vulnerable network stacks.'),
        )]
