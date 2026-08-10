"""
Stateful detector classes for the rule-based detection engine
"""

import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Dict, List, Optional

from .rules import Rule


# Internal helpers

class _RateTracker:
    """Counts events per key inside a sliding time window"""

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
    """Tracks unique values per key inside a sliding time window"""

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


# Base detector

class BaseDetector(ABC):
    """Common behaviour shared by all concrete detectors."""

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self._last_alerted: Dict[str, float] = {}
        self._cleanup_interval = 120.0
        self._last_cleanup = 0.0

    # Public interface 

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    def analyze_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    def reset(self) -> None:
        self._last_alerted.clear()

    #  Helpers for subclasses 

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


# Concrete detectors

class SYNFloodDetector(BaseDetector):
    """RULE-001: Detects TCP SYN floods by counting bare SYN packets per source"""

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


class SYNFINScanDetector(BaseDetector):
    """RULE-014: Detects TCP SYN-FIN scans (SYN and FIN both set — an invalid, evasive flag combo)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        if not (flags.get('syn') and flags.get('fin')):
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
                f'TCP SYN-FIN Scan: {count} SYN+FIN packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP packets with both SYN and FIN flags set in {tw} seconds. '
                 f'This invalid flag combination is used by scanners to slip past simple firewall/IDS filters.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ACKScanDetector(BaseDetector):
    """RULE-015: Detects TCP ACK scans by tracking unique destination ports hit with bare ACK packets."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _UniqueSetTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        # ACK-only: ack set, nothing else — used to probe firewall statefulness
        if not flags.get('ack'):
            return []
        if any(flags.get(f) for f in ('syn', 'fin', 'rst', 'psh', 'urg')):
            return []

        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        if not src_ip or dst_port is None:
            return []

        now = self._now(packet_info)
        unique_ports = self._tracker.add(src_ip, dst_port, now)
        self._maybe_cleanup(now)

        if unique_ports >= self.rule.threshold and not self._in_cooldown(src_ip, now):
            self._record_alert(src_ip, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'TCP ACK Scan: {unique_ports} unique ports probed with bare ACKs in {tw}s from {src_ip}',
                (f'{src_ip} sent bare ACK packets to {unique_ports} distinct destination ports in '
                 f'{tw} seconds without an established connection, consistent with an ACK scan used '
                 f'to map firewall filtering rules.'),
                count=unique_ports,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPSmurfDetector(BaseDetector):
    """RULE-016: Detects Smurf-style attacks — ICMP echo requests sent to a broadcast address."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []
        if packet_info.get('icmp_type') != 8:  # echo request
            return []

        dst_ip = packet_info.get('dst_ip') or ''
        if dst_ip != '255.255.255.255' and not dst_ip.endswith('.255'):
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
                f'ICMP Smurf Attack: {count} broadcast echo requests in {tw}s from {src_ip} to {dst_ip}',
                (f'{src_ip} sent {count} ICMP echo requests to broadcast address {dst_ip} in {tw} seconds. '
                 f'If the source address is spoofed, every host on the subnet will flood the victim with replies.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPRedirectDetector(BaseDetector):
    """RULE-017: Detects ICMP redirect messages, which can be spoofed to hijack victim routing (MITM)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []
        if packet_info.get('icmp_type') != 5:  # redirect
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
                f'ICMP Redirect Attack: {count} redirect messages in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} ICMP redirect messages in {tw} seconds. '
                 f'Spoofed redirects can be used to reroute victim traffic through an attacker-controlled '
                 f'host for man-in-the-middle interception.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class DNSQueryFloodDetector(BaseDetector):
    """RULE-018: Detects an abnormally high rate of DNS queries from a single source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_dns'):
            return []
        if packet_info.get('dns_qr') != 'query':
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
                f'DNS Query Flood: {count} DNS queries in {tw}s from {src_ip}',
                (f'{src_ip} issued {count} DNS queries in {tw} seconds, well above normal resolver '
                 f'usage, consistent with DNS-based denial-of-service or resolver abuse.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class DNSAnyQueryDetector(BaseDetector):
    """RULE-019: Detects repeated DNS ANY-type queries, used for domain fingerprinting or amplification setup."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._any_qtype = rule.params.get('dns_qtype_any', 255)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_dns'):
            return []
        if packet_info.get('dns_qr') != 'query':
            return []
        if packet_info.get('dns_qtype') != self._any_qtype:
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
                f'DNS ANY Query Probe: {count} ANY-type queries in {tw}s from {src_ip}',
                (f'{src_ip} issued {count} DNS ANY-type queries in {tw} seconds. ANY queries return '
                 f'the largest possible response and are commonly used to fingerprint a domain or '
                 f'stage a DNS amplification attack.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class MACSpoofingDetector(BaseDetector):
    """RULE-020: Detects a single source MAC address paired with multiple source IPs (ARP/MAC spoofing)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _UniqueSetTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        src_mac = packet_info.get('src_mac')
        src_ip = packet_info.get('src_ip')
        if not src_mac or not src_ip:
            return []

        now = self._now(packet_info)
        unique_ips = self._tracker.add(src_mac, src_ip, now)
        self._maybe_cleanup(now)

        if unique_ips >= self.rule.threshold and not self._in_cooldown(src_mac, now):
            self._record_alert(src_mac, now)
            tw = self.rule.time_window
            return [self._build_alert(
                packet_info,
                f'MAC Spoofing: MAC {src_mac} used {unique_ips} distinct source IPs in {tw}s',
                (f'MAC address {src_mac} was observed sending traffic from {unique_ips} different '
                 f'source IP addresses within {tw} seconds. On a normal LAN one MAC maps to one IP, '
                 f'so rapid switching suggests ARP/MAC spoofing or a man-in-the-middle host.'),
                count=unique_ips,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class RSTFloodDetector(BaseDetector):
    """RULE-024: Detects TCP RST floods (connection-reset DoS or on-path RST injection)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        flags = packet_info.get('tcp_flags', {})
        if not flags.get('rst'):
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
                f'TCP RST Flood: {count} RST packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP RST packets in {tw} seconds, consistent with a '
                 f'connection-reset denial-of-service attack or on-path RST injection.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class IPFragmentationFloodDetector(BaseDetector):
    """RULE-025: Detects a flood of fragmented IP packets (evasion or teardrop-style DoS)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        ip_flags = packet_info.get('flags')
        if not ip_flags:
            return []
        try:
            is_fragment = 'MF' in ip_flags
        except TypeError:
            return []
        if not is_fragment:
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
                f'IP Fragmentation Flood: {count} fragmented packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} fragmented IP packets in {tw} seconds. Fragmentation is '
                 f'commonly used to evade firewalls/IDS or to mount teardrop-style DoS attacks.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class TCPZeroWindowDetector(BaseDetector):
    """RULE-026: Detects repeated TCP zero-window advertisements (Sockstress-style resource exhaustion)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_tcp'):
            return []
        if packet_info.get('window') != 0:
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
                f'TCP Zero-Window DoS: {count} zero-window packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} TCP packets advertising a zero receive window in {tw} seconds. '
                 f'Sustained zero-window signalling can be used to hold server resources open in a '
                 f'Sockstress-style resource-exhaustion attack.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class DNSTunnelingDetector(BaseDetector):
    """RULE-027: Detects DNS tunneling via abnormally long query names."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._max_qname_length = rule.params.get('max_qname_length', 50)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_dns'):
            return []
        if packet_info.get('dns_qr') != 'query':
            return []
        qname = packet_info.get('dns_query') or ''
        if len(qname) <= self._max_qname_length:
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
                f'DNS Tunneling: {count} oversized DNS query names in {tw}s from {src_ip}',
                (f'{src_ip} issued {count} DNS queries with names longer than {self._max_qname_length} '
                 f'characters in {tw} seconds. Abnormally long, high-entropy query names are the '
                 f'hallmark of DNS tunneling used for data exfiltration or covert command-and-control.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class MalformedPacketFloodDetector(BaseDetector):
    """RULE-028: Detects a flood of malformed/unparseable packets from a single source."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('error'):
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
                f'Malformed Packet Flood: {count} unparseable packets in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} malformed or unparseable packets in {tw} seconds, potentially '
                 f'protocol fuzzing or an attempt to evade signature-based detection.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPTimestampProbeDetector(BaseDetector):
    """RULE-029: Detects ICMP timestamp request probes used for OS fingerprinting/host discovery."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []
        if packet_info.get('icmp_type') != 13:  # timestamp request
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
                f'ICMP Timestamp Probe: {count} timestamp requests in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} ICMP timestamp requests in {tw} seconds. These probes are '
                 f'used for OS fingerprinting and host-discovery reconnaissance.'),
                count=count,
            )]
        return []

    def reset(self) -> None:
        super().reset()
        self._tracker.reset()

    def _cleanup(self, now: float) -> None:
        self._tracker.cleanup(now)


class ICMPUnreachableFloodDetector(BaseDetector):
    """RULE-030: Detects a flood of ICMP destination-unreachable messages (DoS backscatter or network mapping)."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._tracker = _RateTracker(rule.time_window)

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not packet_info.get('has_icmp'):
            return []
        if packet_info.get('icmp_type') != 3:  # destination unreachable
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
                f'ICMP Destination Unreachable Flood: {count} messages in {tw}s from {src_ip}',
                (f'{src_ip} sent {count} ICMP destination-unreachable messages in {tw} seconds, '
                 f'consistent with DoS backscatter from a spoofed attack or aggressive network mapping.'),
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
