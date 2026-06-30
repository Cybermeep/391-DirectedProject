"""
Rule definitions for the rule-based detection engine.

Each Rule describes a single detection policy: what attack it catches,
the severity to assign, and the thresholds that control when it fires.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Rule:
    rule_id: str
    name: str
    attack_type: str
    severity: str           # low | medium | high | critical
    description: str
    enabled: bool = True
    threshold: int = 100    # event count before alerting
    time_window: int = 60   # sliding window in seconds
    cooldown: int = 60      # minimum seconds between repeated alerts for same source
    params: Dict[str, Any] = field(default_factory=dict)


def default_rules() -> List[Rule]:
    """Return the built-in rule set covering common home network intrusions."""
    return [
        Rule(
            rule_id='RULE-001',
            name='SYN Flood',
            attack_type='DoS-SYN-Flood',
            severity='high',
            description='High-rate TCP SYN packets from a single source without completing handshakes',
            threshold=100,
            time_window=10,
            cooldown=30,
        ),
        Rule(
            rule_id='RULE-002',
            name='Port Scan',
            attack_type='PortScan',
            severity='medium',
            description='Single source probing many destination ports in a short time window',
            threshold=20,
            time_window=10,
            cooldown=60,
        ),
        Rule(
            rule_id='RULE-003',
            name='ICMP Flood',
            attack_type='DoS-ICMP-Flood',
            severity='high',
            description='High-rate ICMP packets from a single source',
            threshold=50,
            time_window=5,
            cooldown=30,
        ),
        Rule(
            rule_id='RULE-004',
            name='UDP Flood',
            attack_type='DoS-UDP-Flood',
            severity='high',
            description='High-rate UDP packets from a single source',
            threshold=200,
            time_window=10,
            cooldown=30,
        ),
        Rule(
            rule_id='RULE-005',
            name='Ping Sweep',
            attack_type='Reconnaissance-PingSweep',
            severity='low',
            description='Single source sending ICMP echo requests to many different hosts',
            threshold=10,
            time_window=30,
            cooldown=120,
        ),
        Rule(
            rule_id='RULE-006',
            name='DNS Amplification',
            attack_type='DDoS-DNS-Amplification',
            severity='critical',
            description='Oversized DNS responses indicative of a DNS amplification DDoS attack',
            threshold=10,        # number of oversized responses in window
            time_window=10,
            cooldown=60,
            params={'min_response_size': 512},
        ),
        Rule(
            rule_id='RULE-007',
            name='SSH Brute Force',
            attack_type='Bruteforce-SSH',
            severity='medium',
            description='Repeated TCP SYN attempts to SSH (port 22) from a single source',
            threshold=10,
            time_window=30,
            cooldown=60,
            params={'target_port': 22},
        ),
        Rule(
            rule_id='RULE-008',
            name='FTP Brute Force',
            attack_type='Bruteforce-FTP',
            severity='medium',
            description='Repeated TCP SYN attempts to FTP (port 21) from a single source',
            threshold=10,
            time_window=30,
            cooldown=60,
            params={'target_port': 21},
        ),
        Rule(
            rule_id='RULE-009',
            name='RDP Brute Force',
            attack_type='Bruteforce-RDP',
            severity='high',
            description='Repeated TCP SYN attempts to RDP (port 3389) from a single source',
            threshold=5,
            time_window=30,
            cooldown=60,
            params={'target_port': 3389},
        ),
        Rule(
            rule_id='RULE-010',
            name='TCP NULL Scan',
            attack_type='PortScan-NullScan',
            severity='medium',
            description='TCP packets with no flags set, used to probe firewall rules stealthily',
            threshold=5,
            time_window=10,
            cooldown=60,
        ),
        Rule(
            rule_id='RULE-011',
            name='TCP XMAS Scan',
            attack_type='PortScan-XMASScan',
            severity='medium',
            description='TCP packets with FIN+PSH+URG flags, a Christmas tree scan technique',
            threshold=5,
            time_window=10,
            cooldown=60,
        ),
        Rule(
            rule_id='RULE-012',
            name='TCP FIN Scan',
            attack_type='PortScan-FINScan',
            severity='low',
            description='TCP packets with only FIN flag set, used to bypass stateless firewalls',
            threshold=5,
            time_window=10,
            cooldown=60,
        ),
        Rule(
            rule_id='RULE-013',
            name='Ping of Death',
            attack_type='DoS-PingOfDeath',
            severity='high',
            description='ICMP packets with oversized payloads exceeding safe MTU limits',
            threshold=1,
            time_window=60,
            cooldown=300,
            params={'max_safe_icmp_payload': 1472},
        ),
    ]
