"""
Test script for the Rule-Based Detection Engine.

Run from the backend/ directory:
    python test_rule_engine.py

No network interface or trained model required — all tests use
synthetic packet_info dicts matching PacketProcessor output format.
"""

import sys
import os
import time

print("=" * 60)
print("Rule Engine Test Suite")
print("=" * 60)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# ---------------------------------------------------------------------------
# Test 1: Imports
# ---------------------------------------------------------------------------
print("\n[Test 1] Module imports...")
try:
    from rule_engine import RuleEngine, Rule, default_rules
    print("  ✓ RuleEngine imported")
    print("  ✓ Rule imported")
    print("  ✓ default_rules imported")
except Exception as e:
    print(f"  ✗ Import failed: {e}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Test 2: Default rules
# ---------------------------------------------------------------------------
print("\n[Test 2] Default rule set...")
rules = default_rules()
print(f"  ✓ {len(rules)} built-in rules loaded")
for r in rules:
    print(f"    {r.rule_id}  [{r.severity:<8}]  {r.name}")
assert len(rules) == 13, f"Expected 13 rules, got {len(rules)}"

# ---------------------------------------------------------------------------
# Test 3: Engine initialisation
# ---------------------------------------------------------------------------
print("\n[Test 3] Engine initialisation...")
engine_default = RuleEngine()
stats = engine_default.get_stats()
print(f"  ✓ Engine created with {stats['active_detectors']} active detectors")
print(f"  ✓ get_rules() returns {len(engine_default.get_rules())} rules")
assert stats['active_detectors'] == 13

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_packet(proto='TCP', src_ip='192.168.1.100', dst_ip='10.0.0.1',
                src_port=50000, dst_port=80, flags=None, payload_len=0,
                icmp_type=None, dns_qr=None, ts=None):
    """Build a minimal packet_info dict that matches PacketProcessor output."""
    pkt = {
        'timestamp': ts or time.time(),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'length': 60 + payload_len,
        'payload_length': payload_len,
        'has_tcp':  proto == 'TCP',
        'has_udp':  proto == 'UDP',
        'has_icmp': proto == 'ICMP',
        'has_dns':  dns_qr is not None,
        'dns_qr':   dns_qr,
        'icmp_type': icmp_type,
        'tcp_flags': {
            'syn': False, 'ack': False, 'rst': False, 'fin': False,
            'psh': False, 'urg': False, 'ece': False, 'cwr': False,
        },
    }
    if flags:
        pkt['tcp_flags'].update(flags)
    return pkt


def check(label, condition, on_fail=''):
    """Print ✓/✗ result for a single assertion."""
    if condition:
        print(f"  ✓ {label}")
        return True
    else:
        detail = f' — {on_fail}' if on_fail else ''
        print(f"  ✗ {label}{detail}")
        return False


# Low-threshold rules so each test only needs a handful of packets.
LOW_T_RULES = [
    Rule('RULE-001', 'SYN Flood',        'DoS-SYN-Flood',           'high',     '-', threshold=5, time_window=10, cooldown=2),
    Rule('RULE-002', 'Port Scan',         'PortScan',                 'medium',   '-', threshold=5, time_window=10, cooldown=2),
    Rule('RULE-003', 'ICMP Flood',        'DoS-ICMP-Flood',          'high',     '-', threshold=5, time_window=5,  cooldown=2),
    Rule('RULE-004', 'UDP Flood',         'DoS-UDP-Flood',           'high',     '-', threshold=5, time_window=10, cooldown=2),
    Rule('RULE-005', 'Ping Sweep',        'Reconnaissance-PingSweep','low',      '-', threshold=3, time_window=30, cooldown=2),
    Rule('RULE-006', 'DNS Amplification', 'DDoS-DNS-Amplification',  'critical', '-', threshold=3, time_window=10, cooldown=2, params={'min_response_size': 512}),
    Rule('RULE-007', 'SSH Brute Force',   'Bruteforce-SSH',          'medium',   '-', threshold=3, time_window=30, cooldown=2, params={'target_port': 22}),
    Rule('RULE-008', 'FTP Brute Force',   'Bruteforce-FTP',          'medium',   '-', threshold=3, time_window=30, cooldown=2, params={'target_port': 21}),
    Rule('RULE-009', 'RDP Brute Force',   'Bruteforce-RDP',          'high',     '-', threshold=3, time_window=30, cooldown=2, params={'target_port': 3389}),
    Rule('RULE-010', 'TCP NULL Scan',     'PortScan-NullScan',       'medium',   '-', threshold=3, time_window=10, cooldown=2),
    Rule('RULE-011', 'TCP XMAS Scan',     'PortScan-XMASScan',       'medium',   '-', threshold=3, time_window=10, cooldown=2),
    Rule('RULE-012', 'TCP FIN Scan',      'PortScan-FINScan',        'low',      '-', threshold=3, time_window=10, cooldown=2),
    Rule('RULE-013', 'Ping of Death',     'DoS-PingOfDeath',         'high',     '-', threshold=1, time_window=60, cooldown=5, params={'max_safe_icmp_payload': 1472}),
]

# ---------------------------------------------------------------------------
# Test 4: Each detector fires on matching traffic
# ---------------------------------------------------------------------------
print("\n[Test 4] Detector firing (low-threshold rules)...")
eng = RuleEngine(rules=LOW_T_RULES)
passed = 0
total = 0

def fire_test(label, packets, expect=True):
    global passed, total
    total += 1
    eng.reset()
    alerts = []
    for p in packets:
        alerts.extend(eng.analyze_packet(p))
    fired = len(alerts) > 0
    ok = check(label, fired == expect,
               on_fail='alert not fired' if expect else 'unexpected alert fired')
    if ok:
        passed += 1
    if fired and expect:
        print(f"       attack_type={alerts[0]['attack_type']!r}  severity={alerts[0]['severity']!r}")
    return ok

# RULE-001: SYN Flood — 5 bare SYNs should alert
fire_test('RULE-001 SYN Flood fires on 5 bare SYNs',
          [make_packet('TCP', flags={'syn': True}) for _ in range(5)])

# RULE-001: SYN+ACK packets must NOT trigger SYN flood
fire_test('RULE-001 ignores SYN+ACK (normal handshake)',
          [make_packet('TCP', flags={'syn': True, 'ack': True}) for _ in range(10)],
          expect=False)

# RULE-002: Port Scan — 5 different destination ports
fire_test('RULE-002 Port Scan fires on 5 unique dst ports',
          [make_packet('UDP', dst_port=p) for p in [22, 80, 443, 3306, 5432]])

# RULE-002: Repeated hits to the SAME port should not alert
fire_test('RULE-002 ignores repeated hits to same port',
          [make_packet('UDP', dst_port=80) for _ in range(20)],
          expect=False)

# RULE-003: ICMP Flood — 5 ICMP packets
fire_test('RULE-003 ICMP Flood fires on 5 ICMP packets',
          [make_packet('ICMP') for _ in range(5)])

# RULE-004: UDP Flood — 5 UDP packets
fire_test('RULE-004 UDP Flood fires on 5 UDP packets',
          [make_packet('UDP') for _ in range(5)])

# RULE-005: Ping Sweep — 3 ICMP echo requests to different hosts
fire_test('RULE-005 Ping Sweep fires on 3 unique ICMP targets',
          [make_packet('ICMP', dst_ip=f'192.168.1.{i}', icmp_type=8) for i in range(1, 4)])

# RULE-005: Non-echo ICMP (e.g. time exceeded, type=11) must not count as ping sweep
fire_test('RULE-005 ignores non-echo ICMP types',
          [make_packet('ICMP', dst_ip=f'192.168.1.{i}', icmp_type=11) for i in range(1, 10)],
          expect=False)

# RULE-006: DNS Amplification — 3 large DNS responses from port 53
fire_test('RULE-006 DNS Amplification fires on large DNS responses',
          [make_packet('UDP', src_port=53, dst_port=40000,
                       payload_len=600, dns_qr='response') for _ in range(3)])

# RULE-006: Small DNS responses should not alert
fire_test('RULE-006 ignores small DNS responses',
          [make_packet('UDP', src_port=53, dst_port=40000,
                       payload_len=100, dns_qr='response') for _ in range(10)],
          expect=False)

# RULE-007: SSH Brute Force
fire_test('RULE-007 SSH Brute Force fires on repeated SYNs to port 22',
          [make_packet('TCP', flags={'syn': True}, dst_port=22) for _ in range(3)])

# RULE-008: FTP Brute Force
fire_test('RULE-008 FTP Brute Force fires on repeated SYNs to port 21',
          [make_packet('TCP', flags={'syn': True}, dst_port=21) for _ in range(3)])

# RULE-009: RDP Brute Force
fire_test('RULE-009 RDP Brute Force fires on repeated SYNs to port 3389',
          [make_packet('TCP', flags={'syn': True}, dst_port=3389) for _ in range(3)])

# RULE-010: NULL Scan — TCP with no flags
fire_test('RULE-010 TCP NULL Scan fires on flag-less TCP packets',
          [make_packet('TCP') for _ in range(3)])

# RULE-011: XMAS Scan — FIN+PSH+URG
fire_test('RULE-011 TCP XMAS Scan fires on FIN+PSH+URG',
          [make_packet('TCP', flags={'fin': True, 'psh': True, 'urg': True}) for _ in range(3)])

# RULE-012: FIN Scan — FIN only, no ACK
fire_test('RULE-012 TCP FIN Scan fires on FIN-only packets',
          [make_packet('TCP', flags={'fin': True}) for _ in range(3)])

# RULE-012: FIN+ACK is normal connection teardown — must not alert
fire_test('RULE-012 ignores FIN+ACK (normal teardown)',
          [make_packet('TCP', flags={'fin': True, 'ack': True}) for _ in range(20)],
          expect=False)

# RULE-013: Ping of Death — single oversized ICMP payload
fire_test('RULE-013 Ping of Death fires on oversized ICMP payload',
          [make_packet('ICMP', payload_len=2000)])

# RULE-013: Normal-sized ICMP must not alert
fire_test('RULE-013 ignores ICMP within safe payload limit',
          [make_packet('ICMP', payload_len=64) for _ in range(5)],
          expect=False)

print(f"\n  Detector tests: {passed}/{total} passed")

# ---------------------------------------------------------------------------
# Test 5: Alert cooldown — same source must not re-alert immediately
# ---------------------------------------------------------------------------
print("\n[Test 5] Alert cooldown...")
eng.reset()

# First burst hits threshold → alert fires
first_alerts = []
for _ in range(5):
    first_alerts.extend(eng.analyze_packet(make_packet('TCP', flags={'syn': True})))

# Immediate second burst — cooldown window (2s) hasn't expired
second_alerts = []
for _ in range(5):
    second_alerts.extend(eng.analyze_packet(make_packet('TCP', flags={'syn': True})))

check('First burst triggers alert', bool(first_alerts), 'no alert on first burst')
check('Second burst suppressed by cooldown', not second_alerts, 'duplicate alert emitted')

# ---------------------------------------------------------------------------
# Test 6: Per-source isolation
# ---------------------------------------------------------------------------
print("\n[Test 6] Per-source IP isolation...")
eng.reset()

# Source A sends 4 SYNs (below threshold=5) — must not alert
for _ in range(4):
    eng.analyze_packet(make_packet('TCP', src_ip='10.0.0.1', flags={'syn': True}))

# Source B sends 5 SYNs — only B should alert; A must remain silent
b_alerts = []
for _ in range(5):
    b_alerts.extend(eng.analyze_packet(make_packet('TCP', src_ip='10.0.0.2', flags={'syn': True})))

check('Source B alerted independently', bool(b_alerts) and b_alerts[0]['source_ip'] == '10.0.0.2',
      f'got source_ip={b_alerts[0]["source_ip"]!r}' if b_alerts else 'no alert for B')

# After A sends one more SYN it crosses the threshold
a_alerts = []
a_alerts.extend(eng.analyze_packet(make_packet('TCP', src_ip='10.0.0.1', flags={'syn': True})))
check('Source A alerted on its own threshold', bool(a_alerts) and a_alerts[0]['source_ip'] == '10.0.0.1',
      'A did not alert on its 5th SYN')

# ---------------------------------------------------------------------------
# Test 7: Enable / disable rules
# ---------------------------------------------------------------------------
print("\n[Test 7] enable_rule / disable_rule...")
eng2 = RuleEngine(rules=LOW_T_RULES)

# Disable RULE-001, send 10 SYNs — must stay silent
ok = eng2.disable_rule('RULE-001')
check('disable_rule returns True', ok)
eng2.reset()
silent = []
for _ in range(10):
    silent.extend(eng2.analyze_packet(make_packet('TCP', flags={'syn': True})))
check('Disabled RULE-001 produces no alerts', not silent, f'got {len(silent)} unexpected alert(s)')

# Re-enable and confirm it fires again
eng2.enable_rule('RULE-001')
eng2.reset()
loud = []
for _ in range(5):
    loud.extend(eng2.analyze_packet(make_packet('TCP', flags={'syn': True})))
check('Re-enabled RULE-001 fires again', bool(loud))

# Disable a non-existent rule must return False
check('disable_rule on unknown ID returns False', not eng2.disable_rule('RULE-999'))

# ---------------------------------------------------------------------------
# Test 8: Engine statistics
# ---------------------------------------------------------------------------
print("\n[Test 8] Engine statistics...")
eng3 = RuleEngine(rules=LOW_T_RULES)
eng3.reset()

# Send exactly 5 ICMP packets (threshold=5) — 1 alert expected
for _ in range(5):
    eng3.analyze_packet(make_packet('ICMP'))

s = eng3.get_stats()
check(f'packets_analyzed == 5 (got {s["packets_analyzed"]})',   s['packets_analyzed'] == 5)
check(f'alerts_generated >= 1 (got {s["alerts_generated"]})',   s['alerts_generated'] >= 1)
check(f'active_detectors == 13 (got {s["active_detectors"]})', s['active_detectors'] == 13)

eng3.reset()
s2 = eng3.get_stats()
check('reset() clears packet/alert counters', s2['packets_analyzed'] == 0 and s2['alerts_generated'] == 0)

# ---------------------------------------------------------------------------
# Test 9: Alert dict format (AlertStore compatibility)
# ---------------------------------------------------------------------------
print("\n[Test 9] Alert dict format (AlertStore compatibility)...")

REQUIRED_KEYS = {
    'rule_id', 'attack_type', 'severity',
    'source_ip', 'dest_ip', 'source_port', 'dest_port',
    'protocol', 'message', 'explanation', 'ml_confidence',
}

eng4 = RuleEngine(rules=LOW_T_RULES)
eng4.reset()
sample_alerts = []
for _ in range(5):
    sample_alerts.extend(eng4.analyze_packet(make_packet('ICMP')))

if sample_alerts:
    a = sample_alerts[0]
    missing = REQUIRED_KEYS - set(a.keys())
    check('Alert dict has all required AlertStore keys', not missing,
          f'missing: {missing}')
    check('ml_confidence is 0.0 for rule-based alerts', a['ml_confidence'] == 0.0)
    check('severity is a valid value',
          a['severity'] in ('low', 'medium', 'high', 'critical'))
    check('rule_id starts with RULE-', str(a.get('rule_id', '')).startswith('RULE-'))
    print(f"    rule_id={a['rule_id']!r}  severity={a['severity']!r}  attack_type={a['attack_type']!r}")
else:
    check('Alert generated for format check', False, 'no alert was produced')

# ---------------------------------------------------------------------------
# Test 10: Mixed-traffic scenario (multiple rules simultaneously)
# ---------------------------------------------------------------------------
print("\n[Test 10] Mixed-traffic scenario...")
eng5 = RuleEngine(rules=LOW_T_RULES)
eng5.reset()

mixed_packets = (
    # SYN flood from attacker A
    [make_packet('TCP', src_ip='1.2.3.4', flags={'syn': True}) for _ in range(5)] +
    # Port scan from attacker B
    [make_packet('UDP', src_ip='5.6.7.8', dst_port=p) for p in [22, 80, 443, 3306, 5432]] +
    # XMAS scan from attacker C
    [make_packet('TCP', src_ip='9.10.11.12', flags={'fin': True, 'psh': True, 'urg': True}) for _ in range(3)] +
    # Benign HTTPS traffic from internal host (should produce no alerts)
    [make_packet('TCP', src_ip='192.168.0.10', flags={'syn': True, 'ack': True}, dst_port=443)
     for _ in range(20)]
)

all_alerts = []
for p in mixed_packets:
    all_alerts.extend(eng5.analyze_packet(p))

attack_types = {a['attack_type'] for a in all_alerts}
source_ips   = {a['source_ip']   for a in all_alerts}

check(f'Total alerts generated: {len(all_alerts)} (expected >= 3)', len(all_alerts) >= 3)
check('DoS-SYN-Flood detected',    'DoS-SYN-Flood'    in attack_types)
check('PortScan detected',          'PortScan'          in attack_types)
check('PortScan-XMASScan detected', 'PortScan-XMASScan' in attack_types)
check('Benign host produced no alerts', '192.168.0.10' not in source_ips,
      f'benign host alerted — source_ips={source_ips}')

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print(f"Test suite complete.")
print(f"Detector tests: {passed}/{total} passed")
print("=" * 60)
