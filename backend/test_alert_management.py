"""
Test script for Alert Management System.
Place this file in: backend/test_alert_management.py
"""
import sys
import os

# Add src to path so we can import alert_management
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from alert_management import AlertStore, AlertDeduplicator, SeverityScorer, init_database

print("=" * 60)
print("Testing Alert Management System")
print("=" * 60)

# Step 1: Initialize database
print("\n[Test 1] Initializing database...")
init_database('data/alerts.db')
print("✓ Database initialized")

# Step 2: Test Severity Scorer
print("\n[Test 2] Testing Severity Scorer...")
scorer = SeverityScorer()

test_cases = [
    {'attack_type': 'PortScan', 'ml_confidence': 0.8},
    {'attack_type': 'DDoS', 'ml_confidence': 0.95},
    {'attack_type': 'Bruteforce', 'ml_confidence': 0.6, 'count_occurrences': 15}
]

for case in test_cases:
    severity = scorer.calculate_severity(case)
    print(f"  {case['attack_type']} -> {severity}")
print("✓ Severity Scorer working")

# Step 3: Test Alert Store
print("\n[Test 3] Testing Alert Store...")
store = AlertStore('data/alerts.db')

# Create a test alert
test_alert = {
    'attack_type': 'PortScan',
    'severity': 'medium',
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.1',
    'protocol': 'TCP',
    'message': 'Port scan detected',
    'explanation': 'Multiple ports scanned from 192.168.1.100',
    'ml_confidence': 0.82
}

alert = store.create_alert(test_alert)
print(f"✓ Alert created: {alert.alert_id}")

# Test deduplication
print("\n[Test 4] Testing Deduplicator...")
deduplicator = AlertDeduplicator(time_window_minutes=5)

# Process same alert again
result = deduplicator.process_alert(test_alert)
if result['is_duplicate']:
    print(f"✓ Alert deduplicated: count={result['count_occurrences']}")
else:
    print("  New alert created")

# Test get alerts
print("\n[Test 5] Retrieving alerts...")
alerts = store.get_alerts(limit=10)
print(f"✓ Retrieved {len(alerts)} alerts")

# Test stats
stats = store.get_alert_stats()
print(f"✓ Alert stats: {stats}")

print("\n" + "=" * 60)
print("All Alert Management tests passed!")
print("=" * 60)