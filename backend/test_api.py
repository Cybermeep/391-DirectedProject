"""
Test script for the NIDS API.
"""
import sys
import os
import json
import requests
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("=" * 60)
print("Testing NIDS API")
print("=" * 60)

# Test 1: Start the API server
print("\n[Test 1] Starting API server...")
print("Please run this in a separate terminal:")
print("  python -c \"import sys; sys.path.insert(0, 'src'); from api import start_api; start_api(debug=True)\"")
print("\nPress Enter after the server is running...")
input()

# Test 2: Health check
print("\n[Test 2] Testing health endpoint...")
try:
    response = requests.get('http://localhost:5000/api/health')
    print(f"✓ Health check: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: Create an alert via API
print("\n[Test 3] Creating an alert via API...")
try:
    alert_data = {
        'attack_type': 'PortScan',
        'source_ip': '192.168.1.100',
        'dest_ip': '10.0.0.1',
        'protocol': 'TCP',
        'message': 'Port scan detected from 192.168.1.100',
        'explanation': 'Multiple ports scanned from 192.168.1.100',
        'ml_confidence': 0.82
    }
    
    response = requests.post(
        'http://localhost:5000/api/alerts/',
        json=alert_data,
        headers={'Content-Type': 'application/json'}
    )
    print(f"✓ Response: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: Get alerts
print("\n[Test 4] Getting alerts...")
try:
    response = requests.get('http://localhost:5000/api/alerts/')
    print(f"✓ Got {response.json().get('count', 0)} alerts")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 5: Get stats
print("\n[Test 5] Getting stats...")
try:
    response = requests.get('http://localhost:5000/api/alerts/stats')
    print(f"✓ Stats: {response.json()}")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("API tests complete!")
print("=" * 60)