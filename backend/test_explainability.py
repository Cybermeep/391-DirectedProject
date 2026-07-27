"""
Test script for the Explainability Module.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from explainability import FeatureMapper, ExplanationGenerator

print("=" * 60)
print("Testing Explainability Module")
print("=" * 60)

# Test 1: Feature Mapper
print("\n[Test 1] Testing Feature Mapper...")
mapper = FeatureMapper()

# Test feature descriptions
test_features = ['SYN_Flag_Cnt', 'Flow_Pkts/s', 'RST_Flag_Cnt', 'Tot_Fwd_Pkts']
for feature in test_features:
    desc = mapper.get_description(feature)
    print(f"  {feature} → {desc}")

print("\n✓ Feature Mapper working")

# Test 2: Feature Importance Text
print("\n[Test 2] Testing Feature Importance Text...")
for feature in test_features:
    text = mapper.get_feature_importance_text(feature, 0.75)
    print(f"  {text}")

print("\n✓ Feature Importance Text working")

# Test 3: Attack Patterns
print("\n[Test 3] Testing Attack Patterns...")
attack_types = ['PortScan', 'DDoS', 'Bruteforce', 'DoS', 'Botnet']
for attack in attack_types:
    pattern = mapper.get_attack_pattern_explanation(attack)
    print(f"  {attack}: {pattern.get('description', 'Unknown')}")

print("\n✓ Attack Patterns working")

# Test 4: Explanation Generator
print("\n[Test 4] Testing Explanation Generator...")
generator = ExplanationGenerator(max_features=5)

# Test alert data
alert_data = {
    'attack_type': 'PortScan',
    'source_ip': '192.168.1.100',
    'dest_ip': '10.0.0.1',
    'message': 'Port scan detected',
    'ml_confidence': 0.82
}

# Sample feature importances
feature_importances = {
    'SYN_Flag_Cnt': 0.85,
    'RST_Flag_Cnt': 0.72,
    'Flow_IAT_Mean': 0.65,
    'Tot_Fwd_Pkts': 0.58,
    'ACK_Flag_Cnt': 0.45
}

# Generate explanation
explanation = generator.generate_explanation(alert_data, feature_importances)
print(f"\nExplanation:")
print(f"  {explanation}")

# Test detailed explanation
print("\n[Test 5] Testing Detailed Explanation...")
detailed = generator.generate_detailed_explanation(alert_data, feature_importances, top_k=5)

print(f"  Summary: {detailed['summary']}")
print(f"  Confidence: {detailed['confidence_level']}")
print(f"  Pattern: {detailed['pattern']}")
print(f"  Key Features: {[f['description'] for f in detailed['key_features']]}")
print(f"  Recommendations: {detailed['recommendations']}")

print("\n" + "=" * 60)
print("All Explainability tests passed!")
print("=" * 60)