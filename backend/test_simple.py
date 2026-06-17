"""
Simple test to verify NIDS setup.
"""
import sys
import os

print("=" * 60)
print("NIDS Simple Test")
print("=" * 60)

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Check Python version
print(f"Python version: {sys.version}")

# Test 1: Check files
print("\n[Test 1] Checking project files...")
required_files = [
    "src/core/ring_buffer.py",
    "src/core/packet_capture.py",
    "src/core/packet_processor.py",
    "src/feature_extraction/extractor.py",
    "src/feature_extraction/flow_builder.py",
    "src/ml_pipeline/data_loader.py",
    "src/ml_pipeline/model_builder.py",
    "src/ml_pipeline/inference.py",
]

for file in required_files:
    if os.path.exists(file):
        print(f"✓ {file} exists")
    else:
        print(f"✗ {file} missing")

# Test 2: Import core modules
print("\n[Test 2] Testing core imports...")
try:
    from core.ring_buffer import RingBuffer
    print("✓ RingBuffer imported")
    
    # Test RingBuffer
    buffer = RingBuffer(max_size=5)
    for i in range(10):
        buffer.add(f"item_{i}")
    print(f"✓ RingBuffer works: size={len(buffer)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: Import feature extraction
print("\n[Test 3] Testing feature extraction...")
try:
    from feature_extraction.flow_builder import FlowBuilder
    print("✓ FlowBuilder imported")
    
    from feature_extraction.extractor import FeatureExtractor
    print("✓ FeatureExtractor imported")
    feature_names = FeatureExtractor().get_all_feature_names()
    print(f"✓ {len(feature_names)} features available")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: Import ML modules
print("\n[Test 4] Testing ML modules...")
try:
    from ml_pipeline.data_loader import DataLoader
    print("✓ DataLoader imported")
    
    from ml_pipeline.model_builder import ModelBuilder
    print("✓ ModelBuilder imported")
    
    from ml_pipeline.inference import InferenceEngine
    print("✓ InferenceEngine imported")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("Test complete!")
print("=" * 60)