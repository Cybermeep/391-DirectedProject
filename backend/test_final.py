"""
Final comprehensive test for all modules.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("=" * 60)
print("Comprehensive NIDS Test")
print("=" * 60)

# Test 1: Core
print("\n[Test 1] Core Modules...")
try:
    from core.ring_buffer import RingBuffer
    from core.packet_capture import PacketCapture
    from core.packet_processor import PacketProcessor
    print("✓ All core modules imported")
    
    # Test RingBuffer
    rb = RingBuffer(3)
    rb.add("test")
    print(f"✓ RingBuffer test: size={len(rb)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Feature Extraction
print("\n[Test 2] Feature Extraction Modules...")
try:
    from feature_extraction import FeatureExtractor
    from feature_extraction import FlowBuilder
    from feature_extraction import BasicFeatureExtractor
    from feature_extraction import CountFeatureExtractor
    from feature_extraction import TemporalFeatureExtractor
    from feature_extraction import PayloadFeatureExtractor
    print("✓ All feature extraction modules imported")
    
    # Test FeatureExtractor
    extractor = FeatureExtractor()
    names = extractor.get_all_feature_names()
    print(f"✓ FeatureExtractor has {len(names)} features")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

# Test 3: ML Pipeline
print("\n[Test 3] ML Pipeline Modules...")
try:
    from ml_pipeline import DataLoader, Preprocessor, ModelBuilder, Evaluator, InferenceEngine
    print("✓ All ML pipeline modules imported")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("Test complete!")
print("=" * 60)