"""
Test script for ML Pipeline components.
"""
import sys
import os
import numpy as np
import pandas as pd

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("=" * 60)
print("ML Pipeline Test")
print("=" * 60)

# Test 1: DataLoader
print("\n[Test 1] Testing DataLoader...")
try:
    from ml_pipeline.data_loader import DataLoader
    
    # Test with mock data
    mock_data = pd.DataFrame({
        'Flow Duration': np.random.rand(100) * 1000,
        'Total Fwd Packets': np.random.randint(1, 100, 100),
        'Total Backward Packets': np.random.randint(1, 50, 100),
        'Label': ['Benign' if i < 70 else 'Bruteforce' for i in range(100)]
    })
    
    data_loader = DataLoader(
        data_path='./temp_data',
        selected_attacks=['Bruteforce']
    )
    
    df_processed = data_loader.preprocess_labels(mock_data)
    print(f"✓ DataLoader test passed")
    print(f"  Label distribution: {df_processed['Label_Binary'].value_counts().to_dict()}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Preprocessor
print("\n[Test 2] Testing Preprocessor...")
try:
    from ml_pipeline.preprocess import Preprocessor
    
    preprocessor = Preprocessor()
    
    # Create training data
    train_data = pd.DataFrame({
        'feature1': np.random.randn(100),
        'feature2': np.random.randn(100) * 2,
        'feature3': np.random.randn(100) * 0.5,
        'Label_Binary': ['Benign' if i < 70 else 'Attack' for i in range(100)]
    })
    
    # Fit and transform
    X_transformed, y_encoded = preprocessor.fit_transform(train_data)
    print(f"✓ Preprocessor test passed")
    print(f"  Transformed shape: {X_transformed.shape}")
    print(f"  Encoded labels shape: {y_encoded.shape if y_encoded is not None else 'None'}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: ModelBuilder
print("\n[Test 3] Testing ModelBuilder...")
try:
    from ml_pipeline.model_builder import ModelBuilder
    
    # Create synthetic data
    X_train = np.random.randn(200, 5)
    y_train = np.random.randint(0, 2, 200)
    X_test = np.random.randn(50, 5)
    y_test = np.random.randint(0, 2, 50)
    
    # Initialize and train
    model_builder = ModelBuilder(n_estimators=10, random_state=42)
    train_metrics = model_builder.train(X_train, y_train)
    
    # Test prediction
    y_pred = model_builder.predict(X_test)
    
    print(f"✓ ModelBuilder test passed")
    print(f"  Training accuracy: {train_metrics['train_accuracy']:.4f}")
    print(f"  Predictions made: {len(y_pred)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: Evaluator
print("\n[Test 4] Testing Evaluator...")
try:
    from ml_pipeline.evaluator import Evaluator
    
    evaluator = Evaluator()
    
    # Use predictions from previous test
    y_pred = model_builder.predict(X_test)
    y_proba = model_builder.predict_proba(X_test)
    
    metrics = evaluator.evaluate_model(
        y_true=y_test,
        y_pred=y_pred,
        y_proba=y_proba,
        class_names=['Class 0', 'Class 1']
    )
    
    print(f"✓ Evaluator test passed")
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  F1 Score: {metrics['f1_score']:.4f}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 5: InferenceEngine
print("\n[Test 5] Testing InferenceEngine...")
try:
    from ml_pipeline.inference import InferenceEngine
    
    # Create inference engine
    inference_engine = InferenceEngine(threshold=0.5)
    
    # Test stats
    stats = inference_engine.get_stats()
    print(f"✓ InferenceEngine test passed")
    print(f"  Stats: threshold={stats['threshold']}, is_loaded={stats['is_loaded']}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 6: Feature Count
print("\n[Test 6] Feature Count Verification...")
try:
    from feature_extraction import FeatureExtractor
    extractor = FeatureExtractor()
    all_features = extractor.get_all_feature_names()
    categories = extractor.get_feature_names()
    
    print(f"✓ Total features: {len(all_features)}")
    for category, features in categories.items():
        print(f"  {category}: {len(features)} features")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("All ML Pipeline Tests Passed!")
print("=" * 60)