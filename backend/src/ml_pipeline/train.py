#!/usr/bin/env python3
"""
Training script for the NIDS ML pipeline.

This script handles the complete training pipeline including:
1. Loading and preprocessing the CSE-CIC-IDS2018 dataset
2. Training a Random Forest classifier
3. Evaluating model performance
4. Saving the trained model and preprocessor
"""

import os
import sys
import argparse
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings('ignore')

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_pipeline.data_loader import DataLoader
from ml_pipeline.preprocess import Preprocessor
from ml_pipeline.model_builder import ModelBuilder
from ml_pipeline.evaluator import Evaluator
from ml_pipeline.inference import InferenceEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Train NIDS ML model on CSE-CIC-IDS2018 dataset'
    )
    
    parser.add_argument(
        '--data_path',
        type=str,
        default='./data/datasets/CSE-CIC-IDS2018',
        help='Path to the dataset directory (default: ./data/datasets/CSE-CIC-IDS2018)'
    )
    
    parser.add_argument(
        '--output_path',
        type=str,
        default='./src/ml_pipeline/models',
        help='Path to save models and preprocessor (default: ./src/ml_pipeline/models)'
    )
    
    parser.add_argument(
        '--test_size',
        type=float,
        default=0.3,
        help='Proportion of data for testing (default: 0.3)'
    )
    
    parser.add_argument(
        '--n_estimators',
        type=int,
        default=100,
        help='Number of trees in Random Forest (default: 100)'
    )
    
    parser.add_argument(
        '--max_depth',
        type=int,
        default=None,
        help='Maximum tree depth (default: None)'
    )
    
    parser.add_argument(
        '--optimize',
        action='store_true',
        help='Perform hyperparameter optimization'
    )
    
    parser.add_argument(
        '--balance',
        action='store_true',
        default=True,
        help='Balance the dataset (default: True)'
    )
    
    parser.add_argument(
        '--subset_size',
        type=int,
        default=None,
        help='Number of rows to use (for testing)'
    )
    
    parser.add_argument(
        '--skip_evaluation',
        action='store_true',
        help='Skip evaluation (for quick training)'
    )
    
    return parser.parse_args()


def main():
    """
    Main training function.
    """
    args = parse_arguments()
    
    logger.info("=" * 60)
    logger.info("NIDS ML Pipeline Training")
    logger.info("=" * 60)
    logger.info(f"Data path: {args.data_path}")
    logger.info(f"Output path: {args.output_path}")
    logger.info(f"Test size: {args.test_size}")
    logger.info(f"Number of estimators: {args.n_estimators}")
    logger.info(f"Optimize hyperparameters: {args.optimize}")
    logger.info(f"Balance dataset: {args.balance}")
    logger.info("=" * 60)
    
    # Create output directory
    output_path = Path(args.output_path)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Load data
    logger.info("\n" + "=" * 60)
    logger.info("Step 1: Loading Data")
    logger.info("=" * 60)
    
    data_loader = DataLoader(
        data_path=args.data_path,
        selected_attacks=['DoS', 'DDoS', 'Bruteforce', 'PortScan', 'Botnet']
    )
    
    try:
        df = data_loader.load_dataset(subset_size=args.subset_size)
    except FileNotFoundError as e:
        logger.error(f"Dataset not found: {e}")
        logger.error("Please download the CSE-CIC-IDS2018 dataset to the specified path")
        return 1
    
    # Step 2: Prepare data
    logger.info("\n" + "=" * 60)
    logger.info("Step 2: Preparing Data")
    logger.info("=" * 60)
    
    df_prepared = data_loader.prepare_data(
        df=df,
        balance=args.balance,
        balance_method='downsample'
    )
    
    # Step 3: Split data
    logger.info("\n" + "=" * 60)
    logger.info("Step 3: Splitting Data")
    logger.info("=" * 60)
    
    train_df, test_df = data_loader.split_data(
        df=df_prepared,
        test_size=args.test_size
    )
    
    # Step 4: Preprocess data
    logger.info("\n" + "=" * 60)
    logger.info("Step 4: Preprocessing Data")
    logger.info("=" * 60)
    
    preprocessor = Preprocessor()
    
    # Train preprocessing
    X_train, y_train = preprocessor.fit_transform(train_df)
    
    # Test preprocessing
    X_test = preprocessor.transform(test_df)
    y_test = preprocessor.encode_labels(test_df['Label_Binary'])
    
    logger.info(f"Training features shape: {X_train.shape}")
    logger.info(f"Test features shape: {X_test.shape}")
    
    # Step 5: Train model
    logger.info("\n" + "=" * 60)
    logger.info("Step 5: Training Model")
    logger.info("=" * 60)
    
    model_builder = ModelBuilder(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=42
    )
    
    # Train with validation split
    train_metrics = model_builder.train(
        X_train=X_train,
        y_train=y_train,
        optimize=args.optimize
    )
    
    # Step 6: Evaluate model
    if not args.skip_evaluation:
        logger.info("\n" + "=" * 60)
        logger.info("Step 6: Evaluating Model")
        logger.info("=" * 60)
        
        evaluator = Evaluator()
        
        # Get predictions and probabilities
        y_pred = model_builder.predict(X_test)
        y_proba = model_builder.predict_proba(X_test)
        
        # Evaluate
        metrics = evaluator.evaluate_model(
            y_true=y_test,
            y_pred=y_pred,
            y_proba=y_proba,
            class_names=['Benign', 'Attack']
        )
        
        # Print evaluation
        evaluator.print_evaluation(metrics)
        
        # Save metrics
        evaluator.save_metrics(metrics, str(output_path / 'evaluation_metrics.json'))
        
        # Plot confusion matrix
        evaluator.plot_confusion_matrix(
            metrics,
            class_names=['Benign', 'Attack'],
            save_path=str(output_path / 'confusion_matrix.png')
        )
        
        # Plot feature importance
        if args.optimize:
            # Get feature importance from the trained model
            feature_importances = model_builder.model.feature_importances_
            feature_names = preprocessor.feature_columns
            
            evaluator.plot_feature_importance(
                feature_importances=feature_importances,
                feature_names=feature_names,
                top_n=20,
                save_path=str(output_path / 'feature_importance.png')
            )
        
        logger.info(f"Evaluation complete. Test accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Test F1-score: {metrics['f1_score']:.4f}")
    
    # Step 7: Save model and preprocessor
    logger.info("\n" + "=" * 60)
    logger.info("Step 7: Saving Model and Preprocessor")
    logger.info("=" * 60)
    
    model_path = output_path / 'random_forest.joblib'
    preprocessor_path = output_path / 'preprocessor'
    
    model_builder.save(str(model_path))
    preprocessor.save(str(preprocessor_path))
    
    logger.info(f"Model saved to: {model_path}")
    logger.info(f"Preprocessor saved to: {preprocessor_path}")
    
    # Step 8: Test inference
    logger.info("\n" + "=" * 60)
    logger.info("Step 8: Testing Inference Engine")
    logger.info("=" * 60)
    
    try:
        inference_engine = InferenceEngine(threshold=0.5)
        inference_engine.load_model(str(model_path), str(preprocessor_path))
        
        # Test prediction on a sample
        sample = test_df.iloc[0]
        test_features = sample.drop('Label_Binary').to_dict()
        
        result = inference_engine.predict(test_features)
        logger.info(f"Test prediction: {result['prediction']} (confidence: {result['confidence']:.3f})")
        
        # Get feature importance
        importance_df = inference_engine.get_feature_importance()
        if importance_df is not None:
            logger.info(f"Top 5 important features:\n{importance_df.head(5)}")
            
    except Exception as e:
        logger.error(f"Error testing inference engine: {e}")
    
    logger.info("\n" + "=" * 60)
    logger.info("Training Complete!")
    logger.info("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())