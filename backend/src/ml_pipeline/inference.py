"""
Real-time inference engine for the ML model.

This module provides the inference engine for making real-time predictions
on network traffic using the trained Random Forest model.
"""

import numpy as np
import pandas as pd
from typing import Optional, Dict, Any, List, Union
import joblib
import logging
from datetime import datetime

from .preprocess import Preprocessor

logger = logging.getLogger(__name__)


class InferenceEngine:
    """
    Real-time inference engine for network intrusion detection.
    
    This class provides methods for making predictions on network traffic
    features using a trained model. It handles feature preprocessing and
    provides prediction probabilities and explanations.
    
    Attributes:
        model: Loaded trained model
        preprocessor (Preprocessor): Fitted preprocessor
        feature_columns (List[str]): List of feature column names
        threshold (float): Confidence threshold for attack classification
        is_loaded (bool): Whether the model has been loaded
    """
    
    def __init__(self, threshold: float = 0.5):
        """
        Initialize the inference engine.
        
        Args:
            threshold (float): Confidence threshold for attack classification
                (0.0 to 1.0). Default is 0.5.
                
        Raises:
            ValueError: If threshold is not between 0 and 1
        """
        if not 0 <= threshold <= 1:
            raise ValueError(f"threshold must be between 0 and 1, got {threshold}")
        
        self.model = None
        self.preprocessor = Preprocessor()
        self.feature_columns = None
        self.threshold = threshold
        self.is_loaded = False
        self.prediction_count = 0
        
        logger.info(f"InferenceEngine initialized with threshold={threshold}")
    
    def load_model(self, model_path: str, preprocessor_path: str) -> None:
        """
        Load a trained model and preprocessor from disk.
        
        Args:
            model_path (str): Path to the trained model file
            preprocessor_path (str): Path to the preprocessor files
            
        Raises:
            FileNotFoundError: If model or preprocessor files are not found
        """
        try:
            # Load model
            logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            
            # Load preprocessor
            logger.info(f"Loading preprocessor from {preprocessor_path}")
            self.preprocessor.load(preprocessor_path)
            
            # Store feature columns
            self.feature_columns = self.preprocessor.feature_columns
            
            self.is_loaded = True
            logger.info("Model and preprocessor loaded successfully")
            
        except FileNotFoundError as e:
            logger.error(f"Error loading model or preprocessor: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading model: {e}")
            raise
    
    def predict(self, features: Union[pd.DataFrame, Dict[str, Any], List[float]]) -> Dict[str, Any]:
        """
        Make a prediction on a single sample.
        
        Args:
            features (Union[pd.DataFrame, Dict[str, Any], List[float]]): Input features
                - DataFrame: Single row DataFrame
                - Dict: Feature name to value mapping
                - List: Feature values in order (must match feature_columns)
            
        Returns:
            Dict[str, Any]: Prediction result containing:
                - prediction (str): 'Attack' or 'Benign'
                - confidence (float): Prediction confidence (0-1)
                - probability (float): Probability of being attack
                - timestamp (str): Prediction timestamp
                - features_used (dict): Features used for prediction
                
        Raises:
            RuntimeError: If model hasn't been loaded
            ValueError: If features are invalid
        """
        if not self.is_loaded:
            raise RuntimeError("Model must be loaded before prediction")
        
        # Convert input to DataFrame
        X = self._prepare_features(features)
        
        # Preprocess features
        X_scaled = self.preprocessor.transform(X)
        
        # Get prediction probability
        proba = self.model.predict_proba(X_scaled)
        
        # Get class probabilities
        # Assuming binary classification: [benign_prob, attack_prob]
        attack_prob = proba[0][1] if proba.shape[1] == 2 else proba[0][0]
        benign_prob = 1 - attack_prob
        
        # Determine prediction based on threshold
        is_attack = attack_prob >= self.threshold
        prediction = 'Attack' if is_attack else 'Benign'
        confidence = attack_prob if is_attack else benign_prob
        
        # Update counter
        self.prediction_count += 1
        
        result = {
            'prediction': prediction,
            'confidence': float(confidence),
            'probability_attack': float(attack_prob),
            'probability_benign': float(benign_prob),
            'timestamp': datetime.now().isoformat(),
            'threshold': self.threshold,
            'prediction_id': self.prediction_count,
            'features_used': X.iloc[0].to_dict() if isinstance(X, pd.DataFrame) else X
        }
        
        logger.info(f"Prediction {self.prediction_count}: {prediction} "
                   f"(confidence: {confidence:.3f})")
        
        return result
    
    def predict_batch(self, features: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Make predictions on a batch of samples.
        
        Args:
            features (pd.DataFrame): DataFrame with multiple samples
            
        Returns:
            List[Dict[str, Any]]: List of prediction results
            
        Raises:
            RuntimeError: If model hasn't been loaded
        """
        if not self.is_loaded:
            raise RuntimeError("Model must be loaded before prediction")
        
        logger.info(f"Making predictions on {len(features)} samples")
        
        # Preprocess features
        X_scaled = self.preprocessor.transform(features)
        
        # Get predictions and probabilities
        predictions = self.model.predict(X_scaled)
        proba = self.model.predict_proba(X_scaled)
        
        results = []
        for i, pred in enumerate(predictions):
            attack_prob = proba[i][1] if proba.shape[1] == 2 else proba[i][0]
            benign_prob = 1 - attack_prob
            is_attack = attack_prob >= self.threshold
            
            results.append({
                'prediction': 'Attack' if is_attack else 'Benign',
                'confidence': float(attack_prob if is_attack else benign_prob),
                'probability_attack': float(attack_prob),
                'probability_benign': float(benign_prob),
                'timestamp': datetime.now().isoformat(),
                'sample_index': i
            })
        
        logger.info(f"Batch prediction complete: {len(results)} samples")
        
        return results
    
    def _prepare_features(self, features: Union[pd.DataFrame, Dict[str, Any], List[float]]) -> pd.DataFrame:
        """
        Prepare features for prediction.
        
        Args:
            features (Union[pd.DataFrame, Dict[str, Any], List[float]]): Input features
            
        Returns:
            pd.DataFrame: Prepared features
            
        Raises:
            ValueError: If features are invalid
        """
        if isinstance(features, pd.DataFrame):
            # Ensure DataFrame has correct columns
            if self.feature_columns and set(self.feature_columns) - set(features.columns):
                missing = set(self.feature_columns) - set(features.columns)
                raise ValueError(f"Missing feature columns: {missing}")
            return features
            
        elif isinstance(features, dict):
            # Create DataFrame from dictionary
            df = pd.DataFrame([features])
            # Add missing columns with 0
            if self.feature_columns:
                for col in self.feature_columns:
                    if col not in df.columns:
                        df[col] = 0
            return df
            
        elif isinstance(features, list):
            # Assume features are in order
            if self.feature_columns:
                if len(features) != len(self.feature_columns):
                    raise ValueError(f"Expected {len(self.feature_columns)} features, got {len(features)}")
                df = pd.DataFrame([features], columns=self.feature_columns)
                return df
            else:
                raise ValueError("Feature columns not available")
            
        else:
            raise ValueError(f"Unsupported features type: {type(features)}")
    
    def get_feature_importance(self) -> Optional[pd.DataFrame]:
        """
        Get feature importance from the loaded model.
        
        Returns:
            Optional[pd.DataFrame]: Feature importance DataFrame or None if not available
            
        Raises:
            RuntimeError: If model hasn't been loaded
        """
        if not self.is_loaded:
            raise RuntimeError("Model must be loaded first")
        
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            if self.feature_columns and len(self.feature_columns) == len(importances):
                df = pd.DataFrame({
                    'feature': self.feature_columns,
                    'importance': importances
                }).sort_values('importance', ascending=False)
                return df
        
        return None
    
    def set_threshold(self, threshold: float) -> None:
        """
        Update the classification threshold.
        
        Args:
            threshold (float): New threshold value (0-1)
            
        Raises:
            ValueError: If threshold is not between 0 and 1
        """
        if not 0 <= threshold <= 1:
            raise ValueError(f"threshold must be between 0 and 1, got {threshold}")
        
        self.threshold = threshold
        logger.info(f"Threshold updated to {threshold}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get inference engine statistics.
        
        Returns:
            Dict[str, Any]: Statistics including prediction count and model info
        """
        return {
            'predictions_made': self.prediction_count,
            'threshold': self.threshold,
            'is_loaded': self.is_loaded,
            'feature_count': len(self.feature_columns) if self.feature_columns else 0,
            'model_type': type(self.model).__name__ if self.model else 'None'
        }