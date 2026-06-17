"""
Random Forest model builder for network intrusion detection.

This module builds and trains a Random Forest classifier for network
intrusion detection using the scikit-learn library.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from typing import Optional, Dict, Any, Tuple, List
import logging
import time

logger = logging.getLogger(__name__)


class ModelBuilder:
    """
    Builds and trains Random Forest models for intrusion detection.
    
    This class provides methods for creating, training, and saving
    Random Forest classifiers optimized for network intrusion detection.
    
    Attributes:
        model (RandomForestClassifier): The trained model
        feature_importances (np.ndarray): Feature importance scores
        is_trained (bool): Whether the model has been trained
        best_params (dict): Best parameters from grid search
    """
    
    def __init__(self, 
                 n_estimators: int = 100,
                 max_depth: Optional[int] = None,
                 min_samples_split: int = 2,
                 min_samples_leaf: int = 1,
                 random_state: int = 42,
                 n_jobs: int = -1):
        """
        Initialize the model builder.
        
        Args:
            n_estimators (int): Number of trees in the forest
            max_depth (int, optional): Maximum depth of trees
            min_samples_split (int): Minimum samples required to split
            min_samples_leaf (int): Minimum samples at leaf node
            random_state (int): Random seed for reproducibility
            n_jobs (int): Number of parallel jobs (-1 for all cores)
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=random_state,
            n_jobs=n_jobs,
            class_weight='balanced'  # Handle class imbalance
        )
        self.is_trained = False
        self.best_params = None
        self.training_history = {}
        
        logger.info(f"ModelBuilder initialized with {n_estimators} estimators")
    
    def train(self, 
              X_train: np.ndarray, 
              y_train: np.ndarray,
              X_val: Optional[np.ndarray] = None,
              y_val: Optional[np.ndarray] = None,
              optimize: bool = False) -> Dict[str, Any]:
        """
        Train the Random Forest model.
        
        Args:
            X_train (np.ndarray): Training features
            y_train (np.ndarray): Training labels
            X_val (np.ndarray, optional): Validation features
            y_val (np.ndarray, optional): Validation labels
            optimize (bool): Whether to perform hyperparameter optimization
            
        Returns:
            Dict[str, Any]: Training results including metrics
            
        Raises:
            ValueError: If X_train or y_train are empty
        """
        if len(X_train) == 0 or len(y_train) == 0:
            raise ValueError("Training data cannot be empty")
        
        logger.info(f"Training model with {len(X_train)} samples")
        start_time = time.time()
        
        # Perform hyperparameter optimization if requested
        if optimize:
            logger.info("Performing hyperparameter optimization...")
            self._optimize_hyperparameters(X_train, y_train)
        
        # Train the model
        self.model.fit(X_train, y_train)
        
        # Store feature importances
        self.feature_importances = self.model.feature_importances_
        
        # Calculate training metrics
        training_metrics = {
            'train_accuracy': self.model.score(X_train, y_train),
            'training_time': time.time() - start_time,
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'feature_importance_std': np.std(self.feature_importances)
        }
        
        # Calculate validation metrics if provided
        if X_val is not None and y_val is not None:
            val_predictions = self.model.predict(X_val)
            val_proba = self.model.predict_proba(X_val)
            
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            training_metrics.update({
                'val_accuracy': accuracy_score(y_val, val_predictions),
                'val_precision': precision_score(y_val, val_predictions, average='weighted'),
                'val_recall': recall_score(y_val, val_predictions, average='weighted'),
                'val_f1': f1_score(y_val, val_predictions, average='weighted')
            })
        
        self.is_trained = True
        self.training_history = training_metrics
        
        logger.info(f"Model training complete in {training_metrics['training_time']:.2f}s")
        logger.info(f"Training accuracy: {training_metrics['train_accuracy']:.4f}")
        if 'val_accuracy' in training_metrics:
            logger.info(f"Validation accuracy: {training_metrics['val_accuracy']:.4f}")
        
        return training_metrics
    
    def _optimize_hyperparameters(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Perform hyperparameter optimization using GridSearchCV.
        
        Args:
            X (np.ndarray): Training features
            y (np.ndarray): Training labels
            
        Note:
            This method updates the model with best parameters found.
            For production, consider using a smaller parameter grid.
        """
        # Parameter grid for Random Forest
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2', None]
        }
        
        # Use a reduced grid for faster training if dataset is large
        if len(X) > 100000:
            logger.warning("Large dataset detected, using reduced parameter grid")
            param_grid = {
                'n_estimators': [50, 100],
                'max_depth': [10, 20],
                'min_samples_split': [2, 5]
            }
        
        # Create GridSearchCV with 3-fold cross-validation
        grid_search = GridSearchCV(
            self.model,
            param_grid,
            cv=3,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1
        )
        
        logger.info("Starting grid search...")
        grid_search.fit(X, y)
        
        self.best_params = grid_search.best_params_
        self.model = grid_search.best_estimator_
        
        logger.info(f"Best parameters found: {self.best_params}")
        logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
    
    def evaluate(self, 
                 X_test: np.ndarray, 
                 y_test: np.ndarray,
                 feature_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Evaluate the trained model on test data.
        
        Args:
            X_test (np.ndarray): Test features
            y_test (np.ndarray): Test labels
            feature_names (List[str], optional): Names of features for importance
            
        Returns:
            Dict[str, Any]: Evaluation metrics including:
                - accuracy: Overall accuracy
                - precision: Weighted precision
                - recall: Weighted recall
                - f1_score: Weighted F1 score
                - confusion_matrix: Confusion matrix
                - classification_report: Detailed classification report
                - top_features: Top important features (if feature_names provided)
            
        Raises:
            RuntimeError: If model hasn't been trained
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before evaluation")
        
        logger.info(f"Evaluating model on {len(X_test)} test samples")
        
        # Make predictions
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)
        
        # Calculate metrics
        from sklearn.metrics import (accuracy_score, precision_score, 
                                    recall_score, f1_score, confusion_matrix,
                                    classification_report)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1_score': f1_score(y_test, y_pred, average='weighted'),
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'classification_report': classification_report(y_test, y_pred),
            'predictions': y_pred,
            'probabilities': y_proba
        }
        
        # Get top features
        if feature_names is not None and self.feature_importances is not None:
            # Create feature importance pairs
            feature_importance_pairs = list(zip(feature_names, self.feature_importances))
            # Sort by importance (descending)
            feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)
            # Get top 10 features
            metrics['top_features'] = feature_importance_pairs[:10]
        
        logger.info(f"Test accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Test F1-score: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions on new data.
        
        Args:
            X (np.ndarray): Features to predict on
            
        Returns:
            np.ndarray: Predicted labels
            
        Raises:
            RuntimeError: If model hasn't been trained
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities for new data.
        
        Args:
            X (np.ndarray): Features to predict on
            
        Returns:
            np.ndarray: Prediction probabilities
            
        Raises:
            RuntimeError: If model hasn't been trained
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        return self.model.predict_proba(X)
    
    def get_feature_importance_df(self, feature_names: List[str]) -> pd.DataFrame:
        """
        Get feature importances as a DataFrame.
        
        Args:
            feature_names (List[str]): Names of features
            
        Returns:
            pd.DataFrame: DataFrame with feature names and importances
            
        Raises:
            RuntimeError: If model hasn't been trained
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained to get feature importances")
        
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': self.feature_importances
        })
        importance_df = importance_df.sort_values('importance', ascending=False)
        
        return importance_df
    
    def save(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path (str): Path to save the model
            
        Raises:
            RuntimeError: If model hasn't been trained
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        
        try:
            joblib.dump(self.model, path)
            logger.info(f"Model saved to {path}")
            
            # Save additional metadata
            metadata = {
                'is_trained': self.is_trained,
                'best_params': self.best_params,
                'training_history': self.training_history,
                'n_features': len(self.feature_importances) if self.feature_importances is not None else 0
            }
            metadata_path = f"{path}_metadata.joblib"
            joblib.dump(metadata, metadata_path)
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            raise
    
    def load(self, path: str) -> None:
        """
        Load a trained model from disk.
        
        Args:
            path (str): Path to the saved model
            
        Raises:
            FileNotFoundError: If model file is not found
        """
        try:
            self.model = joblib.load(path)
            self.is_trained = True
            
            # Try to load metadata
            metadata_path = f"{path}_metadata.joblib"
            try:
                metadata = joblib.load(metadata_path)
                self.best_params = metadata.get('best_params')
                self.training_history = metadata.get('training_history', {})
            except:
                logger.warning("No metadata found for model")
            
            logger.info(f"Model loaded from {path}")
        except FileNotFoundError as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def cross_validate(self, 
                      X: np.ndarray, 
                      y: np.ndarray, 
                      cv: int = 5) -> Dict[str, Any]:
        """
        Perform cross-validation on the model.
        
        Args:
            X (np.ndarray): Features
            y (np.ndarray): Labels
            cv (int): Number of folds
            
        Returns:
            Dict[str, Any]: Cross-validation results
        """
        logger.info(f"Performing {cv}-fold cross-validation")
        
        # Use the model as is
        from sklearn.model_selection import cross_val_score
        
        scores = {
            'accuracy': cross_val_score(self.model, X, y, cv=cv, scoring='accuracy'),
            'precision': cross_val_score(self.model, X, y, cv=cv, scoring='precision_weighted'),
            'recall': cross_val_score(self.model, X, y, cv=cv, scoring='recall_weighted'),
            'f1': cross_val_score(self.model, X, y, cv=cv, scoring='f1_weighted')
        }
        
        results = {
            'accuracy_mean': np.mean(scores['accuracy']),
            'accuracy_std': np.std(scores['accuracy']),
            'precision_mean': np.mean(scores['precision']),
            'precision_std': np.std(scores['precision']),
            'recall_mean': np.mean(scores['recall']),
            'recall_std': np.std(scores['recall']),
            'f1_mean': np.mean(scores['f1']),
            'f1_std': np.std(scores['f1']),
            'all_scores': scores
        }
        
        logger.info(f"Cross-validation F1: {results['f1_mean']:.4f} (+/- {results['f1_std']:.4f})")
        
        return results