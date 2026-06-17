"""
Data preprocessing for the ML pipeline.

This module handles feature preprocessing including normalization,
encoding categorical variables, and preparing data for model training.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from typing import Optional, List, Tuple, Dict, Any
import joblib
import logging

logger = logging.getLogger(__name__)


class Preprocessor:
    """
    Handles feature preprocessing for the ML pipeline.
    
    This class provides methods for normalizing features, encoding categorical
    variables, and creating preprocessing pipelines.
    
    Attributes:
        scaler (StandardScaler): Fitted scaler for normalization
        label_encoder (LabelEncoder): Fitted label encoder for labels
        feature_columns (List[str]): List of feature column names
        is_fitted (bool): Whether the preprocessor has been fitted
    """
    
    def __init__(self):
        """Initialize the preprocessor."""
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.is_fitted = False
        logger.info("Preprocessor initialized")
    
    def fit(self, df: pd.DataFrame, target_col: str = 'Label_Binary') -> None:
        """
        Fit the preprocessor on the training data.
        
        Args:
            df (pd.DataFrame): Training DataFrame
            target_col (str): Name of the target column
            
        Raises:
            ValueError: If target column not found in DataFrame
        """
        # Separate features and target
        if target_col in df.columns:
            X = df.drop(columns=[target_col])
            y = df[target_col]
        else:
            X = df
            y = None
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        # Fit scaler on numerical features
        numerical_cols = X.select_dtypes(include=[np.number]).columns.tolist()
        if numerical_cols:
            logger.info(f"Fitting scaler on {len(numerical_cols)} numerical features")
            self.scaler.fit(X[numerical_cols])
        else:
            logger.warning("No numerical columns found for scaling")
        
        # Fit label encoder if target provided
        if y is not None:
            logger.info("Fitting label encoder")
            self.label_encoder.fit(y)
        
        self.is_fitted = True
        logger.info("Preprocessor fitting complete")
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform the data using fitted preprocessor.
        
        Args:
            df (pd.DataFrame): DataFrame to transform
            
        Returns:
            np.ndarray: Transformed features as numpy array
            
        Raises:
            RuntimeError: If preprocessor hasn't been fitted
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform")
        
        # Ensure all feature columns are present
        missing_cols = set(self.feature_columns) - set(df.columns)
        if missing_cols:
            logger.warning(f"Missing columns: {missing_cols}. Adding with zeros.")
            for col in missing_cols:
                df[col] = 0
        
        # Select only feature columns
        X = df[self.feature_columns]
        
        # Convert categorical columns to numeric
        categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
        for col in categorical_cols:
            # Use one-hot encoding or label encoding
            X[col] = pd.Categorical(X[col]).codes
        
        # Ensure all columns are numeric
        X = X.astype(float)
        
        # Scale numerical features
        X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def fit_transform(self, df: pd.DataFrame, target_col: str = 'Label_Binary') -> Tuple[np.ndarray, np.ndarray]:
        """
        Fit and transform the data in one step.
        
        Args:
            df (pd.DataFrame): DataFrame to fit and transform
            target_col (str): Name of the target column
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: (X_transformed, y)
        """
        self.fit(df, target_col)
        
        if target_col in df.columns:
            X = df.drop(columns=[target_col])
            y = df[target_col]
            y_encoded = self.label_encoder.transform(y)
        else:
            X = df
            y_encoded = None
        
        X_transformed = self.transform(X)
        
        return X_transformed, y_encoded
    
    def create_preprocessing_pipeline(self) -> Pipeline:
        """
        Create a complete preprocessing pipeline.
        
        Returns:
            Pipeline: Scikit-learn pipeline with preprocessing steps
        """
        from sklearn.pipeline import Pipeline
        from sklearn.compose import ColumnTransformer
        from sklearn.preprocessing import StandardScaler, OneHotEncoder
        
        # This is a placeholder for when we need to integrate with scikit-learn's pipeline
        # For now, we handle preprocessing manually
        
        logger.info("Creating preprocessing pipeline")
        return Pipeline([
            ('scaler', StandardScaler())
        ])
    
    def save(self, path: str) -> None:
        """
        Save the fitted preprocessor to disk.
        
        Args:
            path (str): Path to save the preprocessor
            
        Raises:
            RuntimeError: If preprocessor hasn't been fitted
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot save unfitted preprocessor")
        
        try:
            # Save scaler
            scaler_path = f"{path}_scaler.joblib"
            joblib.dump(self.scaler, scaler_path)
            
            # Save label encoder
            encoder_path = f"{path}_encoder.joblib"
            joblib.dump(self.label_encoder, encoder_path)
            
            # Save feature columns
            cols_path = f"{path}_columns.joblib"
            joblib.dump(self.feature_columns, cols_path)
            
            logger.info(f"Preprocessor saved to {path}")
        except Exception as e:
            logger.error(f"Error saving preprocessor: {e}")
            raise
    
    def load(self, path: str) -> None:
        """
        Load a fitted preprocessor from disk.
        
        Args:
            path (str): Path to the saved preprocessor
            
        Raises:
            FileNotFoundError: If files are not found
        """
        try:
            scaler_path = f"{path}_scaler.joblib"
            self.scaler = joblib.load(scaler_path)
            
            encoder_path = f"{path}_encoder.joblib"
            self.label_encoder = joblib.load(encoder_path)
            
            cols_path = f"{path}_columns.joblib"
            self.feature_columns = joblib.load(cols_path)
            
            self.is_fitted = True
            logger.info(f"Preprocessor loaded from {path}")
        except FileNotFoundError as e:
            logger.error(f"Error loading preprocessor: {e}")
            raise
    
    def encode_labels(self, y: pd.Series) -> np.ndarray:
        """
        Encode labels to numerical values.
        
        Args:
            y (pd.Series): Label series
            
        Returns:
            np.ndarray: Encoded labels
            
        Raises:
            RuntimeError: If label encoder hasn't been fitted
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before encoding labels")
        
        return self.label_encoder.transform(y)
    
    def decode_labels(self, y: np.ndarray) -> np.ndarray:
        """
        Decode numerical labels back to original labels.
        
        Args:
            y (np.ndarray): Encoded labels
            
        Returns:
            np.ndarray: Decoded labels
            
        Raises:
            RuntimeError: If label encoder hasn't been fitted
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before decoding labels")
        
        return self.label_encoder.inverse_transform(y)