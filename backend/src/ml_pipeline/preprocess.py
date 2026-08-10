"""
Data preprocessing for the ML pipeline
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
    Handles feature preprocessing for the ML pipeline
    
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
    
    def fit(self, df: pd.DataFrame) -> None:
        """
        Fit the preprocessor on the training data
        
        Args:
            df (pd.DataFrame): Training DataFrame (features only, no labels)
        """
        # Store feature columns
        self.feature_columns = df.columns.tolist()
        
        # Make a copy
        X = df.copy()
        
        # Convert categorical columns to numeric
        categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
        if categorical_cols:
            logger.info(f"Converting {len(categorical_cols)} categorical columns to numeric codes")
            for col in categorical_cols:
                X[col] = pd.Categorical(X[col]).codes
        
        # Ensure all columns are numeric
        X = X.astype(float)
        
        # Fit scaler on all features
        if len(X.columns) > 0:
            logger.info(f"Fitting scaler on {len(X.columns)} features")
            self.scaler.fit(X)
        else:
            logger.warning("No features found for scaling")
        
        self.is_fitted = True
        logger.info("Preprocessor fitting complete")
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform the data using fitted preprocessor
        
        Args:
            df (pd.DataFrame): DataFrame to transform
            
        Returns:
            np.ndarray: Transformed features as numpy array
            
        Raises:
            RuntimeError: If preprocessor hasn't been fitted
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform")
        
        # Make a copy to avoid modifying original
        X = df.copy()
        
        # Remove label column if it exists
        if 'Label_Binary' in X.columns:
            X = X.drop(columns=['Label_Binary'])
        
        # Ensure all feature columns are present
        missing_cols = set(self.feature_columns) - set(X.columns)
        if missing_cols:
            logger.warning(f"Missing columns: {missing_cols}. Adding with zeros.")
            for col in missing_cols:
                X[col] = 0
        
        # Select only feature columns (exclude any extra columns)
        X = X[self.feature_columns]
        
        # Convert categorical columns to numeric
        categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
        for col in categorical_cols:
            X[col] = pd.Categorical(X[col]).codes
        
        # Ensure all columns are numeric
        X = X.astype(float)
        
        # Scale numerical features
        X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def fit_transform(self, df: pd.DataFrame, target_col: str = 'Label_Binary') -> Tuple[np.ndarray, np.ndarray]:
        """
        Fit and transform the data in one step
        
        Args:
            df (pd.DataFrame): DataFrame to fit and transform
            target_col (str): Name of the target column
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: (X_transformed, y)
        """
        # Separate features and target
        if target_col in df.columns:
            X = df.drop(columns=[target_col])
            y = df[target_col]
        else:
            X = df
            y = None
        
        # Fit the preprocessor on features
        self.fit(X)
        
        # Fit the label encoder on labels if provided
        if y is not None:
            logger.info("Fitting label encoder on training labels")
            self.label_encoder.fit(y)
        
        # Transform features
        X_transformed = self.transform(X)
        
        # Encode labels if provided
        if y is not None:
            y_encoded = self.label_encoder.transform(y)
        else:
            y_encoded = None
        
        return X_transformed, y_encoded
    
    def create_preprocessing_pipeline(self) -> Pipeline:
        """
        Create a complete preprocessing pipeline
        
        Returns:
            Pipeline: Scikit-learn pipeline with preprocessing steps
        """
        from sklearn.pipeline import Pipeline
        from sklearn.compose import ColumnTransformer
        from sklearn.preprocessing import StandardScaler, OneHotEncoder
        
        logger.info("Creating preprocessing pipeline")
        return Pipeline([
            ('scaler', StandardScaler())
        ])
    
    def save(self, path: str) -> None:
        """
        Save the fitted preprocessor to disk
        
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
        Load a fitted preprocessor from disk
        
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
        Encode labels to numerical values
        
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
        Decode numerical labels back to original labels
        
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