"""
Data loader for the CSE-CIC-IDS2018 dataset.

This module handles loading, preprocessing, and subsetting the CSE-CIC-IDS2018
dataset for network intrusion detection. It supports loading from CSV files,
handling missing values, and selecting specific attack families.
"""

import os
import pandas as pd
import numpy as np
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path
import logging
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)


class DataLoader:
    """
    Handles loading and preprocessing of the CSE-CIC-IDS2018 dataset.
    
    This class provides methods for loading the dataset from CSV files,
    handling missing values, selecting attack families, and preparing
    data for training and testing.
    
    Attributes:
        data_path (str): Path to the dataset directory
        attack_families (List[str]): List of attack types to include
        selected_attacks (List[str]): Specific attack families to include
    """
    
    # Mapping of attack types to families (subsets as per project requirements)
    ATTACK_MAPPING = {
        'Bruteforce': ['Bruteforce', 'FTP-BruteForce', 'SSH-Bruteforce'],
        'DoS': ['DoS', 'DoS-GoldenEye', 'DoS-Hulk', 'DoS-SlowHTTPTest', 'DoS-Slowloris'],
        'DDoS': ['DDoS', 'DDoS-LOIC-HTTP', 'DDoS-LOIC-UDP', 'DDoS-HOIC'],
        'PortScan': ['PortScan', 'Portscan'],
        'Botnet': ['Bot', 'Botnet']
    }
    
    def __init__(self, data_path: str, selected_attacks: Optional[List[str]] = None):
        """
        Initialize the data loader.
        
        Args:
            data_path (str): Path to the dataset directory
            selected_attacks (List[str], optional): Specific attack families to include.
                If None, includes all attack families except benign.
                Default is ['DoS', 'DDoS', 'Bruteforce', 'PortScan', 'Botnet']
        """
        self.data_path = Path(data_path)
        self.selected_attacks = selected_attacks or ['DoS', 'DDoS', 'Bruteforce', 'PortScan', 'Botnet']
        
        # Build attack mapping based on selected families
        self.attack_labels = []
        for family in self.selected_attacks:
            if family in self.ATTACK_MAPPING:
                self.attack_labels.extend(self.ATTACK_MAPPING[family])
        
        logger.info(f"DataLoader initialized with path: {data_path}")
        logger.info(f"Selected attack families: {self.selected_attacks}")
        logger.info(f"Including attack labels: {self.attack_labels}")
    
    def load_dataset(self, subset_size: Optional[int] = None) -> pd.DataFrame:
        """
        Load the dataset from CSV files.
        
        Args:
            subset_size (int, optional): Number of rows to load for testing.
                If None, loads the entire dataset.
            
        Returns:
            pd.DataFrame: Loaded dataset
            
        Raises:
            FileNotFoundError: If dataset files are not found
        """
        logger.info("Loading dataset...")
        
        # Look for CSV files in the data path
        csv_files = list(self.data_path.glob('*.csv'))
        
        if not csv_files:
            # Try looking in subdirectories
            csv_files = list(self.data_path.rglob('*.csv'))
            
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {self.data_path}")
        
        logger.info(f"Found {len(csv_files)} CSV files")
        
        # Load and concatenate all CSV files
        dataframes = []
        for csv_file in csv_files:
            try:
                logger.info(f"Loading {csv_file.name}...")
                df = pd.read_csv(csv_file)
                dataframes.append(df)
            except Exception as e:
                logger.warning(f"Error loading {csv_file}: {e}")
                continue
        
        if not dataframes:
            raise ValueError("No data could be loaded from CSV files")
        
        # Concatenate all dataframes
        df = pd.concat(dataframes, ignore_index=True)
        
        # Apply subset limit if specified
        if subset_size and subset_size < len(df):
            df = df.sample(n=subset_size, random_state=42)
            logger.info(f"Subsetted to {subset_size} rows for testing")
        
        logger.info(f"Loaded dataset with {len(df)} rows and {len(df.columns)} columns")
        return df
    
    def preprocess_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess labels for binary classification.
        
        Maps labels to:
            - 'Benign' for normal traffic
            - 'Attack' for any malicious traffic (including specified families)
        
        Args:
            df (pd.DataFrame): DataFrame with label column
            
        Returns:
            pd.DataFrame: DataFrame with 'Label_Binary' column mapped to binary categories
        """
        # Find the label column - check multiple possible names
        label_col = None
        possible_labels = ['label', 'Label', 'Attack', 'attack', 'Class', 'class', 'Label_Attack', 'target', 'Target']
        
        for col in possible_labels:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            # If no label column found, check for columns that might be labels
            for col in df.columns:
                if 'label' in col.lower() or 'attack' in col.lower() or 'class' in col.lower():
                    label_col = col
                    break
            
            if label_col is None:
                raise ValueError(f"DataFrame must contain a label column. Found columns: {list(df.columns[:20])}")
        
        logger.info(f"Using label column: '{label_col}'")
        
        # Create a copy to avoid modifying the original
        df_processed = df.copy()
        
        # Map labels to binary classification
        def classify_label(label):
            if isinstance(label, str):
                label_lower = label.lower().strip()
                # Check if label is benign
                if label_lower in ['benign', 'normal', 'legitimate', '0', '0.0']:
                    return 'Benign'
                # Check if label is in our selected attack families
                for attack in self.attack_labels:
                    if attack.lower() in label_lower:
                        return 'Attack'
                # If it's numeric, treat 0 as Benign
                if label_lower in ['1', '1.0']:
                    return 'Attack'
                # Default: treat as attack if not benign
                return 'Attack'
            else:
                # If label is numeric, treat 0 as Benign, else Attack
                return 'Benign' if label == 0 else 'Attack'
        
        df_processed['Label_Binary'] = df_processed[label_col].apply(classify_label)
        
        # Remove rows with unknown labels
        df_processed = df_processed[df_processed['Label_Binary'].notna()]
        
        # Count classes
        benign_count = len(df_processed[df_processed['Label_Binary'] == 'Benign'])
        attack_count = len(df_processed[df_processed['Label_Binary'] == 'Attack'])
        
        logger.info(f"Label distribution: Benign={benign_count}, Attack={attack_count}")
        logger.info(f"Attack ratio: {attack_count/(benign_count+attack_count):.2%}")
        
        return df_processed
    
    def handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Handle missing values in the dataset.
        
        Args:
            df (pd.DataFrame): DataFrame with potential missing values
            
        Returns:
            pd.DataFrame: DataFrame with missing values handled
            
        Note:
            - Removes columns with > 50% missing values
            - Fills remaining missing values with median for numerical columns
            - Fills categorical with mode
        """
        df_processed = df.copy()
        
        # Check for missing values
        missing_before = df_processed.isnull().sum().sum()
        logger.info(f"Total missing values before handling: {missing_before}")
        
        if missing_before == 0:
            logger.info("No missing values found")
            return df_processed
        
        # Remove columns with > 50% missing values
        missing_percent = df_processed.isnull().mean()
        high_missing_cols = missing_percent[missing_percent > 0.5].index.tolist()
        
        if high_missing_cols:
            logger.info(f"Removing columns with >50% missing: {len(high_missing_cols)} columns")
            logger.debug(f"Columns removed: {high_missing_cols}")
            df_processed = df_processed.drop(columns=high_missing_cols)
        
        # Fill remaining missing values
        for col in df_processed.columns:
            if df_processed[col].dtype in ['float64', 'int64']:
                # Fill numerical with median
                median_val = df_processed[col].median()
                if pd.isna(median_val):
                    median_val = 0
                df_processed[col] = df_processed[col].fillna(median_val)
            elif df_processed[col].dtype == 'object':
                # Fill categorical with mode
                mode_val = df_processed[col].mode()[0] if not df_processed[col].mode().empty else 'Unknown'
                df_processed[col] = df_processed[col].fillna(mode_val)
        
        missing_after = df_processed.isnull().sum().sum()
        logger.info(f"Total missing values after handling: {missing_after}")
        
        return df_processed
    
    def balance_dataset(self, df: pd.DataFrame, method: str = 'downsample') -> pd.DataFrame:
        """
        Balance the dataset by downsampling benign traffic.
        
        Args:
            df (pd.DataFrame): DataFrame with Label_Binary column
            method (str): Balancing method ('downsample' or 'oversample')
            
        Returns:
            pd.DataFrame: Balanced DataFrame
            
        Note:
            - Downsampling: Reduces benign samples to match attack count
            - Oversampling: Increases attack samples to match benign count (not implemented)
        """
        if 'Label_Binary' not in df.columns:
            raise ValueError("DataFrame must contain 'Label_Binary' column")
        
        # Separate benign and attack
        benign = df[df['Label_Binary'] == 'Benign']
        attack = df[df['Label_Binary'] == 'Attack']
        
        if len(attack) == 0:
            logger.warning("No attack samples found in dataset")
            return df
        
        if method == 'downsample':
            # Downsample benign to match attack count
            benign_downsampled = benign.sample(n=len(attack), random_state=42)
            balanced_df = pd.concat([benign_downsampled, attack], ignore_index=True)
            
            logger.info(f"Balanced dataset: Benign={len(benign_downsampled)}, Attack={len(attack)}")
            
        elif method == 'oversample':
            # TODO: Implement oversampling (e.g., SMOTE)
            logger.warning("Oversampling not implemented, using original dataset")
            balanced_df = df
        else:
            logger.warning(f"Unknown balancing method: {method}, using original dataset")
            balanced_df = df
        
        # Shuffle the dataset
        balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        return balanced_df
    
    def prepare_data(self, 
                    df: pd.DataFrame,
                    balance: bool = True,
                    balance_method: str = 'downsample') -> pd.DataFrame:
        """
        Complete data preparation pipeline.
        
        Args:
            df (pd.DataFrame): Raw DataFrame
            balance (bool): Whether to balance the dataset
            balance_method (str): Balancing method
            
        Returns:
            pd.DataFrame: Prepared DataFrame ready for training
        """
        logger.info("Starting data preparation pipeline...")
        
        # Step 1: Preprocess labels
        df = self.preprocess_labels(df)
        
        # Step 2: Handle missing values
        df = self.handle_missing_values(df)
        
        # Step 3: Balance dataset
        if balance:
            df = self.balance_dataset(df, method=balance_method)
        
        logger.info(f"Data preparation complete. Final dataset size: {len(df)} rows")
        return df
    
    def get_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """
        Get list of feature columns (exclude label columns).
        
        Args:
            df (pd.DataFrame): DataFrame with features
            
        Returns:
            List[str]: List of feature column names
        """
        exclude_cols = ['Label', 'label', 'Class', 'class', 'Label_Binary']
        return [col for col in df.columns if col not in exclude_cols]
    
    def split_data(self, 
                  df: pd.DataFrame, 
                  test_size: float = 0.3,
                  random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Split data into train and test sets.
        
        Args:
            df (pd.DataFrame): Prepared DataFrame
            test_size (float): Proportion of data to use for testing (0.0 to 1.0)
            random_state (int): Random seed for reproducibility
            
        Returns:
            Tuple[pd.DataFrame, pd.DataFrame]: (train_df, test_df)
        """
        from sklearn.model_selection import train_test_split
        
        # Get features and labels
        X = df.drop(columns=['Label_Binary'], errors='ignore')
        y = df['Label_Binary']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Combine features and labels
        train_df = X_train.copy()
        train_df['Label_Binary'] = y_train
        
        test_df = X_test.copy()
        test_df['Label_Binary'] = y_test
        
        logger.info(f"Data split: Train={len(train_df)}, Test={len(test_df)}")
        logger.info(f"Train distribution: Benign={len(train_df[train_df['Label_Binary']=='Benign'])}, "
                   f"Attack={len(train_df[train_df['Label_Binary']=='Attack'])}")
        
        return train_df, test_df