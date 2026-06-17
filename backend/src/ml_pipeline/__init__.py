"""
Machine Learning Pipeline for Network Intrusion Detection.

This module provides a complete ML pipeline for training and evaluating
a Random Forest classifier on the CSE-CIC-IDS2018 dataset for network
intrusion detection.

Exports:
    DataLoader: Handles dataset loading and preprocessing
    Preprocessor: Handles feature preprocessing and normalization
    ModelBuilder: Builds and trains Random Forest models
    Evaluator: Evaluates model performance
    InferenceEngine: Performs real-time inference on network traffic
"""

from .data_loader import DataLoader
from .preprocess import Preprocessor
from .model_builder import ModelBuilder
from .evaluator import Evaluator
from .inference import InferenceEngine

__all__ = [
    'DataLoader',
    'Preprocessor',
    'ModelBuilder',
    'Evaluator',
    'InferenceEngine'
]