"""
Explainability module for the NIDS system.

This module provides human-readable explanations for ML-based alerts
by mapping feature importance to understandable descriptions.
"""

from .feature_mapper import FeatureMapper
from .explanation_generator import ExplanationGenerator

__all__ = [
    'FeatureMapper',
    'ExplanationGenerator'
]