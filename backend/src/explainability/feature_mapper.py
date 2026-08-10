"""
Feature mapper for explainability.

This module maps technical feature names to human-readable descriptions
and provides context about what feature values indicate
"""

import yaml
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class FeatureMapper:
    """
    Maps technical features to human-readable descriptions
    
    Attributes:
        feature_descriptions (Dict): Mapping of feature names to descriptions
        attack_indicators (Dict): Indicators for what feature values mean
        attack_patterns (Dict): Patterns for different attack types
    """
    
    def __init__(self, lookup_file: Optional[str] = None):
        """
        Initialize the feature mapper.
        
        Args:
            lookup_file (str, optional): Path to feature lookup YAML file
        """
        self.feature_descriptions = {}
        self.attack_indicators = {}
        self.attack_patterns = {}
        
        # Load lookup file
        if lookup_file is None:
            lookup_file = Path(__file__).parent / 'feature_lookup.yaml'
        
        self._load_lookup(lookup_file)
        logger.info(f"FeatureMapper initialized with {len(self.feature_descriptions)} features")
    
    def _load_lookup(self, lookup_file: Path) -> None:
        """
        Load the feature lookup YAML file
        
        Args:
            lookup_file (Path): Path to the YAML file
        """
        try:
            if lookup_file.exists():
                with open(lookup_file, 'r') as f:
                    data = yaml.safe_load(f)
                
                self.feature_descriptions = data.get('feature_descriptions', {})
                self.attack_indicators = data.get('attack_indicators', {})
                self.attack_patterns = data.get('attack_patterns', {})
                
                logger.info(f"Loaded {len(self.feature_descriptions)} feature descriptions")
            else:
                logger.warning(f"Lookup file not found: {lookup_file}")
                
        except Exception as e:
            logger.error(f"Error loading lookup file: {e}")
    
    def get_description(self, feature_name: str) -> str:
        """
        Get human-readable description for a feature
        
        Args:
            feature_name (str): Technical feature name
            
        Returns:
            str: Human-readable description
        """
        return self.feature_descriptions.get(feature_name, feature_name.replace('_', ' '))
    
    def get_feature_importance_text(self, feature_name: str, importance: float) -> str:
        """
        Generate text describing feature importance
        
        Args:
            feature_name (str): Technical feature name
            importance (float): Importance score (0-1)
            
        Returns:
            str: Human-readable importance description
        """
        description = self.get_description(feature_name)
        
        # Determine importance level
        if importance > 0.7:
            level = "very strong indicator"
        elif importance > 0.5:
            level = "strong indicator"
        elif importance > 0.3:
            level = "moderate indicator"
        else:
            level = "minor factor"
        
        # Check if this feature has attack indicators
        indicator_text = self._get_indicator_text(feature_name, importance)
        
        return f"{description} (importance: {importance:.3f}) - {level}{indicator_text}"
    
    def _get_indicator_text(self, feature_name: str, importance: float) -> str:
        """
        Get attack indicator text for a feature
        
        Args:
            feature_name (str): Feature name
            importance (float): Importance score
            
        Returns:
            str: Indicator text
        """
        indicators = self.attack_indicators.get('indicators', [])
        
        for indicator in indicators:
            if indicator.get('feature') == feature_name:
                if importance > 0.5:
                    return f" - {indicator.get('high', 'high value indicates attack')}"
                else:
                    return f" - {indicator.get('low', 'normal value')}"
        
        return ""
    
    def get_attack_pattern_explanation(self, attack_type: str) -> Dict[str, Any]:
        """
        Get explanation for an attack type
        
        Args:
            attack_type (str): Type of attack
            
        Returns:
            Dict: Attack pattern explanation
        """
        pattern = self.attack_patterns.get('patterns', {}).get(attack_type, {})
        
        if pattern:
            return {
                'description': pattern.get('description', 'Unknown attack'),
                'key_features': pattern.get('key_features', []),
                'explanation': pattern.get('explanation', 'No explanation available')
            }
        
        return {
            'description': f'Unknown attack type: {attack_type}',
            'key_features': [],
            'explanation': 'No pattern available for this attack type'
        }
    
    def get_feature_value_context(self, feature_name: str, value: float) -> str:
        """
        Get context about what a feature value indicates
        
        Args:
            feature_name (str): Feature name
            value (float): Feature value
            
        Returns:
            str: Context description
        """
        description = self.get_description(feature_name)
        
        # Simple heuristics for value interpretation
        if value > 0.8:
            context = "abnormally high"
        elif value > 0.6:
            context = "elevated"
        elif value > 0.4:
            context = "moderate"
        elif value > 0.2:
            context = "slightly low"
        else:
            context = "very low"
        
        return f"{description} is {context}"