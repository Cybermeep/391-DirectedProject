"""
Severity scoring for alerts.

This module calculates severity scores based on attack type, confidence,
and other factors.
"""

from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class SeverityScorer:
    """
    Calculates severity scores for alerts.
    
    Severity levels: low, medium, high, critical
    """
    
    # Base severity mapping by attack type
    ATTACK_SEVERITY = {
        'PortScan': 'low',
        'Portscan': 'low',
        'Bruteforce': 'medium',
        'FTP-BruteForce': 'medium',
        'SSH-Bruteforce': 'medium',
        'DoS': 'high',
        'DoS-GoldenEye': 'high',
        'DoS-Hulk': 'high',
        'DoS-SlowHTTPTest': 'medium',
        'DoS-Slowloris': 'medium',
        'DDoS': 'critical',
        'DDoS-LOIC-HTTP': 'critical',
        'DDoS-LOIC-UDP': 'critical',
        'DDoS-HOIC': 'critical',
        'Botnet': 'high',
        'Bot': 'high'
    }
    
    def __init__(self):
        """Initialize the severity scorer."""
        logger.info("SeverityScorer initialized")
    
    def calculate_severity(self, alert_data: Dict[str, Any]) -> str:
        """
        Calculate severity for an alert.
        
        Args:
            alert_data (Dict): Alert data including:
                - attack_type (str): Type of attack
                - ml_confidence (float): ML confidence (0-1)
                - count_occurrences (int): Number of occurrences
                
        Returns:
            str: Severity level (low, medium, high, critical)
        """
        attack_type = alert_data.get('attack_type', 'unknown')
        ml_confidence = alert_data.get('ml_confidence', 0.5)
        count = alert_data.get('count_occurrences', 1)
        
        # Get base severity from attack type
        base_severity = self.ATTACK_SEVERITY.get(attack_type, 'medium')
        
        # Adjust based on confidence
        confidence_boost = 0
        if ml_confidence > 0.9:
            confidence_boost = 1
        elif ml_confidence > 0.7:
            confidence_boost = 0.5
        
        # Adjust based on occurrence count
        count_boost = 0
        if count > 10:
            count_boost = 1
        elif count > 5:
            count_boost = 0.5
        
        # Calculate final severity
        severity_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        base_score = severity_scores.get(base_severity, 2)
        final_score = min(base_score + confidence_boost + count_boost, 4)
        
        # Map back to severity string
        severity_map = {
            1: 'low',
            2: 'medium',
            3: 'high',
            4: 'critical'
        }
        
        final_severity = severity_map.get(int(round(final_score)), 'medium')
        
        logger.debug(f"Severity calculated: {final_severity} (base: {base_severity}, "
                    f"confidence: {ml_confidence:.2f}, count: {count})")
        
        return final_severity
    
    def get_severity_priority(self, severity: str) -> int:
        """
        Get numeric priority for severity level.
        
        Args:
            severity (str): Severity level
            
        Returns:
            int: Priority value (1-4, higher = more critical)
        """
        priority_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return priority_map.get(severity, 1)