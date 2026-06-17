"""
Alert deduplication logic.

This module handles deduplication of similar alerts to prevent alert fatigue.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

from .models import Alert, get_session

logger = logging.getLogger(__name__)

class AlertDeduplicator:
    """
    Deduplicates alerts based on similarity and time windows.
    
    If the same alert occurs repeatedly within a time window, increment
    a counter instead of creating a new entry.
    """
    
    def __init__(self, time_window_minutes: int = 5, similarity_threshold: float = 0.9):
        """
        Initialize the deduplicator.
        
        Args:
            time_window_minutes (int): Time window for deduplication in minutes
            similarity_threshold (float): Threshold for considering alerts similar (0-1)
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.similarity_threshold = similarity_threshold
        logger.info(f"Deduplicator initialized with window: {time_window_minutes}m")
    
    def get_alert_hash(self, alert_data: Dict[str, Any]) -> str:
        """
        Generate a hash for an alert based on its key attributes.
        
        Args:
            alert_data (Dict): Alert data
            
        Returns:
            str: Hash string for deduplication
        """
        # Key attributes that define a unique alert
        key_parts = [
            alert_data.get('attack_type', 'unknown'),
            alert_data.get('source_ip', ''),
            alert_data.get('dest_ip', ''),
            alert_data.get('protocol', ''),
        ]
        
        # Create a string from key parts
        key_string = '|'.join(str(part) for part in key_parts)
        
        # Generate hash
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def process_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an alert, deduplicating if a similar one exists.
        
        Args:
            alert_data (Dict): Alert data to process
            
        Returns:
            Dict: Processed alert data with count and status
        """
        session = get_session()
        alert_hash = self.get_alert_hash(alert_data)
        time_threshold = datetime.utcnow() - self.time_window
        
        try:
            # Check for existing similar alerts in the time window
            existing = session.query(Alert).filter(
                Alert.alert_id == alert_hash,
                Alert.timestamp >= time_threshold,
                Alert.status == 'active'
            ).first()
            
            if existing:
                # Update existing alert
                existing.count_occurrences += 1
                existing.last_seen = datetime.utcnow()
                session.commit()
                
                logger.info(f"Deduplicated alert: {alert_hash} (count: {existing.count_occurrences})")
                
                return {
                    'is_duplicate': True,
                    'alert_id': existing.alert_id,
                    'count_occurrences': existing.count_occurrences,
                    'existing_alert': existing.to_dict()
                }
            else:
                # New alert - use alert_hash as ID
                alert_data['alert_id'] = alert_hash
                alert_data['count_occurrences'] = 1
                alert_data['first_seen'] = datetime.utcnow()
                alert_data['last_seen'] = datetime.utcnow()
                alert_data['status'] = 'active'
                
                logger.info(f"New alert: {alert_hash}")
                return {
                    'is_duplicate': False,
                    'alert_id': alert_hash,
                    'count_occurrences': 1,
                    'alert_data': alert_data
                }
                
        except Exception as e:
            session.rollback()
            logger.error(f"Error in deduplication: {e}")
            return {
                'is_duplicate': False,
                'alert_id': None,
                'error': str(e)
            }
        finally:
            session.close()