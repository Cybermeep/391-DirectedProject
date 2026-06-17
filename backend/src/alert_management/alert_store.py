"""
Alert storage and retrieval operations.

This module handles CRUD operations for alerts in the SQLite database.
"""

from datetime import datetime
import uuid
from typing import Optional, List, Dict, Any
import logging

from .models import Alert, get_session

logger = logging.getLogger(__name__)

class AlertStore:
    """Handles storage and retrieval of alerts."""
    
    def __init__(self, db_path='data/alerts.db'):
        """
        Initialize the alert store.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.session = None
        logger.info(f"AlertStore initialized with db: {db_path}")
    
    def create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """
        Create a new alert in the database.
        
        Args:
            alert_data (Dict): Alert data including:
                - severity (str): low, medium, high, critical
                - attack_type (str): Type of attack detected
                - source_ip (str): Source IP address
                - dest_ip (str): Destination IP address
                - source_port (int): Source port
                - dest_port (int): Destination port
                - protocol (str): Protocol (TCP, UDP, etc.)
                - message (str): Alert message
                - explanation (str): Human-readable explanation
                - ml_confidence (float): ML confidence score (0-1)
                - rule_id (str): Rule ID if rule-based
                
        Returns:
            Alert: Created alert object
        """
        session = get_session(self.db_path)
        
        try:
            alert = Alert(
                alert_id=str(uuid.uuid4())[:8],
                timestamp=datetime.utcnow(),
                severity=alert_data.get('severity', 'medium'),
                attack_type=alert_data.get('attack_type', 'unknown'),
                source_ip=alert_data.get('source_ip'),
                dest_ip=alert_data.get('dest_ip'),
                source_port=alert_data.get('source_port'),
                dest_port=alert_data.get('dest_port'),
                protocol=alert_data.get('protocol'),
                message=alert_data.get('message', ''),
                explanation=alert_data.get('explanation', ''),
                ml_confidence=alert_data.get('ml_confidence'),
                rule_id=alert_data.get('rule_id'),
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            
            session.add(alert)
            session.commit()
            session.refresh(alert)
            
            logger.info(f"Alert created: {alert.alert_id} ({alert.attack_type})")
            return alert
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating alert: {e}")
            raise
        finally:
            session.close()
    
    def get_alerts(self, limit: int = 100, offset: int = 0,
                   severity: Optional[str] = None,
                   status: Optional[str] = None) -> List[Alert]:
        """
        Retrieve alerts with optional filters.
        
        Args:
            limit (int): Maximum number of alerts to return
            offset (int): Number of alerts to skip
            severity (str, optional): Filter by severity
            status (str, optional): Filter by status
            
        Returns:
            List[Alert]: List of alert objects
        """
        session = get_session(self.db_path)
        
        try:
            query = session.query(Alert)
            
            if severity:
                query = query.filter(Alert.severity == severity)
            if status:
                query = query.filter(Alert.status == status)
            
            alerts = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
            return alerts
            
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
        finally:
            session.close()
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """
        Retrieve an alert by its ID.
        
        Args:
            alert_id (str): Alert identifier
            
        Returns:
            Optional[Alert]: Alert object or None
        """
        session = get_session(self.db_path)
        
        try:
            return session.query(Alert).filter(Alert.alert_id == alert_id).first()
        except Exception as e:
            logger.error(f"Error retrieving alert: {e}")
            return None
        finally:
            session.close()
    
    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """
        Update the status of an alert.
        
        Args:
            alert_id (str): Alert identifier
            status (str): New status (active, resolved, false_positive)
            
        Returns:
            bool: True if updated successfully
        """
        session = get_session(self.db_path)
        
        try:
            alert = session.query(Alert).filter(Alert.alert_id == alert_id).first()
            if alert:
                alert.status = status
                session.commit()
                logger.info(f"Alert {alert_id} status updated to {status}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating alert: {e}")
            return False
        finally:
            session.close()
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """
        Get statistics about alerts.
        
        Returns:
            Dict: Statistics including counts by severity and status
        """
        session = get_session(self.db_path)
        
        try:
            total = session.query(Alert).count()
            by_severity = {}
            by_status = {}
            
            for severity in ['low', 'medium', 'high', 'critical']:
                count = session.query(Alert).filter(Alert.severity == severity).count()
                if count > 0:
                    by_severity[severity] = count
            
            for status in ['active', 'resolved', 'false_positive']:
                count = session.query(Alert).filter(Alert.status == status).count()
                if count > 0:
                    by_status[status] = count
            
            return {
                'total': total,
                'by_severity': by_severity,
                'by_status': by_status
            }
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {'total': 0, 'by_severity': {}, 'by_status': {}}
        finally:
            session.close()