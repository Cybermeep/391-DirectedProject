"""
Alert storage and retrieval operations.

This module handles CRUD operations for alerts in the SQLite database.
"""

from datetime import datetime
import uuid
from typing import Optional, List, Dict, Any
import logging

from .models import Alert, get_session, _DEFAULT_DB_PATH

logger = logging.getLogger(__name__)

# Keeps the "active" alert log bounded and fresh: once more than this many
# alerts are active at once, the oldest ones (by when they were first
# created, i.e. true FIFO) get auto-archived to 'resolved' - the same
# action the Archive button in the UI already performs, just automatic.
# Archived alerts aren't deleted; they just move to the Archived tab.
MAX_ACTIVE_ALERTS = 100


class AlertStore:
    """Handles storage and retrieval of alerts."""
    
    def __init__(self, db_path=_DEFAULT_DB_PATH):
        """
        Initialize the alert store.
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.session = None
        logger.info(f"AlertStore initialized with db: {db_path}")
    
    def create_alert(self, alert_data: Dict[str, Any], dedup_window_seconds: int = 30) -> Alert:
        """
        Create a new alert in the database, or bump an existing one.

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
            dedup_window_seconds (int): If an active alert with the same
                attack_type + dest_port + rule_id was last seen within
                this many seconds, bump its count_occurrences/last_seen
                instead of inserting a new row. This is what stops a
                single sustained flood (which completes many short flows)
                from creating dozens of near-identical alerts.

        Returns:
            Alert: Created (or bumped) alert object
        """
        from datetime import timedelta

        session = get_session(self.db_path)

        try:
            cutoff = datetime.utcnow() - timedelta(seconds=dedup_window_seconds)
            existing = (
                session.query(Alert)
                .filter(
                    Alert.attack_type == alert_data.get('attack_type', 'unknown'),
                    Alert.source_ip == alert_data.get('source_ip'),
                    Alert.dest_ip == alert_data.get('dest_ip'),
                    Alert.dest_port == alert_data.get('dest_port'),
                    Alert.rule_id == alert_data.get('rule_id'),
                    Alert.status == 'active',
                    Alert.last_seen >= cutoff,
                )
                .order_by(Alert.last_seen.desc())
                .first()
            )

            if existing:
                existing.count_occurrences = (existing.count_occurrences or 1) + 1
                existing.last_seen = datetime.utcnow()
                # Keep the highest confidence/severity seen for this burst.
                if (alert_data.get('ml_confidence') or 0) > (existing.ml_confidence or 0):
                    existing.ml_confidence = alert_data.get('ml_confidence')
                session.commit()
                session.refresh(existing)
                logger.info(f"Alert deduplicated: {existing.alert_id} (now x{existing.count_occurrences})")
                return existing

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

            self._enforce_active_alert_cap(session)

            return alert
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating alert: {e}")
            raise
        finally:
            session.close()
    
    def get_alerts(self, limit: int = 100, offset: int = 0,
                   severity: Optional[str] = None,
                   status: Optional[str] = None,
                   since: Optional[datetime] = None) -> List[Alert]:
        """
        Retrieve alerts with optional filters.
        
        Args:
            limit (int): Maximum number of alerts to return
            offset (int): Number of alerts to skip
            severity (str, optional): Filter by severity
            status (str, optional): Filter by status
            since (datetime, optional): Only alerts at or after this timestamp
            
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
            if since:
                query = query.filter(Alert.timestamp >= since)
            
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
    
    def get_correlated_alerts(self, hours: int = 24, min_group_size: int = 2, limit_groups: int = 20) -> List[Dict[str, Any]]:
        """
        Group recent alerts by source IP - a real attack often shows up
        as a sequence from one source (a port scan, then a brute force
        attempt a minute later), not as isolated unrelated events. Only
        returns sources with at least `min_group_size` alerts, most
        active source first.
        """
        from datetime import timedelta
        from collections import defaultdict

        session = get_session(self.db_path)
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            alerts = (
                session.query(Alert)
                .filter(Alert.timestamp >= since, Alert.source_ip.isnot(None))
                .order_by(Alert.timestamp.asc())
                .all()
            )

            groups = defaultdict(list)
            for alert in alerts:
                groups[alert.source_ip].append(alert.to_dict())

            result = [
                {
                    "source_ip": src_ip,
                    "alert_count": len(group),
                    "first_seen": group[0]["timestamp"],
                    "last_seen": group[-1]["timestamp"],
                    "severities": sorted({a["severity"] for a in group}),
                    "attack_types": [a["attack_type"] for a in group],
                    "alerts": group,
                }
                for src_ip, group in groups.items()
                if len(group) >= min_group_size
            ]
            result.sort(key=lambda g: g["last_seen"], reverse=True)
            return result[:limit_groups]
        finally:
            session.close()

    def _enforce_active_alert_cap(self, session, max_active: int = MAX_ACTIVE_ALERTS) -> None:
        """
        FIFO: if more than max_active alerts are currently 'active',
        auto-archive the oldest ones (by first_seen/creation order) down
        to the cap. Same effect as a user clicking Archive, just automatic -
        archived alerts remain fully visible under the Archived tab, they
        just stop counting toward the active log.
        """
        active_count = session.query(Alert).filter_by(status='active').count()
        overflow = active_count - max_active
        if overflow <= 0:
            return

        oldest = (
            session.query(Alert)
            .filter_by(status='active')
            .order_by(Alert.timestamp.asc())
            .limit(overflow)
            .all()
        )
        for old_alert in oldest:
            old_alert.status = 'resolved'
        session.commit()
        logger.info(f"Auto-archived {len(oldest)} oldest active alert(s) to stay within the {max_active}-alert active cap")

    def get_rule_performance(self) -> List[Dict[str, Any]]:
        """
        Aggregate alert counts per rule_id: how many times each rule has
        fired, when it last fired, and its average confidence. Built from
        real persisted alert history (not an in-memory counter), so it
        survives restarts and reflects everything ever detected, not just
        the current process's uptime.
        """
        from sqlalchemy import func

        session = get_session(self.db_path)
        try:
            rows = (
                session.query(
                    Alert.rule_id,
                    func.count(Alert.id).label("fire_count"),
                    func.max(Alert.last_seen).label("last_fired"),
                    func.avg(Alert.ml_confidence).label("avg_confidence"),
                    func.sum(Alert.count_occurrences).label("total_occurrences"),
                )
                .filter(Alert.rule_id.isnot(None))
                .group_by(Alert.rule_id)
                .all()
            )
            return [
                {
                    "rule_id": r.rule_id,
                    "fire_count": r.fire_count,
                    "total_occurrences": int(r.total_occurrences or r.fire_count),
                    "last_fired": r.last_fired.isoformat() if r.last_fired else None,
                    "avg_confidence": float(r.avg_confidence) if r.avg_confidence is not None else None,
                }
                for r in rows
            ]
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