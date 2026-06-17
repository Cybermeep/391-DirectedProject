"""
Statistics routes for the NIDS API.

This module provides endpoints for system statistics, including
alert statistics and system health.
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

bp = Blueprint('stats', __name__)

@bp.route('/dashboard', methods=['GET'])
def get_dashboard_stats():
    """
    Get comprehensive dashboard statistics.
    
    Returns:
        - Alert counts by severity
        - Alert counts by status
        - Recent alerts timeline
        - System status
    """
    try:
        from alert_management import AlertStore
        
        store = AlertStore()
        stats = store.get_alert_stats()
        
        # Get recent alerts for timeline
        recent_alerts = store.get_alerts(limit=50)
        
        # Group alerts by hour for timeline
        timeline = {}
        now = datetime.utcnow()
        for i in range(24):
            hour = now - timedelta(hours=i)
            hour_key = hour.strftime('%Y-%m-%d %H:00')
            timeline[hour_key] = 0
        
        for alert in recent_alerts:
            if alert.timestamp:
                hour_key = alert.timestamp.strftime('%Y-%m-%d %H:00')
                if hour_key in timeline:
                    timeline[hour_key] += 1
        
        # Format timeline for frontend
        timeline_data = [
            {'time': k, 'count': v} 
            for k, v in sorted(timeline.items())
        ]
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timeline': timeline_data,
            'recent_alerts_count': len(recent_alerts),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/attack_types', methods=['GET'])
def get_attack_type_stats():
    """Get statistics broken down by attack type."""
    try:
        from alert_management import AlertStore
        
        store = AlertStore()
        alerts = store.get_alerts(limit=1000)
        
        attack_counts = {}
        for alert in alerts:
            attack_type = alert.attack_type or 'unknown'
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        # Sort by count descending
        sorted_attacks = sorted(
            [{'attack_type': k, 'count': v} for k, v in attack_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )
        
        return jsonify({
            'success': True,
            'attack_types': sorted_attacks
        })
        
    except Exception as e:
        logger.error(f"Error getting attack type stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/severity_distribution', methods=['GET'])
def get_severity_distribution():
    """Get severity distribution statistics."""
    try:
        from alert_management import AlertStore
        
        store = AlertStore()
        stats = store.get_alert_stats()
        
        return jsonify({
            'success': True,
            'distribution': stats.get('by_severity', {})
        })
        
    except Exception as e:
        logger.error(f"Error getting severity distribution: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500