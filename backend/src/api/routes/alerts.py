"""
Alert routes for the NIDS API.

This module provides REST endpoints for retrieving, creating, and
managing alerts.
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime

# Use absolute imports instead of relative
from alert_management import AlertStore, SeverityScorer, AlertDeduplicator
from api.websocket import emit_new_alert

logger = logging.getLogger(__name__)

bp = Blueprint('alerts', __name__)

@bp.route('/', methods=['GET'])
def get_alerts():
    """
    Get all alerts with optional filtering.
    
    Query parameters:
        - limit (int): Max alerts to return (default: 100)
        - offset (int): Number to skip (default: 0)
        - severity (str): Filter by severity (low, medium, high, critical)
        - status (str): Filter by status (active, resolved, false_positive)
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        severity = request.args.get('severity', None)
        status = request.args.get('status', None)
        
        store = AlertStore()
        alerts = store.get_alerts(limit=limit, offset=offset, severity=severity, status=status)
        
        return jsonify({
            'success': True,
            'count': len(alerts),
            'alerts': [alert.to_dict() for alert in alerts]
        })
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get a specific alert by ID."""
    try:
        store = AlertStore()
        alert = store.get_alert_by_id(alert_id)
        
        if alert:
            return jsonify({'success': True, 'alert': alert.to_dict()})
        else:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
            
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/', methods=['POST'])
def create_alert():
    """
    Create a new alert.
    
    Expected JSON body:
        - attack_type (str): Type of attack
        - source_ip (str): Source IP
        - dest_ip (str): Destination IP
        - protocol (str): Protocol
        - message (str): Alert message
        - explanation (str): Human-readable explanation
        - ml_confidence (float): ML confidence (0-1)
        - rule_id (str): Rule ID (for rule-based alerts)
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Required fields
        if 'attack_type' not in data:
            return jsonify({'success': False, 'error': 'attack_type is required'}), 400
        
        # Calculate severity
        scorer = SeverityScorer()
        severity = scorer.calculate_severity(data)
        data['severity'] = severity
        
        # Check for duplicates
        deduplicator = AlertDeduplicator()
        dedup_result = deduplicator.process_alert(data)
        
        if dedup_result['is_duplicate']:
            return jsonify({
                'success': True,
                'is_duplicate': True,
                'alert_id': dedup_result['alert_id'],
                'count_occurrences': dedup_result['count_occurrences'],
                'message': 'Alert deduplicated'
            })
        else:
            # Create new alert
            store = AlertStore()
            alert_data = dedup_result.get('alert_data', data)
            alert = store.create_alert(alert_data)
            
            # Broadcast via WebSocket
            emit_new_alert(alert.to_dict())
            
            return jsonify({
                'success': True,
                'is_duplicate': False,
                'alert': alert.to_dict()
            }), 201
            
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/<alert_id>/status', methods=['PUT'])
def update_alert_status(alert_id):
    """
    Update the status of an alert.
    
    Expected JSON body:
        - status (str): New status (active, resolved, false_positive)
    """
    try:
        data = request.get_json()
        
        if not data or 'status' not in data:
            return jsonify({'success': False, 'error': 'status is required'}), 400
        
        status = data['status']
        if status not in ['active', 'resolved', 'false_positive']:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        
        store = AlertStore()
        success = store.update_alert_status(alert_id, status)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Alert {alert_id} status updated to {status}'
            })
        else:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
            
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics."""
    try:
        store = AlertStore()
        stats = store.get_alert_stats()
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting alert stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500