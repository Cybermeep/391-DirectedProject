"""
Alert routes for the NIDS API.

This module provides REST endpoints for retrieving, creating, and
managing alerts.
"""

from flask import Blueprint, request, jsonify, Response
import logging
import csv
import io
from datetime import datetime
from explainability import ExplanationGenerator


# Use absolute imports instead of relative
from alert_management import AlertStore, SeverityScorer, AlertDeduplicator
from api.websocket import emit_new_alert
from api.middleware.auth import token_required, tier_required

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

@bp.route('/timeline', methods=['GET'])
def get_alert_timeline():
    """


    Query parameters:
        - hours (int): how far back to look (default: 24)
        - min_group_size (int): only include sources with at least this
          many alerts (default: 2 - a single isolated alert isn't a
          "correlation")
    """
    try:
        hours = request.args.get('hours', 24, type=int)
        min_group_size = request.args.get('min_group_size', 2, type=int)

        store = AlertStore()
        groups = store.get_correlated_alerts(hours=hours, min_group_size=min_group_size)
        return jsonify({'success': True, 'groups': groups})

    except Exception as e:
        logger.error(f"Error getting alert timeline: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/export', methods=['GET'])
@token_required
@tier_required('export_data')
def export_alerts():
    """
    Export alerts as CSV

    Query parameters:
        - days (int): How many days back to include (default: 30)
        - status (str): Filter by status (optional)
        - severity (str): Filter by severity (optional)
    """
    try:
        from datetime import timedelta

        days = request.args.get('days', 30, type=int)
        severity = request.args.get('severity', None)
        status = request.args.get('status', None)
        since = datetime.utcnow() - timedelta(days=days)

        store = AlertStore()
        alerts = store.get_alerts(limit=100000, offset=0, severity=severity, status=status, since=since)

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            'alert_id', 'timestamp', 'severity', 'attack_type', 'source_ip', 'source_port',
            'dest_ip', 'dest_port', 'protocol', 'message', 'explanation', 'ml_confidence',
            'rule_id', 'count_occurrences', 'status',
        ])
        for alert in alerts:
            writer.writerow([
                alert.alert_id, alert.timestamp.isoformat() if alert.timestamp else '',
                alert.severity, alert.attack_type, alert.source_ip, alert.source_port,
                alert.dest_ip, alert.dest_port, alert.protocol, alert.message, alert.explanation,
                alert.ml_confidence, alert.rule_id, alert.count_occurrences, alert.status,
            ])

        filename = f"nids-alerts-{datetime.utcnow().strftime('%Y%m%d')}.csv"
        return Response(
            buffer.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'},
        )

    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
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

@bp.route('/<alert_id>/explain', methods=['GET'])
def explain_alert(alert_id):
    """
    Get a human-readable explanation for an alert.
    
    Query Parameters:
        - detailed (bool): Whether to return detailed explanation (default: False)
    """
    try:
        # Get the alert
        store = AlertStore()
        alert = store.get_alert_by_id(alert_id)
        
        if not alert:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        
        # Get detailed flag
        detailed = request.args.get('detailed', 'false').lower() == 'true'
        
        # Prepare alert data
        alert_data = alert.to_dict()
        
        # Generate feature importances (simulated for now - will be real when model is trained)
        # In production, this would come from the model's feature_importances_
        feature_importances = {
            'SYN_Flag_Cnt': 0.85,
            'RST_Flag_Cnt': 0.72,
            'Flow_IAT_Mean': 0.65,
            'Tot_Fwd_Pkts': 0.58,
            'ACK_Flag_Cnt': 0.45,
            'Flow_Pkts/s': 0.42,
            'Tot_Bwd_Pkts': 0.38,
            'Fwd_Pkt_Len_Mean': 0.35
        }
        
        # Generate explanation
        generator = ExplanationGenerator(max_features=5)
        
        if detailed:
            explanation = generator.generate_detailed_explanation(alert_data, feature_importances)
            return jsonify({
                'success': True,
                'explanation': explanation
            })
        else:
            explanation = generator.generate_explanation(alert_data, feature_importances)
            return jsonify({
                'success': True,
                'explanation': explanation
            })
        
    except Exception as e:
        logger.error(f"Error generating explanation for alert {alert_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500