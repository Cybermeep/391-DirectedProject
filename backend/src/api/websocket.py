"""
WebSocket handlers for real-time updates.

This module manages WebSocket connections for pushing alerts and
system status updates to the frontend in real-time.
"""

from flask_socketio import emit, join_room, leave_room
from flask import request
import logging
from datetime import datetime

from .app import socketio

logger = logging.getLogger(__name__)

# Track connected clients
connected_clients = set()

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    client_id = request.sid
    connected_clients.add(client_id)
    logger.info(f"Client connected: {client_id}")
    emit('connection_response', {'status': 'connected', 'message': 'Welcome to NIDS WebSocket'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    client_id = request.sid
    connected_clients.discard(client_id)
    logger.info(f"Client disconnected: {client_id}")

@socketio.on('subscribe_alerts')
def handle_subscribe_alerts(data):
    """Subscribe client to alert updates."""
    client_id = request.sid
    join_room('alerts_room')
    logger.info(f"Client {client_id} subscribed to alerts")
    emit('subscription_response', {'status': 'subscribed', 'room': 'alerts_room'})

@socketio.on('unsubscribe_alerts')
def handle_unsubscribe_alerts(data):
    """Unsubscribe client from alert updates."""
    client_id = request.sid
    leave_room('alerts_room')
    logger.info(f"Client {client_id} unsubscribed from alerts")

@socketio.on('get_alert_history')
def handle_alert_history(data):
    """Get historical alerts."""
    from alert_management import AlertStore
    
    limit = data.get('limit', 100)
    offset = data.get('offset', 0)
    
    store = AlertStore()
    alerts = store.get_alerts(limit=limit, offset=offset)
    
    emit('alert_history', {
        'count': len(alerts),
        'alerts': [alert.to_dict() for alert in alerts]
    })

def emit_new_alert(alert_data):
    """
    Emit a new alert to all subscribed clients.
    
    Args:
        alert_data (dict): Alert data to send
    """
    socketio.emit('new_alert', alert_data, room='alerts_room')
    logger.info(f"Alert broadcasted to {len(connected_clients)} clients")

def emit_system_status(status_data):
    """
    Emit system status updates to all clients.
    
    Args:
        status_data (dict): Status data to send
    """
    socketio.emit('system_status', status_data)