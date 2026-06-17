"""
API module for the NIDS system.

This module provides REST API endpoints and WebSocket support
for the frontend dashboard.
"""

from .app import app, socketio, start_api
from .websocket import emit_new_alert, emit_system_status

__all__ = [
    'app',
    'socketio',
    'start_api',
    'emit_new_alert',
    'emit_system_status'
]