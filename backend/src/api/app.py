"""
Flask application for the NIDS API.

This module creates the main Flask application with CORS support,
WebSocket capabilities, and route registration.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Enable CORS for frontend communication
CORS(app, origins=["http://localhost:3000", "http://localhost:5173", "*"])

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Import routes after app initialization to avoid circular imports
from .routes import alerts, capture, stats

# Register blueprints
app.register_blueprint(alerts.bp, url_prefix='/api/alerts')
app.register_blueprint(capture.bp, url_prefix='/api/capture')
app.register_blueprint(stats.bp, url_prefix='/api/stats')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for the API."""
    return {
        'status': 'healthy',
        'service': 'NIDS API',
        'version': '1.0.0'
    }

@app.route('/api/status', methods=['GET'])
def system_status():
    """Get overall system status."""
    from alert_management import AlertStore
    
    store = AlertStore()
    stats = store.get_alert_stats()
    
    return {
        'status': 'running',
        'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'alerts': stats
    }

# Login endpoint (simple auth)
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Simple login endpoint."""
    from .middleware.auth import login as auth_login
    return auth_login()

def start_api(host='0.0.0.0', port=5000, debug=False):
    """
    Start the Flask API server with SocketIO support.
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        debug (bool): Enable debug mode
    """
    logger.info(f"Starting API server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    start_api(debug=True)