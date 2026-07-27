"""
Flask application for the NIDS API.

This module creates the main Flask application with CORS support,
WebSocket capabilities, and route registration.

NOTE on eventlet: eventlet.monkey_patch() MUST run before anything else
(sockets, threading, ssl) is imported anywhere in the process. That patch
call lives at the very top of run_api.py (the actual process entry point),
not here, since by the time this module is imported other stdlib modules
may already be loaded.
"""

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import logging
import os
from dotenv import load_dotenv

import appconfig
from auth.models import init_auth_database
import rules.models  # noqa: F401 - registers the Rule table on the shared Base before create_all
import core.packet_stats  # noqa: F401 - registers the packet_hourly_stats table on the shared Base before create_all
from rules.evaluator import RuleEngine
from rules.ast_nodes import node_from_dict

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = appconfig.SECRET_KEY

# Enable CORS for frontend communication.
# NOTE: flask-cors treats a literal "*" as "allow every origin" and will
# silently ignore any other origins listed alongside it - the previous
# config (["http://localhost:3000", "http://localhost:5173", "*"]) was
# not doing what it looked like it was doing. In an Electron app the
# renderer normally talks to the bundled backend over http://localhost,
# so we scope this to the actual dev/prod ports instead of a wildcard.
ALLOWED_ORIGINS = os.getenv(
    "CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"
).split(",")
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode='eventlet')

# --- Bootstrap the accounts/rules database (separate from alerts.db) -------
init_auth_database()

# --- In-process rule engine, loaded from whatever's enabled in SQLite ------
rule_engine = RuleEngine()
app.config['RULE_ENGINE'] = rule_engine


def _load_enabled_rules():
    from auth.models import get_auth_session
    from rules.models import Rule

    session = get_auth_session()
    try:
        # Only AST (non-builtin) rules go into the per-flow rule_engine -
        # built-in signatures are rate/window-based and evaluated by
        # RateSignatureEngine instead (see rules/rate_signatures.py).
        enabled_rules = session.query(Rule).filter_by(enabled=True, is_builtin=False).all()
        compiled = [(r.id, r.name, r.severity, node_from_dict(r.ast)) for r in enabled_rules]
        rule_engine.load_rules(compiled)
    except Exception:
        logger.exception("Failed to load rules at startup")
    finally:
        session.close()


from rules.models import seed_builtin_signatures  # noqa: E402
seed_builtin_signatures()
_load_enabled_rules()

# Import routes after app initialization to avoid circular imports
from .routes import alerts, capture, stats, predict, auth, rules as rules_routes

# Register blueprints
app.register_blueprint(alerts.bp, url_prefix='/api/alerts')
app.register_blueprint(capture.bp, url_prefix='/api/capture')
app.register_blueprint(stats.bp, url_prefix='/api/stats')
app.register_blueprint(predict.bp, url_prefix='/api')
app.register_blueprint(auth.bp, url_prefix='/api/auth')
app.register_blueprint(rules_routes.bp, url_prefix='/api/rules')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for the API."""
    return jsonify({
        'status': 'healthy',
        'service': 'NIDS API',
        'version': '1.0.0'
    })


@app.route('/api/status', methods=['GET'])
def system_status():
    """Get overall system status."""
    import datetime
    from alert_management import AlertStore

    store = AlertStore(db_path=appconfig.ALERTS_DB_PATH)
    stats = store.get_alert_stats()

    return jsonify({
        'status': 'running',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'alerts': stats
    })


def start_api(host='0.0.0.0', port=5000, debug=False):
    """
    Start the Flask API server with SocketIO support.

    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        debug (bool): Enable debug mode
    """
    logger.info(f"Starting API server on {host}:{port}")
    # use_reloader is forced off: Werkzeug's reloader forks a second process
    # which does not play well with eventlet's monkey-patched threading/
    # sockets and was a latent source of the capture thread misbehaving.
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_api(debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
