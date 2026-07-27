"""
Routes for the NIDS API.
"""

from .alerts import bp as alerts_bp
from .capture import bp as capture_bp
from .stats import bp as stats_bp
from .predict import bp as predict_bp
from .auth import bp as auth_bp
from .rules import bp as rules_bp

__all__ = ['alerts_bp', 'capture_bp', 'stats_bp', 'predict_bp', 'auth_bp', 'rules_bp']