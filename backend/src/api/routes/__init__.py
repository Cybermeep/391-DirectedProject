"""
Routes for the NIDS API.
"""

from .alerts import bp as alerts_bp
from .capture import bp as capture_bp
from .stats import bp as stats_bp

__all__ = ['alerts_bp', 'capture_bp', 'stats_bp']