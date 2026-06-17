"""
Alert management module for the NIDS system.

This module handles alert storage, deduplication, and severity scoring.
"""

from .models import Alert, init_database, get_session
from .alert_store import AlertStore
from .deduplicator import AlertDeduplicator
from .severity_scorer import SeverityScorer

__all__ = [
    'Alert',
    'AlertStore',
    'AlertDeduplicator',
    'SeverityScorer',
    'init_database',
    'get_session'
]