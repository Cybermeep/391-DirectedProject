"""
Statistics routes for the NIDS API.

This module provides endpoints for system statistics, including
alert statistics and system health.
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timedelta

from api.middleware.auth import optional_token

logger = logging.getLogger(__name__)

bp = Blueprint('stats', __name__)

@bp.route('/dashboard', methods=['GET'])
@optional_token
def get_dashboard_stats():
    """
    Get comprehensive dashboard statistics.

    Query parameters:
        - hours (int): How many hours of history to include (default: 24).
          Capped by the requesting user's tier (appconfig.TIER_LIMITS'
          alert_history_days) - free defaults to 24h regardless of what's
          requested, Pro up to 30 days, Enterprise up to 365 days. An
          anonymous/unauthenticated request is treated as free-tier.

    Returns:
        - Alert counts by severity
        - Alert counts by status
        - Recent alerts timeline
        - System status
    """
    try:
        from alert_management import AlertStore
        from core.packet_stats import get_hourly_counts
        from appconfig import TIER_LIMITS

        user = getattr(request, 'user', None)
        tier = (user or {}).get('tier', 'free')
        max_hours = TIER_LIMITS.get(tier, TIER_LIMITS['free'])['alert_history_days'] * 24

        requested_hours = request.args.get('hours', 24, type=int)
        hours = max(1, min(requested_hours, max_hours))

        store = AlertStore()
        stats = store.get_alert_stats()

        since = datetime.utcnow() - timedelta(hours=hours)
        # Fetch enough rows to actually cover the requested window - the
        # previous fixed limit=50 would silently undercount any window
        # with more than 50 alerts in it (increasingly likely for
        # multi-day/multi-month Pro/Enterprise ranges).
        recent_alerts = store.get_alerts(limit=100000, offset=0, since=since)

        # Group alerts by hour for timeline
        timeline = {}
        now = datetime.utcnow()
        for i in range(hours):
            hour = now - timedelta(hours=i)
            hour_key = hour.strftime('%Y-%m-%d %H:00')
            timeline[hour_key] = 0

        for alert in recent_alerts:
            if alert.timestamp:
                hour_key = alert.timestamp.strftime('%Y-%m-%d %H:00')
                if hour_key in timeline:
                    timeline[hour_key] += 1

        packet_counts = get_hourly_counts()

        # Format timeline for frontend
        timeline_data = [
            {'time': k, 'threats_detected': v, 'total_packets': packet_counts.get(k, 0)}
            for k, v in sorted(timeline.items())
        ]
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timeline': timeline_data,
            'recent_alerts_count': len(recent_alerts),
            'hours_included': hours,
            'max_hours_for_tier': max_hours,
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

@bp.route('/rule_performance', methods=['GET'])
def get_rule_performance():
    """
    Per-rule performance: how many times each rule has fired, when it
    last fired, and average confidence - merged with the rule's own
    metadata (name, severity, threshold). Alert data lives in alerts.db;
    rule metadata lives in app.db - two separate SQLite files, so this
    queries each and merges by rule_id/code in Python rather than a
    cross-database SQL join, which SQLite doesn't support directly.
    """
    try:
        from alert_management import AlertStore
        from rules.models import get_rules_session, Rule

        store = AlertStore()
        performance = store.get_rule_performance()
        perf_by_id = {p['rule_id']: p for p in performance}

        session = get_rules_session()
        try:
            rules = session.query(Rule).all()
            results = []
            for rule in rules:
                perf = perf_by_id.get(rule.code, {})
                results.append({
                    'rule_id': rule.code,
                    'name': rule.name,
                    'attack_type': rule.attack_type,
                    'severity': rule.severity,
                    'threshold': rule.threshold,
                    'window_seconds': rule.window_seconds,
                    'is_builtin': rule.is_builtin,
                    'enabled': rule.enabled,
                    'fire_count': perf.get('fire_count', 0),
                    'total_occurrences': perf.get('total_occurrences', 0),
                    'last_fired': perf.get('last_fired'),
                    'avg_confidence': perf.get('avg_confidence'),
                })
            # Rules with no matching DB row (e.g. custom AST rules identified
            # by numeric id, not a "RULE-XXX" code) still show up via their
            # own alert history even without rule metadata.
            known_ids = {r.code for r in rules if r.code}
            for rule_id, perf in perf_by_id.items():
                if rule_id not in known_ids:
                    results.append({
                        'rule_id': rule_id, 'name': rule_id, 'attack_type': None,
                        'severity': None, 'threshold': None, 'window_seconds': None,
                        'is_builtin': False, 'enabled': None,
                        'fire_count': perf.get('fire_count', 0),
                        'total_occurrences': perf.get('total_occurrences', 0),
                        'last_fired': perf.get('last_fired'),
                        'avg_confidence': perf.get('avg_confidence'),
                    })

            results.sort(key=lambda r: r['fire_count'], reverse=True)
            return jsonify({'success': True, 'rules': results})
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting rule performance: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
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