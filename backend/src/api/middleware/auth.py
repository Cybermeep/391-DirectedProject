"""
Authentication middleware for the NIDS API.

This module provides request decorators for JWT-based authentication and
tier-based feature gating
"""

from functools import wraps
from flask import request, jsonify

from auth.auth_service import verify_token, feature_enabled


def token_required(f):
    """Decorator to require a valid JWT for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"success": False, "error": "Token is required"}), 401

        if token.startswith("Bearer "):
            token = token[7:]

        payload = verify_token(token)
        if not payload:
            return jsonify({"success": False, "error": "Invalid or expired token"}), 401

        request.user = payload  # {'sub', 'username', 'email', 'tier', ...}
        return f(*args, **kwargs)

    return decorated


def optional_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        request.user = None
        if token:
            if token.startswith("Bearer "):
                token = token[7:]
            payload = verify_token(token)
            if payload:
                request.user = payload
        return f(*args, **kwargs)

    return decorated


def tier_required(feature: str):
   
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(request, "user", None)
            if not user:
                return jsonify({"success": False, "error": "Authentication required"}), 401

            if not feature_enabled(user.get("tier", "free"), feature):
                return jsonify({
                    "success": False,
                    "error": f"This feature requires a plan upgrade",
                    "upgrade_required": True,
                    "current_tier": user.get("tier", "free"),
                }), 402

            return f(*args, **kwargs)
        return decorated
    return wrapper
