"""
Auth routes for the NIDS API: register, login, logout, current user,
Google sign-in, and tier upgrade (dummy billing).
"""

import logging
from flask import Blueprint, request, jsonify

from auth.auth_service import (
    AuthError,
    register_user,
    login_local,
    login_or_create_google_user,
    generate_token,
    issue_refresh_token,
    revoke_refresh_token,
    upgrade_tier,
    downgrade_tier,
    get_user_by_id,
)
from auth.models import get_auth_session
from api.middleware.auth import token_required

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__)


def _auth_success_response(user, status_code=200):
    session = get_auth_session()
    try:
        access_token = generate_token(user)
        refresh_token = issue_refresh_token(session, user)
    finally:
        session.close()

    return jsonify({
        "success": True,
        "token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict(),
    }), status_code


@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    try:
        user = register_user(
            username=data.get("username", ""),
            email=data.get("email", ""),
            password=data.get("password", ""),
        )
        return _auth_success_response(user, 201)
    except AuthError as e:
        return jsonify({"success": False, "error": e.message}), e.status_code
    except Exception as e:
        logger.exception("Registration failed")
        return jsonify({"success": False, "error": "Registration failed"}), 500


@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    identifier = data.get("email") or data.get("username", "")
    password = data.get("password", "")

    if not identifier or not password:
        return jsonify({"success": False, "error": "Email/username and password are required"}), 400

    try:
        user = login_local(identifier, password)
        return _auth_success_response(user)
    except AuthError as e:
        return jsonify({"success": False, "error": e.message}), e.status_code
    except Exception:
        logger.exception("Login failed")
        return jsonify({"success": False, "error": "Login failed"}), 500


@bp.route("/google", methods=["POST"])
def google_login():
    data = request.get_json(silent=True) or {}
    id_token_str = data.get("id_token") or data.get("credential")

    if not id_token_str:
        return jsonify({"success": False, "error": "id_token is required"}), 400

    try:
        user = login_or_create_google_user(id_token_str)
        return _auth_success_response(user)
    except AuthError as e:
        return jsonify({"success": False, "error": e.message}), e.status_code
    except Exception:
        logger.exception("Google login failed")
        return jsonify({"success": False, "error": "Google login failed"}), 500


@bp.route("/logout", methods=["POST"])
@token_required
def logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token")

    if refresh_token:
        session = get_auth_session()
        try:
            revoke_refresh_token(session, refresh_token)
        finally:
            session.close()

    # Access tokens are short-lived JWTs and are not individually revocable
    # server-side; the client is responsible for discarding it. Revoking the
    # refresh token above prevents it from being used to mint a new one.
    return jsonify({"success": True, "message": "Logged out"})


@bp.route("/me", methods=["GET"])
@token_required
def me():
    user = get_user_by_id(request.user["sub"])
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404
    return jsonify({"success": True, "user": user.to_dict()})


@bp.route("/upgrade", methods=["POST"])
@token_required
def upgrade():

    data = request.get_json(silent=True) or {}

    try:
        user = upgrade_tier(
            user_id=request.user["sub"],
            tier=data.get("tier", ""),
            card_number=data.get("card_number", ""),
            exp_month=int(data.get("exp_month", 0) or 0),
            exp_year=int(data.get("exp_year", 0) or 0),
            cvc=data.get("cvc", ""),
        )
        new_token = generate_token(user)
        return jsonify({"success": True, "user": user.to_dict(), "token": new_token})
    except AuthError as e:
        return jsonify({"success": False, "error": e.message}), e.status_code
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid card details"}), 422
    except Exception:
        logger.exception("Upgrade failed")
        return jsonify({"success": False, "error": "Upgrade failed"}), 500


@bp.route("/downgrade", methods=["POST"])
@token_required
def downgrade():
    """Revert the current user to the free tier - immediate, no payment step."""
    try:
        user = downgrade_tier(request.user["sub"])
        new_token = generate_token(user)
        return jsonify({"success": True, "user": user.to_dict(), "token": new_token})
    except AuthError as e:
        return jsonify({"success": False, "error": e.message}), e.status_code
    except Exception:
        logger.exception("Downgrade failed")
        return jsonify({"success": False, "error": "Downgrade failed"}), 500
