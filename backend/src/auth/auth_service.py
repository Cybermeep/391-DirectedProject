"""
Authentication and account service.

Handles registration, local login, Google sign-in, JWT issuance/verification,
and (dummy) tier upgrades. All password handling goes through Werkzeug's
PBKDF2-based helpers (already a Flask dependency, so no extra crypto
library is required for this part).
"""

import re
import hashlib
import logging
from datetime import datetime, timedelta

import jwt
from werkzeug.security import generate_password_hash, check_password_hash

from appconfig import JWT_SECRET, JWT_EXPIRY_HOURS, GOOGLE_CLIENT_ID, TIER_LIMITS
from .models import User, RefreshToken, BillingRecord, get_auth_session

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    """Raised for any expected auth failure (bad credentials, taken email, etc.)."""

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise AuthError("Invalid email address")
    return email


def validate_password(password: str) -> None:
    if not password or len(password) < 8:
        raise AuthError("Password must be at least 8 characters")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        raise AuthError("Password must contain both letters and numbers")


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not re.match(r"^[A-Za-z0-9_\-]{3,32}$", username):
        raise AuthError("Username must be 3-32 characters (letters, numbers, _ or -)")
    return username


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------

def generate_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        "tier": user.tier,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def issue_refresh_token(session, user: User) -> str:
    import secrets as _secrets

    raw = _secrets.token_urlsafe(48)
    record = RefreshToken(
        user_id=user.id,
        token_hash=_hash_refresh_token(raw),
        expires_at=datetime.utcnow() + timedelta(days=30),
    )
    session.add(record)
    session.commit()
    return raw


def revoke_refresh_token(session, raw_token: str) -> bool:
    token_hash = _hash_refresh_token(raw_token)
    record = session.query(RefreshToken).filter_by(token_hash=token_hash, revoked=False).first()
    if record:
        record.revoked = True
        session.commit()
        return True
    return False


# --------------------------------------------------------------------------
# Registration / local login
# --------------------------------------------------------------------------

def register_user(username: str, email: str, password: str) -> User:
    session = get_auth_session()
    try:
        email = validate_email(email)
        username = validate_username(username)
        validate_password(password)

        if session.query(User).filter_by(email=email).first():
            raise AuthError("An account with this email already exists", 409)
        if session.query(User).filter_by(username=username).first():
            raise AuthError("Username already taken", 409)

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            auth_provider="local",
            tier="free",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        logger.info(f"New user registered: {username} ({email})")
        return user
    finally:
        session.close()


def login_local(email_or_username: str, password: str) -> User:
    session = get_auth_session()
    try:
        identifier = (email_or_username or "").strip().lower()
        user = (
            session.query(User)
            .filter((User.email == identifier) | (User.username == identifier))
            .first()
        )

        if not user or not user.password_hash:
            raise AuthError("Invalid credentials", 401)
        if not check_password_hash(user.password_hash, password):
            raise AuthError("Invalid credentials", 401)
        if not user.is_active:
            raise AuthError("This account has been disabled", 403)

        user.last_login = datetime.utcnow()
        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


# --------------------------------------------------------------------------
# Google sign-in
# --------------------------------------------------------------------------

def login_or_create_google_user(id_token_str: str) -> User:
    """
    Verify a Google ID token (sent from the frontend after Google Identity
    Services sign-in) and find-or-create the matching local account, linked
    by email.
    """
    if not GOOGLE_CLIENT_ID:
        raise AuthError(
            "Google sign-in is not configured on this server (missing GOOGLE_CLIENT_ID)", 500
        )

    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests
    except ImportError:
        raise AuthError(
            "Google sign-in requires the 'google-auth' package on the backend", 500
        )

    try:
        info = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError as e:
        raise AuthError(f"Invalid Google token: {e}", 401)

    if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise AuthError("Invalid token issuer", 401)

    email = (info.get("email") or "").strip().lower()
    if not email:
        raise AuthError("Google account has no email", 400)
    if not info.get("email_verified", False):
        raise AuthError("Google email is not verified", 400)

    google_id = info["sub"]

    session = get_auth_session()
    try:
        user = session.query(User).filter_by(google_id=google_id).first()
        if not user:
            # Link to an existing local account with the same email, if any.
            user = session.query(User).filter_by(email=email).first()

        if user:
            user.google_id = google_id
            if user.auth_provider == "local" and not user.password_hash:
                user.auth_provider = "google"
            user.last_login = datetime.utcnow()
        else:
            base_username = email.split("@")[0]
            username = base_username
            suffix = 1
            while session.query(User).filter_by(username=username).first():
                suffix += 1
                username = f"{base_username}{suffix}"

            user = User(
                username=username,
                email=email,
                password_hash=None,
                auth_provider="google",
                google_id=google_id,
                tier="free",
                last_login=datetime.utcnow(),
            )
            session.add(user)

        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


# --------------------------------------------------------------------------
# Tier / billing (dummy payment - no real card data ever leaves the client
# in a usable form; only a masked summary is persisted)
# --------------------------------------------------------------------------

CARD_BRAND_PATTERNS = [
    ("Visa", re.compile(r"^4")),
    ("Mastercard", re.compile(r"^(5[1-5]|2[2-7])")),
    ("Amex", re.compile(r"^3[47]")),
    ("Discover", re.compile(r"^6(?:011|5)")),
]


def _luhn_valid(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_card_brand(card_number: str) -> str:
    digits = re.sub(r"\D", "", card_number)
    for brand, pattern in CARD_BRAND_PATTERNS:
        if pattern.match(digits):
            return brand
    return "Unknown"


def validate_dummy_card(card_number: str, exp_month: int, exp_year: int, cvc: str) -> dict:
    """
    Client-facing "does this look like a valid card" check. NOTHING here
    talks to a real payment processor - it's format/Luhn validation only,
    purely so the upgrade flow feels real for a school-project demo.
    """
    digits = re.sub(r"\D", "", card_number or "")
    if not _luhn_valid(digits):
        raise AuthError("Card number failed validation", 422)

    now = datetime.utcnow()
    if not (1 <= exp_month <= 12):
        raise AuthError("Invalid expiration month", 422)
    exp_check = datetime(exp_year, exp_month, 1) + timedelta(days=31)
    if exp_check < now:
        raise AuthError("Card has expired", 422)

    if not re.match(r"^\d{3,4}$", str(cvc or "")):
        raise AuthError("Invalid CVC", 422)

    return {
        "brand": detect_card_brand(digits),
        "last4": digits[-4:],
    }


TIER_PRICING_CENTS = {"pro": 999, "enterprise": 2999}


def upgrade_tier(user_id: int, tier: str, card_number: str, exp_month: int, exp_year: int, cvc: str) -> User:
    if tier not in ("pro", "enterprise"):
        raise AuthError("Invalid tier", 400)

    card_info = validate_dummy_card(card_number, exp_month, exp_year, cvc)

    session = get_auth_session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            raise AuthError("User not found", 404)

        user.tier = tier
        user.tier_expires_at = datetime.utcnow() + timedelta(days=30)

        record = BillingRecord(
            user_id=user.id,
            tier=tier,
            card_brand=card_info["brand"],
            card_last4=card_info["last4"],
            amount_cents=TIER_PRICING_CENTS[tier],
        )
        session.add(record)
        session.commit()
        session.refresh(user)
        logger.info(f"User {user.username} upgraded to {tier}")
        return user
    finally:
        session.close()


def downgrade_tier(user_id: int) -> User:
    """Revert a user to the free tier. No payment step - this is always free and immediate."""
    session = get_auth_session()
    try:
        user = session.query(User).get(user_id)
        if not user:
            raise AuthError("User not found", 404)
        user.tier = "free"
        user.tier_expires_at = None
        session.commit()
        session.refresh(user)
        logger.info(f"User {user.username} downgraded to free")
        return user
    finally:
        session.close()


def get_user_by_id(user_id: int):
    session = get_auth_session()
    try:
        return session.query(User).get(user_id)
    finally:
        session.close()


def feature_enabled(tier: str, feature: str) -> bool:
    return bool(TIER_LIMITS.get(tier, TIER_LIMITS["free"]).get(feature, False))
