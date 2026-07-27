"""
Database models for user accounts, sessions, and subscription tier.

Uses the same SQLAlchemy declarative style as alert_management.models so
the codebase stays consistent. Lives in its own database (app.db) so the
alerts DB schema is never coupled to account data.
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

from appconfig import APP_DB_URI

Base = declarative_base()


class User(Base):
    """A user account. Supports local (email/password) and Google sign-in."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)

    # Nullable because Google-only accounts never set a local password.
    password_hash = Column(String(255), nullable=True)

    # 'local' | 'google'. A user can still hold both a password_hash and a
    # google_id if they linked both methods to the same email.
    auth_provider = Column(String(20), nullable=False, default="local")
    google_id = Column(String(255), unique=True, nullable=True, index=True)

    tier = Column(String(20), nullable=False, default="free")  # free | pro | enterprise
    tier_expires_at = Column(DateTime, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "auth_provider": self.auth_provider,
            "tier": self.tier,
            "tier_expires_at": self.tier_expires_at.isoformat() if self.tier_expires_at else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "has_password": bool(self.password_hash),
            "google_linked": bool(self.google_id),
        }


class RefreshToken(Base):
    """
    Long-lived refresh tokens, tracked server-side so logout / logout-all
    can actually revoke a session instead of just deleting the client copy.
    """

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)

    user = relationship("User")


class BillingRecord(Base):
    """
    Dummy billing history. No real payment data is ever stored - only a
    masked card summary (last 4 digits + brand) purely for display, so the
    'upgrade' screen has something to show under Billing History.
    """

    __tablename__ = "billing_records"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tier = Column(String(20), nullable=False)
    card_brand = Column(String(20))
    card_last4 = Column(String(4))
    amount_cents = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


_engine = None
_SessionLocal = None


def init_auth_database():
    """Create tables if they don't exist yet. Safe to call repeatedly."""
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(APP_DB_URI, echo=False, connect_args={"check_same_thread": False})
        Base.metadata.create_all(_engine)
        _SessionLocal = sessionmaker(bind=_engine)
    return _engine


def get_auth_session():
    """Get a new SQLAlchemy session against app.db."""
    init_auth_database()
    return _SessionLocal()
