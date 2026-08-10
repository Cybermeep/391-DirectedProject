"""
Database model for user-generated rule/signatures
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from auth.models import Base, get_auth_session  # share the same Base/engine as User


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True)
    # User-created custom rules always set this.
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    code = Column(String(20), nullable=True, index=True)  # display id, e.g. "RULE-001"
    name = Column(String(120), nullable=False)
    description = Column(Text)
    attack_type = Column(String(60), nullable=True)  # e.g. "DoS-SYN-Flood"
    rule_text = Column(Text, nullable=False)   # the AST expression actually evaluated
    ast = Column(JSON, nullable=False)          # validated AST, as produced by ast_nodes
    severity = Column(String(20), default="medium")
    threshold = Column(Integer, nullable=True)       
    window_seconds = Column(Integer, nullable=True)  
    is_builtin = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User")

    def to_dict(self):
        return {
            "id": self.id,
            "code": self.code,
            "user_id": self.user_id,
            "name": self.name,
            "description": self.description,
            "attack_type": self.attack_type,
            "rule_text": self.rule_text,
            "ast": self.ast,
            "severity": self.severity,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "is_builtin": self.is_builtin,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


def get_rules_session():
    """Rules live in the same DB as users - reuse the auth session factory."""
    return get_auth_session()


def seed_builtin_signatures() -> None:
  
    external_rules = _get_external_default_rules()
    if external_rules:
        _seed_from_external(external_rules)
    else:
        _seed_from_builtin_rate_signatures()


def _get_external_default_rules():
    try:
        from core import external_rule_engine
        if not external_rule_engine.is_active():
            return None
        from rule_engine.rules import default_rules
        return default_rules()
    except Exception:
        return None


def _seed_from_external(external_rules) -> None:
    session = get_rules_session()
    try:
        existing_codes = {r.code for r in session.query(Rule).filter_by(is_builtin=True).all()}
        for r in external_rules:
            if r.rule_id in existing_codes:
                continue
            session.add(Rule(
                user_id=None,
                code=r.rule_id,
                name=r.name,
                description=getattr(r, "description", ""),
                attack_type=r.attack_type,
                rule_text=f"external rule_engine: {r.threshold} events / {r.time_window}s from one source",
                ast={"type": "builtin", "code": r.rule_id, "source": "rule_engine"},
                severity=r.severity,
                threshold=r.threshold,
                window_seconds=int(r.time_window),
                is_builtin=True,
                enabled=getattr(r, "enabled", True),
            ))
        session.commit()
    finally:
        session.close()


def _seed_from_builtin_rate_signatures() -> None:
    from rules.rate_signatures import BUILTIN_SIGNATURES

    session = get_rules_session()
    try:
        existing_codes = {r.code for r in session.query(Rule).filter_by(is_builtin=True).all()}
        for sig in BUILTIN_SIGNATURES:
            if sig.code in existing_codes:
                continue
            session.add(Rule(
                user_id=None,
                code=sig.code,
                name=sig.name,
                description=sig.description,
                attack_type=sig.attack_type,
                rule_text=f"built-in: {sig.threshold} events / {sig.window_seconds}s from one source",
                ast={"type": "builtin", "code": sig.code},
                severity=sig.severity,
                threshold=sig.threshold,
                window_seconds=sig.window_seconds,
                is_builtin=True,
                enabled=True,
            ))
        session.commit()
    finally:
        session.close()


def get_enabled_builtin_codes():
    session = get_rules_session()
    try:
        return [r.code for r in session.query(Rule).filter_by(is_builtin=True, enabled=True).all()]
    finally:
        session.close()
