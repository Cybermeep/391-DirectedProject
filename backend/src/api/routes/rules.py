"""
Rule/signature routes for the NIDS API.

Lets a user write a rule in the mini rule-language (see rules.parser),
validates it into an AST server-side (never trusting client-parsed ASTs),
and stores it for the rule engine to run alongside the ML pipeline.

Custom rules are an enterprise-tier feature (see appconfig.TIER_LIMITS).
"""

import logging
from flask import Blueprint, request, jsonify

from flask import current_app
from rules.parser import parse_rule, rule_to_string
from rules.ast_nodes import RuleSyntaxError, FEATURE_FIELDS
from rules.models import Rule, get_rules_session
from api.middleware.auth import token_required, tier_required, feature_enabled

logger = logging.getLogger(__name__)

bp = Blueprint("rules", __name__)


@bp.route("/fields", methods=["GET"])
@token_required
def list_fields():
    """Return the whitelisted feature names a rule can reference (for building a UI picker)."""
    return jsonify({"success": True, "fields": FEATURE_FIELDS})


@bp.route("/validate", methods=["POST"])
@token_required
def validate_rule():
    """Parse + validate a rule string without saving it. Used for live-typing feedback in the UI."""
    data = request.get_json(silent=True) or {}
    rule_text = data.get("rule_text", "")

    try:
        ast_root = parse_rule(rule_text)
        return jsonify({
            "success": True,
            "valid": True,
            "ast": ast_root.to_dict(),
            "normalized": rule_to_string(ast_root),
        })
    except RuleSyntaxError as e:
        return jsonify({"success": True, "valid": False, "error": str(e)})


@bp.route("/", methods=["GET"])
@token_required
def list_rules():
    session = get_rules_session()
    try:
        rules = (
            session.query(Rule)
            .filter((Rule.is_builtin == True) | (Rule.user_id == request.user["sub"]))  # noqa: E712
            .order_by(Rule.is_builtin.desc(), Rule.code, Rule.created_at.desc())
            .all()
        )
        return jsonify({"success": True, "count": len(rules), "rules": [r.to_dict() for r in rules]})
    finally:
        session.close()


@bp.route("/", methods=["POST"])
@token_required
@tier_required("custom_rules")
def create_rule():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    rule_text = data.get("rule_text", "")
    severity = data.get("severity", "medium")

    if not name:
        return jsonify({"success": False, "error": "Rule name is required"}), 400
    if severity not in ("low", "medium", "high", "critical"):
        return jsonify({"success": False, "error": "Invalid severity"}), 400

    try:
        ast_root = parse_rule(rule_text)
    except RuleSyntaxError as e:
        return jsonify({"success": False, "error": f"Invalid rule: {e}"}), 422

    session = get_rules_session()
    try:
        rule = Rule(
            user_id=request.user["sub"],
            name=name,
            description=data.get("description", ""),
            rule_text=rule_text,
            ast=ast_root.to_dict(),
            severity=severity,
            enabled=bool(data.get("enabled", True)),
        )
        session.add(rule)
        session.commit()
        session.refresh(rule)

        _refresh_rule_engine()
        return jsonify({"success": True, "rule": rule.to_dict()}), 201
    finally:
        session.close()


@bp.route("/<int:rule_id>", methods=["PUT"])
@token_required
def update_rule(rule_id):
    data = request.get_json(silent=True) or {}
    session = get_rules_session()
    try:
        rule = session.query(Rule).filter_by(id=rule_id).first()
        if not rule:
            return jsonify({"success": False, "error": "Rule not found"}), 404

        if rule.is_builtin:
            # Anyone can flip a built-in signature on/off - it's a global,
            # pre-validated detection, not something a free-tier restriction
            # makes sense for. Nothing else about a built-in row is editable.
            disallowed = set(data.keys()) - {"enabled"}
            if disallowed:
                return jsonify({
                    "success": False,
                    "error": f"Built-in signatures only support toggling 'enabled' (not {', '.join(disallowed)})",
                }), 403
            if "enabled" in data:
                rule.enabled = bool(data["enabled"])
        else:
            if rule.user_id != request.user["sub"]:
                return jsonify({"success": False, "error": "Rule not found"}), 404
            if not feature_enabled(request.user.get("tier", "free"), "custom_rules"):
                return jsonify({
                    "success": False,
                    "error": "Editing custom rules requires a plan upgrade",
                    "upgrade_required": True,
                    "current_tier": request.user.get("tier", "free"),
                }), 402

            if "rule_text" in data:
                try:
                    ast_root = parse_rule(data["rule_text"])
                except RuleSyntaxError as e:
                    return jsonify({"success": False, "error": f"Invalid rule: {e}"}), 422
                rule.rule_text = data["rule_text"]
                rule.ast = ast_root.to_dict()

            if "name" in data:
                rule.name = data["name"].strip()
            if "description" in data:
                rule.description = data["description"]
            if "severity" in data:
                if data["severity"] not in ("low", "medium", "high", "critical"):
                    return jsonify({"success": False, "error": "Invalid severity"}), 400
                rule.severity = data["severity"]
            if "enabled" in data:
                rule.enabled = bool(data["enabled"])

        session.commit()
        session.refresh(rule)
        _refresh_rule_engine()
        return jsonify({"success": True, "rule": rule.to_dict()})
    finally:
        session.close()


@bp.route("/<int:rule_id>", methods=["DELETE"])
@token_required
@tier_required("custom_rules")
def delete_rule(rule_id):
    session = get_rules_session()
    try:
        rule = session.query(Rule).filter_by(id=rule_id).first()
        if not rule:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        if rule.is_builtin:
            return jsonify({"success": False, "error": "Built-in signatures can't be deleted, only disabled"}), 403
        if rule.user_id != request.user["sub"]:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        session.delete(rule)
        session.commit()
        _refresh_rule_engine()
        return jsonify({"success": True, "message": "Rule deleted"})
    finally:
        session.close()


def _refresh_rule_engine():
    """Reload the in-process RuleEngine's compiled rule set (AST rules) and the active capture pipeline's built-in signature set (rate rules), after any CUD operation."""
    try:
        from rules.ast_nodes import node_from_dict

        session = get_rules_session()
        try:
            engine = current_app.config.get("RULE_ENGINE")
            if engine is not None:
                enabled_rules = session.query(Rule).filter_by(enabled=True, is_builtin=False).all()
                compiled = [
                    (r.id, r.name, r.severity, node_from_dict(r.ast))
                    for r in enabled_rules
                ]
                engine.load_rules(compiled)

            pipeline = current_app.config.get("DETECTION_PIPELINE")
            if pipeline is not None:
                enabled_codes = [r.code for r in session.query(Rule).filter_by(enabled=True, is_builtin=True).all()]
                pipeline.load_enabled_builtin_signatures(enabled_codes)

            from core import external_rule_engine
            if external_rule_engine.is_active():
                external_engine = external_rule_engine.get_engine()
                for r in session.query(Rule).filter_by(is_builtin=True).all():
                    if r.enabled:
                        external_engine.enable_rule(r.code)
                    else:
                        external_engine.disable_rule(r.code)
        finally:
            session.close()
    except Exception:
        logger.exception("Failed to refresh rule engine")
