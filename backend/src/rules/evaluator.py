"""
Evaluates a parsed rule AST against a feature dict (the same 78-feature
vector produced by feature_extraction and consumed by the ML model).
"""

import operator as _op
import logging
from typing import Dict, Any

from .ast_nodes import ComparisonNode, AndNode, OrNode, NotNode, RuleSyntaxError

logger = logging.getLogger(__name__)

_OPS = {
    ">": _op.gt,
    "<": _op.lt,
    ">=": _op.ge,
    "<=": _op.le,
    "==": _op.eq,
    "!=": _op.ne,
}


def evaluate_rule(node, features: Dict[str, Any]) -> bool:
    """
    Evaluate an AST node against a feature dict.

    Missing features evaluate the containing comparison to False rather
    than raising, so one malformed/missing field can't take down the whole
    rule engine for a live packet flow - it just means that particular
    rule doesn't fire.
    """
    if isinstance(node, ComparisonNode):
        if node.field_name not in features:
            logger.debug(f"Rule evaluation: feature '{node.field_name}' missing from input, treating as no-match")
            return False
        try:
            actual_value = float(features[node.field_name])
        except (TypeError, ValueError):
            return False
        return _OPS[node.operator](actual_value, node.value)

    elif isinstance(node, AndNode):
        return evaluate_rule(node.left, features) and evaluate_rule(node.right, features)

    elif isinstance(node, OrNode):
        return evaluate_rule(node.left, features) or evaluate_rule(node.right, features)

    elif isinstance(node, NotNode):
        return not evaluate_rule(node.operand, features)

    else:
        raise RuleSyntaxError(f"Cannot evaluate unknown node type: {type(node)}")


class RuleEngine:
    """
    Holds a set of loaded (enabled) rules and evaluates all of them against
    a feature vector, in parallel with - not instead of - the ML pipeline.

    Flow -> Features -> [ML model] + [RuleEngine.evaluate_all] -> Alerts
    """

    def __init__(self):
        self._compiled_rules = []  # list of (rule_id, name, severity, ast_root)

    def load_rules(self, rule_rows):
        """
        rule_rows: iterable of objects/dicts with id, name, severity, and a
        parsed AST root (already validated via ast_nodes.node_from_dict).
        """
        self._compiled_rules = list(rule_rows)
        logger.info(f"RuleEngine loaded {len(self._compiled_rules)} enabled rule(s)")

    def evaluate_all(self, features: Dict[str, Any]):
        """Return a list of {rule_id, name, severity} for every rule that matched."""
        matches = []
        for rule_id, name, severity, ast_root in self._compiled_rules:
            try:
                if evaluate_rule(ast_root, features):
                    matches.append({"rule_id": rule_id, "name": name, "severity": severity})
            except Exception:
                logger.exception(f"Error evaluating rule {rule_id}, skipping")
        return matches
