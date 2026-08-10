"""
Unit tests for the rule/signature engine (rules.parser, rules.evaluator)

Run with:
    cd backend && python -m unittest test_rules_engine.py -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rules.parser import parse_rule, rule_to_string
from rules.ast_nodes import RuleSyntaxError, node_from_dict, ComparisonNode
from rules.evaluator import evaluate_rule


class TestRuleParser(unittest.TestCase):
    def test_simple_comparison(self):
        node = parse_rule("SYN_Flag_Cnt > 5")
        self.assertIsInstance(node, ComparisonNode)
        self.assertEqual(node.field_name, "SYN_Flag_Cnt")
        self.assertEqual(node.operator, ">")
        self.assertEqual(node.value, 5.0)

    def test_and_or_precedence(self):
        # AND should bind tighter than OR: a OR b AND c == a OR (b AND c)
        node = parse_rule("Dst_Port == 80 OR SYN_Flag_Cnt > 1 AND RST_Flag_Cnt > 1")
        self.assertEqual(node.to_dict()["type"], "OR")
        self.assertEqual(node.to_dict()["right"]["type"], "AND")

    def test_parentheses_override_precedence(self):
        node = parse_rule("(Dst_Port == 80 OR SYN_Flag_Cnt > 1) AND RST_Flag_Cnt > 1")
        self.assertEqual(node.to_dict()["type"], "AND")
        self.assertEqual(node.to_dict()["left"]["type"], "OR")

    def test_not_operator(self):
        node = parse_rule("NOT SYN_Flag_Cnt > 5")
        self.assertEqual(node.to_dict()["type"], "not")

    def test_field_with_slash(self):
        node = parse_rule("Flow_Byts/s > 1000")
        self.assertEqual(node.field_name, "Flow_Byts/s")

    def test_unknown_field_rejected(self):
        with self.assertRaises(RuleSyntaxError):
            parse_rule("Made_Up_Field > 5")

    def test_typo_case_rejected(self):
        # Field names are case-sensitive against the whitelist on purpose.
        with self.assertRaises(RuleSyntaxError):
            parse_rule("syn_flag_cnt > 5")

    def test_non_numeric_value_rejected(self):
        with self.assertRaises(RuleSyntaxError):
            parse_rule("Protocol == TCP")

    def test_empty_rule_rejected(self):
        with self.assertRaises(RuleSyntaxError):
            parse_rule("")

    def test_unbalanced_parens_rejected(self):
        with self.assertRaises(RuleSyntaxError):
            parse_rule("(SYN_Flag_Cnt > 5")

    def test_garbage_input_rejected(self):
        with self.assertRaises(RuleSyntaxError):
            parse_rule("SYN_Flag_Cnt > 5; DROP TABLE users;")

    def test_round_trip_to_string(self):
        original = "SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3"
        node = parse_rule(original)
        rendered = rule_to_string(node)
        # Re-parsing the rendered form should produce an equivalent AST.
        reparsed = parse_rule(rendered)
        self.assertEqual(node.to_dict(), reparsed.to_dict())

    def test_ast_json_round_trip(self):
        node = parse_rule("SYN_Flag_Cnt > 5 AND (RST_Flag_Cnt > 3 OR Flow_Byts/s > 1000)")
        rebuilt = node_from_dict(node.to_dict())
        self.assertEqual(node.to_dict(), rebuilt.to_dict())

    def test_node_from_dict_rejects_unknown_field(self):
        with self.assertRaises(RuleSyntaxError):
            node_from_dict({"type": "comparison", "field": "not_real", "operator": ">", "value": 1})


class TestRuleEvaluator(unittest.TestCase):
    def setUp(self):
        self.features = {
            "SYN_Flag_Cnt": 10,
            "RST_Flag_Cnt": 1,
            "Flow_Byts/s": 5000,
            "Dst_Port": 80,
        }

    def test_and_match(self):
        node = parse_rule("SYN_Flag_Cnt > 5 AND Flow_Byts/s > 1000")
        self.assertTrue(evaluate_rule(node, self.features))

    def test_and_no_match(self):
        node = parse_rule("SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 5")
        self.assertFalse(evaluate_rule(node, self.features))

    def test_or_match(self):
        node = parse_rule("RST_Flag_Cnt > 5 OR SYN_Flag_Cnt > 5")
        self.assertTrue(evaluate_rule(node, self.features))

    def test_not_match(self):
        node = parse_rule("NOT RST_Flag_Cnt > 5")
        self.assertTrue(evaluate_rule(node, self.features))

    def test_missing_feature_is_false_not_error(self):
        node = parse_rule("Idle_Mean > 5")
        self.assertFalse(evaluate_rule(node, self.features))

    def test_example_syn_flood_rule(self):
        # The exact example rule shown in the frontend's rule-builder help text.
        node = parse_rule("SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3 AND Flow_Byts/s > 1000")
        self.assertFalse(evaluate_rule(node, self.features))  # RST_Flag_Cnt is only 1 here
        self.features["RST_Flag_Cnt"] = 4
        self.assertTrue(evaluate_rule(node, self.features))


if __name__ == "__main__":
    unittest.main()
