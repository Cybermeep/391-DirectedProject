"""
Recursive-descent parser for the user-facing rule/signature language.

"""

import re
from typing import List, Tuple

from .ast_nodes import (
    ComparisonNode, AndNode, OrNode, NotNode,
    FEATURE_FIELDS_SET, VALID_OPERATORS, RuleSyntaxError,
)

TOKEN_SPEC = [
    ("WS", r"\s+"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("OP", r">=|<=|==|!=|>|<"),
    ("NUMBER", r"-?\d+(?:\.\d+)?"),
    ("AND", r"(?i:\bAND\b)"),
    ("OR", r"(?i:\bOR\b)"),
    ("NOT", r"(?i:\bNOT\b)"),
    # Field/identifier: starts with a letter/underscore, may contain
    # letters, digits, underscore, and '/' (e.g. Flow_Byts/s, Down/Up_Ratio).
    ("IDENT", r"[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z0-9_]+)*"),
]
MASTER_RE = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPEC))

MAX_RULE_LENGTH = 2000
MAX_AST_DEPTH = 25


def tokenize(text: str) -> List[Tuple[str, str]]:
    if len(text) > MAX_RULE_LENGTH:
        raise RuleSyntaxError(f"Rule text exceeds maximum length of {MAX_RULE_LENGTH} characters")

    tokens = []
    pos = 0
    while pos < len(text):
        match = MASTER_RE.match(text, pos)
        if not match:
            raise RuleSyntaxError(f"Unexpected character at position {pos}: '{text[pos]}'")
        kind = match.lastgroup
        value = match.group()
        if kind != "WS":
            tokens.append((kind, value))
        pos = match.end()
    return tokens


class _Parser:
    """Simple recursive-descent parser operating over a flat token list"""

    def __init__(self, tokens: List[Tuple[str, str]]):
        self.tokens = tokens
        self.i = 0

    def _peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def _advance(self):
        tok = self._peek()
        self.i += 1
        return tok

    def _expect(self, kind):
        tok = self._peek()
        if tok[0] != kind:
            raise RuleSyntaxError(f"Expected {kind} but found '{tok[1] if tok[1] else 'end of input'}'")
        return self._advance()

    def parse(self):
        if not self.tokens:
            raise RuleSyntaxError("Rule cannot be empty")
        node = self._or_expr(depth=0)
        if self.i != len(self.tokens):
            leftover = self._peek()[1]
            raise RuleSyntaxError(f"Unexpected trailing input near '{leftover}'")
        return node

    def _or_expr(self, depth):
        node = self._and_expr(depth + 1)
        while self._peek()[0] == "OR":
            self._advance()
            right = self._and_expr(depth + 1)
            node = OrNode(node, right)
        return node

    def _and_expr(self, depth):
        node = self._unary(depth + 1)
        while self._peek()[0] == "AND":
            self._advance()
            right = self._unary(depth + 1)
            node = AndNode(node, right)
        return node

    def _unary(self, depth):
        if depth > MAX_AST_DEPTH:
            raise RuleSyntaxError("Rule is too deeply nested")

        if self._peek()[0] == "NOT":
            self._advance()
            return NotNode(self._unary(depth + 1))

        if self._peek()[0] == "LPAREN":
            self._advance()
            node = self._or_expr(depth + 1)
            self._expect("RPAREN")
            return node

        return self._comparison()

    def _comparison(self):
        field_tok = self._expect("IDENT")
        field_name = field_tok[1]
        if field_name not in FEATURE_FIELDS_SET:
            raise RuleSyntaxError(
                f"Unknown field '{field_name}'. It must be one of the model's "
                f"known network-flow features."
            )

        op_tok = self._expect("OP")
        operator = op_tok[1]
        if operator not in VALID_OPERATORS:
            raise RuleSyntaxError(f"Unknown operator '{operator}'")

        value_tok = self._peek()
        if value_tok[0] != "NUMBER":
            raise RuleSyntaxError(
                f"Expected a numeric value after '{field_name} {operator}', "
                f"got '{value_tok[1] if value_tok[1] else 'end of input'}'"
            )
        self._advance()

        return ComparisonNode(field_name, operator, float(value_tok[1]))


def parse_rule(text: str):
    """
    Parse and fully validate a rule string, returning its AST root node
    """
    tokens = tokenize(text)
    return _Parser(tokens).parse()


def rule_to_string(node) -> str:
    """Render an AST node back to its textual form (for display / round-tripping)"""
    from .ast_nodes import ComparisonNode as C, AndNode as A, OrNode as O, NotNode as N

    if isinstance(node, C):
        return f"{node.field_name} {node.operator} {node.value:g}"
    if isinstance(node, A):
        return f"({rule_to_string(node.left)} AND {rule_to_string(node.right)})"
    if isinstance(node, O):
        return f"({rule_to_string(node.left)} OR {rule_to_string(node.right)})"
    if isinstance(node, N):
        return f"NOT ({rule_to_string(node.operand)})"
    raise RuleSyntaxError("Unknown node in AST")
