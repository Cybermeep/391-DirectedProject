"""
AST node definitions for the user-facing rule/signature language.

A rule is a boolean expression over the same 78 flow features the ML
model consumes, e.g.:

    SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3 AND Flow_Byts/s > 1000

Grammar (case-insensitive keywords, left-associative):

    expr        := or_expr
    or_expr     := and_expr ( "OR" and_expr )*
    and_expr    := unary ( "AND" unary )*
    unary       := "NOT" unary | comparison | "(" or_expr ")"
    comparison  := FIELD OPERATOR NUMBER
    OPERATOR    := ">" | "<" | ">=" | "<=" | "==" | "!="
    FIELD       := one of the 78 whitelisted feature names (see FEATURE_FIELDS)
"""

from dataclasses import dataclass, field
from typing import Union, List

# The exact 78 features the trained model expects (label column excluded).
# Field names in rules are validated against this whitelist so a rule can
# never reference something the inference/feature-extraction pipeline
# doesn't actually produce - this IS the "ensure their input is valid in
# our engine" guarantee.
FEATURE_FIELDS: List[str] = [
    'Dst_Port', 'Protocol', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts',
    'TotLen_Fwd_Pkts', 'TotLen_Bwd_Pkts', 'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min',
    'Fwd_Pkt_Len_Mean', 'Fwd_Pkt_Len_Std', 'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min',
    'Bwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Std', 'Flow_Byts/s', 'Flow_Pkts/s',
    'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min',
    'Fwd_IAT_Tot', 'Fwd_IAT_Mean', 'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min',
    'Bwd_IAT_Tot', 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
    'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags',
    'Fwd_Header_Len', 'Bwd_Header_Len', 'Fwd_Pkts/s', 'Bwd_Pkts/s',
    'Pkt_Len_Min', 'Pkt_Len_Max', 'Pkt_Len_Mean', 'Pkt_Len_Std', 'Pkt_Len_Var',
    'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt',
    'ACK_Flag_Cnt', 'URG_Flag_Cnt', 'CWE_Flag_Count', 'ECE_Flag_Cnt',
    'Down/Up_Ratio', 'Pkt_Size_Avg', 'Fwd_Seg_Size_Avg', 'Bwd_Seg_Size_Avg',
    'Fwd_Byts/b_Avg', 'Fwd_Pkts/b_Avg', 'Fwd_Blk_Rate_Avg',
    'Bwd_Byts/b_Avg', 'Bwd_Pkts/b_Avg', 'Bwd_Blk_Rate_Avg',
    'Subflow_Fwd_Pkts', 'Subflow_Fwd_Byts', 'Subflow_Bwd_Pkts',
    'Subflow_Bwd_Byts', 'Init_Fwd_Win_Byts', 'Init_Bwd_Win_Byts',
    'Fwd_Act_Data_Pkts', 'Fwd_Seg_Size_Min', 'Active_Mean', 'Active_Std',
    'Active_Max', 'Active_Min', 'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min',
]
FEATURE_FIELDS_SET = set(FEATURE_FIELDS)

VALID_OPERATORS = (">", "<", ">=", "<=", "==", "!=")


class RuleSyntaxError(Exception):
    """Raised when a rule string or AST is structurally or semantically invalid."""
    pass


@dataclass
class ComparisonNode:
    field_name: str
    operator: str
    value: float

    def to_dict(self):
        return {"type": "comparison", "field": self.field_name, "operator": self.operator, "value": self.value}


@dataclass
class NotNode:
    operand: Union["ComparisonNode", "AndNode", "OrNode", "NotNode"]

    def to_dict(self):
        return {"type": "not", "operand": self.operand.to_dict()}


@dataclass
class AndNode:
    left: Union[ComparisonNode, "AndNode", "OrNode", NotNode]
    right: Union[ComparisonNode, "AndNode", "OrNode", NotNode]

    def to_dict(self):
        return {"type": "AND", "left": self.left.to_dict(), "right": self.right.to_dict()}


@dataclass
class OrNode:
    left: Union[ComparisonNode, AndNode, "OrNode", NotNode]
    right: Union[ComparisonNode, AndNode, "OrNode", NotNode]

    def to_dict(self):
        return {"type": "OR", "left": self.left.to_dict(), "right": self.right.to_dict()}


def node_from_dict(data: dict):
    """Reconstruct an AST node tree from its JSON dict form (as stored in SQLite)."""
    if not isinstance(data, dict) or "type" not in data:
        raise RuleSyntaxError("Malformed AST node")

    node_type = data["type"]

    if node_type == "comparison":
        field_name = data.get("field")
        operator = data.get("operator")
        value = data.get("value")

        if field_name not in FEATURE_FIELDS_SET:
            raise RuleSyntaxError(f"Unknown field: {field_name}")
        if operator not in VALID_OPERATORS:
            raise RuleSyntaxError(f"Unknown operator: {operator}")
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise RuleSyntaxError(f"Comparison value must be numeric, got: {value!r}")

        return ComparisonNode(field_name, operator, value)

    elif node_type == "AND":
        return AndNode(node_from_dict(data.get("left")), node_from_dict(data.get("right")))

    elif node_type == "OR":
        return OrNode(node_from_dict(data.get("left")), node_from_dict(data.get("right")))

    elif node_type == "not":
        return NotNode(node_from_dict(data.get("operand")))

    else:
        raise RuleSyntaxError(f"Unknown node type: {node_type}")
