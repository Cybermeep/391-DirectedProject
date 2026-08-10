"""
rule_engine — Rule-based network intrusion detection for the NIDS
"""

from .engine import RuleEngine
from .rules import Rule, default_rules

__all__ = ['RuleEngine', 'Rule', 'default_rules']
