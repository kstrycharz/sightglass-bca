"""Detection rules: the deterministic spine that produces every finding."""

from core.rules.loader import RuleLoadError, load_rule_pack
from core.rules.model import Pattern, Rule, RulePack, shannon_entropy
from core.rules.scanner import (
    ExtractedString,
    Match,
    extract_ascii,
    extract_strings,
    extract_utf16le,
    mask,
    scan_bytes,
    scan_file,
)
from core.rules.shape import Shape, ShapePolicy, ShapeVerdict, classify, has_nearby

__all__ = [
    "ExtractedString",
    "Match",
    "Pattern",
    "Rule",
    "RuleLoadError",
    "RulePack",
    "Shape",
    "ShapePolicy",
    "ShapeVerdict",
    "classify",
    "extract_ascii",
    "extract_strings",
    "extract_utf16le",
    "has_nearby",
    "load_rule_pack",
    "mask",
    "scan_bytes",
    "scan_file",
    "shannon_entropy",
]
