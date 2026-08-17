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

__all__ = [
    "ExtractedString",
    "Match",
    "Pattern",
    "Rule",
    "RuleLoadError",
    "RulePack",
    "extract_ascii",
    "extract_strings",
    "extract_utf16le",
    "load_rule_pack",
    "mask",
    "scan_bytes",
    "scan_file",
    "shannon_entropy",
]
