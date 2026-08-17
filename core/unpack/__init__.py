"""Recursive container extraction with hard budgets.

Dependency-free like core.rules, so the unpack analyzer image stays small and
the logic stays testable on the host.
"""

from core.unpack.budget import BudgetExceeded, ExtractionBudget
from core.unpack.detect import Container, Detection, detect, is_probably_text
from core.unpack.extractor import (
    ExtractedNode,
    ExtractionResult,
    Extractor,
    should_scan,
    summarise,
)

__all__ = [
    "BudgetExceeded",
    "Container",
    "Detection",
    "ExtractedNode",
    "ExtractionBudget",
    "ExtractionResult",
    "Extractor",
    "detect",
    "is_probably_text",
    "should_scan",
    "summarise",
]
