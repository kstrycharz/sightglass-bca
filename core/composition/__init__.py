"""Binary composition analysis: what a shipped artifact is made of.

Layer 1 of docs/ROADMAP-COMPOSITION.md — components the artifact declares
about itself. Deliberately separate from the detection engine: rules answer
"is this specific bad thing present?", composition answers "what is this made
of?", and the two have different precision requirements and different failure
modes.
"""

from core.composition.detect import detect_in_file, inventory
from core.composition.model import (
    Component,
    ComponentInventory,
    Confidence,
    Ecosystem,
)

__all__ = [
    "Component",
    "ComponentInventory",
    "Confidence",
    "Ecosystem",
    "detect_in_file",
    "inventory",
]
