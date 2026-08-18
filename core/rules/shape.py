"""Structural classification of candidate values.

Entropy alone cannot tell a credential from a certificate. Both are
high-entropy; only one is a secret you can use. This module answers the
question entropy cannot: *what shape is this, structurally?*

It exists because of a measured failure. Scanning a real 34 MB vendor release,
96.8% of all matches came from one rule whose fallback pattern was
``\\b([A-Za-z0-9/+]{40})\\b`` — any forty base64-ish characters. That fired on
every PDF content stream and on every base64 line of the MSI's code-signing
certificate chain, and reported each one as a *critical* AWS credential. 386
of them in a single artifact.

The lesson generalises: a secret is identified by **shape plus context**, never
by entropy plus length. A 40-character window carved out of a 3000-character
base64 blob is not a token at all — it is a slice of something else, and no
amount of entropy scoring will tell you that. Looking at what surrounds it
will.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

# Characters that can appear inside a continuous base64/PEM payload.
_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
)

# A discrete credential is delimited. A blob is not. Anything embedded in a
# base64 run longer than this is a slice of a larger structure — a certificate,
# an embedded binary, a PDF stream, an inline image.
BLOB_RUN_THRESHOLD = 120

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
_DIGEST_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})

# Markers that identify the surrounding text as encoded cryptographic or
# document structure rather than configuration.
_STRUCTURE_MARKERS: tuple[str, ...] = (
    "MII",  # DER SEQUENCE in base64 — every X.509 certificate and RSA key
    "BgkqhkiG",  # PKCS#1 OID, base64
    "-----BEGIN",
    "-----END",
    "%PDF",
    "endstream",
    "endobj",
    "/Filter",
    "FlateDecode",
    "<?xml",
    "data:image/",
    "base64,",
)

_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|\.{1,2}[\\/])")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^[0-9.,:_\-+eE]+$")


class Shape(StrEnum):
    """What a value structurally appears to be."""

    CREDENTIAL_LIKE = "credential_like"
    """Nothing disqualifying. Mixed classes, delimited, not obviously derived."""

    BLOB_SLICE = "blob_slice"
    """A window cut out of a longer continuous base64 run."""

    ENCODED_STRUCTURE = "encoded_structure"
    """Surrounded by certificate, PEM, or document-format markers."""

    HEX_DIGEST = "hex_digest"
    """All hex at a digest length — MD5, SHA-1, SHA-256, a git object id."""

    UUID = "uuid"
    PATH_OR_URL = "path_or_url"
    NUMERIC = "numeric"
    LOW_VARIETY = "low_variety"
    """Too few distinct characters to be key material."""

    @property
    def is_disqualifying(self) -> bool:
        return self is not Shape.CREDENTIAL_LIKE


@dataclass(frozen=True, slots=True)
class ShapeVerdict:
    shape: Shape
    reason: str

    @property
    def rejected(self) -> bool:
        return self.shape.is_disqualifying


def base64_run_length(haystack: str, start: int, end: int) -> int:
    """Length of the continuous base64-alphabet run containing ``[start, end)``.

    This is the single most valuable signal in the module. A real credential is
    delimited — by a quote, an equals sign, whitespace, a comma. A slice of a
    certificate or a PDF stream sits in the middle of thousands of unbroken
    base64 characters.
    """
    left = start
    while left > 0 and haystack[left - 1] in _BASE64_ALPHABET:
        left -= 1
    right = end
    length = len(haystack)
    while right < length and haystack[right] in _BASE64_ALPHABET:
        right += 1
    return right - left


def character_classes(value: str) -> int:
    """How many of {lower, upper, digit, symbol} appear."""
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


class ShapePolicy(StrEnum):
    """How much of the filter a rule wants.

    The distinction is load-bearing, and getting it wrong costs recall. A rule
    anchored on a distinctive prefix — ``AKIA[0-9A-Z]{16}``, ``ghp_``,
    ``sk_live_`` — has already established that the match is a credential; the
    value-shape heuristics can only take that away. Applying them cost the AWS
    access key rule its own fixture (``AKIA2E0A8F3B5C7D9E1F`` reads as a code
    identifier: starts with a letter, alphanumeric, two character classes).

    Context rejection is different. No prefix makes a certificate slice a
    credential, so ``CONTEXT`` applies to every rule.
    """

    CONTEXT = "context"
    """Reject only on surroundings: blob slices and encoded structure."""

    STRICT = "strict"
    """Also reject on the value's own shape. For rules that match shape alone,
    where the heuristics are the only specificity available."""


def classify(
    value: str,
    *,
    haystack: str = "",
    start: int = -1,
    end: int = -1,
    policy: ShapePolicy = ShapePolicy.CONTEXT,
    require_mixed_case: bool = False,
) -> ShapeVerdict:
    """Classify a candidate value, using its surroundings when available.

    ``haystack`` plus ``start``/``end`` locate the value inside the string it
    came from. Without them only the value itself is judged, which is
    materially weaker — the blob check is the whole point.
    """
    stripped = value.strip()
    if not stripped:
        return ShapeVerdict(Shape.LOW_VARIETY, "empty")

    # --- context checks: always applied, strongest first ------------------
    if haystack and 0 <= start < end <= len(haystack):
        run = base64_run_length(haystack, start, end)
        if run >= BLOB_RUN_THRESHOLD:
            return ShapeVerdict(
                Shape.BLOB_SLICE,
                f"inside a {run}-character base64 run; a delimited credential is not",
            )

        window = haystack[max(0, start - 200) : min(len(haystack), end + 200)]
        for marker in _STRUCTURE_MARKERS:
            if marker in window:
                return ShapeVerdict(
                    Shape.ENCODED_STRUCTURE, f"surrounded by {marker!r} — encoded structure"
                )

    if policy is ShapePolicy.CONTEXT:
        return ShapeVerdict(Shape.CREDENTIAL_LIKE, "no disqualifying context")

    # --- value-shape checks: only for rules matching on shape alone -------
    if _UUID_RE.match(stripped):
        return ShapeVerdict(Shape.UUID, "UUID/GUID")

    if _HEX_RE.match(stripped):
        if len(stripped) in _DIGEST_LENGTHS:
            return ShapeVerdict(Shape.HEX_DIGEST, f"{len(stripped)}-character hex digest")
        return ShapeVerdict(Shape.HEX_DIGEST, "hex string")

    if _URL_RE.match(stripped) or _PATH_RE.match(stripped):
        return ShapeVerdict(Shape.PATH_OR_URL, "path or URL")

    if _NUMERIC_RE.match(stripped):
        return ShapeVerdict(Shape.NUMERIC, "numeric")

    distinct = len(set(stripped))
    if distinct <= 4 or distinct / len(stripped) < 0.18:
        return ShapeVerdict(Shape.LOW_VARIETY, f"only {distinct} distinct characters")

    # There is deliberately no "looks like a code identifier" heuristic here.
    # One was written and removed: `^[A-Za-z][A-Za-z0-9]*$` with a character
    # class count separates nothing useful, and adding an entropy cut left
    # `getUserNameFromSession` (3.7) and `AKIA2E0A8F3B5C7D9E1F` (3.9) two
    # tenths of a bit apart. It rejected a real AWS key fixture before any
    # artifact reached it. A rule pack's specificity belongs in its patterns
    # and its required context, not in a heuristic that guesses whether random
    # letters are a word. Do not re-add it without a labelled corpus showing
    # it separates the two populations.
    if require_mixed_case and character_classes(stripped) < 3:
        # Vendor-issued secrets of this shape (AWS secret keys, generic API
        # keys) mix upper, lower, and digits. A single-class run of the same
        # length is far more likely to be encoded data.
        return ShapeVerdict(
            Shape.LOW_VARIETY,
            f"only {character_classes(stripped)} character classes; "
            "issued credentials of this shape mix upper, lower, and digits",
        )

    return ShapeVerdict(Shape.CREDENTIAL_LIKE, "no disqualifying structure")


def has_nearby(haystack: str, start: int, keywords: tuple[str, ...], window: int) -> bool:
    """Whether any keyword appears within ``window`` characters of ``start``.

    Proximity is what makes a shape-based rule specific. Forty base64
    characters are meaningless; forty base64 characters within eighty
    characters of ``aws_secret_access_key`` are a credential.
    """
    if not keywords:
        return True
    lower = haystack.lower()
    left = max(0, start - window)
    right = min(len(haystack), start + window)
    return any(keyword.lower() in lower[left:right] for keyword in keywords)
