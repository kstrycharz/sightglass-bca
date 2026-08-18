"""Structural classification.

Every test here traces to a measured false positive. Scanning a real 34 MB
vendor release, 96.8% of all matches were 40-character windows carved out of
the MSI's code-signing certificate and the PDFs' content streams, each reported
as a *critical* AWS credential. This module is what stopped that, and these
tests are what keep it stopped.
"""

from __future__ import annotations

import pytest

from core.rules.shape import (
    BLOB_RUN_THRESHOLD,
    Shape,
    ShapePolicy,
    base64_run_length,
    character_classes,
    classify,
    has_nearby,
)

# A real certificate body, base64. This exact shape produced 386 critical
# findings before the blob check existed.
CERTIFICATE = (
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxBLfqV0Qd4tb1eT2TZwamjPjlGjhVtnBKAQ"
    "JG9dKILBl1fYSCkTtuGkU3pMLey5SnCNoIwZD7JIvU4Tb0cUBhflGdd1yXqBPCCjQjBAMA4GA1UdDwE"
    "B2wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAB5BK3MjTvDDnFFlm5wioooMhfNzKWtN1gHi4bkyU8B"
)


class TestBlobDetection:
    """The single most valuable check in the module."""

    def test_a_window_inside_a_certificate_is_a_blob_slice(self) -> None:
        start = 40
        verdict = classify(
            CERTIFICATE[start : start + 40],
            haystack=CERTIFICATE,
            start=start,
            end=start + 40,
        )
        assert verdict.shape is Shape.BLOB_SLICE
        assert verdict.rejected

    def test_a_delimited_credential_is_not_a_blob_slice(self) -> None:
        """The same length and alphabet, but delimited — which is exactly what
        distinguishes a credential from a slice of encoded data."""
        line = 'aws_secret_access_key = "Kq2vN8xR4mT7wZ1cB5nH9jL3fD6gY0pA2sE4uI8o"'
        start = line.index("Kq2v")
        verdict = classify(line[start : start + 40], haystack=line, start=start, end=start + 40)
        assert verdict.shape is Shape.CREDENTIAL_LIKE

    def test_run_length_measures_the_whole_surrounding_run(self) -> None:
        assert base64_run_length(CERTIFICATE, 40, 80) == len(CERTIFICATE)

    def test_run_length_stops_at_delimiters(self) -> None:
        text = 'key="abcdefghij" other="x"'
        start = text.index("abcdefghij")
        assert base64_run_length(text, start, start + 10) == 10

    def test_threshold_is_the_documented_value(self) -> None:
        """Load-bearing constant: below it, real credentials get rejected."""
        assert BLOB_RUN_THRESHOLD == 120


class TestEncodedStructure:
    @pytest.mark.parametrize(
        "marker",
        ["MII", "BgkqhkiG", "-----BEGIN CERTIFICATE-----", "endstream", "FlateDecode"],
    )
    def test_structure_markers_reject(self, marker: str) -> None:
        haystack = f"{marker} aBcDeF0123456789aBcDeF0123456789aBcDeF01 trailing"
        start = haystack.index("aBcDeF0123")
        verdict = classify(
            haystack[start : start + 40], haystack=haystack, start=start, end=start + 40
        )
        assert verdict.rejected


class TestPolicyTiers:
    """Context rejection applies to every rule; value-shape rejection does not.

    Applying value-shape heuristics to prefix-anchored rules cost the AWS
    access key rule its own fixture — `AKIA2E0A8F3B5C7D9E1F` reads as a code
    identifier by every structural measure available.
    """

    def test_prefixed_key_survives_context_policy(self) -> None:
        verdict = classify("AKIA2E0A8F3B5C7D9E1F", policy=ShapePolicy.CONTEXT)
        assert not verdict.rejected

    def test_hex_digest_survives_context_policy(self) -> None:
        verdict = classify("9f8e7d6c5b4a39281706f5e4d3c2b1a0", policy=ShapePolicy.CONTEXT)
        assert not verdict.rejected

    def test_hex_digest_is_rejected_under_strict(self) -> None:
        verdict = classify("d41d8cd98f00b204e9800998ecf8427e", policy=ShapePolicy.STRICT)
        assert verdict.shape is Shape.HEX_DIGEST

    def test_uuid_is_rejected_under_strict(self) -> None:
        verdict = classify("550e8400-e29b-41d4-a716-446655440000", policy=ShapePolicy.STRICT)
        assert verdict.shape is Shape.UUID

    def test_low_variety_is_rejected_under_strict(self) -> None:
        # Not "aaaa..." — that is valid hex and classifies as a digest first.
        verdict = classify("zzzzzzzzzzzzzzzzzzzzzzzz", policy=ShapePolicy.STRICT)
        assert verdict.shape is Shape.LOW_VARIETY


class TestNoIdentifierHeuristic:
    """There is deliberately no "looks like code" check.

    One existed and was removed: it put `getUserNameFromSession` (entropy 3.7)
    and `AKIA2E0A8F3B5C7D9E1F` (3.9) two tenths of a bit apart, and rejected a
    real AWS key fixture. Specificity belongs in patterns and required context.
    """

    def test_a_prefixed_key_is_never_rejected_as_code(self) -> None:
        verdict = classify("AKIA2E0A8F3B5C7D9E1F", policy=ShapePolicy.STRICT)
        assert not verdict.rejected


class TestMixedCase:
    def test_single_class_run_rejected_when_required(self) -> None:
        verdict = classify(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN",
            policy=ShapePolicy.STRICT,
            require_mixed_case=True,
        )
        assert verdict.rejected

    def test_mixed_case_value_accepted(self) -> None:
        verdict = classify(
            "Kq2vN8xR4mT7wZ1cB5nH9jL3fD6gY0pA2sE4uI8o",
            policy=ShapePolicy.STRICT,
            require_mixed_case=True,
        )
        assert not verdict.rejected

    def test_character_class_counting(self) -> None:
        assert character_classes("abc") == 1
        assert character_classes("aBc") == 2
        assert character_classes("aB3") == 3
        assert character_classes("aB3/") == 4


class TestProximity:
    def test_keyword_within_window(self) -> None:
        text = 'aws_secret_access_key = "' + "x" * 40 + '"'
        assert has_nearby(text, text.index("x"), ("aws",), 100)

    def test_keyword_outside_window(self) -> None:
        text = "aws" + " " * 500 + "x" * 40
        assert not has_nearby(text, text.index("x" * 40), ("aws",), 100)

    def test_no_keywords_means_no_constraint(self) -> None:
        assert has_nearby("anything", 0, (), 100)

    def test_matching_is_case_insensitive(self) -> None:
        assert has_nearby("AWS_SECRET = value", 13, ("aws",), 100)
