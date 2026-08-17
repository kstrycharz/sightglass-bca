#!/usr/bin/env python3
"""Static scan analyzer: strings, rule matching, entropy, file identification.

Runs inside a locked-down container with no network. It reads the artifact from
``/input``, the rule pack from ``/rules``, and writes one JSON document to
``/output/result.json``.

It shares ``core.rules`` with the host rather than reimplementing the scanner,
so the engine that produces findings in production is the same one the unit
tests exercise. The alternative — a standalone script that drifts from the
tested code — is how a scanner quietly stops matching.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/sightglass")

from core.rules import load_rule_pack, scan_file
from core.rules.scanner import MIN_STRING_LENGTH

SCHEMA_VERSION = 1
INPUT_DIR = Path("/input")
RULES_DIR = Path("/rules")
OUTPUT_DIR = Path("/output")
RESULT_PATH = OUTPUT_DIR / "result.json"

# Magic bytes are enough for S1's purposes here; full LIEF/pefile parsing lands
# with the identify analyzer. This exists so the report can say "PE32+
# executable" rather than "file".
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"\xca\xfe\xba\xbe", "macho", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "macho", "application/x-mach-binary"),
    (b"PK\x03\x04", "archive", "application/zip"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "application/x-7z-compressed"),
    (b"\x1f\x8b", "archive", "application/gzip"),
    (b"hsqs", "filesystem", "application/x-squashfs"),
    (b"\xd0\xcf\x11\xe0", "installer", "application/x-msi"),
    (b"-----BEGIN", "certificate", "application/x-pem-file"),
)


def identify(path: Path) -> dict[str, Any]:
    """Cheap file identification from magic bytes and structure."""
    with path.open("rb") as handle:
        header = handle.read(4096)

    kind, media_type = "unknown", None
    for magic, detected_kind, detected_media in _SIGNATURES:
        if header.startswith(magic):
            kind, media_type = detected_kind, detected_media
            break

    result: dict[str, Any] = {"kind": kind, "media_type": media_type}

    if kind == "pe":
        result.update(_identify_pe(path, header))
    elif kind == "elf":
        result.update(_identify_elf(header))
    elif kind == "unknown" and _looks_like_text(header):
        result["kind"] = "text"
        result["media_type"] = "text/plain"

    return result


def _identify_pe(path: Path, header: bytes) -> dict[str, Any]:
    """Architecture and characteristics from the COFF header."""
    info: dict[str, Any] = {}
    try:
        if len(header) < 0x40:
            return info
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        with path.open("rb") as handle:
            handle.seek(pe_offset)
            coff = handle.read(24)
        if not coff.startswith(b"PE\x00\x00"):
            return info
        machine = int.from_bytes(coff[4:6], "little")
        info["architecture"] = {
            0x014C: "x86",
            0x8664: "x86_64",
            0x01C0: "arm",
            0xAA64: "arm64",
            0x0200: "ia64",
        }.get(machine, f"unknown(0x{machine:04x})")
        characteristics = int.from_bytes(coff[22:24], "little")
        info["is_dll"] = bool(characteristics & 0x2000)
    except OSError:
        pass
    return info


def _identify_elf(header: bytes) -> dict[str, Any]:
    if len(header) < 20:
        return {}
    is_64 = header[4] == 2
    little = header[5] == 1
    machine = int.from_bytes(header[18:20], "little" if little else "big")
    return {
        "architecture": {
            0x03: "x86",
            0x3E: "x86_64",
            0x28: "arm",
            0xB7: "arm64",
            0x08: "mips",
            0xF3: "riscv",
        }.get(machine, f"unknown(0x{machine:02x})"),
        "elf_class": "64-bit" if is_64 else "32-bit",
    }


def _looks_like_text(header: bytes) -> bool:
    if not header:
        return False
    printable = sum(1 for b in header if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(header) > 0.95


def find_artifact() -> Path | None:
    """The single file mounted at /input. The orchestrator stages exactly one."""
    candidates = sorted(p for p in INPUT_DIR.rglob("*") if p.is_file())
    return candidates[0] if candidates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sightglass static analyzer")
    parser.add_argument("--min-string-length", type=int, default=MIN_STRING_LENGTH)
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="truncate artifacts larger than this; recorded in the result",
    )
    parser.add_argument(
        "--include-plaintext",
        action="store_true",
        help=(
            "include discovered secret values in the result. Off by default: "
            "the orchestrator passes it only for runs that opted into "
            "plaintext retention (§14), so the value never lands on disk "
            "otherwise."
        ),
    )
    args = parser.parse_args(argv)

    started = time.monotonic()
    artifact = find_artifact()
    if artifact is None:
        print("no artifact found in /input", file=sys.stderr)
        return 2

    try:
        pack = load_rule_pack(RULES_DIR)
    except Exception as exc:
        print(f"could not load rule pack from {RULES_DIR}: {exc}", file=sys.stderr)
        return 3

    size = artifact.stat().st_size
    matches = scan_file(str(artifact), pack, max_bytes=args.max_bytes)

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analyzer": "static",
        "artifact": {
            "name": artifact.name,
            "size_bytes": size,
            "truncated": size > args.max_bytes,
            **identify(artifact),
        },
        "rule_pack": {"version": pack.version, "hash": pack.hash},
        "tool_versions": {
            "python": platform.python_version(),
            "sightglass_scanner": str(SCHEMA_VERSION),
        },
        "duration_s": round(time.monotonic() - started, 3),
        # Sorted by the scanner; preserved here so evidence rows land in the
        # same order on every run regardless of scheduling (§2.5).
        "plaintext_included": args.include_plaintext,
        "matches": [
            {
                "rule_id": m.rule_id,
                "value_hash": m.value_hash,
                "value_masked": m.masked,
                **({"value_plaintext": m.value} if args.include_plaintext else {}),
                "offset": m.offset,
                "encoding": m.encoding,
                "entropy": m.entropy,
                "context": m.context,
            }
            for m in matches
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"scanned {artifact.name} ({size} bytes): {len(matches)} matches", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
