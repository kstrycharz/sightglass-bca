"""Extraction budgets — the zip-bomb defence.

A 42 KB zip can expand to 4.5 petabytes. Recursive extraction without hard
budgets is a denial-of-service primitive pointed at your own infrastructure,
and it is not a theoretical concern: nested archives are exactly what this tool
is built to walk into.

Three independent caps, all tracked **cumulatively across the entire extraction
tree** rather than per archive. Per-archive limits are useless here — a bomb
that is ten benign-looking archives deep defeats them trivially.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_FILES = 20_000
# Scaled per MB of input, with the ceiling below. A modern Electron app ships
# a node_modules tree of 50-100k tiny files, and a flat 20k cap truncated a
# 213 MB NVIDIA installer six seconds in — leaving its 376 MB app.asar, where
# the application's own code lives, entirely unopened.
FILES_PER_INPUT_MB = 600
MAX_FILES_CEILING = 250_000
DEFAULT_MAX_TOTAL_BYTES = 10 * 1024**3
DEFAULT_EXPANSION_FACTOR = 20
# Files smaller than this are not worth recursing into, and a bomb made of
# millions of tiny entries is the cheapest one to build.
MIN_INTERESTING_BYTES = 8


class BudgetExceeded(RuntimeError):  # noqa: N818 - names the event, not a type
    """Extraction stopped because a cap was hit.

    Not an error in the usual sense — the run continues with a partial tree and
    the report says so. Silently truncating would be far worse: the user would
    read "no findings" from an artifact that was never fully opened.
    """

    def __init__(self, limit: str, detail: str) -> None:
        self.limit = limit
        self.detail = detail
        super().__init__(f"extraction budget exceeded ({limit}): {detail}")


@dataclass(slots=True)
class ExtractionBudget:
    """Mutable running totals for one extraction tree."""

    max_depth: int = DEFAULT_MAX_DEPTH
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    files_written: int = 0
    bytes_written: int = 0
    exceeded: list[str] = field(default_factory=list)

    @classmethod
    def for_input(cls, input_size_bytes: int, **overrides: int) -> ExtractionBudget:
        """Scale the byte cap to the input.

        ``min(20x input, 10 GB)``. The multiplier catches bombs while leaving
        room for legitimately compressible artifacts — an installer of mostly
        text config can honestly expand tenfold.
        """
        scaled = max(input_size_bytes * DEFAULT_EXPANSION_FACTOR, 64 * 1024 * 1024)

        # The file cap scales too. Bytes are the bomb defence — a bomb is
        # measured in what it writes — while the file cap guards against inode
        # exhaustion from millions of tiny entries. Holding it flat while the
        # byte cap scales just truncates large, legitimate artifacts.
        input_mb = max(input_size_bytes // (1024 * 1024), 1)
        files = max(DEFAULT_MAX_FILES, min(input_mb * FILES_PER_INPUT_MB, MAX_FILES_CEILING))

        budget = cls(
            max_total_bytes=min(scaled, DEFAULT_MAX_TOTAL_BYTES),
            max_files=files,
        )
        for key, value in overrides.items():
            setattr(budget, key, value)
        return budget

    @property
    def bytes_remaining(self) -> int:
        return max(0, self.max_total_bytes - self.bytes_written)

    @property
    def files_remaining(self) -> int:
        return max(0, self.max_files - self.files_written)

    @property
    def is_exhausted(self) -> bool:
        return self.bytes_remaining <= 0 or self.files_remaining <= 0

    def check_depth(self, depth: int) -> None:
        if depth > self.max_depth:
            self.note(f"depth {depth} exceeds max_depth {self.max_depth}")
            raise BudgetExceeded("max_depth", f"depth {depth} > {self.max_depth}")

    def reserve(self, size_bytes: int) -> None:
        """Account for a file about to be written. Raises before it is."""
        if self.files_written + 1 > self.max_files:
            self.note(f"file count would exceed max_files {self.max_files}")
            raise BudgetExceeded("max_files", f"{self.files_written} files already written")
        if self.bytes_written + size_bytes > self.max_total_bytes:
            self.note(
                f"writing {size_bytes} bytes would exceed max_total_bytes "
                f"{self.max_total_bytes}"
            )
            raise BudgetExceeded(
                "max_total_bytes",
                f"{self.bytes_written} of {self.max_total_bytes} bytes already written",
            )
        self.files_written += 1
        self.bytes_written += size_bytes

    def note(self, message: str) -> None:
        if message not in self.exceeded:
            self.exceeded.append(message)

    def to_dict(self) -> dict[str, object]:
        return {
            "max_depth": self.max_depth,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "files_written": self.files_written,
            "bytes_written": self.bytes_written,
            "truncated": bool(self.exceeded),
            "reasons": list(self.exceeded),
        }
