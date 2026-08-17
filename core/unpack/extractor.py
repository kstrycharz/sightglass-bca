"""Recursive extraction.

Walks a container, extracts it, and walks whatever came out — until the tree is
exhausted or a budget stops it. The result is a real tree, so a report can say
``setup.exe → app.7z → resources/app.asar → config/prod.json`` rather than
listing forty loose files with no provenance.

Runs inside the unpack analyzer container, with no network and a read-only
rootfs. It shells out to ``7z`` where that is the right tool and falls back to
the Python standard library where it is not, so the image stays small and the
logic stays testable on the host.

Path traversal is treated as hostile input regardless of the artifact being
"cooperative": a zip entry named ``../../etc/passwd`` is a bug in someone's
build tooling far more often than it is an attack, and either way it must not
escape the output directory.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.unpack.budget import BudgetExceeded, ExtractionBudget
from core.unpack.detect import Container, detect

SEVENZIP_BINARY = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
SEVENZIP_TIMEOUT_S = 300

# Formats 7z handles well enough that reimplementing them would be a mistake.
_SEVENZIP_FORMATS = frozenset(
    {
        Container.SEVENZIP,
        Container.RAR,
        Container.CAB,
        Container.MSI,
        Container.ISO,
        Container.NSIS,
        Container.XZ,
        Container.BZIP2,
        Container.DMG,
        Container.CPIO,
    }
)

_ZIP_FORMATS = frozenset({Container.ZIP, Container.JAR, Container.APK})


@dataclass(slots=True)
class ExtractedNode:
    """One file in the extraction tree."""

    path_in_tree: str
    """Human-readable provenance: ``setup.exe → app.7z → config/prod.json``."""
    relative_path: str
    """Path on disk relative to the extraction root, for locating the bytes."""
    parent_path_in_tree: str | None
    depth: int
    size_bytes: int
    container: str
    extracted_by: str
    sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "path_in_tree": self.path_in_tree,
            "relative_path": self.relative_path,
            "parent_path_in_tree": self.parent_path_in_tree,
            "depth": self.depth,
            "size_bytes": self.size_bytes,
            "container": self.container,
            "extracted_by": self.extracted_by,
            "sha256": self.sha256,
        }


@dataclass(slots=True)
class ExtractionResult:
    nodes: list[ExtractedNode] = field(default_factory=list)
    budget: ExtractionBudget = field(default_factory=ExtractionBudget)
    errors: list[str] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return bool(self.budget.exceeded)

    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "budget": self.budget.to_dict(),
            "errors": self.errors,
            "truncated": self.truncated,
        }


def _safe_join(root: Path, member: str) -> Path | None:
    """Resolve an archive member under ``root``, or ``None`` if it escapes.

    Covers ``../`` traversal, absolute paths, and (on Windows) drive-relative
    paths. Returning None rather than raising keeps one malicious entry from
    aborting extraction of an otherwise useful archive.
    """
    cleaned = member.replace("\\", "/")
    # Strip a drive letter before stripping leading slashes. Archives built on
    # Windows sometimes carry `C:/...` members, and pathlib treats those as
    # absolute even when joined — so without this the entry silently vanishes
    # instead of being confined, and a zip loses files with no error.
    if len(cleaned) > 1 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    if not cleaned or cleaned in (".", ".."):
        return None
    candidate = (root / cleaned).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


class Extractor:
    def __init__(self, budget: ExtractionBudget | None = None) -> None:
        self.budget = budget or ExtractionBudget()
        self.result = ExtractionResult(budget=self.budget)

    # -- public ------------------------------------------------------------
    def extract_tree(
        self, artifact: Path, output_root: Path, *, root_name: str
    ) -> ExtractionResult:
        """Extract ``artifact`` recursively into ``output_root``."""
        output_root.mkdir(parents=True, exist_ok=True)
        self._walk(artifact, output_root, path_in_tree=root_name, depth=0)
        return self.result

    # -- recursion ---------------------------------------------------------
    def _walk(self, source: Path, output_root: Path, *, path_in_tree: str, depth: int) -> None:
        try:
            self.budget.check_depth(depth)
        except BudgetExceeded as exc:
            self.result.errors.append(f"{path_in_tree}: {exc}")
            return

        if self.budget.is_exhausted:
            return

        detection = detect(source)
        if not detection.should_unpack:
            return

        destination = output_root / _slugify(path_in_tree, depth)
        try:
            destination.mkdir(parents=True, exist_ok=True)
            written = self._extract_one(source, destination, detection.container)
        except BudgetExceeded as exc:
            self.result.errors.append(f"{path_in_tree}: {exc}")
            return
        except Exception as exc:
            # A container we cannot open is worth recording, not worth
            # aborting for: the rest of the tree may still hold the finding.
            self.result.errors.append(
                f"{path_in_tree}: {detection.container} extraction failed: {exc}"
            )
            return

        for child in written:
            relative = child.relative_to(output_root).as_posix()
            child_name = child.relative_to(destination).as_posix()
            child_path_in_tree = f"{path_in_tree} → {child_name}"

            child_detection = detect(child)
            self.result.nodes.append(
                ExtractedNode(
                    path_in_tree=child_path_in_tree,
                    relative_path=relative,
                    parent_path_in_tree=path_in_tree,
                    depth=depth + 1,
                    size_bytes=child.stat().st_size,
                    container=str(child_detection.container),
                    extracted_by=str(detection.container),
                )
            )

            if child_detection.should_unpack:
                self._walk(child, output_root, path_in_tree=child_path_in_tree, depth=depth + 1)

    # -- format dispatch ---------------------------------------------------
    def _extract_one(self, source: Path, destination: Path, container: Container) -> list[Path]:
        if container in _ZIP_FORMATS:
            return self._extract_zip(source, destination)
        if container is Container.TAR:
            return self._extract_tar(source, destination)
        if container is Container.GZIP:
            return self._extract_gzip(source, destination)
        if container is Container.ASAR:
            return self._extract_asar(source, destination)
        if container is Container.PYINSTALLER:
            # PyInstaller archives are a zip-like CArchive appended to a PE;
            # 7z opens the outer PE and finds the payload often enough to be
            # worth trying before giving up.
            return self._extract_with_7z(source, destination)
        if container in _SEVENZIP_FORMATS or container is Container.INNO:
            return self._extract_with_7z(source, destination)
        if container is Container.SQUASHFS:
            return self._extract_squashfs(source, destination)
        raise NotImplementedError(f"no extractor for {container}")

    def _extract_zip(self, source: Path, destination: Path) -> list[Path]:
        written: list[Path] = []
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                target = _safe_join(destination, info.filename)
                if target is None:
                    self.result.errors.append(
                        f"refused path-traversing zip entry {info.filename!r}"
                    )
                    continue
                # Reserve against the *declared* size before writing a byte, so
                # a bomb is stopped by its own header rather than by the disk.
                self.budget.reserve(info.file_size)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as reader, target.open("wb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                written.append(target)
        return written

    def _extract_tar(self, source: Path, destination: Path) -> list[Path]:
        written: list[Path] = []
        with tarfile.open(source) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                target = _safe_join(destination, member.name)
                if target is None:
                    self.result.errors.append(f"refused path-traversing tar entry {member.name!r}")
                    continue
                self.budget.reserve(member.size)
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                with extracted as reader, target.open("wb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                written.append(target)
        return written

    def _extract_gzip(self, source: Path, destination: Path) -> list[Path]:
        """A .tar.gz is a tar inside a gzip; plain .gz holds a single file."""
        if tarfile.is_tarfile(source):
            return self._extract_tar(source, destination)

        import gzip

        target = destination / (source.stem or "decompressed")
        self.budget.reserve(min(self.budget.bytes_remaining, source.stat().st_size * 20))
        with gzip.open(source, "rb") as reader, target.open("wb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
        return [target]

    def _extract_asar(self, source: Path, destination: Path) -> list[Path]:
        """Electron ASAR: an 8-byte pickle header, a JSON directory, then data.

        Worth implementing directly — Electron apps routinely ship their whole
        JavaScript source and config here, which is a rich seam for exactly the
        secrets this tool looks for.
        """
        import json
        import struct

        written: list[Path] = []
        with source.open("rb") as handle:
            header = handle.read(16)
            if len(header) < 16:
                raise ValueError("truncated ASAR header")
            (header_size,) = struct.unpack("<I", header[12:16])
            directory = json.loads(handle.read(header_size).rstrip(b"\x00").decode("utf-8"))
            base_offset = 16 + header_size

            def walk(node: dict[str, Any], prefix: str) -> None:
                files = node.get("files")
                if not isinstance(files, dict):
                    return
                for name, entry in files.items():
                    if not isinstance(entry, dict):
                        continue
                    child_path = f"{prefix}/{name}" if prefix else name
                    if "files" in entry:
                        walk(entry, child_path)
                        continue
                    size = int(entry.get("size", 0))
                    offset = int(entry.get("offset", 0))
                    target = _safe_join(destination, child_path)
                    if target is None:
                        self.result.errors.append(f"refused ASAR entry {child_path!r}")
                        continue
                    self.budget.reserve(size)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    handle.seek(base_offset + offset)
                    target.write_bytes(handle.read(size))
                    written.append(target)

            walk(directory, "")
        return written

    def _extract_with_7z(self, source: Path, destination: Path) -> list[Path]:
        if SEVENZIP_BINARY is None:
            raise RuntimeError("7z is not available in this image")

        # Fixed binary, argument list (never a shell string), and a timeout.
        completed = subprocess.run(
            [
                SEVENZIP_BINARY,
                "x",
                str(source),
                f"-o{destination}",
                "-y",
                "-bd",
                "-snld",  # do not follow symlinks out of the destination
                "-p",  # empty password: never block on an interactive prompt
            ],
            capture_output=True,
            timeout=SEVENZIP_TIMEOUT_S,
            check=False,
        )
        # 7z returns 1 for warnings (skipped entries), 2+ for real failures. A
        # partial extraction is still worth scanning.
        if completed.returncode > 1:
            stderr = completed.stderr.decode("utf-8", "replace").strip()[:400]
            raise RuntimeError(f"7z exited {completed.returncode}: {stderr}")

        return self._collect(destination)

    def _extract_squashfs(self, source: Path, destination: Path) -> list[Path]:
        binary = shutil.which("unsquashfs")
        if binary is None:
            raise RuntimeError("unsquashfs is not available in this image")
        completed = subprocess.run(
            [binary, "-f", "-no-progress", "-d", str(destination), str(source)],
            capture_output=True,
            timeout=SEVENZIP_TIMEOUT_S,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", "replace").strip()[:400]
            raise RuntimeError(f"unsquashfs exited {completed.returncode}: {stderr}")
        return self._collect(destination)

    def _collect(self, destination: Path) -> list[Path]:
        """Register files an external tool wrote, charging them to the budget.

        External extractors write before we can reserve, so the budget is
        applied after the fact here: anything over the cap is deleted rather
        than reported, which keeps the invariant true even though the bytes
        briefly existed.
        """
        collected: list[Path] = []
        for path in sorted(destination.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            size = path.stat().st_size
            if size < 1:
                continue
            try:
                self.budget.reserve(size)
            except BudgetExceeded:
                path.unlink(missing_ok=True)
                raise
            collected.append(path)
        return collected


def _slugify(path_in_tree: str, depth: int) -> str:
    """A filesystem-safe directory name for one node's extracted contents."""
    tail = path_in_tree.split(" → ")[-1]
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in tail)[:60]
    return f"d{depth}_{safe or 'node'}"


def should_scan(path: Path) -> bool:
    """Whether an extracted file is worth handing to the static scanner.

    Excludes only things that cannot hold a string. Deliberately permissive:
    the cost of scanning a useless file is milliseconds; the cost of skipping
    the one holding the key is the whole product.
    """
    try:
        if path.stat().st_size < 8:
            return False
    except OSError:
        return False
    return True


def summarise(result: ExtractionResult) -> str:
    containers = sum(1 for n in result.nodes if Container(n.container).is_container)
    return (
        f"{len(result.nodes)} files from {containers} nested container(s), "
        f"{result.budget.bytes_written:,} bytes" + (" (truncated)" if result.truncated else "")
    )
