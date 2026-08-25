"""Recursive extraction: detection, budgets, and the zip-bomb defence.

The budget tests matter more than the format tests. A format we cannot open is
a missed finding; a budget we do not enforce is a denial-of-service primitive
pointed at the operator's own infrastructure.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from core.unpack import Container, ExtractionBudget, Extractor, detect
from core.unpack.budget import BudgetExceeded
from core.unpack.extractor import _safe_join


def make_zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def make_targz(path: Path, entries: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return path


class TestDetection:
    def test_detects_zip(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"f.txt": b"hello world"})
        assert detect(archive).container is Container.ZIP

    def test_detects_targz(self, tmp_path: Path) -> None:
        archive = make_targz(tmp_path / "a.tar.gz", {"f.txt": b"hello world"})
        assert detect(archive).container is Container.GZIP

    def test_jar_is_distinguished_from_plain_zip(self, tmp_path: Path) -> None:
        """Same magic bytes, different meaning. Both unpack; the report should
        not call a JAR a zip."""
        archive = make_zip(tmp_path / "app.jar", {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0"})
        assert detect(archive).container is Container.JAR

    def test_content_beats_extension(self, tmp_path: Path) -> None:
        """A zip named config.dat is exactly the case worth catching —
        installers rename payloads all the time."""
        archive = make_zip(tmp_path / "config.dat", {"secret.txt": b"x" * 64})
        assert detect(archive).container is Container.ZIP

    def test_plain_pe_is_not_a_container(self, tmp_path: Path) -> None:
        binary = tmp_path / "app.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 4096)
        assert detect(binary).should_unpack is False

    def test_pe_carrying_an_nsis_payload_is_a_container(self, tmp_path: Path) -> None:
        installer = tmp_path / "setup.exe"
        installer.write_bytes(b"MZ" + b"\x00" * 2048 + b"NullsoftInst" + b"\x00" * 512)
        detection = detect(installer)
        assert detection.container is Container.NSIS
        assert detection.should_unpack

    def test_installer_marker_in_trailing_overlay_is_found(self, tmp_path: Path) -> None:
        """Installer markers live in overlay data at the end of the file, which
        is precisely where a header-only sniff never looks."""
        installer = tmp_path / "setup.exe"
        installer.write_bytes(b"MZ" + b"\x00" * 200_000 + b"Inno Setup" + b"\x00" * 64)
        assert detect(installer).container is Container.INNO

    def test_tiny_files_are_not_containers(self, tmp_path: Path) -> None:
        small = tmp_path / "x.bin"
        small.write_bytes(b"PK\x03\x04")
        assert detect(small).should_unpack is False


class TestRecursion:
    def test_walks_three_levels_and_records_provenance(self, tmp_path: Path) -> None:
        """The headline capability. A finding must be able to say
        release.zip → payload.tar.gz → config/prod.json."""
        inner = make_targz(
            tmp_path / "payload.tar.gz", {"config/prod.json": b'{"token":"ghp_aaaaaaaaaa"}'}
        )
        outer = make_zip(tmp_path / "release.zip", {"payload.tar.gz": inner.read_bytes()})

        result = Extractor().extract_tree(outer, tmp_path / "out", root_name="release.zip")
        paths = [n.path_in_tree for n in result.nodes]

        assert any("payload.tar.gz" in p for p in paths)
        deepest = max(result.nodes, key=lambda n: n.depth)
        assert deepest.depth >= 2
        assert "config/prod.json" in deepest.path_in_tree
        assert deepest.path_in_tree.startswith("release.zip → ")

    def test_extracted_bytes_are_readable(self, tmp_path: Path) -> None:
        inner = make_targz(tmp_path / "inner.tar.gz", {"secret.txt": b"AKIA2E0A8F3B5C7D9E1F"})
        outer = make_zip(tmp_path / "outer.zip", {"inner.tar.gz": inner.read_bytes()})
        out = tmp_path / "out"

        result = Extractor().extract_tree(outer, out, root_name="outer.zip")
        leaf = next(n for n in result.nodes if n.path_in_tree.endswith("secret.txt"))
        assert (out / leaf.relative_path).read_bytes() == b"AKIA2E0A8F3B5C7D9E1F"

    def test_non_container_leaves_are_recorded_not_recursed(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"notes.txt": b"nothing to see here at all"})
        result = Extractor().extract_tree(archive, tmp_path / "out", root_name="a.zip")

        assert len(result.nodes) == 1
        assert result.nodes[0].container == "none"


class TestBudgets:
    def test_depth_cap_stops_recursion(self, tmp_path: Path) -> None:
        current = make_zip(tmp_path / "level0.zip", {"payload.txt": b"deep payload value"})
        for level in range(1, 6):
            nxt = tmp_path / f"level{level}.zip"
            make_zip(nxt, {f"level{level - 1}.zip": current.read_bytes()})
            current = nxt

        budget = ExtractionBudget(max_depth=2)
        result = Extractor(budget).extract_tree(current, tmp_path / "out", root_name="top.zip")

        assert max(n.depth for n in result.nodes) <= 3
        assert result.truncated or any("max_depth" in e for e in result.errors)

    def test_file_count_cap(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "many.zip", {f"file{i}.txt": b"x" * 32 for i in range(50)})
        budget = ExtractionBudget(max_files=10)
        result = Extractor(budget).extract_tree(archive, tmp_path / "out", root_name="many.zip")

        assert budget.files_written <= 10
        assert result.truncated

    def test_zip_bomb_is_stopped_by_its_own_header(self, tmp_path: Path) -> None:
        """The declared size is checked before a single byte is written, so a
        bomb never reaches the disk at all."""
        bomb = tmp_path / "bomb.zip"
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("huge.bin", b"\x00" * (20 * 1024 * 1024))

        budget = ExtractionBudget(max_total_bytes=1024 * 1024)
        result = Extractor(budget).extract_tree(bomb, tmp_path / "out", root_name="bomb.zip")

        assert budget.bytes_written <= 1024 * 1024
        assert result.truncated
        assert result.nodes == []

    def test_budget_scales_to_input_size(self) -> None:
        budget = ExtractionBudget.for_input(100 * 1024 * 1024)
        assert budget.max_total_bytes == 100 * 1024 * 1024 * 20

    def test_budget_never_exceeds_the_absolute_ceiling(self) -> None:
        budget = ExtractionBudget.for_input(50 * 1024**3)
        assert budget.max_total_bytes == 10 * 1024**3

    def test_reserve_raises_before_writing(self) -> None:
        budget = ExtractionBudget(max_total_bytes=100)
        budget.reserve(60)
        with pytest.raises(BudgetExceeded):
            budget.reserve(60)
        assert budget.bytes_written == 60


class TestPathTraversal:
    """A zip entry named ../../etc/passwd is usually a build-tooling bug rather
    than an attack. Either way it must not escape the output directory."""

    @pytest.mark.parametrize(
        "member",
        ["../escape.txt", "../../etc/passwd", "a/../../../out.txt"],
    )
    def test_traversal_attempts_are_refused(self, tmp_path: Path, member: str) -> None:
        assert _safe_join(tmp_path / "root", member) is None

    @pytest.mark.parametrize("member", ["/absolute/path.txt", "C:/windows/thing.dll"])
    def test_absolute_paths_are_confined_rather_than_dropped(
        self, tmp_path: Path, member: str
    ) -> None:
        """Confined, not refused. An absolute member name is almost always a
        packaging quirk, and the file may well be the one holding the secret —
        so it is rewritten under the extraction root rather than discarded."""
        root = tmp_path / "root"
        root.mkdir()
        resolved = _safe_join(root, member)
        assert resolved is not None
        assert resolved.is_relative_to(root.resolve())

    def test_ordinary_nested_paths_are_allowed(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        resolved = _safe_join(root, "config/nested/prod.json")
        assert resolved is not None
        assert resolved.is_relative_to(root.resolve())

    def test_traversing_entry_is_skipped_without_aborting_the_archive(self, tmp_path: Path) -> None:
        archive = tmp_path / "mixed.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../escaped.txt", b"should not be written anywhere")
            handle.writestr("legitimate.txt", b"this one is fine and long enough")

        result = Extractor().extract_tree(archive, tmp_path / "out", root_name="mixed.zip")

        names = [n.path_in_tree for n in result.nodes]
        assert any("legitimate.txt" in n for n in names)
        assert not any("escaped" in n for n in names)
        assert not (tmp_path / "escaped.txt").exists()
        assert any("path-traversing" in e for e in result.errors)


class TestResilience:
    def test_corrupt_archive_is_recorded_not_fatal(self, tmp_path: Path) -> None:
        """The rest of the tree may still hold the finding."""
        broken = tmp_path / "broken.zip"
        broken.write_bytes(b"PK\x03\x04" + b"\xff" * 512)

        result = Extractor().extract_tree(broken, tmp_path / "out", root_name="broken.zip")
        assert result.errors
        assert result.nodes == []


class TestLargeInstallerDetection:
    """A PE's installer marker lives at the START of its overlay, not at the
    end of the file.

    Found in the field: a 203 MB NSIS installer was classified as an ordinary
    PE with no payload, so nothing was unpacked and the scan reported zero
    findings on 203 MB of compressed data — which reads as "clean". The head
    window stopped at 33 KB and the tail window began 512 KB from the end,
    leaving everything between them unexamined. Installers are the product's
    headline input, and the bug got *more* likely the bigger they were.
    """

    @staticmethod
    def _pe(path: Path, overlay_at: int, total: int, marker: bytes = b"Nullsoft") -> None:
        buf = bytearray(b"\x00" * total)
        buf[0:2] = b"MZ"
        pe = 0x80
        buf[0x3C:0x40] = pe.to_bytes(4, "little")
        buf[pe : pe + 4] = b"PE\x00\x00"
        buf[pe + 6 : pe + 8] = (1).to_bytes(2, "little")
        buf[pe + 20 : pe + 22] = (0xE0).to_bytes(2, "little")
        section = pe + 24 + 0xE0
        buf[section + 16 : section + 20] = (overlay_at - 0x400).to_bytes(4, "little")
        buf[section + 20 : section + 24] = (0x400).to_bytes(4, "little")
        buf[overlay_at : overlay_at + len(marker)] = marker
        path.write_bytes(bytes(buf))

    def test_marker_beyond_the_head_window_is_found(self, tmp_path: Path) -> None:
        """The regression itself: 5 MB in is past the head and nowhere near
        the tail."""
        target = tmp_path / "setup.exe"
        self._pe(target, overlay_at=5_000_000, total=60_000_000)
        assert detect(target).container is Container.NSIS

    def test_small_installer_still_detected(self, tmp_path: Path) -> None:
        target = tmp_path / "setup.exe"
        self._pe(target, overlay_at=20_000, total=200_000)
        assert detect(target).container is Container.NSIS

    def test_inno_setup_in_the_overlay(self, tmp_path: Path) -> None:
        target = tmp_path / "setup.exe"
        self._pe(target, overlay_at=3_000_000, total=20_000_000, marker=b"Inno Setup")
        assert detect(target).container is Container.INNO

    def test_ordinary_pe_is_not_an_installer(self, tmp_path: Path) -> None:
        """The exclusion still has to hold, or every DLL becomes a container."""
        target = tmp_path / "app.exe"
        self._pe(target, overlay_at=20_000, total=200_000, marker=b"ordinary bytes")
        detection = detect(target)
        assert detection.container is Container.NONE
        assert detection.should_unpack is False

    def test_truncated_pe_header_does_not_raise(self, tmp_path: Path) -> None:
        """Hostile artifacts are the input here; a malformed header is a file
        to sniff differently, not an exception to propagate."""
        target = tmp_path / "broken.exe"
        target.write_bytes(b"MZ" + b"\xff" * 4096)
        assert detect(target).container is Container.NONE

    def test_section_table_pointing_past_eof_is_ignored(self, tmp_path: Path) -> None:
        target = tmp_path / "liar.exe"
        self._pe(target, overlay_at=20_000, total=200_000)
        data = bytearray(target.read_bytes())
        section = 0x80 + 24 + 0xE0
        data[section + 20 : section + 24] = (0x7FFFFFFF).to_bytes(4, "little")
        target.write_bytes(bytes(data))
        # Must not raise, and must not seek to a nonsense offset.
        assert detect(target).container in (Container.NONE, Container.NSIS)
