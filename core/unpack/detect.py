"""Container-format detection.

Deciding *what* a file is, so the unpacker knows whether to open it and with
which tool. Content sniffing first, extension second: a `config.dat` that is
really a zip is exactly the case worth catching, and installers routinely
rename their payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Container(StrEnum):
    """A format the unpacker can open."""

    ZIP = "zip"
    SEVENZIP = "7z"
    TAR = "tar"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    RAR = "rar"
    CAB = "cab"
    MSI = "msi"
    ISO = "iso"
    NSIS = "nsis"
    INNO = "inno"
    SQUASHFS = "squashfs"
    CPIO = "cpio"
    DMG = "dmg"
    ASAR = "asar"
    PYINSTALLER = "pyinstaller"
    JAR = "jar"
    APK = "apk"
    NONE = "none"

    @property
    def is_container(self) -> bool:
        return self is not Container.NONE


@dataclass(frozen=True, slots=True)
class Detection:
    container: Container
    confidence: float
    reason: str

    @property
    def should_unpack(self) -> bool:
        return self.container.is_container and self.confidence >= 0.5


# (offset, magic bytes, container). Ordered most specific first: a JAR is a
# zip, an APK is a zip, and an ASAR is not — so the zip signature must be
# checked *after* the more specific extension tests.
_MAGIC: tuple[tuple[int, bytes, Container], ...] = (
    (0, b"7z\xbc\xaf\x27\x1c", Container.SEVENZIP),
    (0, b"Rar!\x1a\x07", Container.RAR),
    (0, b"MSCF", Container.CAB),
    (0, b"hsqs", Container.SQUASHFS),
    (0, b"sqsh", Container.SQUASHFS),
    (0, b"\xfd7zXZ\x00", Container.XZ),
    (0, b"BZh", Container.BZIP2),
    (0, b"\x1f\x8b", Container.GZIP),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", Container.MSI),
    (0, b"070701", Container.CPIO),
    (0, b"070707", Container.CPIO),
    (257, b"ustar", Container.TAR),
    (0x8001, b"CD001", Container.ISO),
    (0, b"PK\x03\x04", Container.ZIP),
    (0, b"PK\x05\x06", Container.ZIP),
)

_ZIP_FAMILY_EXTENSIONS = {
    ".jar": Container.JAR,
    ".war": Container.JAR,
    ".ear": Container.JAR,
    ".apk": Container.APK,
    ".aab": Container.APK,
    ".ipa": Container.ZIP,
    ".whl": Container.ZIP,
    ".nupkg": Container.ZIP,
    ".vsix": Container.ZIP,
    ".xpi": Container.ZIP,
    ".docx": Container.ZIP,
    ".xlsx": Container.ZIP,
    ".pptx": Container.ZIP,
    ".appx": Container.ZIP,
}

_EXTENSION_ONLY = {
    ".asar": Container.ASAR,
    ".tgz": Container.GZIP,
    ".tbz2": Container.BZIP2,
    ".txz": Container.XZ,
    ".dmg": Container.DMG,
}

# Markers that identify a PE as a self-extracting installer rather than an
# ordinary executable. Found by scanning the file, not by trusting the name.
_PE_INSTALLER_MARKERS: tuple[tuple[bytes, Container], ...] = (
    (b"Nullsoft", Container.NSIS),
    (b"NullsoftInst", Container.NSIS),
    (b"Inno Setup", Container.INNO),
    (b"JR.Inno.Setup", Container.INNO),
    (b"_MEIPASS", Container.PYINSTALLER),
    (b"MEI\x0c\x0b\x0a\x0b\x0e", Container.PYINSTALLER),
    (b"PyInstaller", Container.PYINSTALLER),
)

_SNIFF_BYTES = 0x8100
# Installer markers live in overlay data at the end of the file, which is
# exactly where a header-only sniff never looks.
_TAIL_BYTES = 512 * 1024


def detect(path: Path) -> Detection:
    """Identify the container format of ``path``, if any."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(_SNIFF_BYTES)
            if size > _SNIFF_BYTES:
                handle.seek(max(0, size - _TAIL_BYTES))
                tail = handle.read(_TAIL_BYTES)
            else:
                tail = b""
    except OSError as exc:
        return Detection(Container.NONE, 0.0, f"unreadable: {exc}")

    if size < 16:
        return Detection(Container.NONE, 1.0, "too small to be a container")

    suffix = path.suffix.lower()

    if suffix in _EXTENSION_ONLY:
        return Detection(_EXTENSION_ONLY[suffix], 0.7, f"extension {suffix}")

    for offset, magic, container in _MAGIC:
        window = head[offset : offset + len(magic)]
        if window != magic:
            continue

        if container is Container.ZIP and suffix in _ZIP_FAMILY_EXTENSIONS:
            # Same bytes, different meaning: a JAR wants its manifest read, an
            # APK its resources. Both still unpack as zip.
            return Detection(_ZIP_FAMILY_EXTENSIONS[suffix], 0.95, f"zip signature with {suffix}")
        return Detection(container, 0.95, f"magic at offset {offset}")

    # A PE that carries an installer payload. Checked last because most PEs are
    # not installers, and the scan is comparatively expensive.
    if head.startswith(b"MZ"):
        haystack = head + tail
        for marker, container in _PE_INSTALLER_MARKERS:
            if marker in haystack:
                return Detection(container, 0.85, f"PE containing {marker.decode('latin-1')!r}")
        return Detection(Container.NONE, 0.9, "PE with no installer payload detected")

    return Detection(Container.NONE, 0.8, "no container signature")


def is_probably_text(path: Path, sample_bytes: int = 4096) -> bool:
    """Whether a file is text. Text files are never containers, and skipping
    detection on them keeps large source trees cheap to walk."""
    try:
        with path.open("rb") as handle:
            sample = handle.read(sample_bytes)
    except OSError:
        return False
    if not sample or b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(sample) > 0.90
