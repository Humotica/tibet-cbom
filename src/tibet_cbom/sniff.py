from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


TBZ_MAGIC = b"\x54\x42\x5A"
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
PDF_MAGIC = b"%PDF"
JSON_HINT_OPEN = b"{"
JSON_HINT_LIST = b"["

SEALED_EXTENSIONS = frozenset({
    "tza", "tbz", "claude", "gemini", "gpt", "kit", "iddrop",
    "parentattest", "capsule", "marco", "richard", "jasper",
    "codex", "aint",
})

STAGING_SUFFIXES = frozenset({"part", "tmp", "writing", "inflight"})


class IntakeClass(Enum):
    SEALED_TBZ = "sealed-tbz"
    SEALED_TBZ_NO_EXT = "sealed-tbz-no-ext"
    DISGUISED = "disguised"
    EXECUTABLE = "executable"
    PDF = "pdf"
    JSON_TEXT = "json-text"
    UNKNOWN = "unknown"
    EMPTY = "empty"
    STAGING = "staging"


@dataclass
class SniffResult:
    intake_class: IntakeClass
    extension: str
    surface_extension_implies_sealed: bool
    magic_prefix_hex: str
    size_bytes: int
    disposition_hint: str


def _read_prefix(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return b""


def _classify_disposition(intake: IntakeClass) -> str:
    if intake in {IntakeClass.SEALED_TBZ, IntakeClass.SEALED_TBZ_NO_EXT}:
        return "trusted-candidate"
    if intake == IntakeClass.DISGUISED:
        return "triage-disguised"
    if intake == IntakeClass.EXECUTABLE:
        return "quarantine"
    if intake == IntakeClass.PDF:
        return "reject"
    if intake == IntakeClass.JSON_TEXT:
        return "reseal-candidate"
    if intake == IntakeClass.STAGING:
        return "ignore"
    if intake == IntakeClass.EMPTY:
        return "reject"
    return "quarantine"


def sniff_payload(path: Path) -> SniffResult:
    if not path.exists() or not path.is_file():
        return SniffResult(
            intake_class=IntakeClass.UNKNOWN,
            extension="",
            surface_extension_implies_sealed=False,
            magic_prefix_hex="",
            size_bytes=0,
            disposition_hint="quarantine",
        )

    extension = path.suffix.lstrip(".").lower()
    if extension in STAGING_SUFFIXES:
        return SniffResult(
            intake_class=IntakeClass.STAGING,
            extension=extension,
            surface_extension_implies_sealed=False,
            magic_prefix_hex="",
            size_bytes=path.stat().st_size,
            disposition_hint="ignore",
        )

    size_bytes = path.stat().st_size
    if size_bytes == 0:
        return SniffResult(
            intake_class=IntakeClass.EMPTY,
            extension=extension,
            surface_extension_implies_sealed=False,
            magic_prefix_hex="",
            size_bytes=0,
            disposition_hint="reject",
        )

    prefix = _read_prefix(path, 16)
    surface_implies_sealed = extension in SEALED_EXTENSIONS
    magic_hex = prefix[:8].hex()

    if prefix.startswith(TBZ_MAGIC):
        intake = (
            IntakeClass.SEALED_TBZ
            if surface_implies_sealed else
            IntakeClass.SEALED_TBZ_NO_EXT
        )
        return SniffResult(
            intake_class=intake,
            extension=extension,
            surface_extension_implies_sealed=surface_implies_sealed,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint=_classify_disposition(intake),
        )

    if surface_implies_sealed:
        return SniffResult(
            intake_class=IntakeClass.DISGUISED,
            extension=extension,
            surface_extension_implies_sealed=True,
            magic_prefix_hex=magic_hex,
            size_bytes=size_bytes,
            disposition_hint="triage-disguised",
        )

    if prefix.startswith(ELF_MAGIC) or prefix.startswith(PE_MAGIC):
        intake = IntakeClass.EXECUTABLE
    elif prefix.startswith(PDF_MAGIC):
        intake = IntakeClass.PDF
    else:
        stripped = prefix.lstrip(b" \t\n\r")
        if stripped.startswith(JSON_HINT_OPEN) or stripped.startswith(JSON_HINT_LIST):
            intake = IntakeClass.JSON_TEXT
        else:
            intake = IntakeClass.UNKNOWN

    return SniffResult(
        intake_class=intake,
        extension=extension,
        surface_extension_implies_sealed=False,
        magic_prefix_hex=magic_hex,
        size_bytes=size_bytes,
        disposition_hint=_classify_disposition(intake),
    )
