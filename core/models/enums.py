"""Shared vocabulary.

These are plain ``StrEnum`` and stored as strings rather than as PostgreSQL
enum types: adding a severity or a status should be a code change and a
migration of *data*, not an ``ALTER TYPE`` that locks the table.
"""

from __future__ import annotations

from enum import StrEnum

# Re-exported: Severity lives in core.vocab so the detection engine can be
# imported inside analyzer containers without pulling in a database layer.
from core.vocab import Severity as Severity


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED)


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    OOM = "oom"
    FAILED = "failed"
    SKIPPED = "skipped"

    @property
    def is_degraded(self) -> bool:
        """Degraded stages still let the run finish, but the report must say so
        rather than implying the artifact was clean."""
        return self in (StageStatus.TIMEOUT, StageStatus.OOM, StageStatus.FAILED)


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    NEEDS_REVIEW = "needs_review"

    @property
    def is_actionable(self) -> bool:
        return self in (FindingStatus.OPEN, FindingStatus.CONFIRMED, FindingStatus.NEEDS_REVIEW)


class DetectedBy(StrEnum):
    """Provenance. The UI renders these in visually distinct treatments and the
    'deterministic view only' toggle hides anything that is not ``RULE``.

    ``LLM`` alone is deliberately not a permitted value on a persisted finding:
    a model may never assert a finding into existence (§2.5). It exists in the
    enum so that the constraint can be expressed and tested.
    """

    RULE = "rule"
    BOTH = "both"
    LLM = "llm"


class ArtifactKind(StrEnum):
    """What S1 identified. Drives which unpackers and analyzers get scheduled."""

    UNKNOWN = "unknown"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DOTNET = "dotnet"
    JAVA = "java"
    ARCHIVE = "archive"
    INSTALLER = "installer"
    FIRMWARE = "firmware"
    FILESYSTEM = "filesystem"
    SCRIPT = "script"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    DATA = "data"
    TEXT = "text"


class LlmVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    ERROR = "error"
    """The model was unreachable or returned unparseable output. Recorded
    rather than hidden — a run where triage silently did nothing must not look
    like a run where triage confirmed everything."""


class AuditAction(StrEnum):
    RUN_CREATED = "run_created"
    ARTIFACT_UPLOADED = "artifact_uploaded"
    ATTESTATION_RECORDED = "attestation_recorded"
    PLAINTEXT_REVEALED = "plaintext_revealed"
    FINDING_STATUS_CHANGED = "finding_status_changed"
    SUPPRESSION_CREATED = "suppression_created"
    LLM_CALL = "llm_call"
    EXPORT = "export"
    CONFIG_CHANGED = "config_changed"
