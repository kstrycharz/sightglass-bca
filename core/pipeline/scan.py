"""The scan pipeline: stage an artifact, run analyzers, correlate, persist.

M1 handles a single artifact. Recursive unpacking (S2) turns the single
``_run_static`` call into a fan-out over the artifact tree in M2; the shape
here is built for that — staging is per-artifact, and evidence is keyed by
artifact id rather than assumed to belong to the root.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import SIGHTGLASS_VERSION, get_settings
from core.models import (
    Artifact,
    AuditLog,
    Evidence,
    Run,
    RunManifest,
    RunStage,
    Suppression,
)
from core.models.enums import AuditAction, RunStatus, StageStatus
from core.pipeline.correlator import correlate
from core.rules import load_rule_pack
from core.sandbox import (
    BindMount,
    MountMode,
    SandboxResult,
    SandboxSpec,
    SandboxStatus,
    driver_from_settings,
)
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR
from core.storage import get_object_store

log = structlog.get_logger(__name__)

STATIC_IMAGE = os.environ.get("SIGHTGLASS_STATIC_IMAGE", "sightglass/static:dev")
# A container path, not a host one — PurePosixPath so it is correct even when
# the orchestrator runs on Windows.
RULES_MOUNT = PurePosixPath("/rules")


@dataclass(slots=True)
class ScanOutcome:
    run_id: str
    status: RunStatus
    finding_count: int = 0
    evidence_count: int = 0
    suppressed_count: int = 0
    error: str | None = None


def run_scan(run_id: str, session: Session) -> ScanOutcome:
    """Execute a full scan. Owns the run's state transitions."""
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")

    run.status = RunStatus.RUNNING
    run.started_at = datetime.now(UTC)
    session.flush()

    settings = get_settings()
    run_dir = Path(settings.run_root) / run_id
    try:
        outcome = _execute(run, session, run_dir)
    except Exception as exc:
        log.exception("scan.failed", run_id=run_id)
        run.status = RunStatus.FAILED
        run.error = str(exc)[:2000]
        run.finished_at = datetime.now(UTC)
        return ScanOutcome(run_id=run_id, status=RunStatus.FAILED, error=str(exc))
    finally:
        # Staging holds a decrypted copy of the customer's artifact. It does not
        # outlive the run.
        shutil.rmtree(run_dir, ignore_errors=True)

    run.status = RunStatus.COMPLETED
    run.finished_at = datetime.now(UTC)
    return outcome


def _execute(run: Run, session: Session, run_dir: Path) -> ScanOutcome:
    settings = get_settings()
    pack = load_rule_pack(Path(settings.repo_root) / "detections")

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.parent_id.is_(None))
    ).first()
    if root is None:
        raise LookupError(f"run {run.id} has no root artifact")

    staging = run_dir / "staging"
    rules_dir = run_dir / "rules"
    results = run_dir / "results" / "static"
    for directory in (staging, rules_dir, results):
        directory.mkdir(parents=True, exist_ok=True)

    # The rule pack travels with the run rather than being baked into the
    # image, so a rule change takes effect without an image rebuild and the
    # manifest still records exactly which pack ran.
    source_rules = Path(settings.repo_root) / "detections"
    for rule_file in sorted(source_rules.glob("*.yaml")):
        shutil.copy2(rule_file, rules_dir / rule_file.name)
    version_file = source_rules / "VERSION"
    if version_file.is_file():
        shutil.copy2(version_file, rules_dir / "VERSION")

    artifact_path = staging / root.name
    get_object_store().download_to(str(root.storage_key), artifact_path)
    _grant_analyzer_access(results)

    stage = RunStage(run_id=run.id, artifact_id=root.id, analyzer="static")
    stage.started_at = datetime.now(UTC)
    session.add(stage)
    session.flush()

    result = _run_static(run, staging, rules_dir, results)
    _record_stage(stage, result)

    evidence: list[Evidence] = []
    if result.status is SandboxStatus.COMPLETED and result.exit_code == 0:
        payload = _read_result(results)
        if payload:
            _apply_identification(root, payload)
            evidence = _to_evidence(run, root, payload)
            session.add_all(evidence)
            stage.evidence_count = len(evidence)
    session.flush()

    suppressions = list(session.scalars(select(Suppression)))
    correlation = correlate(
        run.id,
        evidence,
        pack,
        artifact_paths={root.id: root.path_in_tree},
        suppressions=suppressions,
    )
    session.add_all(correlation.findings)
    session.flush()
    session.add_all(correlation.locations)

    session.add(
        RunManifest(
            run_id=run.id,
            sightglass_version=SIGHTGLASS_VERSION,
            artifact_sha256=root.sha256,
            rule_pack_version=pack.version,
            rule_pack_hash=pack.hash,
            image_digests={"static": result.image_digest or "unknown"},
            tool_versions=_read_tool_versions(results),
        )
    )
    _link_previous_run(run, root, session)

    log.info(
        "scan.completed",
        run_id=run.id,
        evidence=len(evidence),
        findings=len(correlation.findings),
        suppressed=correlation.suppressed,
        by_severity=correlation.counts_by_severity,
    )
    return ScanOutcome(
        run_id=run.id,
        status=RunStatus.COMPLETED,
        finding_count=len(correlation.findings),
        evidence_count=len(evidence),
        suppressed_count=correlation.suppressed,
    )


def _run_static(run: Run, staging: Path, rules_dir: Path, results: Path) -> SandboxResult:
    command: list[str] = []
    if run.retain_plaintext:
        # Only for runs that explicitly opted in (§14). Otherwise the value
        # never leaves the container.
        command.append("--include-plaintext")

    driver = driver_from_settings()
    try:
        spec = SandboxSpec(
            image=STATIC_IMAGE,
            run_id=run.id,
            analyzer="static",
            command=tuple(command),
            timeout_s=900,
            mounts=(
                BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                BindMount(str(rules_dir), RULES_MOUNT, MountMode.READ_ONLY),
                BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
            ),
        )
        return driver.run(spec)
    finally:
        driver.close()


def _record_stage(stage: RunStage, result: SandboxResult) -> None:
    stage.finished_at = datetime.now(UTC)
    stage.duration_s = round(result.duration_s, 3)
    stage.exit_code = result.exit_code
    stage.image_digest = result.image_digest
    stage.error = result.error or (
        result.stderr.decode("utf-8", "replace")[:2000] if result.exit_code else None
    )
    stage.status = {
        SandboxStatus.COMPLETED: (
            StageStatus.COMPLETED if result.exit_code == 0 else StageStatus.FAILED
        ),
        SandboxStatus.TIMEOUT: StageStatus.TIMEOUT,
        SandboxStatus.OOM: StageStatus.OOM,
        SandboxStatus.START_FAILED: StageStatus.FAILED,
        SandboxStatus.ERROR: StageStatus.FAILED,
    }[result.status]


def _read_result(results: Path) -> dict[str, Any] | None:
    path = results / "result.json"
    if not path.is_file():
        return None
    try:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.warning("scan.unparseable_result", error=str(exc))
        return None
    return payload


def _read_tool_versions(results: Path) -> dict[str, Any]:
    payload = _read_result(results) or {}
    versions: dict[str, Any] = payload.get("tool_versions", {})
    return versions


def _apply_identification(artifact: Artifact, payload: dict[str, Any]) -> None:
    identified = payload.get("artifact", {})
    artifact.kind = identified.get("kind", artifact.kind)
    artifact.media_type = identified.get("media_type")
    artifact.architecture = identified.get("architecture")
    artifact.identified = {
        k: v
        for k, v in identified.items()
        if k not in ("kind", "media_type", "architecture", "name")
    }


def _to_evidence(run: Run, artifact: Artifact, payload: dict[str, Any]) -> list[Evidence]:
    rows: list[Evidence] = []
    for match in payload.get("matches", []):
        rows.append(
            Evidence(
                run_id=run.id,
                artifact_id=artifact.id,
                analyzer="static",
                rule_id=match["rule_id"],
                value_hash=match["value_hash"],
                value_masked=match["value_masked"],
                value_plaintext=match.get("value_plaintext") if run.retain_plaintext else None,
                offset=match.get("offset"),
                encoding=match.get("encoding"),
                entropy=match.get("entropy"),
                context_snippet=match.get("context"),
            )
        )
    return rows


def _link_previous_run(run: Run, root: Artifact, session: Session) -> None:
    """Point this run at the last completed run of a same-named artifact.

    "What is new since the last release" is the question CI actually asks, and
    answering it needs a predecessor recorded at scan time rather than guessed
    at report time.
    """
    previous = session.scalars(
        select(Run)
        .join(Artifact, Artifact.run_id == Run.id)
        .where(
            Run.id != run.id,
            Run.status == RunStatus.COMPLETED,
            Artifact.parent_id.is_(None),
            Artifact.name == root.name,
        )
        .order_by(Run.created_at.desc())
        .limit(1)
    ).first()
    if previous is not None:
        run.previous_run_id = previous.id


def _grant_analyzer_access(path: Path) -> None:
    """The analyzer runs as uid 10001 and must be able to write its results.

    No-op on Windows, where Docker Desktop bind mounts do not carry POSIX
    ownership and the container already sees a permissive mount.
    """
    if os.name == "nt":
        return
    from core.sandbox.spec import ANALYZER_GID, ANALYZER_UID

    chown = getattr(os, "chown", None)
    if chown is None:  # pragma: no cover - Windows returns early above
        return
    try:
        chown(path, ANALYZER_UID, ANALYZER_GID)
    except (PermissionError, OSError):
        path.chmod(0o777)


def record_audit(session: Session, action: AuditAction, **kwargs: Any) -> None:
    session.add(AuditLog.record(action, **kwargs))
