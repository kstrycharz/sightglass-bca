"""The scan pipeline: stage, unpack, scan, correlate, persist.

Two analyzer passes rather than one container per file. The unpack container
walks the artifact recursively and writes the whole tree to disk; the static
container then scans that entire tree in a single pass. A container per
extracted file would turn a 400-file installer into 400 container starts —
minutes of pure overhead for milliseconds of work.

Provenance survives the whole way: every finding location carries the path that
produced it, so the report says
``release.zip → payload.tar.gz → config/prod.json`` rather than naming a
temporary directory.
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
from core.models import Artifact, Evidence, Run, RunManifest, RunStage, Suppression
from core.models.enums import RunStatus, StageStatus
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
UNPACK_IMAGE = os.environ.get("SIGHTGLASS_UNPACK_IMAGE", "sightglass/unpack:dev")
RULES_MOUNT = PurePosixPath("/rules")

UNPACK_TIMEOUT_S = 900
STATIC_TIMEOUT_S = 1800
# Extracted files above this are stored in MinIO; smaller ones are analysed and
# discarded. Retaining every file from every installer would dominate storage
# for little benefit — findings carry their own context snippets.
RETAIN_EXTRACTED_MAX_BYTES = 32 * 1024 * 1024

# Strings no rule matched, sampled for the AI rule-author loop. Collected on
# every scan because it costs one extra pass and is the only honest answer to
# "what did we miss?" — see core/llm/discovery.py.
RESIDUE_SAMPLE_SIZE = 400


@dataclass(slots=True)
class ScanOutcome:
    run_id: str
    status: RunStatus
    finding_count: int = 0
    evidence_count: int = 0
    suppressed_count: int = 0
    artifact_count: int = 1
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
        # Staging holds a plaintext copy of the customer's artifact and
        # everything inside it. It does not outlive the run.
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

    # Layout: the original artifact alone in unpack_in/ (the unpack analyzer
    # expects exactly one), and scan_in/ holding the original plus everything
    # extracted, so the static pass sees the whole tree at once.
    unpack_in = run_dir / "unpack_in"
    unpack_out = run_dir / "unpack_out"
    scan_in = run_dir / "scan_in"
    scan_out = run_dir / "scan_out"
    rules_dir = run_dir / "rules"
    for directory in (unpack_in, unpack_out, scan_in, scan_out, rules_dir):
        directory.mkdir(parents=True, exist_ok=True)

    _stage_rules(Path(settings.repo_root) / "detections", rules_dir)

    artifact_path = unpack_in / root.name
    get_object_store().download_to(str(root.storage_key), artifact_path)

    # --- S2: unpack ------------------------------------------------------
    unpack_result, unpack_payload = _run_unpack(run, session, root, unpack_in, unpack_out)
    artifacts_by_path = _materialise_tree(run, session, root, unpack_payload, unpack_out)

    # --- stage everything for the scanner --------------------------------
    root_staged = scan_in / "root" / root.name
    root_staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact_path, root_staged)
    staged_paths: dict[str, str] = {"root/" + root.name: root.id}

    extracted_dir = unpack_out / "extracted"
    if extracted_dir.is_dir():
        target = scan_in / "extracted"
        shutil.copytree(extracted_dir, target, dirs_exist_ok=True)
        for node in unpack_payload.get("nodes", []):
            relative = node["relative_path"]
            artifact_id = artifacts_by_path.get(node["path_in_tree"])
            if artifact_id:
                staged_paths[f"extracted/{relative}"] = artifact_id

    _grant_analyzer_access(scan_out)

    # --- S3: static scan over the whole tree ------------------------------
    static_result, static_payload = _run_static(run, session, root, scan_in, rules_dir, scan_out)

    evidence = _to_evidence(run, static_payload, staged_paths, root)
    session.add_all(evidence)
    session.flush()

    _apply_identification(session, run, static_payload, staged_paths)

    # --- S6: correlate ----------------------------------------------------
    artifact_paths = {
        artifact.id: artifact.path_in_tree
        for artifact in session.scalars(select(Artifact).where(Artifact.run_id == run.id))
    }
    suppressions = list(session.scalars(select(Suppression)))
    correlation = correlate(
        run.id, evidence, pack, artifact_paths=artifact_paths, suppressions=suppressions
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
            image_digests={
                "unpack": unpack_result.image_digest or "unknown",
                "static": static_result.image_digest or "unknown",
            },
            tool_versions={
                **(unpack_payload.get("tool_versions") or {}),
                **(static_payload.get("tool_versions") or {}),
            },
            residue=static_payload.get("residue") or [],
            recon=static_payload.get("recon") or {},
        )
    )
    _link_previous_run(run, root, session)

    artifact_count = 1 + len(artifacts_by_path)
    log.info(
        "scan.completed",
        run_id=run.id,
        artifacts=artifact_count,
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
        artifact_count=artifact_count,
    )


# --- stages ---------------------------------------------------------------
def _run_unpack(
    run: Run, session: Session, root: Artifact, staging: Path, results: Path
) -> tuple[SandboxResult, dict[str, Any]]:
    _grant_analyzer_access(results)
    stage = RunStage(run_id=run.id, artifact_id=root.id, analyzer="unpack")
    stage.started_at = datetime.now(UTC)
    session.add(stage)
    session.flush()

    driver = driver_from_settings()
    try:
        result = driver.run(
            SandboxSpec(
                image=UNPACK_IMAGE,
                run_id=run.id,
                analyzer="unpack",
                timeout_s=UNPACK_TIMEOUT_S,
                nano_cpus=_analyzer_nano_cpus(),
                mounts=(
                    BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                    BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
                ),
            )
        )
    finally:
        driver.close()

    _record_stage(stage, result)
    payload = _read_result(results) or {}
    nodes = payload.get("nodes", [])
    stage.evidence_count = len(nodes)
    if payload.get("truncated"):
        # Surfaced rather than swallowed: a truncated tree that reports "no
        # findings" would be indistinguishable from a clean artifact.
        stage.status = StageStatus.COMPLETED
        stage.error = "; ".join((payload.get("budget") or {}).get("reasons", []))[:2000]
    return result, payload


def _run_static(
    run: Run, session: Session, root: Artifact, staging: Path, rules_dir: Path, results: Path
) -> tuple[SandboxResult, dict[str, Any]]:
    stage = RunStage(run_id=run.id, artifact_id=root.id, analyzer="static")
    stage.started_at = datetime.now(UTC)
    session.add(stage)
    session.flush()

    command: list[str] = ["--recon", "--emit-residue", str(RESIDUE_SAMPLE_SIZE)]
    if run.retain_plaintext:
        command.append("--include-plaintext")

    driver = driver_from_settings()
    try:
        result = driver.run(
            SandboxSpec(
                image=STATIC_IMAGE,
                run_id=run.id,
                analyzer="static",
                command=tuple(command),
                timeout_s=STATIC_TIMEOUT_S,
                # The static analyzer parallelises across this quota; see
                # Settings.analyzer_cpus for the measurements.
                nano_cpus=_analyzer_nano_cpus(),
                mounts=(
                    BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                    BindMount(str(rules_dir), RULES_MOUNT, MountMode.READ_ONLY),
                    BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
                ),
            )
        )
    finally:
        driver.close()

    _record_stage(stage, result)
    payload = _read_result(results) or {}
    stage.evidence_count = sum(len(f.get("matches", [])) for f in payload.get("files", []))
    return result, payload


# --- tree -----------------------------------------------------------------
def _materialise_tree(
    run: Run,
    session: Session,
    root: Artifact,
    payload: dict[str, Any],
    unpack_out: Path,
) -> dict[str, str]:
    """Turn the unpack manifest into Artifact rows. Returns path_in_tree -> id."""
    by_path: dict[str, str] = {}
    store = get_object_store()
    extracted_dir = unpack_out / "extracted"

    # Sorted by depth so a parent always exists before its children.
    nodes = sorted(payload.get("nodes", []), key=lambda n: (n["depth"], n["path_in_tree"]))
    for node in nodes:
        parent_path = node.get("parent_path_in_tree")
        parent_id = root.id if parent_path == root.path_in_tree else by_path.get(parent_path or "")
        if parent_id is None:
            parent_id = root.id

        on_disk = extracted_dir / node["relative_path"]
        storage_key: str | None = None
        if on_disk.is_file() and node["size_bytes"] <= RETAIN_EXTRACTED_MAX_BYTES:
            try:
                storage_key = store.put_file(on_disk, name=Path(node["relative_path"]).name).key
            except Exception as exc:
                log.warning(
                    "scan.store_extracted_failed", path=node["path_in_tree"], error=str(exc)
                )

        artifact = Artifact(
            run_id=run.id,
            parent_id=parent_id,
            name=Path(node["relative_path"]).name,
            path_in_tree=node["path_in_tree"],
            depth=node["depth"],
            sha256=node.get("sha256") or "",
            size_bytes=node["size_bytes"],
            storage_key=storage_key,
            extracted_by=node.get("extracted_by"),
        )
        session.add(artifact)
        session.flush()
        by_path[node["path_in_tree"]] = artifact.id

    return by_path


def _to_evidence(
    run: Run,
    payload: dict[str, Any],
    staged_paths: dict[str, str],
    root: Artifact,
) -> list[Evidence]:
    rows: list[Evidence] = []
    for entry in payload.get("files", []):
        artifact_id = staged_paths.get(entry.get("relative_path", ""))
        if artifact_id is None:
            # A file the scanner saw but the tree does not know about. Attribute
            # it to the root rather than dropping the finding on the floor.
            artifact_id = root.id
        for match in entry.get("matches", []):
            rows.append(
                Evidence(
                    run_id=run.id,
                    artifact_id=artifact_id,
                    analyzer="static",
                    rule_id=match["rule_id"],
                    value_hash=match["value_hash"],
                    value_masked=match["value_masked"],
                    value_plaintext=(
                        match.get("value_plaintext") if run.retain_plaintext else None
                    ),
                    offset=match.get("offset"),
                    encoding=match.get("encoding"),
                    entropy=match.get("entropy"),
                    context_snippet=match.get("context"),
                )
            )
    return rows


def _apply_identification(
    session: Session, run: Run, payload: dict[str, Any], staged_paths: dict[str, str]
) -> None:
    by_id = {
        artifact.id: artifact
        for artifact in session.scalars(select(Artifact).where(Artifact.run_id == run.id))
    }
    for entry in payload.get("files", []):
        artifact = by_id.get(staged_paths.get(entry.get("relative_path", ""), ""))
        if artifact is None:
            continue
        artifact.kind = entry.get("kind", artifact.kind)
        artifact.media_type = entry.get("media_type")
        artifact.architecture = entry.get("architecture")
        artifact.identified = {
            k: v
            for k, v in entry.items()
            if k
            not in ("kind", "media_type", "architecture", "matches", "relative_path", "size_bytes")
        }


# --- helpers --------------------------------------------------------------
def _stage_rules(source: Path, destination: Path) -> None:
    """The rule pack travels with the run rather than being baked into the
    image, so a rule change takes effect without a rebuild and the manifest
    still records exactly which pack ran."""
    for rule_file in sorted(source.glob("*.yaml")):
        shutil.copy2(rule_file, destination / rule_file.name)
    version_file = source / "VERSION"
    if version_file.is_file():
        shutil.copy2(version_file, destination / "VERSION")


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


def _analyzer_nano_cpus() -> int:
    """CPU quota for an analyzer container, from settings, in nano-CPUs.

    Floored at one whole core: a fractional quota makes the analyzer's own
    cgroup read round down to a single worker anyway, and a sub-core quota
    turns a CPU-bound scan into a timeout.
    """
    cpus = max(1.0, get_settings().analyzer_cpus)
    return int(cpus * 1_000_000_000)


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
