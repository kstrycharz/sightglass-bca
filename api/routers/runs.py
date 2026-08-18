"""Run management: upload, list, detail, progress, triage."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.schemas.models import (
    ArtifactOut,
    ManifestOut,
    RunCreated,
    RunDetail,
    RunSummary,
    StageOut,
    TriageResponse,
)
from core.db import get_session, session_scope
from core.models import Artifact, Finding, FindingLocation, Run, RunStage
from core.models.enums import RunStatus
from core.pipeline.ingest import AttestationRequired, ingest_artifact

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/runs", tags=["runs"])


@router.post("", response_model=RunCreated, status_code=status.HTTP_201_CREATED)
async def create_run(
    file: Annotated[UploadFile, File(description="The artifact to analyse.")],
    profile: Annotated[str, Form()] = "standard",
    attested_by: Annotated[str, Form(description="Who is attesting authorization.")] = "",
    attestation_reference: Annotated[
        str, Form(description="Contract, ticket, or engagement reference.")
    ] = "",
    llm_enabled: Annotated[bool, Form()] = False,
    retain_plaintext: Annotated[bool, Form()] = False,
) -> RunCreated:
    """Upload an artifact and queue a scan.

    The attestation is not optional and not a checkbox: it is recorded in the
    audit log and stamped into every report. An upload without one is rejected
    (§14).
    """
    if not file.filename:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "a filename is required")

    try:
        with session_scope() as session:
            result = ingest_artifact(
                session,
                file.file,
                filename=file.filename,
                attested_by=attested_by,
                attestation_reference=attestation_reference,
                profile=profile,
                llm_enabled=llm_enabled,
                retain_plaintext=retain_plaintext,
            )
            payload = RunCreated(
                run_id=result.run.id,
                artifact_name=result.artifact.name,
                artifact_sha256=result.artifact.sha256,
                size_bytes=result.artifact.size_bytes,
                status=result.run.status,
            )
    except AttestationRequired as exc:
        # 422 rather than 400: the request was well-formed, the authorization
        # claim was not adequate.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None

    from core.orchestrator.tasks import scan_run

    scan_run.delay(payload.run_id)
    return payload


@router.get("", response_model=list[RunSummary])
def list_runs(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(le=200)] = 50,
    offset: int = 0,
) -> list[RunSummary]:
    runs = session.scalars(
        select(Run).order_by(Run.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return [_summarise(session, run) for run in runs]


@router.get("/{run_id}", response_model=RunDetail)
def get_run(run_id: str, session: Annotated[Session, Depends(get_session)]) -> RunDetail:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"run {run_id} not found")

    summary = _summarise(session, run)
    stages = session.scalars(
        select(RunStage).where(RunStage.run_id == run_id).order_by(RunStage.created_at)
    ).all()

    manifest = None
    if run.manifest is not None:
        manifest = ManifestOut.model_validate(run.manifest)
        manifest.fingerprint = run.manifest.fingerprint

    return RunDetail(
        **summary.model_dump(),
        stages=[StageOut.model_validate(s) for s in stages],
        manifest=manifest,
        artifact_tree=_build_tree(session, run),
        previous_run_id=run.previous_run_id,
    )


@router.get("/{run_id}/events")
async def stream_events(run_id: str) -> StreamingResponse:
    """Server-sent progress.

    SSE rather than WebSocket (§4): it survives corporate proxies that mangle
    upgrade handshakes, and reconnection semantics come free.
    """

    async def generate() -> AsyncIterator[str]:
        last: str | None = None
        for _ in range(600):  # ~20 minutes at 2s, then the client reconnects
            with session_scope() as session:
                run = session.get(Run, run_id)
                if run is None:
                    yield _sse({"error": "run not found"})
                    return
                stages = session.scalars(select(RunStage).where(RunStage.run_id == run_id)).all()
                payload = {
                    "status": run.status,
                    "stages": [
                        {"analyzer": s.analyzer, "status": s.status, "duration_s": s.duration_s}
                        for s in stages
                    ],
                    "finding_count": session.scalar(
                        select(func.count()).select_from(Finding).where(Finding.run_id == run_id)
                    )
                    or 0,
                }
                terminal = RunStatus(run.status).is_terminal

            serialised = json.dumps(payload, sort_keys=True)
            if serialised != last:
                # Only emit on change: a client left open on a finished run
                # should cost nothing.
                yield _sse(payload)
                last = serialised
            if terminal:
                return
            await asyncio.sleep(2)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, sort_keys=True)}\n\n"


@router.post("/{run_id}/triage", response_model=TriageResponse)
def triage(run_id: str) -> TriageResponse:
    """Run LLM triage over this run's findings.

    Explicitly triggered. Triage never runs implicitly, because a scan must
    complete and be useful whether or not a model is reachable (§2.5).
    """
    from core.orchestrator.tasks import triage_run_task

    try:
        result = triage_run_task.apply(args=[run_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return TriageResponse(**result)


def _summarise(session: Session, run: Run) -> RunSummary:
    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.parent_id.is_(None))
    ).first()

    rows = session.execute(
        select(Finding.severity, func.count())
        .where(Finding.run_id == run.id)
        .group_by(Finding.severity)
    ).all()
    counts = dict(rows)

    new_since = None
    if run.previous_run_id:
        previous_ids = set(
            session.scalars(select(Finding.id).where(Finding.run_id == run.previous_run_id)).all()
        )
        current_ids = set(session.scalars(select(Finding.id).where(Finding.run_id == run.id)).all())
        # Finding IDs are content-derived, so "what is new" is a set difference
        # rather than a fuzzy match (§2.5).
        new_since = len(current_ids - previous_ids)

    artifact_count = (
        session.scalar(select(func.count()).select_from(Artifact).where(Artifact.run_id == run.id))
        or 1
    )

    return RunSummary(
        id=run.id,
        status=run.status,
        profile=run.profile,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error=run.error,
        attested_by=run.attested_by,
        attestation_reference=run.attestation_reference,
        llm_enabled=run.llm_enabled,
        artifact_name=root.name if root else None,
        artifact_sha256=root.sha256 if root else None,
        artifact_size_bytes=root.size_bytes if root else None,
        finding_count=sum(counts.values()),
        severity_counts=counts,
        artifact_count=artifact_count,
        new_since_previous=new_since,
    )


def _build_tree(session: Session, run: Run) -> ArtifactOut | None:
    artifacts = session.scalars(select(Artifact).where(Artifact.run_id == run.id)).all()
    if not artifacts:
        return None

    # Findings per artifact, so a tree node carries a badge and the operator can
    # see at a glance which nested file is the problem — which is the whole
    # reason for showing the tree rather than a flat list.
    finding_counts: dict[str, int] = dict(
        session.execute(
            select(FindingLocation.artifact_id, func.count())
            .where(FindingLocation.run_id == run.id)
            .group_by(FindingLocation.artifact_id)
        ).all()
    )

    by_parent: dict[str | None, list[Artifact]] = {}
    for artifact in sorted(artifacts, key=lambda a: (a.depth, a.path_in_tree)):
        by_parent.setdefault(artifact.parent_id, []).append(artifact)

    def build(artifact: Artifact) -> ArtifactOut:
        node = ArtifactOut.model_validate(artifact)
        node.finding_count = finding_counts.get(artifact.id, 0)
        node.children = [build(child) for child in by_parent.get(artifact.id, [])]
        return node

    roots = by_parent.get(None, [])
    return build(roots[0]) if roots else None


@router.post("/{run_id}/discover")
def discover(run_id: str) -> dict[str, Any]:
    """Propose detection rules for what this run's rule pack missed.

    The AI author loop. It reads the strings no rule matched and proposes
    patterns; the response is YAML for a human to review and merge. Nothing
    here alters the run's findings, and a proposal that is never merged has no
    effect on anything.
    """
    from core.orchestrator.tasks import discover_rules_task

    try:
        result: dict[str, Any] = discover_rules_task.apply(args=[run_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error") and not result.get("proposals"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return result
