"""Analysis tasks.

Kept separate from ``tasks.py`` (which holds the operational tasks) so the
import graph stays legible as the stage count grows.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select

from core.db import session_scope
from core.orchestrator.celery_app import QUEUE_LLM, QUEUE_STATIC, celery_app

log = structlog.get_logger(__name__)


@celery_app.task(name="sightglass.scan_run", queue=QUEUE_STATIC, bind=True, max_retries=0)
def scan_run(self: Any, run_id: str) -> dict[str, Any]:
    """Run the full scan pipeline for one run.

    ``max_retries=0`` on purpose: analyzer containers are not free, and a
    retried scan of a hung artifact just hangs again. The run state machine
    records the failure and a human decides whether to re-run.
    """
    from core.pipeline.scan import run_scan

    with session_scope() as session:
        outcome = run_scan(run_id, session)

    return {
        "run_id": outcome.run_id,
        "status": str(outcome.status),
        "findings": outcome.finding_count,
        "evidence": outcome.evidence_count,
        "suppressed": outcome.suppressed_count,
        "error": outcome.error,
    }


@celery_app.task(name="sightglass.triage_run", queue=QUEUE_LLM, max_retries=0)
def triage_run_task(run_id: str) -> dict[str, Any]:
    """Run LLM triage over a completed run's findings.

    Never implicit, and never fatal. If the model is unreachable this returns
    an error and the deterministic report stands entirely unchanged — that is
    the §2.5 guarantee, and it is why triage is a separate task rather than a
    stage of the scan.
    """
    from core.llm import LLMConfigError, load_config, provider_for_role, triage_run
    from core.models import Finding, FindingLocation

    try:
        config = load_config()
        if not config.enabled:
            return {"run_id": run_id, "error": "the LLM layer is disabled in config/llm.yaml"}
        provider = provider_for_role("triage", config)
    except (LLMConfigError, NotImplementedError) as exc:
        return {"run_id": run_id, "error": str(exc)}

    health = provider.health()
    if not health.healthy:
        return {"run_id": run_id, "error": f"triage provider unavailable: {health.detail}"}

    # Page the model in first. On bandwidth-bound hardware a cold 9 GB model
    # takes 20+ seconds to load and then answers in two — without this, that
    # load time lands on the first finding and looks like the model is slow.
    warm = getattr(provider, "warm", None)
    if callable(warm):
        warm()

    with session_scope() as session:
        findings = list(session.scalars(select(Finding).where(Finding.run_id == run_id)))
        if not findings:
            return {
                "run_id": run_id,
                "triaged": 0,
                "confirmed": 0,
                "dismissed": 0,
                "needs_review": 0,
                "errors": 0,
                "duration_s": 0.0,
                "model": provider.model,
            }

        locations = session.scalars(
            select(FindingLocation).where(FindingLocation.run_id == run_id)
        ).all()
        paths: dict[str, str] = {}
        counts: dict[str, int] = {}
        for location in locations:
            paths.setdefault(location.finding_id, location.path_in_tree)
            counts[location.finding_id] = counts.get(location.finding_id, 0) + 1

        result = triage_run(provider, findings, paths, run_id=run_id, location_counts=counts)
        session.add_all(result.calls)

    return {
        "run_id": run_id,
        "triaged": result.triaged,
        "confirmed": result.confirmed,
        "dismissed": result.dismissed,
        "needs_review": result.needs_review,
        "errors": result.errors,
        "duration_s": round(result.total_duration_s, 2),
        "model": provider.model,
    }
