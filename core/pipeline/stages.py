"""Which analyzer stages did not finish.

One definition, used twice: the scan pipeline sets the run's status from it,
and the release gate decides from it whether a scan can support a PASS. Those
two answers must never disagree — a run displayed as `completed` that the gate
calls INCONCLUSIVE is a contradiction the operator has to resolve by reading
source, and the opposite pairing is a gate that passes what the dashboard knows
was never examined.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import RunStage
from core.models.enums import StageStatus


def degraded_stages(session: Session, run_id: str) -> list[RunStage]:
    """Stages that timed out, OOMed, failed, or truncated their input.

    Their absence from the findings list is not evidence of a clean artifact.
    Sorted by analyzer so the resulting message is stable between runs.
    """
    stages = session.scalars(select(RunStage).where(RunStage.run_id == run_id)).all()
    return sorted(
        (stage for stage in stages if StageStatus(stage.status).is_degraded),
        key=lambda stage: stage.analyzer,
    )


def describe_degraded(stages: list[RunStage]) -> list[str]:
    """Render for a human: ``static (failed)``."""
    return [f"{stage.analyzer} ({stage.status})" for stage in stages]
