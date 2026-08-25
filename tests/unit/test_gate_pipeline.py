"""End-to-end gate evaluation against a real schema.

Uses in-memory SQLite rather than mocks. The point of this file is to catch the
class of bug a mocked session hides completely — a wrong column name, a join
that does not hold, a status string that never matches the enum — which is
exactly what breaks when the ORM moves underneath the gate.

No Docker, no Postgres, so it runs in the unit lane per §8.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.models import Artifact, Finding, FindingLocation, Run, RunStage
from core.models.base import Base
from core.models.enums import RunStatus, StageStatus
from core.pipeline.gate import RunNotReady, gate_run, resolve_baseline
from core.policy import BaselineMode, GateDecision, Policy
from core.vocab import Severity


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as active:
        yield active
    engine.dispose()


def _make_run(session: Session, run_id: str, *, status: str = RunStatus.COMPLETED) -> Run:
    now = datetime.now(UTC)
    run = Run(
        id=run_id,
        status=status,
        profile="standard",
        attested_by="kyle",
        attestation_reference="SEC-1",
        attested_at=now,
    )
    session.add(run)
    artifact = Artifact(
        id=f"art-{run_id}",
        run_id=run_id,
        name="installer.exe",
        path_in_tree="installer.exe",
        sha256="0" * 64,
        size_bytes=1024,
    )
    session.add(artifact)
    run.root_artifact_id = artifact.id
    session.flush()
    return run


def _add_finding(
    session: Session,
    run_id: str,
    finding_id: str,
    *,
    severity: Severity = Severity.CRITICAL,
    rule_id: str = "aws_secret_key",
    status: str = "open",
    llm_verdict: str | None = None,
    with_location: bool = True,
) -> Finding:
    finding = Finding(
        id=finding_id,
        run_id=run_id,
        rule_id=rule_id,
        category="cloud_credentials",
        title="AWS secret access key",
        severity=severity.value,
        value_masked="AKIA****************",
        value_hash="a" * 64,
        status=status,
        llm_verdict=llm_verdict,
    )
    session.add(finding)
    if with_location:
        session.add(
            FindingLocation(
                finding_id=finding_id,
                run_id=run_id,
                artifact_id=f"art-{run_id}",
                path_in_tree="installer.exe",
                offset=4096,
            )
        )
    session.flush()
    return finding


def test_clean_run_passes(session: Session) -> None:
    _make_run(session, "run-1")
    verdict, baseline = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.PASS
    assert baseline.source == "none"


def test_critical_finding_blocks_and_carries_its_artifact_path(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "f-critical")

    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].finding_id == "f-critical"
    # Proves the location projection actually resolves against real rows.
    assert verdict.violations[0].artifact_path == "installer.exe"


def test_inherited_finding_does_not_block_the_second_run(session: Session) -> None:
    """The whole baseline story, against real rows."""
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "shared-finding")

    second = _make_run(session, "run-2")
    second.previous_run_id = "run-1"
    _add_finding(session, "run-2", "shared-finding")
    session.flush()

    verdict, baseline = gate_run(session, "run-2", Policy())
    assert baseline.source == "previous_run"
    assert verdict.decision is GateDecision.PASS
    assert len(verdict.inherited) == 1


def test_newly_introduced_finding_blocks_the_second_run(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "shared-finding")

    second = _make_run(session, "run-2")
    second.previous_run_id = "run-1"
    _add_finding(session, "run-2", "shared-finding")
    _add_finding(session, "run-2", "brand-new", rule_id="private_key")
    session.flush()

    verdict, _ = gate_run(session, "run-2", Policy())
    assert verdict.decision is GateDecision.BLOCKED
    assert [v.finding_id for v in verdict.violations] == ["brand-new"]


def test_baseline_mode_all_blocks_on_inherited_findings(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "shared-finding")
    second = _make_run(session, "run-2")
    second.previous_run_id = "run-1"
    _add_finding(session, "run-2", "shared-finding")
    session.flush()

    policy = Policy(baseline_mode=BaselineMode.ALL)
    verdict, _ = gate_run(session, "run-2", policy)
    assert verdict.decision is GateDecision.BLOCKED


def test_incomplete_baseline_run_is_refused(session: Session) -> None:
    """A failed predecessor saw an unknown fraction of the artifact. Using it
    as a baseline would mark genuinely new secrets as inherited."""
    _make_run(session, "run-1", status=RunStatus.FAILED)
    _add_finding(session, "run-1", "shared-finding")
    second = _make_run(session, "run-2")
    second.previous_run_id = "run-1"
    _add_finding(session, "run-2", "shared-finding")
    session.flush()

    verdict, baseline = gate_run(session, "run-2", Policy())
    assert baseline.source == "none"
    assert verdict.decision is GateDecision.BLOCKED


def test_explicit_baseline_run_overrides_the_linked_one(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "shared-finding")
    _make_run(session, "run-oldest")

    third = _make_run(session, "run-3")
    third.previous_run_id = "run-oldest"
    _add_finding(session, "run-3", "shared-finding")
    session.flush()

    verdict, baseline = gate_run(session, "run-3", Policy(), baseline_run_id="run-1")
    assert baseline.source == "explicit_run"
    assert verdict.decision is GateDecision.PASS


def test_degraded_stage_makes_a_clean_run_inconclusive(session: Session) -> None:
    _make_run(session, "run-1")
    session.add(
        RunStage(
            id="stage-1",
            run_id="run-1",
            artifact_id="art-run-1",
            analyzer="unpack",
            status=StageStatus.OOM,
        )
    )
    session.flush()

    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.INCONCLUSIVE
    assert verdict.degraded_stages == ("unpack (oom)",)


def test_completed_stages_do_not_degrade_the_verdict(session: Session) -> None:
    _make_run(session, "run-1")
    session.add(
        RunStage(
            id="stage-1",
            run_id="run-1",
            artifact_id="art-run-1",
            analyzer="static",
            status=StageStatus.COMPLETED,
        )
    )
    session.flush()
    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.PASS


def test_failed_run_is_inconclusive_never_pass(session: Session) -> None:
    run = _make_run(session, "run-1", status=RunStatus.FAILED)
    run.error = "worker died"
    session.flush()

    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.INCONCLUSIVE
    assert "worker died" in verdict.degraded_stages[0]


def test_unfinished_run_is_refused_rather_than_guessed(session: Session) -> None:
    _make_run(session, "run-1", status=RunStatus.RUNNING)
    with pytest.raises(RunNotReady):
        gate_run(session, "run-1", Policy())


def test_missing_run_is_refused(session: Session) -> None:
    with pytest.raises(RunNotReady):
        gate_run(session, "nope", Policy())


def test_llm_dismissal_does_not_unblock_against_real_rows(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(
        session,
        "run-1",
        "f-1",
        status="false_positive",
        llm_verdict="false_positive",
    )
    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.BLOCKED

    trusting, _ = gate_run(session, "run-1", Policy(trust_llm_dismissals=True))
    assert trusting.decision is GateDecision.PASS


def test_human_accepted_risk_passes(session: Session) -> None:
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "f-1", status="accepted_risk")
    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.PASS


def test_finding_without_a_location_still_gates(session: Session) -> None:
    """Defensive: a finding whose locations failed to persist must not crash
    the gate into an exception that reads as a tool error."""
    _make_run(session, "run-1")
    _add_finding(session, "run-1", "f-1", with_location=False)
    verdict, _ = gate_run(session, "run-1", Policy())
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].artifact_path == ""


def test_resolve_baseline_with_supplied_ids(session: Session) -> None:
    run = _make_run(session, "run-1")
    baseline = resolve_baseline(session, run, baseline_finding_ids=frozenset({"x"}))
    assert baseline.source == "supplied_ids"
    assert baseline.finding_ids == frozenset({"x"})
