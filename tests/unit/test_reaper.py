"""Reaper behaviour.

The expensive mistake here is reaping a container out from under a live run —
a 40-minute Ghidra job vanishing because a sweep ran. These tests pin the
conservative direction as hard as the cleanup direction.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from core.sandbox.base import DriverHealth, ManagedContainer, SandboxDriver, SandboxResult
from core.sandbox.reaper import Reaper
from core.sandbox.spec import SandboxSpec

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)


class FakeDriver(SandboxDriver):
    name = "fake"

    def __init__(self, containers: list[ManagedContainer], *, fail_on: set[str] | None = None):
        self._containers = containers
        self._fail_on = fail_on or set()
        self.removed: list[str] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:  # pragma: no cover - unused here
        raise NotImplementedError

    def health(self) -> DriverHealth:
        return DriverHealth(healthy=True, driver=self.name)

    def list_managed(self) -> Sequence[ManagedContainer]:
        return list(self._containers)

    def remove(self, container_id: str, *, force: bool = True) -> None:
        if container_id in self._fail_on:
            raise RuntimeError("daemon said no")
        self.removed.append(container_id)


def container(cid: str, run_id: str, *, age_minutes: int = 5, running: bool = True):
    return ManagedContainer(
        container_id=cid,
        run_id=run_id,
        analyzer="ghidra",
        created_at=NOW - timedelta(minutes=age_minutes),
        running=running,
    )


class TestLiveRunProtection:
    def test_does_not_reap_a_live_run(self) -> None:
        driver = FakeDriver([container("c1", "run-live", age_minutes=40)])
        report = Reaper(driver).reap(["run-live"], now=NOW)

        assert driver.removed == []
        assert report.removed_count == 0
        assert report.inspected == 1

    def test_unknown_liveness_falls_back_to_age_only(self) -> None:
        """Before the runs table exists, the reaper must not guess that a run
        is dead — it can only act on age."""
        driver = FakeDriver(
            [
                container("young", "run-a", age_minutes=10),
                container("old", "run-b", age_minutes=60 * 9),
            ]
        )
        report = Reaper(driver).reap(None, now=NOW)

        assert driver.removed == ["old"]
        assert report.removed_count == 1


class TestOrphanCleanup:
    def test_reaps_containers_of_finished_runs(self) -> None:
        driver = FakeDriver([container("c1", "run-live"), container("c2", "run-finished")])
        Reaper(driver).reap(["run-live"], now=NOW)
        assert driver.removed == ["c2"]

    def test_age_overrides_liveness(self) -> None:
        """A container running for longer than max_age has outlived its
        watchdog, which means the watchdog process is gone."""
        driver = FakeDriver([container("c1", "run-live", age_minutes=60 * 7)])
        Reaper(driver, max_age=timedelta(hours=6)).reap(["run-live"], now=NOW)
        assert driver.removed == ["c1"]

    def test_exited_containers_of_finished_runs_are_removed(self) -> None:
        driver = FakeDriver([container("c1", "run-gone", running=False)])
        Reaper(driver).reap([], now=NOW)
        assert driver.removed == ["c1"]


class TestResilience:
    def test_one_failed_removal_does_not_stop_the_sweep(self) -> None:
        driver = FakeDriver(
            [
                container("bad", "run-gone"),
                container("good", "run-gone"),
            ],
            fail_on={"bad"},
        )
        report = Reaper(driver).reap([], now=NOW)

        assert driver.removed == ["good"]
        assert report.removed_count == 1
        assert len(report.failed) == 1
        assert report.failed[0][0] == "bad"

    def test_empty_sweep_is_a_no_op(self) -> None:
        driver = FakeDriver([])
        report = Reaper(driver).reap(["run-live"], now=NOW)
        assert report.inspected == 0
        assert report.removed_count == 0
