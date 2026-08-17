"""Watchdog escalation.

Tested against a fake handle with a fake clock, because the thing being
verified is the *sequence* — wait, SIGTERM, grace, SIGKILL — and doing that
against a real container would mean 900-second tests that still wouldn't prove
the ordering.
"""

from __future__ import annotations

import pytest

from core.sandbox.watchdog import WatchdogVerdict, enforce_deadline


class FakeHandle:
    """Records the signals it received and yields scripted wait() results."""

    def __init__(self, wait_results: list[int | None]) -> None:
        self._results = list(wait_results)
        self.calls: list[str] = []
        self.wait_timeouts: list[float] = []

    def wait(self, timeout_s: float) -> int | None:
        self.calls.append("wait")
        self.wait_timeouts.append(timeout_s)
        return self._results.pop(0) if self._results else None

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


class TestHappyPath:
    def test_container_that_exits_in_time_is_not_signalled(self) -> None:
        handle = FakeHandle([0])
        outcome = enforce_deadline(handle, timeout_s=900, grace_s=10, clock=FakeClock())

        assert outcome.verdict is WatchdogVerdict.EXITED
        assert outcome.exit_code == 0
        assert outcome.timed_out is False
        assert handle.calls == ["wait"]

    def test_nonzero_exit_is_still_a_clean_exit(self) -> None:
        """A failing analyzer is not a hung analyzer; the run records the code
        and moves on."""
        outcome = enforce_deadline(FakeHandle([3]), timeout_s=60, grace_s=5, clock=FakeClock())
        assert outcome.verdict is WatchdogVerdict.EXITED
        assert outcome.exit_code == 3

    def test_first_wait_uses_the_full_deadline(self) -> None:
        handle = FakeHandle([0])
        enforce_deadline(handle, timeout_s=900, grace_s=10, clock=FakeClock())
        assert handle.wait_timeouts[0] == 900


class TestEscalation:
    def test_sigterm_is_tried_before_sigkill(self) -> None:
        handle = FakeHandle([None, 143])  # deadline blown, then dies on SIGTERM
        outcome = enforce_deadline(handle, timeout_s=10, grace_s=10, clock=FakeClock())

        assert outcome.verdict is WatchdogVerdict.TERMINATED
        assert outcome.exit_code == 143
        assert outcome.timed_out is True
        assert handle.calls == ["wait", "terminate", "wait"]
        assert "kill" not in handle.calls

    def test_sigkill_follows_an_ignored_sigterm(self) -> None:
        handle = FakeHandle([None, None, 137])
        outcome = enforce_deadline(handle, timeout_s=10, grace_s=10, clock=FakeClock())

        assert outcome.verdict is WatchdogVerdict.KILLED
        assert outcome.exit_code == 137
        assert handle.calls == ["wait", "terminate", "wait", "kill", "wait"]

    def test_grace_period_is_honoured(self) -> None:
        handle = FakeHandle([None, 143])
        enforce_deadline(handle, timeout_s=10, grace_s=7, clock=FakeClock())
        assert handle.wait_timeouts == [10, 7]

    def test_zero_grace_goes_straight_to_sigkill(self) -> None:
        handle = FakeHandle([None, 137])
        outcome = enforce_deadline(handle, timeout_s=10, grace_s=0, clock=FakeClock())

        assert outcome.verdict is WatchdogVerdict.KILLED
        assert handle.calls == ["wait", "terminate", "kill", "wait"]

    def test_surviving_sigkill_is_reported_not_waited_on_forever(self) -> None:
        """A container the runtime cannot kill is the reaper's problem. The run
        must not block on it."""
        handle = FakeHandle([None, None, None])
        outcome = enforce_deadline(handle, timeout_s=10, grace_s=10, clock=FakeClock())

        assert outcome.verdict is WatchdogVerdict.ESCAPED
        assert outcome.exit_code is None
        assert outcome.timed_out is True


class TestArgumentValidation:
    @pytest.mark.parametrize("timeout", [0, -1])
    def test_rejects_non_positive_timeout(self, timeout: int) -> None:
        with pytest.raises(ValueError, match="timeout_s"):
            enforce_deadline(FakeHandle([0]), timeout_s=timeout, grace_s=1)

    def test_rejects_negative_grace(self) -> None:
        with pytest.raises(ValueError, match="grace_s"):
            enforce_deadline(FakeHandle([0]), timeout_s=1, grace_s=-1)
