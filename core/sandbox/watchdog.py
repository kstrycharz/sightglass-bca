"""Wall-clock deadline enforcement for sandboxed containers.

Split out from the driver because the escalation sequence — wait, SIGTERM,
grace, SIGKILL — is the part most likely to be subtly wrong, and it is far
easier to test against a fake handle than against a real Docker daemon.

The governing rule (§6): a hung analyzer is terminated and marked, and the run
carries on. Ghidra will hang on some binaries. That must cost the user one
degraded analyzer, not their whole scan.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ContainerHandle(Protocol):
    """The minimum a driver must expose for the watchdog to police a container."""

    def wait(self, timeout_s: float) -> int | None:
        """Block until exit, returning the exit code.

        Returns ``None`` if ``timeout_s`` elapsed first. Must not raise on
        timeout — that path is normal control flow here.
        """

    def terminate(self) -> None:
        """Send SIGTERM. Best-effort; must not raise if already gone."""

    def kill(self) -> None:
        """Send SIGKILL. Best-effort; must not raise if already gone."""


class WatchdogVerdict(StrEnum):
    EXITED = "exited"
    """Container finished within its deadline."""

    TERMINATED = "terminated"
    """Deadline hit; container stopped politely within the grace period."""

    KILLED = "killed"
    """Deadline hit and SIGTERM was ignored; container was SIGKILLed."""

    ESCAPED = "escaped"
    """Deadline hit and the container survived even SIGKILL within grace.

    This should be impossible. If it happens the runtime is wedged, and the
    reaper is left to clean up — we do not block the run waiting on it.
    """


@dataclass(frozen=True, slots=True)
class WatchdogOutcome:
    verdict: WatchdogVerdict
    exit_code: int | None
    waited_s: float

    @property
    def timed_out(self) -> bool:
        return self.verdict is not WatchdogVerdict.EXITED


def enforce_deadline(
    handle: ContainerHandle,
    timeout_s: float,
    grace_s: float,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> WatchdogOutcome:
    """Wait for ``handle``, escalating to SIGTERM then SIGKILL past the deadline.

    ``clock`` is injectable so tests can assert the escalation sequence without
    burning real seconds.
    """
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    if grace_s < 0:
        raise ValueError("grace_s must not be negative")

    started = clock()
    exit_code = handle.wait(timeout_s)
    if exit_code is not None:
        return WatchdogOutcome(WatchdogVerdict.EXITED, exit_code, clock() - started)

    # Deadline blown. Ask politely first: analyzers that trap SIGTERM get a
    # chance to flush partial results to /output, which is often still useful.
    handle.terminate()
    if grace_s > 0:
        exit_code = handle.wait(grace_s)
        if exit_code is not None:
            return WatchdogOutcome(WatchdogVerdict.TERMINATED, exit_code, clock() - started)

    handle.kill()
    # Short bounded wait purely to confirm the kill landed; SIGKILL is not
    # refusable, so anything longer would just be superstition.
    exit_code = handle.wait(min(grace_s, 5.0) or 5.0)
    verdict = WatchdogVerdict.KILLED if exit_code is not None else WatchdogVerdict.ESCAPED
    return WatchdogOutcome(verdict, exit_code, clock() - started)
