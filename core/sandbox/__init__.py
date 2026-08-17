"""Sandbox boundary: the isolation layer every analyzer runs behind.

Import drivers through :func:`get_driver` rather than by module, so that
swapping runtimes stays a configuration change.
"""

from __future__ import annotations

from pathlib import Path

from core.sandbox.base import (
    DriverHealth,
    ManagedContainer,
    SandboxDriver,
    SandboxResult,
    SandboxStatus,
)
from core.sandbox.docker_driver import DockerDriver, DockerUnavailable
from core.sandbox.reaper import Reaper, ReapReport
from core.sandbox.spec import (
    ANALYZER_GID,
    ANALYZER_UID,
    INPUT_DIR,
    OUTPUT_DIR,
    BindMount,
    MountMode,
    NetworkMode,
    SandboxSpec,
    SpecViolation,
    TmpfsMount,
    Ulimit,
)
from core.sandbox.stub_drivers import GvisorDriver, PodmanDriver
from core.sandbox.watchdog import WatchdogOutcome, WatchdogVerdict, enforce_deadline

__all__ = [
    "ANALYZER_GID",
    "ANALYZER_UID",
    "AVAILABLE_DRIVERS",
    "INPUT_DIR",
    "OUTPUT_DIR",
    "BindMount",
    "DockerDriver",
    "DockerUnavailable",
    "DriverHealth",
    "GvisorDriver",
    "ManagedContainer",
    "MountMode",
    "NetworkMode",
    "PodmanDriver",
    "ReapReport",
    "Reaper",
    "SandboxDriver",
    "SandboxResult",
    "SandboxSpec",
    "SandboxStatus",
    "SpecViolation",
    "TmpfsMount",
    "Ulimit",
    "WatchdogOutcome",
    "WatchdogVerdict",
    "driver_from_settings",
    "enforce_deadline",
    "get_driver",
]

AVAILABLE_DRIVERS = ("docker", "gvisor", "podman")


def get_driver(
    kind: str,
    *,
    run_root: Path,
    repo_root: Path | None = None,
    host_run_root: str | None = None,
) -> SandboxDriver:
    """Instantiate a driver by name.

    Unknown names raise rather than defaulting, because "the sandbox runtime
    silently fell back to something else" is not a failure mode this project
    can afford. The unimplemented drivers are constructible on purpose: they
    fail at ``run()`` with a message naming their milestone, so a
    misconfiguration is legible instead of an ImportError.
    """
    match kind:
        case "docker":
            return DockerDriver(run_root=run_root, repo_root=repo_root, host_run_root=host_run_root)
        case "podman":
            return PodmanDriver()
        case "gvisor":
            return GvisorDriver()
        case _:
            raise ValueError(
                f"unknown sandbox driver {kind!r}; expected one of {list(AVAILABLE_DRIVERS)}"
            )


def driver_from_settings() -> SandboxDriver:
    """Build the configured driver from application settings.

    The API, worker, and CLI all need a driver wired the same way; doing it in
    one place means a new field (``host_run_root`` was one) cannot be picked up
    by two of the three and silently missed by the other.
    """
    from core.config import get_settings

    settings = get_settings()
    return get_driver(
        settings.sandbox_driver,
        run_root=settings.run_root,
        repo_root=settings.repo_root,
        host_run_root=settings.run_root_host or None,
    )
