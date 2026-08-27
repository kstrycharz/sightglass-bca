"""The worker container healthcheck.

The check exists because a wedged worker used to be visible only in logs
(CLAUDE.md §6). What matters is that it reports on *this* worker rather than on
whichever lane happens to be alive, and that its argv is the one the installed
Celery actually accepts.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from core.orchestrator.health import (
    CELERY_APP,
    PING_TIMEOUT_SECONDS,
    main,
    node_name,
    ping_command,
)


class TestNodeName:
    def test_it_matches_celerys_default_naming(self) -> None:
        """Celery names a worker `celery@<hostname>` when `--hostname` is not
        given, and the worker services deliberately do not give one."""
        assert node_name("abc123") == "celery@abc123"

    def test_it_falls_back_to_this_containers_hostname(self) -> None:
        import socket

        assert node_name() == f"celery@{socket.gethostname()}"


class TestPingCommand:
    def test_it_targets_one_node_and_not_the_cluster(self) -> None:
        """Without `-d` this answers for any worker on the broker, so the fast
        lane would look healthy for as long as the heavy lane replied."""
        argv = ping_command("abc123")
        assert "-d" in argv
        assert argv[argv.index("-d") + 1] == "celery@abc123"

    def test_inspect_options_precede_the_subcommand(self) -> None:
        """`-t` and `-d` belong to `inspect`, not to `ping`; that is the order
        `celery inspect --help` documents."""
        argv = ping_command("abc123")
        for option in ("-t", "-d"):
            assert argv.index("inspect") < argv.index(option) < argv.index("ping")

    def test_it_names_the_app_the_workers_run(self) -> None:
        """A healthcheck against a different app would ping nothing and mark a
        healthy worker unhealthy forever."""
        argv = ping_command()
        assert argv[argv.index("-A") + 1] == CELERY_APP
        assert CELERY_APP == "core.orchestrator.celery_app:celery_app"

    def test_the_timeout_leaves_room_inside_the_healthcheck_timeout(self) -> None:
        """docker-compose gives the check 15s; a ping that outlived that would
        be reported as a failure regardless of what the worker said."""
        assert 0 < PING_TIMEOUT_SECONDS < 15


class TestExitCode:
    """Docker reads the exit code and nothing else."""

    def _patch(self, monkeypatch: pytest.MonkeyPatch, returncode: int) -> list[list[str]]:
        seen: list[list[str]] = []

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen.append(argv)
            return subprocess.CompletedProcess(argv, returncode, stdout="out", stderr="err")

        monkeypatch.setattr(subprocess, "run", fake_run)
        return seen

    def test_a_replying_worker_is_healthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, 0)
        assert main() == 0

    def test_a_silent_worker_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unreachable broker and a wedged worker both land here."""
        self._patch(monkeypatch, 1)
        assert main() == 1

    def test_it_pings_its_own_node(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = self._patch(monkeypatch, 0)
        main()
        assert seen == [ping_command()]

    def test_failure_output_is_surfaced(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Docker keeps the last healthcheck output; a silent failure would
        leave `docker inspect` showing nothing to act on."""
        self._patch(monkeypatch, 1)
        main()
        assert "err" in capsys.readouterr().err

    def test_success_stays_quiet(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch(monkeypatch, 0)
        main()
        assert capsys.readouterr().err == ""
