"""Whether *this* worker container is still answering.

Compose restarts a process that exits. It cannot see a worker that is running
but wedged — a task that never returns, a lost broker connection — which until
now was visible only by reading logs (CLAUDE.md §6).

`celery inspect ping` with no destination answers for the whole cluster, so the
fast lane would look healthy for as long as the heavy lane replied. This pings
this container's own node by name, so each worker's healthcheck reports on
itself.

Run as the container healthcheck::

    python -m core.orchestrator.health

Implemented in Python rather than as a shell one-liner because the healthcheck
has to name the node, and neither way of getting the hostname in a shell is
safe here: `$HOSTNAME` is a bash variable and the healthcheck runs under `sh`,
and `hostname(1)` is not guaranteed to be installed in a slim image. The
interpreter is guaranteed — it is a Python image.
"""

from __future__ import annotations

import socket
import subprocess
import sys

CELERY_APP = "core.orchestrator.celery_app:celery_app"

# Long enough that a worker busy with a short task still replies, short enough
# that the check finishes inside the healthcheck's own timeout.
PING_TIMEOUT_SECONDS = 5.0


def node_name(hostname: str | None = None) -> str:
    """This container's Celery node name.

    Celery names a worker ``celery@<hostname>`` unless `--hostname` says
    otherwise, and Docker sets the container hostname to its short id. The
    worker services deliberately do not set `--hostname`: a fixed name would
    collide the moment anyone runs `docker compose up --scale worker=2`.
    """
    return f"celery@{hostname or socket.gethostname()}"


def ping_command(hostname: str | None = None) -> list[str]:
    """The argv for pinging one node.

    `-t` and `-d` belong to `inspect`, not to `ping`, so they precede the
    subcommand — that is the order `celery inspect --help` documents.
    """
    return [
        "celery",
        "-A",
        CELERY_APP,
        "inspect",
        "-t",
        str(PING_TIMEOUT_SECONDS),
        "-d",
        node_name(hostname),
        "ping",
    ]


def main() -> int:
    # Fixed argv, no shell: nothing here is attacker-influenced.
    completed = subprocess.run(
        ping_command(),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        # Docker keeps the last healthcheck output and shows it in
        # `docker inspect`, which is the only place anyone will look.
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
