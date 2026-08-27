"""Reading docker-compose.yml in tests, without a YAML dependency in the suite.

The deployment topology carries real guarantees — the schema is migrated before
a worker touches the database, an analyzer image is never fetched from a
registry — and those live in the compose file rather than in Python, so this is
where they get asserted.
"""

from __future__ import annotations

from pathlib import Path

COMPOSE_PATH = Path("docker-compose.yml")


def compose_service(name: str) -> str:
    """The body of one service block.

    Splitting on two-space indentation does not work: the body lines are
    indented four, so `"\\n  "` matches them too and returns an empty block that
    makes every assertion against it pass. Read to the next line that starts a
    sibling key instead.
    """
    lines = COMPOSE_PATH.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index(f"  {name}:") + 1
    except ValueError:  # pragma: no cover - only on a malformed compose file
        raise AssertionError(f"docker-compose.yml has no service named {name!r}") from None
    body: list[str] = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("    "):
            break
        body.append(line)
    return "\n".join(body)
