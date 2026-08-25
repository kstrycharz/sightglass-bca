"""Sightglass API application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from api.routers import findings, gate, health, runs, settings
from core.auth import redact
from core.config import SIGHTGLASS_VERSION, get_settings
from core.logging import configure_logging

log = structlog.get_logger(__name__)

DESCRIPTION = """
Sightglass analyses the artifacts you are about to ship — installers,
executables, firmware images — for exposed secrets, sensitive data, and
unintended IP disclosure.

Every artifact submitted requires an authorization attestation. The operator
must own, or be contractually authorized to test, what they upload.
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app_settings = get_settings()
    configure_logging(level=app_settings.log_level, json_output=app_settings.log_json)
    log.info(
        "api.startup",
        version=SIGHTGLASS_VERSION,
        environment=app_settings.environment,
        sandbox_driver=app_settings.sandbox_driver,
        egress_policy=app_settings.egress_policy,
        air_gapped=app_settings.air_gapped,
    )

    # First-boot convenience so `make dev` works from a clean clone. It is
    # idempotent and never drops or alters anything; real deployments run
    # `alembic upgrade head` so schema changes stay reviewable.
    from core.db import create_all

    try:
        create_all()
    except Exception as exc:
        log.warning("api.schema_bootstrap_failed", error=str(exc))

    _announce_auth(app_settings.auth_required)

    yield
    log.info("api.shutdown")


def _announce_auth(auth_required: bool) -> None:
    """Say plainly whether the API is protected, and bootstrap it if it is.

    Secure-by-default only works if a fresh deployment can still be used, so
    the first start with no tokens mints an admin one and prints it — once,
    unrecoverably. The alternative is a shipped default credential, which is
    worse, or defaulting the control off, which is how an unauthenticated API
    ends up on a network.
    """
    if not auth_required:
        # Loud on purpose. This is the configuration where anyone who can reach
        # the port can read every finding.
        log.warning(
            "api.auth_disabled",
            detail=(
                "SIGHTGLASS_AUTH_REQUIRED is false: the API accepts unauthenticated "
                "requests. Acceptable only for a local single-user stack."
            ),
        )
        return

    from core.db import session_scope
    from core.pipeline.tokens import ensure_bootstrap_token

    try:
        with session_scope() as session:
            minted = ensure_bootstrap_token(session)
    except Exception as exc:
        # Never let bootstrap failure take the API down: an operator can mint a
        # token with the CLI, and a crash-looping API is harder to recover from
        # than a missing one.
        log.warning("api.auth_bootstrap_failed", error=str(exc))
        return

    if minted is None:
        log.info("api.auth_enabled")
        return

    banner = (
        "\n"
        + "=" * 78
        + "\n  SIGHTGLASS: no API tokens existed, so a bootstrap admin token was created.\n"
        + "  It is shown once and is not recoverable. Store it now.\n\n"
        + f"      {minted.token}\n\n"
        + "  Use it as:  sightglass scan ... --token <token>\n"
        + "  Then mint scoped tokens and revoke this one:\n"
        + "      sightglass token create ci-pipeline --scope ci\n"
        + "      sightglass token revoke bootstrap\n"
        + "=" * 78
    )
    print(banner, flush=True)
    log.warning("api.auth_bootstrap_token_created", prefix=redact(minted.token))


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sightglass",
        description=DESCRIPTION,
        version=SIGHTGLASS_VERSION,
        lifespan=lifespan,
    )
    # CORS is deliberately absent: the dashboard is served same-origin in the
    # reference deployment, and a findings page — a list of a company's exposed
    # secrets — is the last thing that should be reachable cross-origin.
    app.include_router(health.router)
    app.include_router(runs.router)
    app.include_router(findings.router)
    app.include_router(gate.router)
    app.include_router(settings.router)
    return app


app = create_app()
