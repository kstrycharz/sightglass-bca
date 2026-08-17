"""Sightglass API application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from api.routers import findings, health, runs, settings
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

    yield
    log.info("api.shutdown")


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
    app.include_router(settings.router)
    return app


app = create_app()
