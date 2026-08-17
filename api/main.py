"""Sightglass API application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from api.routers import health
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
    settings = get_settings()
    configure_logging(level=settings.log_level, json_output=settings.log_json)
    log.info(
        "api.startup",
        version=SIGHTGLASS_VERSION,
        environment=settings.environment,
        sandbox_driver=settings.sandbox_driver,
        egress_policy=settings.egress_policy,
        air_gapped=settings.air_gapped,
    )
    yield
    log.info("api.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sightglass",
        description=DESCRIPTION,
        version=SIGHTGLASS_VERSION,
        lifespan=lifespan,
    )
    app.include_router(health.router)
    return app


app = create_app()
