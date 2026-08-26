"""First-run setup: mint the one and only bootstrap admin token over HTTP.

A fresh deployment has authentication required by default and no token to
authenticate with. ``ensure_bootstrap_token`` already existed to break that
bind, but its only channel was a console banner — easy to miss, impossible to
recover once scrolled past, and printed by whichever process happens to win
the race to start first. This exposes the same one-shot mint over HTTP instead,
so the dashboard's setup wizard (or `curl`, for a headless operator) can
complete it deliberately, once, and show the result somewhere the operator is
actually looking.

Unauthenticated by construction, and safe to leave that way: the guard is not
"no credential presented" but "no token exists yet" — the same fact
``ensure_bootstrap_token`` already gates on. The instant any token exists,
including the one this endpoint itself mints, every subsequent call here
returns 409.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.db import get_session, session_scope
from core.pipeline.tokens import ensure_bootstrap_token, tokens_exist

router = APIRouter(prefix="/api/setup", tags=["setup"])


class SetupStatus(BaseModel):
    needs_setup: bool


class BootstrapResponse(BaseModel):
    token: str
    name: str


@router.get("/status", response_model=SetupStatus)
def setup_status(session: Annotated[Session, Depends(get_session)]) -> SetupStatus:
    return SetupStatus(needs_setup=not tokens_exist(session))


@router.post("/bootstrap", response_model=BootstrapResponse, status_code=status.HTTP_201_CREATED)
def bootstrap() -> BootstrapResponse:
    with session_scope() as session:
        minted = ensure_bootstrap_token(session)
        if minted is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Setup has already been completed; an API token already exists.",
            )
        return BootstrapResponse(token=minted.token, name=minted.name)
