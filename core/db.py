"""Database engine and session management.

Synchronous SQLAlchemy on purpose. The heavy work happens in Celery workers and
in containers, not in the event loop, and an async ORM would buy latency we do
not need at the cost of two colours of every data-access function.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        # Workers fork; a stale pooled connection inherited across a fork
        # surfaces much later as a baffling "server closed the connection".
        pool_recycle=1800,
        pool_size=5,
        max_overflow=10,
        future=True,
    )


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope. Commits on success, rolls back on any exception."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency. Read paths use this; write paths use session_scope."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def create_all() -> None:
    """Create the schema directly, bypassing migrations.

    Only for tests and first-boot bootstrap. Real deployments run
    ``alembic upgrade head`` so that schema changes are reviewable and
    reversible.
    """
    from core.models import tables  # noqa: F401 - registers the mappers
    from core.models.base import Base

    Base.metadata.create_all(bind=get_engine())
