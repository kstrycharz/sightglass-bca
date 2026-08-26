"""Database engine and session management.

Synchronous SQLAlchemy on purpose. The heavy work happens in Celery workers and
in containers, not in the event loop, and an async ORM would buy latency we do
not need at the cost of two colours of every data-access function.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import get_settings

if TYPE_CHECKING:
    from alembic.config import Config


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

    Tests only. Every deployment path goes through :func:`upgrade_schema`,
    because ``create_all`` creates missing *tables* and is blind to a missing
    *column* — it reports success against a schema the code cannot actually
    use, which is a failure that only appears under load in production.
    """
    from core.models import tables  # noqa: F401 - registers the mappers
    from core.models.base import Base

    Base.metadata.create_all(bind=get_engine())


# The revision describing the schema as it stood before Alembic existed. A
# database created by the old bootstrap is adopted here rather than having the
# baseline replayed onto tables that already exist.
BASELINE_REVISION = "0001_baseline"


def _alembic_config() -> Config:
    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / "alembic.ini"))
    # Absolute, because the worker and the API have different working
    # directories and a relative script location resolves in only one of them.
    config.set_main_option("script_location", str(root / "alembic"))
    return config


def upgrade_schema() -> None:
    """Bring the database to the latest revision.

    Handles the three states a deployment can be in:

    * **empty** — every migration runs, creating the schema from nothing;
    * **created by the old ``create_all()`` bootstrap** — no version table but
      real data, so it is stamped at the baseline and then upgraded;
    * **already migrated** — a no-op.

    Idempotent, and safe to call from more than one service at start-up:
    Alembic takes a lock on the version table, so a second caller waits rather
    than racing.
    """
    from alembic import command
    from sqlalchemy import inspect

    config = _alembic_config()
    engine = get_engine()

    # Alembic runs on *this* engine's connection rather than building its own
    # from settings, so the schema that gets migrated is necessarily the schema
    # this process is about to query.
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())

        if "alembic_version" not in tables and "runs" in tables:
            command.stamp(config, BASELINE_REVISION)

        command.upgrade(config, "head")
