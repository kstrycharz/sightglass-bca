"""Alembic environment.

Two deliberate choices:

**The URL comes from the application settings, never from alembic.ini.** A
migration that can be pointed at a different database than the app is a way to
upgrade the wrong one, and the failure is silent until something reads the
schema it did not get.

**Offline mode is supported.** An air-gapped operator who is not allowed to let
this process reach the database still needs the SQL, and `--sql` is how they
get a script for a DBA to review. That is the same audience the whole product
is built for.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from core.config import get_settings
from core.models import tables  # noqa: F401 - imported for its side effect: registers every mapper
from core.models.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _configure(connection: object) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Without this, a widened column or a changed enum is invisible to
        # autogenerate and ships as silent drift between models and schema.
        compare_type=True,
        # SQLite cannot ALTER a column in place, and the unit suite migrates
        # SQLite. Without batch mode a future ALTER would pass review, pass in
        # Postgres, and fail only in the tests — or worse, be written to avoid
        # the tests and lose its coverage.
        render_as_batch=connection.dialect.name == "sqlite",  # type: ignore[attr-defined]
    )


def run_migrations_online() -> None:
    """Migrate, preferring a connection the caller supplied.

    ``core.db.upgrade_schema`` passes its own connection through
    ``config.attributes``. That is not a convenience: it is what guarantees the
    migration runs against the same database the application is about to serve
    from. Building an engine here from settings would let the two diverge, and
    the symptom of migrating the wrong database is silence.

    The fallback path exists for the command line (`alembic upgrade head`),
    where there is no application to borrow a connection from.
    """
    supplied = config.attributes.get("connection")
    if supplied is not None:
        _configure(supplied)
        with context.begin_transaction():
            context.run_migrations()
        return

    from sqlalchemy import create_engine

    connectable = create_engine(_database_url(), poolclass=pool.NullPool, future=True)
    with connectable.connect() as connection:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
