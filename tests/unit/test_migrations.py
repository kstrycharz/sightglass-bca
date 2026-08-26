"""Schema migrations.

The failure this exists for was live and expensive: a column was added to a
model, the deployment was rebuilt, and `create_all()` reported success because
the *table* already existed. Every request that touched the run manifest then
returned 500, and a 213 MB scan died at the manifest write with the artifact
already uploaded and unpacked.

`create_all()` is blind to a missing column by design. So the tests that matter
here are not "does the migration run" but "does a database in each of the three
states a real deployment can be in end up correct".

Migrations are exercised against SQLite: it is what the rest of the unit suite
uses, needs no Docker, and every operation these revisions perform is portable.
The Postgres-specific risk — a type that renders differently — is what
`compare_type` in `alembic/env.py` is there to catch at authoring time.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text

import core.db as db_module
from core.db import BASELINE_REVISION, _alembic_config, upgrade_schema
from core.models.base import Base


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """A real on-disk SQLite database wired in as *the* engine.

    On-disk rather than in-memory because Alembic opens its own connection, and
    an in-memory database is not shared across connections — the migration
    would run against a second, empty database and the assertions would pass
    for the wrong reason.
    """
    url = f"sqlite:///{tmp_path / 'sightglass.db'}"
    active = create_engine(url, future=True)
    monkeypatch.setattr(db_module, "get_engine", lambda: active)
    yield active
    active.dispose()


def _columns(engine: Engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {c["name"] for c in inspect(connection).get_columns(table)}


def _tables(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return set(inspect(connection).get_table_names())


def _run(engine: Engine, action: object, target: str) -> None:
    """Drive Alembic against the test engine.

    The same handoff `upgrade_schema` performs: without it, `env.py` falls back
    to building an engine from settings and the migration runs against whatever
    Postgres the environment points at — which, in a unit test, is nothing.
    """
    config = _alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        action(config, target)  # type: ignore[operator]


def _stamped(engine: Engine) -> str | None:
    with engine.connect() as connection:
        if "alembic_version" not in _tables(engine):
            return None
        row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
    return row[0] if row else None


class TestRevisionGraph:
    def test_there_is_exactly_one_head(self) -> None:
        """Two heads means someone branched, and `upgrade head` then fails on
        a deployment rather than in review."""
        script = ScriptDirectory.from_config(_alembic_config())
        assert len(script.get_heads()) == 1

    def test_the_baseline_this_code_stamps_actually_exists(self) -> None:
        """`upgrade_schema` names a revision as a string. If that revision is
        renamed, adoption of an existing database fails at start-up — on the
        deployment, not here, unless this test holds the two together."""
        script = ScriptDirectory.from_config(_alembic_config())
        assert script.get_revision(BASELINE_REVISION) is not None

    def test_every_revision_is_reversible(self) -> None:
        """A migration with no downgrade is a one-way door on a release that
        has to be rolled back at 3am."""
        script = ScriptDirectory.from_config(_alembic_config())
        for revision in script.walk_revisions():
            source = Path(revision.path).read_text(encoding="utf-8")
            body = source.split("def downgrade()", 1)[1]
            assert "pass" not in body.split("\n")[1], revision.revision


class TestEmptyDatabase:
    def test_migrating_from_nothing_produces_the_whole_schema(self, engine: Engine) -> None:
        upgrade_schema()
        expected = set(Base.metadata.tables)
        assert expected <= _tables(engine)

    def test_and_lands_at_head(self, engine: Engine) -> None:
        upgrade_schema()
        script = ScriptDirectory.from_config(_alembic_config())
        assert _stamped(engine) == script.get_current_head()

    def test_the_schema_matches_what_the_models_expect(self, engine: Engine) -> None:
        """The check with teeth: every column the ORM will select must exist.

        A migration that creates the tables but misses a column is exactly the
        production failure this module was written for, and it is invisible to
        a test that only asserts the tables are present.
        """
        upgrade_schema()
        for name, table in Base.metadata.tables.items():
            declared = {column.name for column in table.columns}
            missing = declared - _columns(engine, name)
            assert not missing, f"{name} is missing {sorted(missing)}"


class TestAdoptingAPreMigrationDatabase:
    """The state every existing deployment is in: real data, no version table."""

    def test_a_create_all_database_is_adopted_not_replayed(self, engine: Engine) -> None:
        """Replaying the baseline onto populated tables would fail on the first
        CREATE TABLE, taking the service down on the upgrade that introduced
        migrations — the worst possible moment to find out."""
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE run_manifests"))
            connection.execute(
                text("CREATE TABLE run_manifests (id VARCHAR PRIMARY KEY, run_id VARCHAR)")
            )

        upgrade_schema()

        assert "components" in _columns(engine, "run_manifests")

    def test_existing_rows_survive_the_adoption(self, engine: Engine) -> None:
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE run_manifests"))
            connection.execute(
                text("CREATE TABLE run_manifests (id VARCHAR PRIMARY KEY, run_id VARCHAR)")
            )
            connection.execute(
                text("INSERT INTO run_manifests (id, run_id) VALUES ('m1', 'r1')")
            )

        upgrade_schema()

        with engine.connect() as connection:
            assert connection.execute(text("SELECT run_id FROM run_manifests")).scalar() == "r1"

    def test_an_empty_database_is_not_mistaken_for_a_legacy_one(self, engine: Engine) -> None:
        """Adoption keys off `runs` existing. Stamping a genuinely empty
        database would skip the baseline and leave it with no tables at all."""
        upgrade_schema()
        assert "runs" in _tables(engine)


class TestIdempotence:
    def test_running_twice_changes_nothing(self, engine: Engine) -> None:
        """Both the API and the workers call this at start-up."""
        upgrade_schema()
        first = _stamped(engine)
        upgrade_schema()
        assert _stamped(engine) == first

    def test_downgrade_then_upgrade_round_trips(self, engine: Engine) -> None:
        upgrade_schema()
        _run(engine, command.downgrade, BASELINE_REVISION)
        assert "components" not in _columns(engine, "run_manifests")
        _run(engine, command.upgrade, "head")
        assert "components" in _columns(engine, "run_manifests")
