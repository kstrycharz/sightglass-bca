"""Record the component inventory on the run manifest.

Composition analysis writes a CycloneDX-shaped inventory per run. It lives on
the manifest rather than in its own table because it is a single immutable
document produced once per scan, read whole, and never queried by component —
the same reasoning as ``recon``.

The column is nullable with a default so that a database upgraded while runs
are in flight keeps serving them; every row written after this point sets it
explicitly.

Revision ID: 0002_manifest_components
Revises: 0001_baseline
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_manifest_components"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "run_manifests",
        sa.Column("components", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("run_manifests", "components")
