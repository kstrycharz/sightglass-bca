"""Store the `explain` and `summarize` roles' output.

Both roles were configurable and routed long before anything invoked them, so
their output had nowhere to live. These columns are that home.

`llm_explanation` is deliberately not `llm_reasoning`. Reasoning is triage's
one-line justification for a verdict and is part of the audit trail for a
status change; explanation is long-form reviewer prose from a different role
and, under the default routing, a different model. Reusing one column would
mean asking for an explanation silently destroyed the record of why a finding
was dismissed.

Every column is nullable: these are advisory fields on a pipeline that must
produce a complete report with no model configured at all, so "absent" is the
normal state, not a migration failure.

Revision ID: 0003_llm_explain_summary
Revises: 0002_manifest_components
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_llm_explain_summary"
down_revision: str | None = "0002_manifest_components"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("llm_explanation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("llm_explained_by", sa.String(length=128), nullable=True))
    op.add_column(
        "findings",
        sa.Column("llm_explained_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.add_column("runs", sa.Column("llm_summary", sa.Text(), nullable=True))
    op.add_column("runs", sa.Column("llm_summary_model", sa.String(length=128), nullable=True))
    op.add_column(
        "runs",
        sa.Column("llm_summary_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("runs", "llm_summary_at")
    op.drop_column("runs", "llm_summary_model")
    op.drop_column("runs", "llm_summary")

    op.drop_column("findings", "llm_explained_at")
    op.drop_column("findings", "llm_explained_by")
    op.drop_column("findings", "llm_explanation")
