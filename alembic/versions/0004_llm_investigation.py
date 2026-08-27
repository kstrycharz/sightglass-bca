"""Store the `investigate` role's output.

Agentic investigation lets the model use read-only tools against the artifact —
read bytes, decode a value, search the run's strings — and report what it
found. The conclusion needs somewhere to live, and so does the transcript: a
claim with no supporting tool call in `llm_investigation_steps` is a claim a
reviewer should not trust, and keeping the steps is what makes that checkable.

Nullable throughout, like every other llm_* column. Investigation is advisory
on a pipeline that must produce a complete report with no model configured at
all, so "absent" is the normal state.

Revision ID: 0004_llm_investigation
Revises: 0003_llm_explain_summary
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_llm_investigation"
down_revision: str | None = "0003_llm_explain_summary"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("llm_investigation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("llm_investigation_steps", sa.JSON(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("llm_investigation_confidence", sa.String(length=10), nullable=True),
    )
    op.add_column(
        "findings", sa.Column("llm_investigated_by", sa.String(length=128), nullable=True)
    )
    op.add_column(
        "findings",
        sa.Column("llm_investigated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "llm_investigated_at")
    op.drop_column("findings", "llm_investigated_by")
    op.drop_column("findings", "llm_investigation_confidence")
    op.drop_column("findings", "llm_investigation_steps")
    op.drop_column("findings", "llm_investigation")
