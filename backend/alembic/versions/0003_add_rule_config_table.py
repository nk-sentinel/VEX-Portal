"""add rule_config table

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-01 00:00:00.000000

Hand-written, following ``0002_add_user_table.py``'s precedent: timestamp
columns render as plain ``sa.DateTime()`` (identical DDL to ``UtcDateTime()``
— see that type's own docstring in ``app/repos/models.py``), and the file
carries no import of application code.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "rule_config",
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("auto_determination_enabled", sa.Boolean(), nullable=False),
        sa.Column("agreement_bar", sa.Float(), nullable=True),
        sa.Column("thresholds_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("rule_id", name=op.f("pk_rule_config")),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("rule_config")
