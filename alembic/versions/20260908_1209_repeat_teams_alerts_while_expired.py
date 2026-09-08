"""Repeat Teams alerts while a certificate is expired

Adds the interval, in hours, at which an expired certificate re-alerts Teams.

Revision ID: 1ae4ee8d581f
Revises: 7b867b93631e
Create Date: 2026-09-08 12:09:59.589807+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "1ae4ee8d581f"
down_revision: str | None = "7b867b93631e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A server default is required, not optional: the table already holds the
    # settings row, and a NOT NULL column with no default cannot be added to
    # it. Existing installations adopt hourly alerts, which is the default for
    # new ones too.
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "expired_teams_every_hours",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("expired_teams_every_hours")
