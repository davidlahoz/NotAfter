"""Configurable calendar timings

The renewal lead time and the attendee alarms were constants in the code.
They are settings now, so that how far ahead invites land can be changed
without a deploy.

Revision ID: fb3fd17b1560
Revises: 1ae4ee8d581f
Create Date: 2026-09-08 13:13:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "fb3fd17b1560"
down_revision: str | None = "1ae4ee8d581f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Server defaults are required, not optional: the settings row already
    # exists, and a NOT NULL column with no default cannot be added to it.
    # The values are the constants these settings replace, so an existing
    # installation keeps the behaviour it had.
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "calendar_renew_lead_days",
                sa.Integer(),
                nullable=False,
                server_default="30",
            )
        )
        batch_op.add_column(
            sa.Column(
                "calendar_alarm_days",
                sa.JSON(),
                nullable=False,
                server_default="[7, 1]",
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("calendar_alarm_days")
        batch_op.drop_column("calendar_renew_lead_days")
