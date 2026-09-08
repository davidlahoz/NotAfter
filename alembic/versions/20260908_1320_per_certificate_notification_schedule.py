"""per certificate notification schedule

Revision ID: c515e9ca78dc
Revises: fb3fd17b1560
Create Date: 2026-09-08 13:20:03.622828+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c515e9ca78dc"
down_revision: str | None = "fb3fd17b1560"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The three schedule columns are nullable on purpose: null means "follow
    # the global setting", so a certificate differs only where somebody said
    # it should, and existing rows keep behaving exactly as they did.
    with op.batch_alter_table("certificate", schema=None) as batch_op:
        # The certificate table already holds rows, so this needs a server
        # default. False keeps every existing certificate on the default
        # recipient list, which is what it had before this column existed.
        batch_op.add_column(
            sa.Column(
                "recipients_replace_defaults",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(sa.Column("reminder_days", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("calendar_renew_lead_days", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("calendar_alarm_days", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("certificate", schema=None) as batch_op:
        batch_op.drop_column("calendar_alarm_days")
        batch_op.drop_column("calendar_renew_lead_days")
        batch_op.drop_column("reminder_days")
        batch_op.drop_column("recipients_replace_defaults")
