# SPDX-License-Identifier: AGPL-3.0-only
"""scheduled_actions.lease_until: lets another worker reclaim an action whose worker died.

Revision ID: 0002_scheduled_action_lease
Revises: 0001_initial
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_scheduled_action_lease"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scheduled_actions", sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scheduled_actions", "lease_until")
