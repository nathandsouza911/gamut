# SPDX-License-Identifier: AGPL-3.0-only
"""Disabled panel users and the job reclaim count.

- users.disabled: a disabled user cannot sign in (OIDC or bootstrap password) and any
  session they still hold is rejected.
- jobs.reclaim_count: how many times the job was claimed again after its worker's
  lease expired. After MAX_RECLAIMS (app.jobs.queue) the job fails instead of being
  run again, so a job that crashes its worker cannot loop forever.

Revision ID: 0003_review_fixes
Revises: 0002_leases
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_review_fixes"
down_revision: str | None = "0002_leases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "jobs",
        sa.Column("reclaim_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("jobs", "reclaim_count")
    op.drop_column("users", "disabled")
