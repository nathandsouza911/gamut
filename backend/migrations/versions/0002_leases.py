# SPDX-License-Identifier: AGPL-3.0-only
"""Leases with claim tokens for jobs and scheduled actions.

- scheduled_actions.lease_until: another worker reclaims an action whose worker died.
- jobs.claim_token, scheduled_actions.claim_token: a fresh value on every claim. A
  worker writes a job's or action's state only while the row still carries its token,
  so a worker whose lease was taken over cannot overwrite the new owner's work.

Revision ID: 0002_leases
Revises: 0001_initial
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0002_leases"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scheduled_actions", sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "scheduled_actions", sa.Column("claim_token", pg.UUID(as_uuid=True), nullable=True)
    )
    op.add_column("jobs", sa.Column("claim_token", pg.UUID(as_uuid=True), nullable=True))


def downgrade() -> None:
    op.drop_column("jobs", "claim_token")
    op.drop_column("scheduled_actions", "claim_token")
    op.drop_column("scheduled_actions", "lease_until")
