# SPDX-License-Identifier: AGPL-3.0-only
"""Delegated admin service account (DASA) tenants.

- tenants.auth_mode: `oauth` (Milestone 1, existing rows) or `dasa` (service account only).
- tenants.customer_id: Google's customer id, needed by GAM in dasa mode.
- tenant_credentials.sa_client_email / sa_client_id: the non-secret identifiers of the
  uploaded service account, shown in the setup guide.

Revision ID: 0004_dasa
Revises: 0003_review_fixes
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_dasa"
down_revision: str | None = "0003_review_fixes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

auth_mode = postgresql.ENUM("oauth", "dasa", name="auth_mode", create_type=False)


def upgrade() -> None:
    auth_mode.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "tenants",
        sa.Column("auth_mode", auth_mode, nullable=False, server_default="oauth"),
    )
    op.add_column("tenants", sa.Column("customer_id", sa.Text(), nullable=True))
    op.add_column("tenant_credentials", sa.Column("sa_client_email", sa.Text(), nullable=True))
    op.add_column("tenant_credentials", sa.Column("sa_client_id", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenant_credentials", "sa_client_id")
    op.drop_column("tenant_credentials", "sa_client_email")
    op.drop_column("tenants", "customer_id")
    op.drop_column("tenants", "auth_mode")
    auth_mode.drop(op.get_bind(), checkfirst=True)
