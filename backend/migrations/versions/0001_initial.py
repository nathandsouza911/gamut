# SPDX-License-Identifier: AGPL-3.0-only
"""Initial schema: nine tables, enums and the gamut_app grants.

Runs as gamut_owner, which therefore owns every object created here. The gamut_app
role must already exist (backend/docker/initdb/10-gamut-roles.sh creates it).

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "gamut_app"

ENUMS = {
    "tenant_status": ("pending", "active", "degraded", "disabled"),
    "role": ("owner", "admin", "technician", "auditor"),
    "job_status": (
        "queued",
        "running",
        "waiting",
        "failed",
        "succeeded",
        "cancelled",
        "awaiting_approval",
    ),
    "step_status": ("pending", "running", "waiting", "succeeded", "failed", "skipped"),
    "scheduled_status": ("scheduled", "cancelled", "running", "done", "refused", "failed"),
}

# Full DML for the app role. audit_events is handled separately (SELECT, INSERT only).
DML_TABLES = (
    "users",
    "sessions",
    "tenants",
    "tenant_credentials",
    "memberships",
    "jobs",
    "job_steps",
    "scheduled_actions",
)


def _enum(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS[name], name=name, create_type=False)


def _uuid_pk() -> sa.Column[object]:
    return sa.Column(
        "id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
    )


def _ts(name: str, nullable: bool = True, now: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if now else None,
    )


def _jsonb(name: str, default: str) -> sa.Column[object]:
    return sa.Column(
        name, pg.JSONB(), nullable=False, server_default=sa.text(f"'{default}'::jsonb")
    )


def _fk(name: str, target: str, ondelete: str, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(
        name, pg.UUID(as_uuid=True), sa.ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def upgrade() -> None:
    bind = op.get_bind()
    for name, values in ENUMS.items():
        pg.ENUM(*values, name=name).create(bind)

    op.create_table(
        "users",
        _uuid_pk(),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("display_name", sa.Text()),
        sa.Column("oidc_subject", sa.Text(), unique=True),
        sa.Column("is_owner", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("password_hash", sa.Text()),
        _ts("created_at", nullable=False, now=True),
    )

    op.create_table(
        "sessions",
        sa.Column("id_hash", sa.LargeBinary(), primary_key=True),
        _fk("user_id", "users.id", "CASCADE", nullable=False),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        _ts("created_at", nullable=False, now=True),
        _ts("last_seen_at", nullable=False, now=True),
        _ts("expires_at", nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    op.create_table(
        "tenants",
        _uuid_pk(),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
        sa.Column("primary_domain", sa.Text(), nullable=False, unique=True),
        sa.Column("domains", pg.ARRAY(sa.Text()), nullable=False),
        sa.Column("admin_email", sa.Text()),
        sa.Column(
            "status", _enum("tenant_status"), nullable=False, server_default="pending"
        ),
        _ts("last_health_check_at"),
        sa.Column("last_health_message", sa.Text()),
        _ts("created_at", nullable=False, now=True),
    )

    op.create_table(
        "tenant_credentials",
        sa.Column(
            "tenant_id",
            pg.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_key", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("file_names", pg.ARRAY(sa.Text()), nullable=False),
        _fk("uploaded_by", "users.id", "SET NULL"),
        _ts("uploaded_at", nullable=False, now=True),
    )

    op.create_table(
        "memberships",
        _uuid_pk(),
        _fk("user_id", "users.id", "CASCADE", nullable=False),
        _fk("tenant_id", "tenants.id", "CASCADE", nullable=False),
        sa.Column("role", _enum("role"), nullable=False),
        _ts("created_at", nullable=False, now=True),
        sa.UniqueConstraint("user_id", "tenant_id", name="uq_memberships_user_tenant"),
        sa.CheckConstraint("role <> 'owner'", name="ck_memberships_role_not_owner"),
    )
    op.create_index("ix_memberships_tenant_id", "memberships", ["tenant_id"])

    op.create_table(
        "jobs",
        _uuid_pk(),
        _fk("tenant_id", "tenants.id", "CASCADE", nullable=False),
        sa.Column("workflow", sa.Text(), nullable=False),
        _jsonb("params", "{}"),
        sa.Column("status", _enum("job_status"), nullable=False, server_default="queued"),
        _fk("created_by", "users.id", "SET NULL"),
        _fk("approved_by", "users.id", "SET NULL"),
        sa.Column("idempotency_key", sa.Text(), unique=True),
        sa.Column("gam_version", sa.Text()),
        _ts("lease_until"),
        _ts("created_at", nullable=False, now=True),
        _ts("started_at"),
        _ts("finished_at"),
    )
    op.create_index("ix_jobs_tenant_id", "jobs", ["tenant_id"])
    op.create_index("ix_jobs_status", "jobs", ["status"])

    op.create_table(
        "job_steps",
        _uuid_pk(),
        _fk("job_id", "jobs.id", "CASCADE", nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        _jsonb("args", "[]"),
        sa.Column("optional", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", _enum("step_status"), nullable=False, server_default="pending"),
        sa.Column("exit_code", sa.Integer()),
        sa.Column("output", sa.Text()),
        _jsonb("data", "{}"),
        _ts("next_poll_at"),
        sa.Column("poll_attempts", sa.Integer(), nullable=False, server_default="0"),
        _ts("started_at"),
        _ts("finished_at"),
        sa.UniqueConstraint("job_id", "position", name="uq_job_steps_job_position"),
        sa.CheckConstraint("kind IN ('run', 'async', 'schedule')", name="ck_job_steps_kind"),
    )

    op.create_table(
        "scheduled_actions",
        _uuid_pk(),
        _fk("tenant_id", "tenants.id", "CASCADE", nullable=False),
        _fk("job_id", "jobs.id", "CASCADE", nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        _jsonb("params", "{}"),
        _ts("run_at", nullable=False),
        sa.Column(
            "status", _enum("scheduled_status"), nullable=False, server_default="scheduled"
        ),
        sa.Column("result", sa.Text()),
        _ts("created_at", nullable=False, now=True),
    )
    op.create_index("ix_scheduled_actions_tenant_id", "scheduled_actions", ["tenant_id"])

    # tenant_id deliberately has no foreign key: audit events outlive their tenant.
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        _ts("time", nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("tenant_id", pg.UUID(as_uuid=True)),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text()),
        sa.Column("details", pg.JSONB(), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=False),
        sa.Column("hash", sa.Text(), nullable=False, unique=True),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])

    # --- Privileges for the app role -------------------------------------------------
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(DML_TABLES)} TO {APP_ROLE}"
    )
    # Append-only for the app: no UPDATE or DELETE. Only the owner (or a superuser) can
    # rewrite it, which the hash chain makes detectable (tamper-evident, not immutable).
    op.execute(f"GRANT SELECT, INSERT ON audit_events TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE ON audit_events FROM {APP_ROLE}")
    op.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
    op.execute(f"REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM {APP_ROLE}, PUBLIC")


def downgrade() -> None:
    for table in (
        "audit_events",
        "scheduled_actions",
        "job_steps",
        "jobs",
        "memberships",
        "tenant_credentials",
        "tenants",
        "sessions",
        "users",
    ):
        op.drop_table(table)
    bind = op.get_bind()
    for name in ENUMS:
        pg.ENUM(name=name).drop(bind)
