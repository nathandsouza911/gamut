# SPDX-License-Identifier: AGPL-3.0-only
"""SQLAlchemy models for the nine Milestone 1 tables, and their enums.

Every query for tenant data must filter on tenant_id, directly or through the parent job.
The schema itself is created by migration 0001_initial, not by metadata.create_all().
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class TenantStatus(enum.StrEnum):
    pending = "pending"
    active = "active"
    degraded = "degraded"
    disabled = "disabled"


class AuthMode(enum.StrEnum):
    """How GAMUT reaches the tenant: an admin OAuth token plus a service account (oauth),
    or only a service account holding Admin console roles (dasa)."""

    oauth = "oauth"
    dasa = "dasa"


class Role(enum.StrEnum):
    """`owner` lives on users.is_owner; memberships hold admin, technician or auditor."""

    owner = "owner"
    admin = "admin"
    technician = "technician"
    auditor = "auditor"


class JobStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    waiting = "waiting"
    failed = "failed"
    succeeded = "succeeded"
    cancelled = "cancelled"
    awaiting_approval = "awaiting_approval"  # reserved for a later approval step


class StepStatus(enum.StrEnum):
    pending = "pending"
    running = "running"
    waiting = "waiting"
    succeeded = "succeeded"
    failed = "failed"
    skipped = "skipped"


class ScheduledStatus(enum.StrEnum):
    scheduled = "scheduled"
    cancelled = "cancelled"
    running = "running"
    done = "done"
    refused = "refused"
    failed = "failed"


STEP_KINDS = ("run", "async", "schedule")


def _pg_enum(cls: type[enum.StrEnum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e])


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Base(DeclarativeBase):
    pass


class User(Base):
    """A person who signs in to the panel (not a Google Workspace user)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(Text)
    oidc_subject: Mapped[str | None] = mapped_column(Text, unique=True)
    is_owner: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    # Only the bootstrap admin has a password (argon2 hash); everyone else uses OIDC.
    password_hash: Mapped[str | None] = mapped_column(Text)
    # A disabled user cannot sign in, and sessions they still hold are rejected.
    disabled: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = _created_at()


class Session(Base):
    """Server-side session. The cookie holds a random id; only its SHA-256 is stored."""

    __tablename__ = "sessions"

    id_hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    csrf_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    primary_domain: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # Every domain the tenant owns (primary included); target emails must match one.
    domains: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    admin_email: Mapped[str | None] = mapped_column(Text)
    status: Mapped[TenantStatus] = mapped_column(
        _pg_enum(TenantStatus, "tenant_status"),
        nullable=False,
        server_default=TenantStatus.pending.value,
    )
    auth_mode: Mapped[AuthMode] = mapped_column(
        _pg_enum(AuthMode, "auth_mode"),
        nullable=False,
        server_default=AuthMode.oauth.value,
    )
    # Google's customer id (for example C04jm7qkb); required by GAM in dasa mode.
    customer_id: Mapped[str | None] = mapped_column(Text)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


class TenantCredential(Base):
    """The tenant's GAM files, sealed (see app/crypto/envelope.py). Read by the worker only."""

    __tablename__ = "tenant_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    file_names: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    # Non-secret identifiers read from oauth2service.json, shown to guide setup.
    sa_client_email: Mapped[str | None] = mapped_column(Text)
    sa_client_id: Mapped[str | None] = mapped_column(Text)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    uploaded_at: Mapped[datetime] = _created_at()


class Membership(Base):
    """One role per user per tenant (admin, technician or auditor)."""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_memberships_user_tenant"),
        CheckConstraint("role <> 'owner'", name="ck_memberships_role_not_owner"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[Role] = mapped_column(_pg_enum(Role, "role"), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow: Mapped[str] = mapped_column(Text, nullable=False)
    # Stored after validation, with secrets removed.
    params: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    status: Mapped[JobStatus] = mapped_column(
        _pg_enum(JobStatus, "job_status"),
        nullable=False,
        server_default=JobStatus.queued.value,
        index=True,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(Text, unique=True)
    gam_version: Mapped[str | None] = mapped_column(Text)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # New on every claim; state is written only while the row still carries it.
    claim_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # Claims after an expired lease; the job fails after app.jobs.queue.MAX_RECLAIMS.
    reclaim_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = _created_at()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class JobStep(Base):
    __tablename__ = "job_steps"
    __table_args__ = (
        UniqueConstraint("job_id", "position", name="uq_job_steps_job_position"),
        CheckConstraint(
            "kind IN (" + ", ".join(f"'{k}'" for k in STEP_KINDS) + ")",
            name="ck_job_steps_kind",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    key: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # one of STEP_KINDS
    args: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    optional: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    status: Mapped[StepStatus] = mapped_column(
        _pg_enum(StepStatus, "step_status"),
        nullable=False,
        server_default=StepStatus.pending.value,
    )
    exit_code: Mapped[int | None] = mapped_column(Integer)
    output: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    next_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    poll_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScheduledAction(Base):
    """A delayed step, such as account deletion."""

    __tablename__ = "scheduled_actions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[ScheduledStatus] = mapped_column(
        _pg_enum(ScheduledStatus, "scheduled_status"),
        nullable=False,
        server_default=ScheduledStatus.scheduled.value,
    )
    result: Mapped[str | None] = mapped_column(Text)
    # Set while a worker runs the action; an expired lease means the worker died.
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # New on every claim; state is written only while the row still carries it.
    claim_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = _created_at()


class AuditEvent(Base):
    """Append-only, hash-chained (app/audit/chain.py). gamut_app has INSERT and SELECT only.

    tenant_id has no foreign key on purpose: events must outlive their tenant.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
