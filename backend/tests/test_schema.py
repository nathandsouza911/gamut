# SPDX-License-Identifier: AGPL-3.0-only
from collections.abc import Callable

import psycopg.errors
import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.models import (
    AuditEvent,
    Base,
    Job,
    JobStatus,
    Membership,
    Role,
    ScheduledStatus,
    StepStatus,
    Tenant,
    TenantStatus,
    User,
)

EXPECTED_TABLES = {
    "users",
    "sessions",
    "tenants",
    "tenant_credentials",
    "memberships",
    "jobs",
    "job_steps",
    "scheduled_actions",
    "audit_events",
}


def _enum_values(engine: Engine, type_name: str) -> list[str]:
    with engine.connect() as conn:
        return list(
            conn.execute(text(f"SELECT unnest(enum_range(NULL::{type_name}))::text")).scalars()
        )


def test_jobs_has_approval_fields(owner_engine: Engine) -> None:
    columns = {c["name"]: c for c in inspect(owner_engine).get_columns("jobs")}

    assert "approved_by" in columns
    assert columns["approved_by"]["nullable"] is True
    assert "awaiting_approval" in _enum_values(owner_engine, "job_status")
    assert JobStatus.awaiting_approval.value == "awaiting_approval"


def test_all_tables_exist(owner_engine: Engine) -> None:
    assert EXPECTED_TABLES <= set(inspect(owner_engine).get_table_names())


def test_enum_types_match_python(owner_engine: Engine) -> None:
    assert _enum_values(owner_engine, "tenant_status") == [
        "pending",
        "active",
        "degraded",
        "disabled",
    ]
    assert _enum_values(owner_engine, "role") == ["owner", "admin", "technician", "auditor"]
    assert _enum_values(owner_engine, "job_status") == [
        "queued",
        "running",
        "waiting",
        "failed",
        "succeeded",
        "cancelled",
        "awaiting_approval",
    ]
    assert _enum_values(owner_engine, "step_status") == [
        "pending",
        "running",
        "waiting",
        "succeeded",
        "failed",
        "skipped",
    ]
    assert _enum_values(owner_engine, "scheduled_status") == [
        "scheduled",
        "cancelled",
        "running",
        "done",
        "refused",
        "failed",
    ]
    for py_enum, pg_name in [
        (TenantStatus, "tenant_status"),
        (Role, "role"),
        (JobStatus, "job_status"),
        (StepStatus, "step_status"),
        (ScheduledStatus, "scheduled_status"),
    ]:
        assert [m.value for m in py_enum] == _enum_values(owner_engine, pg_name)


def test_app_role_has_dml_on_tenant_tables(
    app_session: Session,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
) -> None:
    user = make_user()
    tenant = make_tenant()
    app_session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=Role.technician))
    job = Job(tenant_id=tenant.id, workflow="offboarding", params={}, created_by=user.id)
    app_session.add(job)
    app_session.commit()

    assert job.status is JobStatus.queued
    assert job.approved_by is None
    tenant.name = "Renamed"
    app_session.commit()
    app_session.delete(job)
    app_session.commit()


def test_membership_is_unique_per_user_and_tenant(
    app_session: Session,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
) -> None:
    user = make_user()
    tenant = make_tenant()
    app_session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=Role.admin))
    app_session.commit()
    app_session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=Role.auditor))

    with pytest.raises(IntegrityError):
        app_session.commit()
    app_session.rollback()


def test_membership_cannot_hold_owner_role(
    app_session: Session,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
) -> None:
    app_session.add(
        Membership(user_id=make_user().id, tenant_id=make_tenant().id, role=Role.owner)
    )
    with pytest.raises(IntegrityError):
        app_session.commit()
    app_session.rollback()


def test_audit_events_survive_tenant_deletion(
    app_session: Session, make_tenant: Callable[..., Tenant]
) -> None:
    tenant = make_tenant()
    tenant_id = tenant.id
    append_event(app_session, actor="a", tenant_id=tenant_id, action="x", target=None, details={})
    app_session.commit()
    app_session.delete(tenant)
    app_session.commit()

    event = app_session.scalars(select(AuditEvent)).one()
    assert event.tenant_id == tenant_id


def test_app_role_cannot_truncate(app_session: Session) -> None:
    with pytest.raises(ProgrammingError) as excinfo:
        app_session.execute(text("TRUNCATE jobs"))
    assert isinstance(excinfo.value.orig, psycopg.errors.InsufficientPrivilege)
    app_session.rollback()


def test_models_match_migration(owner_engine: Engine) -> None:
    with owner_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
