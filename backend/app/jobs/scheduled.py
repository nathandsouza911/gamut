# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled actions: work that runs later, such as deleting an offboarded account.

A workflow step creates a `scheduled` row with create_scheduled_action. Until it runs it
can be cancelled (cancel_scheduled_action). The worker loop calls run_due_actions each
tick: it claims due rows with FOR UPDATE SKIP LOCKED, marks them `running` with a lease
(a row whose worker died is claimed again once the lease expires), decrypts the
tenant's GAM files into a per-action directory and calls the action's handler. The
handler returns done, refused (its guard said no) or failed; the result is stored and
audited. Handlers are looked up by name in a registry (register_action); workflow
modules register theirs when they are imported.

No database transaction is open while a handler runs.
"""

import logging
import uuid
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.crypto.envelope import materialize
from app.gam.commands import redact_argv
from app.jobs.execute import (
    PrepareError,
    error_outcome,
    job_actor,
    open_tenant_files,
    scrub,
    secret_values,
)
from app.jobs.queue import ConflictError
from app.models import Job, ScheduledAction, ScheduledStatus, Tenant, TenantStatus
from app.settings import get_settings
from app.workflows.base import load_builtin_workflows

log = logging.getLogger(__name__)

ACTION_LEASE_S = 900
RESULT_MAX = 4_000
_FINAL = (ScheduledStatus.done, ScheduledStatus.refused, ScheduledStatus.failed)


@dataclass
class ActionContext:
    session: Session
    tenant: Tenant
    job: Job
    action: ScheduledAction  # .params holds what the creating step stored
    cfg_dir: Path  # the tenant's decrypted GAM files (GAMCFGDIR)


@dataclass(frozen=True)
class ActionResult:
    """status: done, refused (a guard declined; it will not run again) or failed."""

    status: ScheduledStatus
    result: str = ""
    argv: list[str] = field(default_factory=list)  # audited after redact_argv
    exit_code: int | None = None


ActionHandler = Callable[[ActionContext], ActionResult]


class UnknownAction(LookupError):
    pass


class ScheduledActionNotFound(LookupError):
    pass


_HANDLERS: dict[str, ActionHandler] = {}


def register_action(name: str, handler: ActionHandler) -> ActionHandler:
    _HANDLERS[name] = handler
    return handler


def get_action(name: str) -> ActionHandler:
    load_builtin_workflows()
    try:
        return _HANDLERS[name]
    except KeyError:
        raise UnknownAction(name) from None


def _now() -> datetime:
    return datetime.now(UTC)


def _target(row: ScheduledAction, tenant: Tenant | None) -> str | None:
    target = row.params.get("target") if isinstance(row.params, dict) else None
    if target:
        return str(target)
    return tenant.primary_domain if tenant is not None else None


def create_scheduled_action(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    job_id: uuid.UUID,
    action: str,
    run_at: datetime,
    params: dict[str, Any],
    actor: str,
) -> ScheduledAction:
    """Add a `scheduled` action of `job` (in the caller's transaction; no commit).

    Raises UnknownAction for an unregistered action and ScheduledActionNotFound when
    the job is not the tenant's. Audited as `scheduled_action.created`.
    """
    get_action(action)
    job = session.get(Job, job_id)
    if job is None or job.tenant_id != tenant_id:
        raise ScheduledActionNotFound("job not found")
    row = ScheduledAction(
        tenant_id=tenant_id, job_id=job_id, action=action, run_at=run_at, params=params,
        status=ScheduledStatus.scheduled,
    )
    session.add(row)
    session.flush()
    append_event(
        session, actor=actor, tenant_id=tenant_id, action="scheduled_action.created",
        target=_target(row, session.get(Tenant, tenant_id)),
        details={"action_id": str(row.id), "action": action, "job_id": str(job_id),
                 "run_at": run_at.isoformat()},
    )
    return row


def cancel_scheduled_action(
    session: Session, *, tenant_id: uuid.UUID, action_id: uuid.UUID, actor: str
) -> ScheduledAction:
    """Cancel a `scheduled` action (no commit). Audited as `scheduled_action.cancelled`.

    Raises ScheduledActionNotFound when the id is not the tenant's, and ConflictError
    (409) once it is running or finished.
    """
    row = session.scalar(
        select(ScheduledAction)
        .where(ScheduledAction.id == action_id, ScheduledAction.tenant_id == tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise ScheduledActionNotFound("scheduled action not found")
    if row.status != ScheduledStatus.scheduled:
        raise ConflictError(f"the action is {row.status.value} and can no longer be cancelled")
    row.status = ScheduledStatus.cancelled
    session.flush()
    append_event(
        session, actor=actor, tenant_id=tenant_id, action="scheduled_action.cancelled",
        target=_target(row, session.get(Tenant, tenant_id)),
        details={"action_id": str(row.id), "action": row.action, "job_id": str(row.job_id)},
    )
    return row


def _claim(session: Session, lease_s: int) -> ScheduledAction | None:
    now = _now()
    row = session.scalar(
        select(ScheduledAction)
        .where(or_(
            and_(ScheduledAction.status == ScheduledStatus.scheduled,
                 ScheduledAction.run_at <= now),
            and_(ScheduledAction.status == ScheduledStatus.running,
                 or_(ScheduledAction.lease_until.is_(None), ScheduledAction.lease_until < now)),
        ))
        .order_by(ScheduledAction.run_at, ScheduledAction.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    )
    if row is None:
        session.commit()
        return None
    reclaimed = row.status == ScheduledStatus.running
    row.status = ScheduledStatus.running
    row.lease_until = now + timedelta(seconds=lease_s)
    session.flush()
    job = session.get(Job, row.job_id)
    append_event(
        session,
        actor=job_actor(session, job) if job is not None else "system",
        tenant_id=row.tenant_id, action="scheduled_action.started",
        target=_target(row, session.get(Tenant, row.tenant_id)),
        details={"action_id": str(row.id), "action": row.action, "job_id": str(row.job_id),
                 "lease_expired": reclaimed},
    )
    session.commit()
    return row


def _finish(
    session: Session, row: ScheduledAction, tenant: Tenant, actor: str, result: ActionResult,
    secrets: list[str],
) -> None:
    status = result.status if result.status in _FINAL else ScheduledStatus.failed
    row.status = status
    row.result = scrub(result.result, secrets)[:RESULT_MAX]
    row.lease_until = None
    session.flush()
    append_event(
        session, actor=actor, tenant_id=tenant.id, action=f"scheduled_action.{status.value}",
        target=_target(row, tenant),
        details={"action_id": str(row.id), "action": row.action, "job_id": str(row.job_id),
                 "argv": redact_argv(result.argv), "exit_code": result.exit_code},
    )
    session.commit()


def _run_one(session: Session, row: ScheduledAction, private_key: X25519PrivateKey) -> None:
    tenant = session.get(Tenant, row.tenant_id)
    job = session.get(Job, row.job_id)
    if tenant is None or job is None:
        return  # deleted together with the tenant or job (cascade)
    actor = job_actor(session, job)

    def fail(message: str, status: ScheduledStatus = ScheduledStatus.failed) -> None:
        _finish(session, row, tenant, actor, ActionResult(status=status, result=message), [])

    if tenant.status == TenantStatus.disabled:
        fail("The tenant is disabled, so the action did not run.", ScheduledStatus.refused)
        return
    try:
        handler = get_action(row.action)
    except UnknownAction:
        fail(f"Unknown action {row.action!r}.")
        return
    try:
        files = open_tenant_files(session, tenant, private_key)
    except PrepareError as exc:
        fail(str(exc))
        return
    secrets = secret_values(files)
    with ExitStack() as stack:
        try:
            cfg_dir = stack.enter_context(materialize(files, base=get_settings().job_dir))
        except Exception as exc:
            log.warning("action directory could not be prepared: %s", type(exc).__name__)
            fail(f"The worker could not prepare the job directory ({type(exc).__name__}).")
            return
        del files
        session.commit()  # nothing stays open while the handler runs GAM
        ctx = ActionContext(session=session, tenant=tenant, job=job, action=row, cfg_dir=cfg_dir)
        try:
            result = handler(ctx)
        except Exception as exc:
            session.rollback()
            outcome = error_outcome(exc)
            result = ActionResult(status=ScheduledStatus.failed, result=outcome.output)
    _finish(session, row, tenant, actor, result, secrets)


def run_due_actions(
    session: Session,
    private_key: X25519PrivateKey,
    *,
    limit: int = 10,
    lease_s: int = ACTION_LEASE_S,
) -> int:
    """Run up to `limit` due actions, one at a time; returns how many were claimed."""
    previous = session.expire_on_commit
    session.expire_on_commit = False
    try:
        count = 0
        while count < limit:
            row = _claim(session, lease_s)
            if row is None:
                break
            count += 1
            _run_one(session, row, private_key)
        return count
    finally:
        session.expire_on_commit = previous
