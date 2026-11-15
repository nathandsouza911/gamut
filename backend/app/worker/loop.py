# SPDX-License-Identifier: AGPL-3.0-only
"""The worker's main loop.

Each tick:
1. claim one runnable job (queued, a due waiting step, or an expired lease) and run it
   (app.jobs.queue.claim_next / run_job);
2. run the scheduled actions that are due (app.jobs.scheduled.run_due_actions);
3. queue a health check for every tenant whose last check is older than 24 hours.
When a tick did nothing the loop sleeps IDLE_SLEEP_S (2 s), waking early on stop.
An error in a tick is logged and the loop goes on; leases recover interrupted work.
"""

import logging
import os
import socket
import threading
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.db import get_engine, session_scope
from app.jobs.queue import HEARTBEAT_S, LEASE_S, claim_next, create_job, plan_job, run_job
from app.jobs.scheduled import run_due_actions
from app.models import Job, JobStatus, Tenant, TenantCredential, TenantStatus
from app.workflows.health import HEALTH_WORKFLOW

log = logging.getLogger(__name__)

IDLE_SLEEP_S = 2.0
HEALTH_INTERVAL = timedelta(hours=24)
_ACTIVE = (JobStatus.queued, JobStatus.running, JobStatus.waiting)


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def enqueue_due_health_checks(session: Session) -> int:
    """Queue a health check (actor "system") for each tenant that needs one.

    A tenant needs one when it is not disabled, has credentials and an admin_email, its
    last check is missing or older than 24 hours, and it has no queued, running or
    waiting health check. The idempotency key names the tenant, its last check and the
    day, so two workers racing here create one job. No commit. Returns jobs created.
    """
    now = datetime.now(UTC)
    pending_check = exists().where(
        Job.tenant_id == Tenant.id,
        Job.workflow == HEALTH_WORKFLOW,
        Job.status.in_(_ACTIVE),
    )
    tenants = list(session.scalars(
        select(Tenant)
        .join(TenantCredential, TenantCredential.tenant_id == Tenant.id)
        .where(
            Tenant.status != TenantStatus.disabled,
            Tenant.admin_email.is_not(None),
            or_(Tenant.last_health_check_at.is_(None),
                Tenant.last_health_check_at < now - HEALTH_INTERVAL),
            ~pending_check,
        )
        .order_by(Tenant.created_at)
    ))
    created = 0
    for tenant in tenants:
        last = tenant.last_health_check_at.isoformat() if tenant.last_health_check_at else "never"
        key = f"health-daily:{tenant.id}:{last}:{now.date().isoformat()}"
        if session.scalar(select(Job.id).where(Job.idempotency_key == key)) is not None:
            continue
        try:
            planned = plan_job(HEALTH_WORKFLOW, {}, tenant)
        except ValueError:
            log.info("tenant %s: health check cannot be planned", tenant.id)
            continue
        create_job(
            session, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
            steps=planned.steps, actor=None, idempotency_key=key,
        )
        created += 1
    return created


def tick(
    private_key: X25519PrivateKey,
    worker_id: str,
    *,
    lease_s: int = LEASE_S,
    heartbeat_s: float = HEARTBEAT_S,
) -> bool:
    """One loop iteration; True when it claimed a job, ran an action or queued a check."""
    busy = False
    with Session(get_engine(), expire_on_commit=False) as session:
        job = claim_next(session, worker_id, lease_s)
    if job is not None:
        busy = True
        run_job(job, private_key, lease_s=lease_s, heartbeat_s=heartbeat_s)
    with Session(get_engine(), expire_on_commit=False) as session:
        if run_due_actions(session, private_key):
            busy = True
    with session_scope() as session:
        if enqueue_due_health_checks(session):
            busy = True
    return busy


def run_forever(
    stop: threading.Event,
    private_key: X25519PrivateKey,
    *,
    worker_id: str | None = None,
    idle_sleep_s: float = IDLE_SLEEP_S,
    lease_s: int = LEASE_S,
    heartbeat_s: float = HEARTBEAT_S,
) -> None:
    """Tick until `stop` is set (the job in progress finishes first)."""
    worker_id = worker_id or default_worker_id()
    log.info("worker %s started", worker_id)
    while not stop.is_set():
        try:
            busy = tick(private_key, worker_id, lease_s=lease_s, heartbeat_s=heartbeat_s)
        except Exception as exc:
            log.error("worker tick failed: %s", type(exc).__name__, exc_info=exc)
            busy = False
        if not busy:
            stop.wait(idle_sleep_s)
    log.info("worker %s stopped", worker_id)
