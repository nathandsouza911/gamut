# SPDX-License-Identifier: AGPL-3.0-only
"""Run a job's steps (worker side).

run_steps opens the tenant's sealed GAM files with the worker's private key, writes them
into one per-job directory (app.crypto.envelope.materialize) for the whole run, and
executes each unfinished step in order through its workflow. After each step it stores
the outcome, appends an audit event and commits, so progress is visible while the job
runs. It stops at the first failed step, or at a waiting step (the worker loop polls it
later). When the job ends it calls the workflow's on_finished hook.

Stored output is capped and scrubbed of the credential values it could contain (tokens,
client secrets, private keys), in case GAM ever prints one.
"""

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.crypto.envelope import SealedBundle, materialize, open_bundle
from app.gam.commands import redact_argv
from app.gam.runner import gam_version
from app.models import Job, JobStatus, JobStep, StepStatus, Tenant, TenantCredential, User
from app.settings import get_settings
from app.workflows.base import StepContext, StepOutcome, Workflow, get_workflow

log = logging.getLogger(__name__)

STORED_OUTPUT_MAX = 64_000
REDACTED = "[redacted]"
# JSON keys in GAM's credential files whose values are secret.
SECRET_KEYS = frozenset(
    {"client_secret", "refresh_token", "token", "access_token", "id_token", "private_key",
     "private_key_id"}
)
_MIN_SECRET_LEN = 8
_UNFINISHED = (StepStatus.pending, StepStatus.running, StepStatus.waiting, StepStatus.failed)


def _collect(value: Any, found: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_KEYS and isinstance(item, str):
                found.add(item)
                found.update(line.strip() for line in item.splitlines())
            else:
                _collect(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect(item, found)


def secret_values(files: dict[str, bytes]) -> list[str]:
    """Secret strings in the credential files, longest first."""
    found: set[str] = set()
    for content in files.values():
        try:
            _collect(json.loads(content), found)
        except (UnicodeDecodeError, ValueError):
            continue
    return sorted((s for s in found if len(s) >= _MIN_SECRET_LEN), key=len, reverse=True)


def scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def _now() -> datetime:
    return datetime.now(UTC)


def _actor(session: Session, job: Job) -> str:
    if job.created_by is not None:
        user = session.get(User, job.created_by)
        if user is not None:
            return user.email
    return "system"


def _target(job: Job, tenant: Tenant) -> str:
    target = job.params.get("target") if isinstance(job.params, dict) else None
    return str(target) if target else tenant.primary_domain


def _record(
    session: Session,
    *,
    job: Job,
    tenant: Tenant,
    step: JobStep,
    outcome: StepOutcome,
    secrets: list[str],
    actor: str,
) -> None:
    """Store the outcome on the step, audit it and commit."""
    step.status = outcome.status
    step.exit_code = outcome.exit_code
    step.output = scrub(outcome.output, secrets)[:STORED_OUTPUT_MAX]
    step.data = outcome.data
    if outcome.argv:
        step.args = redact_argv(outcome.argv)
    if outcome.status == StepStatus.waiting:
        step.poll_attempts += 1
        step.next_poll_at = _now() + timedelta(seconds=outcome.poll_after_s or 60)
    else:
        step.next_poll_at = None
        step.finished_at = _now()
    session.flush()
    append_event(
        session,
        actor=actor,
        tenant_id=tenant.id,
        action=f"job.step.{outcome.status.value}",
        target=_target(job, tenant),
        details={
            "job_id": str(job.id),
            "workflow": job.workflow,
            "step": step.key,
            "position": step.position,
            "argv": list(step.args),
            "exit_code": outcome.exit_code,
            "gam_version": job.gam_version,
        },
    )
    session.commit()


def _finish(
    session: Session, job: Job, tenant: Tenant, workflow: Workflow, status: JobStatus, actor: str
) -> None:
    job.status = status
    job.finished_at = _now()
    job.lease_until = None
    session.flush()
    workflow.on_finished(session, job)
    append_event(
        session, actor=actor, tenant_id=tenant.id, action=f"job.{status.value}",
        target=_target(job, tenant),
        details={"job_id": str(job.id), "workflow": job.workflow, "gam_version": job.gam_version},
    )
    session.commit()


def _fail_before_start(
    session: Session, job: Job, tenant: Tenant, workflow: Workflow, steps: list[JobStep],
    reason: str, actor: str,
) -> None:
    step = steps[0]
    step.started_at = _now()
    _record(
        session, job=job, tenant=tenant, step=step,
        outcome=StepOutcome(status=StepStatus.failed, output=reason), secrets=[], actor=actor,
    )
    _finish(session, job, tenant, workflow, JobStatus.failed, actor)


def run_steps(session: Session, job: Job, private_key: X25519PrivateKey) -> None:
    """Run `job`'s unfinished steps in order (see the module docstring).

    Sets: job.status running -> succeeded | failed (or waiting), job.started_at (first
    run), job.gam_version, job.finished_at; per step status, started_at, exit_code,
    output (scrubbed, capped), data, args (redacted argv actually run), finished_at or
    next_poll_at/poll_attempts for waiting steps. Commits after each step.
    """
    tenant = session.get(Tenant, job.tenant_id)
    if tenant is None:
        return  # deleted; its jobs went with it
    workflow = get_workflow(job.workflow)
    actor = _actor(session, job)
    steps = [
        s for s in session.scalars(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        )
        if s.status in _UNFINISHED
    ]
    job.status = JobStatus.running
    job.started_at = job.started_at or _now()
    job.gam_version = gam_version()
    session.commit()
    if not steps:
        _finish(session, job, tenant, workflow, JobStatus.succeeded, actor)
        return

    credential = session.get(TenantCredential, tenant.id)
    if credential is None:
        _fail_before_start(
            session, job, tenant, workflow, steps,
            "The tenant has no stored credentials. Upload its GAM files first.", actor,
        )
        return
    sealed = SealedBundle(
        credential.ciphertext, credential.nonce, credential.wrapped_key, credential.key_version
    )
    try:
        files = open_bundle(sealed, private_key, associated_data=tenant.id.bytes)
    except (InvalidTag, ValueError):
        log.warning("credentials for tenant %s could not be decrypted", tenant.id)
        _fail_before_start(
            session, job, tenant, workflow, steps,
            "The stored credentials could not be decrypted (wrong credential key?). "
            "Upload the tenant's GAM files again.", actor,
        )
        return
    secrets = secret_values(files)

    with materialize(files, base=get_settings().job_dir) as cfg_dir:
        del files
        for step in steps:
            step.status = StepStatus.running
            step.started_at = step.started_at or _now()
            session.commit()
            ctx = StepContext(session=session, tenant=tenant, job=job, step=step, cfg_dir=cfg_dir)
            try:
                outcome = workflow.execute(step, ctx)
            except Exception as exc:  # a workflow bug must not leave the step running
                log.exception("step %s of job %s raised", step.key, job.id)
                outcome = StepOutcome(
                    status=StepStatus.failed, output=f"internal error ({type(exc).__name__})"
                )
            _record(
                session, job=job, tenant=tenant, step=step, outcome=outcome,
                secrets=secrets, actor=actor,
            )
            if outcome.status == StepStatus.failed:
                _finish(session, job, tenant, workflow, JobStatus.failed, actor)
                return
            if outcome.status == StepStatus.waiting:
                job.status = JobStatus.waiting
                session.commit()
                return
    _finish(session, job, tenant, workflow, JobStatus.succeeded, actor)
