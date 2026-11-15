# SPDX-License-Identifier: AGPL-3.0-only
"""Run a job's steps (worker side).

run_steps opens the tenant's sealed GAM files with the worker's private key, writes them
into one per-job directory (app.crypto.envelope.materialize) for the whole run, and
executes each runnable step in order through its workflow. After each step it stores
the outcome, appends an audit event and commits, so progress is visible while the job
runs. It stops at the first failed step, or at a waiting step (the worker loop claims
the job again when the step is due and calls the workflow's execute() for it again).
When the job ends it calls the workflow's on_finished hook.

Runnable steps are `pending` ones, `running` ones (left behind by a worker whose lease
expired; steps are safe to run twice) and `waiting` ones. A `failed` step never runs
again by itself: app.jobs.queue.retry_step sets it back to pending.

No database transaction is open while a step executes (GAM can run for minutes): the
session is committed first and objects stay loaded (expire_on_commit is off during the
run). A workflow that queries through ctx.session should finish its transaction before
it starts GAM.

GAM exits that mean "Google's rate limit or quota was hit" (exit 9 with one of the
quota reasons in GAM's error line; see docs/decisions.md) do not fail the step: it
waits with backoff and runs again, at most MAX_QUOTA_RETRIES times in a row.

A step that raises keeps the data earlier runs stored (kept_data); an outcome the
workflow returns replaces it.

Stored output is capped and scrubbed of the credential values it could contain (tokens,
client secrets, private keys), in case GAM ever prints one.
"""

import json
import logging
import re
import uuid
from contextlib import ExitStack
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.crypto.envelope import SealedBundle, materialize, open_bundle, open_json
from app.gam.commands import redact_argv
from app.gam.runner import gam_version
from app.models import (
    Job,
    JobStatus,
    JobStep,
    StepStatus,
    Tenant,
    TenantCredential,
    TenantStatus,
    User,
)
from app.settings import get_settings
from app.workflows.base import (
    SEALED_PARAMS_KEY,
    StepContext,
    StepOutcome,
    Workflow,
    combined_output,
    get_workflow,
    sealed_params_aad,
)

log = logging.getLogger(__name__)

STORED_OUTPUT_MAX = 64_000
ERROR_MESSAGE_MAX = 2_000
REDACTED = "[redacted]"
# JSON keys in GAM's credential files whose values are secret.
SECRET_KEYS = frozenset(
    {"client_secret", "refresh_token", "token", "access_token", "id_token", "private_key",
     "private_key_id"}
)
_MIN_SECRET_LEN = 8
_RUNNABLE = (StepStatus.pending, StepStatus.running, StepStatus.waiting)

# Waiting steps: next poll after min(30 * 2**attempts, 900) seconds.
BACKOFF_BASE_S = 30
BACKOFF_MAX_S = 900

# GAM 7.52.3 exits with HTTP_ERROR_RC (9) when an API call still fails after its own
# retries; the error line is "ERROR: <status>: <reason> - <message>". These reasons are
# Google's rate-limit and quota errors (gam/gamlib/glgapi.py DEFAULT_RETRY_REASONS).
RATE_LIMIT_EXIT_CODE = 9
_RATE_LIMIT_REASON = re.compile(
    r"\b\d{3}: (?:quotaExceeded|rateLimitExceeded|userRateLimitExceeded"
    r"|sharingRateLimitExceeded) - "
)
MAX_QUOTA_RETRIES = 6


class PrepareError(Exception):
    """The job cannot start; the message is safe to show to an operator."""


class LeaseLost(Exception):
    """Another worker claimed the job (its claim_token changed): stop without writing."""


# session.info key holding the claim token run_steps fences its writes with.
_FENCE_KEY = "gamut.claim_token"


def _commit(session: Session, job: Job) -> None:
    """Commit, but only while the job still carries this run's claim token.

    The job row is locked (FOR UPDATE) and its token compared inside the transaction
    being committed, so a worker whose lease was taken over can never commit job or
    step state over the new owner's. On a mismatch nothing is written: LeaseLost.
    """
    token = session.info.get(_FENCE_KEY)
    if token is not None:
        with session.no_autoflush:
            current = session.scalar(
                select(Job.claim_token).where(Job.id == job.id).with_for_update()
            )
        if current != token:
            raise LeaseLost(str(job.id))
    session.commit()


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
    """`text` with secret values replaced and NUL bytes removed (PostgreSQL text and
    jsonb cannot store NUL)."""
    text = text.replace("\x00", "")
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def backoff_seconds(attempts: int, poll_after_s: int | None = None) -> int:
    """Delay before polling a waiting step again: min(30 * 2**attempts, 900) seconds.

    `attempts` is how many times the step has already waited. A workflow may ask for a
    longer delay (poll_after_s); the result never exceeds 900 seconds.
    """
    delay: int = BACKOFF_BASE_S * 2 ** min(max(attempts, 0), 10)
    return min(max(delay, poll_after_s or 0), BACKOFF_MAX_S)


def is_rate_limited(exit_code: int | None, output: str) -> bool:
    """True when GAM gave up on a Google rate-limit or quota error."""
    return exit_code == RATE_LIMIT_EXIT_CODE and bool(_RATE_LIMIT_REASON.search(output))


def open_tenant_files(
    session: Session, tenant: Tenant, private_key: X25519PrivateKey
) -> dict[str, bytes]:
    """The tenant's decrypted GAM files. Raises PrepareError (operator-safe message)."""
    credential = session.get(TenantCredential, tenant.id)
    if credential is None:
        raise PrepareError("The tenant has no stored credentials. Upload its GAM files first.")
    sealed = SealedBundle(
        credential.ciphertext, credential.nonce, credential.wrapped_key, credential.key_version
    )
    try:
        return open_bundle(sealed, private_key, associated_data=tenant.id.bytes)
    except (InvalidTag, ValueError):
        log.warning("credentials for tenant %s could not be decrypted", tenant.id)
        raise PrepareError(
            "The stored credentials could not be decrypted (wrong credential key?). "
            "Upload the tenant's GAM files again."
        ) from None
    except Exception as exc:
        log.warning("credentials for tenant %s: %s", tenant.id, type(exc).__name__)
        raise PrepareError(
            f"The stored credentials could not be opened ({type(exc).__name__})."
        ) from None


def open_sealed_params(
    job: Job, tenant: Tenant, private_key: X25519PrivateKey
) -> dict[str, Any]:
    """The job's sealed parameters, opened ({} if none). Raises PrepareError."""
    blob = job.params.get(SEALED_PARAMS_KEY) if isinstance(job.params, dict) else None
    if blob is None:
        return {}
    try:
        value = open_json(blob, private_key, associated_data=sealed_params_aad(tenant.id))
    except (InvalidTag, ValueError):
        log.warning("sealed parameters of job %s could not be opened", job.id)
        raise PrepareError(
            "The job's protected parameters could not be decrypted (wrong credential key?). "
            "Start a new job."
        ) from None
    if not isinstance(value, dict):
        raise PrepareError("The job's protected parameters are malformed. Start a new job.")
    return value


def error_outcome(exc: Exception) -> StepOutcome:
    """A failed outcome for an exception raised by a workflow.

    A plain ValueError carries an operator-readable message (the Workflow contract), so
    it is shown; anything else is shown only by type and logged.
    """
    if type(exc) is ValueError:
        log.info("step raised ValueError")
        return StepOutcome(status=StepStatus.failed, output=str(exc)[:ERROR_MESSAGE_MAX])
    log.error("step raised %s", type(exc).__name__, exc_info=exc)
    return StepOutcome(status=StepStatus.failed, output=f"internal error ({type(exc).__name__})")


def _now() -> datetime:
    return datetime.now(UTC)


def job_actor(session: Session, job: Job) -> str:
    """Audit actor for work done on behalf of `job`: its creator's email, or "system"."""
    if job.created_by is not None:
        user = session.get(User, job.created_by)
        if user is not None:
            return user.email
    return "system"


def job_target(job: Job, tenant: Tenant) -> str:
    target = job.params.get("target") if isinstance(job.params, dict) else None
    return str(target) if target else tenant.primary_domain


def _audit_step(
    session: Session, *, job: Job, tenant: Tenant, step: JobStep, status: StepStatus,
    exit_code: int | None, actor: str,
) -> None:
    append_event(
        session,
        actor=actor,
        tenant_id=tenant.id,
        action=f"job.step.{status.value}",
        target=job_target(job, tenant),
        details={
            "job_id": str(job.id),
            "workflow": job.workflow,
            "step": step.key,
            "position": step.position,
            "argv": list(step.args),
            "exit_code": exit_code,
            "gam_version": job.gam_version,
            # What the step recorded (for example the group list kept for a restore),
            # once it has a result. The audit log outlives the job rows.
            **({"data": step.data} if status != StepStatus.running and step.data else {}),
        },
    )


def kept_data(step: JobStep) -> dict[str, Any]:
    """The step's data as last committed, for outcomes that carry no data of their own.

    A step that ends in an exception (error_outcome) or fails before GAM runs keeps
    what earlier runs recorded (a group list, a transfer id). Outcomes a workflow
    returns itself replace the data as before, so a workflow can still drop keys.
    """
    return dict(step.data) if isinstance(step.data, dict) else {}


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
        delay = backoff_seconds(step.poll_attempts, outcome.poll_after_s)
        step.poll_attempts += 1
        step.next_poll_at = _now() + timedelta(seconds=delay)
    else:
        step.next_poll_at = None
        step.finished_at = _now()
    session.flush()
    _audit_step(session, job=job, tenant=tenant, step=step, status=outcome.status,
                exit_code=outcome.exit_code, actor=actor)
    _commit(session, job)


def _finish(
    session: Session, job: Job, tenant: Tenant, workflow: Workflow, status: JobStatus,
    actor: str, reason: str | None = None,
) -> None:
    job.status = status
    job.finished_at = _now()
    job.lease_until = None
    session.flush()
    workflow.on_finished(session, job)
    details: dict[str, Any] = {
        "job_id": str(job.id), "workflow": job.workflow, "gam_version": job.gam_version
    }
    if reason:
        details["reason"] = reason
    append_event(
        session, actor=actor, tenant_id=tenant.id, action=f"job.{status.value}",
        target=job_target(job, tenant), details=details,
    )
    _commit(session, job)


def _fail_before_start(
    session: Session, job: Job, tenant: Tenant, workflow: Workflow, steps: list[JobStep],
    reason: str, actor: str,
) -> None:
    """Fail the job without running GAM: the first runnable step carries `reason`."""
    if steps:
        step = steps[0]
        step.started_at = step.started_at or _now()
        _record(
            session, job=job, tenant=tenant, step=step,
            outcome=StepOutcome(status=StepStatus.failed, output=reason,
                                data=kept_data(step)),
            secrets=[],
            actor=actor,
        )
    _finish(session, job, tenant, workflow, JobStatus.failed, actor, reason=reason)


def _quota_wait(step: JobStep, outcome: StepOutcome) -> StepOutcome:
    """Turn a rate-limited GAM failure into a waiting outcome (bounded)."""
    if outcome.status != StepStatus.failed or not is_rate_limited(
        outcome.exit_code, outcome.output
    ):
        return outcome
    previous = dict(step.data) if isinstance(step.data, dict) else {}
    retries = int(previous.get("quota_retries", 0))
    if retries >= MAX_QUOTA_RETRIES:
        return StepOutcome(
            status=StepStatus.failed,
            output=combined_output(
                outcome.output,
                f"Google's rate limit or quota was still reached after {retries} waits. "
                "Retry the step later.",
            ),
            data=outcome.data, exit_code=outcome.exit_code, argv=outcome.argv,
        )
    return StepOutcome(
        status=StepStatus.waiting,
        output=combined_output(
            outcome.output,
            f"Google rate limit or quota reached; the step runs again later "
            f"(wait {retries + 1} of {MAX_QUOTA_RETRIES}).",
        ),
        data={**previous, **outcome.data, "quota_retries": retries + 1},
        exit_code=outcome.exit_code,
        argv=outcome.argv,
    )


def run_steps(
    session: Session,
    job: Job,
    private_key: X25519PrivateKey,
    *,
    claim_token: uuid.UUID | None = None,
) -> None:
    """Run `job`'s runnable steps in order (see the module docstring).

    Sets: job.status running -> succeeded | failed | waiting, job.started_at (first
    run), job.gam_version, job.finished_at, job.lease_until (cleared when the job waits
    or ends); per step status, started_at, exit_code, output (scrubbed, capped), data,
    args (redacted argv actually run), finished_at or next_poll_at/poll_attempts for
    waiting steps. Commits after each transition. A disabled tenant, missing or
    undecryptable credentials, or a worker that cannot run GAM or create the job
    directory fail the job with an operator-readable message on the first runnable step.

    claim_token (the value claim_next gave the job) fences every commit: once another
    worker has claimed the job, this run stops at its next write and writes nothing
    (it logs and returns). A GAM call already running is not killed; it finishes (within
    its timeout) and its result is discarded. The new owner runs that step again, which
    is safe because steps are idempotent, whereas killing GAM mid-call could leave a
    change half-applied. Without a token (tests, tools) writes are not fenced.
    """
    job_id = job.id
    previous = session.expire_on_commit
    session.expire_on_commit = False  # no lazy loads (= transactions) while GAM runs
    session.info[_FENCE_KEY] = claim_token
    try:
        _run_steps(session, job, private_key)
    except LeaseLost:
        session.rollback()
        log.warning("job %s was claimed by another worker; this run stopped", job_id)
    finally:
        session.info.pop(_FENCE_KEY, None)
        session.expire_on_commit = previous


def _run_steps(session: Session, job: Job, private_key: X25519PrivateKey) -> None:
    tenant = session.get(Tenant, job.tenant_id)
    if tenant is None:
        return  # deleted; its jobs went with it
    workflow = get_workflow(job.workflow)
    actor = job_actor(session, job)
    all_steps = list(session.scalars(
        select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
    ))
    steps = [s for s in all_steps if s.status in _RUNNABLE]
    job.status = JobStatus.running
    job.started_at = job.started_at or _now()

    if tenant.status == TenantStatus.disabled:
        _fail_before_start(
            session, job, tenant, workflow, steps,
            "The tenant is disabled, so its jobs do not run. Enable the tenant, then retry "
            "the step.", actor,
        )
        return
    try:
        job.gam_version = gam_version()
    except Exception as exc:
        log.warning("gam version failed: %s", type(exc).__name__)
        _fail_before_start(
            session, job, tenant, workflow, steps,
            f"The worker could not run GAM ({type(exc).__name__}). Check the worker's GAM "
            "installation and its job directory (GAMUT_JOB_DIR).", actor,
        )
        return
    _commit(session, job)
    if any(s.status == StepStatus.failed for s in all_steps):
        # Only retry_step or skip_step resolve a failed step.
        _finish(session, job, tenant, workflow, JobStatus.failed, actor)
        return
    if not steps:
        _finish(session, job, tenant, workflow, JobStatus.succeeded, actor)
        return

    try:
        files = open_tenant_files(session, tenant, private_key)
        sealed = open_sealed_params(job, tenant, private_key)
    except PrepareError as exc:
        _fail_before_start(session, job, tenant, workflow, steps, str(exc), actor)
        return
    secrets = secret_values(files)

    with ExitStack() as stack:
        try:
            cfg_dir = stack.enter_context(materialize(files, base=get_settings().job_dir))
        except Exception as exc:
            log.warning("job directory could not be prepared: %s", type(exc).__name__)
            _fail_before_start(
                session, job, tenant, workflow, steps,
                f"The worker could not prepare the job directory ({type(exc).__name__}). "
                "Check GAMUT_JOB_DIR on the worker.", actor,
            )
            return
        del files
        for step in steps:
            step.status = StepStatus.running
            step.started_at = step.started_at or _now()
            session.flush()
            _audit_step(session, job=job, tenant=tenant, step=step, status=StepStatus.running,
                        exit_code=None, actor=actor)
            _commit(session, job)  # nothing stays open while GAM runs
            ctx = StepContext(session=session, tenant=tenant, job=job, step=step,
                              cfg_dir=cfg_dir, sealed=sealed)
            try:
                outcome = workflow.execute(step, ctx)
            except Exception as exc:  # a workflow error must not leave the step running
                session.rollback()  # step.data reloads as last committed
                outcome = replace(error_outcome(exc), data=kept_data(step))
            outcome = _quota_wait(step, outcome)
            _record(
                session, job=job, tenant=tenant, step=step, outcome=outcome,
                secrets=secrets, actor=actor,
            )
            if outcome.status == StepStatus.failed:
                _finish(session, job, tenant, workflow, JobStatus.failed, actor)
                return
            if outcome.status == StepStatus.waiting:
                job.status = JobStatus.waiting
                job.lease_until = None
                _commit(session, job)
                return
    _finish(session, job, tenant, workflow, JobStatus.succeeded, actor)
