# SPDX-License-Identifier: AGPL-3.0-only
"""Job creation. (Claiming, leases and waiting steps are added by the worker loop.)"""

from typing import Any

from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.gam.commands import redact_argv
from app.models import Job, JobStatus, JobStep, Tenant, User
from app.workflows.base import get_workflow


def create_job(
    session: Session,
    *,
    tenant: Tenant,
    workflow_name: str,
    params: dict[str, Any],
    created_by: User | None,
    actor: str,
    idempotency_key: str | None = None,
) -> Job:
    """Validate params, plan the steps and write the job, its steps and a `job.create`
    audit event (in the caller's transaction).

    Raises pydantic.ValidationError for bad params, ValueError when the workflow cannot
    plan for this tenant (message safe to show) and UnknownWorkflow for a bad name.
    Step args are stored redacted.
    """
    workflow = get_workflow(workflow_name)
    validated = workflow.params_model.model_validate(params)
    specs = workflow.plan(validated, tenant)
    job = Job(
        tenant_id=tenant.id,
        workflow=workflow.name,
        params=validated.model_dump(mode="json"),
        status=JobStatus.queued,
        created_by=created_by.id if created_by is not None else None,
        idempotency_key=idempotency_key,
    )
    session.add(job)
    session.flush()
    for position, spec in enumerate(specs):
        session.add(JobStep(
            job_id=job.id,
            position=position,
            key=spec.key,
            title=spec.title,
            kind=spec.kind,
            args=redact_argv(spec.args),
            optional=spec.optional,
        ))
    session.flush()
    append_event(
        session, actor=actor, tenant_id=tenant.id, action="job.create", target=str(job.id),
        details={"workflow": workflow.name, "job_id": str(job.id), "steps": [s.key for s in specs]},
    )
    return job
