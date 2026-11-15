# SPDX-License-Identifier: AGPL-3.0-only
"""Health check: proves a tenant's GAM files work.

Two read-only steps:
1. `info domain formatjson`: a directory call with the admin OAuth token (oauth2.txt).
2. `user <admin_email> check serviceaccount`: GAM's own test of the service account's
   domain-wide delegation scopes (oauth2service.json).

GAM gives no machine-readable list of missing scopes (`check serviceaccount` has no CSV
or JSON form; exit code 10 means scopes are not authorized), so a failure shows GAM's
capped output to the operator instead of parsed scope names. See docs/decisions.md.

When the job ends, on_finished records the result on the tenant: pass -> active; fail ->
pending stays pending, active becomes degraded. Disabled tenants are left alone.
"""

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.gam.commands import Email, check_service_account, info_domain
from app.gam.validate import assert_in_tenant
from app.models import Job, JobStatus, JobStep, StepStatus, Tenant
from app.tenants.service import HEALTH_MESSAGE_MAX, apply_health_result
from app.workflows.base import StepContext, StepOutcome, StepSpec, register, run_gam_step

HEALTH_WORKFLOW = "health_check"
SCOPES_NOT_AUTHORIZED_EXIT = 10
PASSED = "Health check passed"


class HealthParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthCheck:
    name = HEALTH_WORKFLOW
    params_model: type[BaseModel] = HealthParams

    def plan(self, params: HealthParams, tenant: Tenant) -> list[StepSpec]:
        if not tenant.admin_email:
            raise ValueError(
                "set the tenant's admin_email (a user in its domains) before a health check"
            )
        admin = Email(tenant.admin_email)
        assert_in_tenant(admin, tenant.domains)
        return [
            StepSpec(
                key="info_domain",
                title="Read the domain with the admin token",
                args=info_domain(),
            ),
            StepSpec(
                key="check_service_account",
                title=f"Check the service account's scopes for {admin}",
                args=check_service_account(admin),
            ),
        ]

    def execute(self, step: JobStep, ctx: StepContext) -> StepOutcome:
        specs = {spec.key: spec for spec in self.plan(HealthParams(), ctx.tenant)}
        return run_gam_step(specs[step.key].args, ctx.cfg_dir)

    def on_finished(self, session: Session, job: Job) -> None:
        tenant = session.get(Tenant, job.tenant_id)
        if tenant is None:
            return
        if job.status == JobStatus.succeeded:
            apply_health_result(session, tenant, ok=True, message=PASSED)
            return
        failed = session.scalar(
            select(JobStep)
            .where(JobStep.job_id == job.id, JobStep.status == StepStatus.failed)
            .order_by(JobStep.position)
        )
        if failed is None:
            message = "Health check did not complete"
        else:
            if failed.exit_code == SCOPES_NOT_AUTHORIZED_EXIT:
                head = (
                    "The service account's scopes are not authorized (GAM exit code 10). "
                    "Authorize them in the Admin console (domain-wide delegation)."
                )
            elif failed.exit_code is None:
                head = f"{failed.title}: failed"
            else:
                head = f"{failed.title}: failed (GAM exit code {failed.exit_code})"
            message = f"{head}\n{failed.output or ''}".rstrip()
        apply_health_result(session, tenant, ok=False, message=message[:HEALTH_MESSAGE_MAX])


register(HealthCheck())
