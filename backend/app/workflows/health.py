# SPDX-License-Identifier: AGPL-3.0-only
"""Health check: proves a tenant's GAM setup works. Every check runs, even after a failure,
so an operator sees all setup problems at once (continue_on_failure).

OAuth tenants (all read-only):
1. `info domain <primary domain> formatjson`: a directory call with the admin OAuth token
   (oauth2.txt; needs only the domain.readonly scope).
2. `user <admin_email> check serviceaccount`: GAM's own test of the service account's
   domain-wide delegation scopes (oauth2service.json).
3. `print transferapps`: needs the Data Transfer privilege.

DASA tenants (delegated admin service account; no oauth2.txt):
1. `info user <admin_email> quick formatjson`: the service account can read the directory
   (it needs Admin roles) and the account belongs to the tenant's customer id.
2. `user <admin_email> check serviceaccount scope <gmail.settings.basic>`: Gmail
   delegation of the one scope GAMUT uses (the stored key's `us_scopes` names only it).
3. `print transferapps`: the Data Transfer role.

GAM gives no machine-readable list of missing scopes (`check serviceaccount` has no CSV
or JSON form; exit code 10 means scopes are not authorized), so a failure shows GAM's
capped output to the operator instead of parsed scope names. See docs/decisions.md.

When the job ends, on_finished records the result on the tenant: pass -> active; fail ->
pending stays pending, active becomes degraded. Disabled tenants are left alone.
"""

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.gam.commands import (
    CustomerId,
    DomainName,
    Email,
    check_service_account,
    info_domain,
    info_user,
    print_transfer_apps,
)
from app.gam.parsers import parse_user_info_json
from app.gam.validate import assert_in_tenant
from app.models import AuthMode, Job, JobStatus, JobStep, StepStatus, Tenant
from app.tenants.service import (
    GMAIL_SETTINGS_BASIC_SCOPE,
    HEALTH_MESSAGE_MAX,
    apply_health_result,
)
from app.workflows.base import (
    StepContext,
    StepOutcome,
    StepSpec,
    register,
    run_gam_step,
)

HEALTH_WORKFLOW = "health_check"
SCOPES_NOT_AUTHORIZED_EXIT = 10
PASSED = "Health check passed"
STEP_OUTPUT_MAX = 1200  # per failed step in the tenant's message

# The setup section the UI links a failed check to.
SETUP_SECTION: dict[str, str] = {
    "directory_role": "roles",
    "data_transfer": "roles",
    "gmail_delegation": "delegation",
    "check_service_account": "delegation",
    "info_domain": "credentials",
}

NOT_AUTHORIZED = "Not Authorized"
SCOPES_HINT = (
    "The service account's scopes are not authorized (GAM exit code 10). "
    "Authorize them in the Admin console (domain-wide delegation)."
)
ROLES_HINT = "Assign the Admin roles to the service account; changes can take a few minutes."
DATA_TRANSFER_HINT = (
    "Assign a custom Admin role with the Data Transfer privilege to the service account; "
    "changes can take a few minutes."
)
OAUTH_DATA_TRANSFER_HINT = (
    "The admin's OAuth token needs the Data Transfer scope "
    "(https://www.googleapis.com/auth/admin.datatransfer) and the admin needs the Data "
    "Transfer privilege. Re-run GAM's `oauth create` with that scope selected and upload "
    "the new oauth2.txt."
)


class HealthParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthCheck:
    name = HEALTH_WORKFLOW
    params_model: type[BaseModel] = HealthParams
    continue_on_failure = True

    def plan(self, params: HealthParams, tenant: Tenant) -> list[StepSpec]:
        if not tenant.admin_email:
            raise ValueError(
                "set the tenant's admin_email (a user in its domains) before a health check"
            )
        admin = Email(tenant.admin_email)
        assert_in_tenant(admin, tenant.domains)
        transfer = StepSpec(
            key="data_transfer", title="Data Transfer role", args=print_transfer_apps()
        )
        if tenant.auth_mode == AuthMode.dasa:
            if not tenant.customer_id:
                raise ValueError(
                    "set the tenant's customer ID (Admin console > Account > Account settings) "
                    "before a health check"
                )
            CustomerId(tenant.customer_id)
            return [
                StepSpec(
                    key="directory_role",
                    title="Directory access (Admin roles on the service account)",
                    args=info_user(admin),
                ),
                StepSpec(
                    key="gmail_delegation",
                    title="Gmail delegation (gmail.settings.basic)",
                    args=check_service_account(admin, GMAIL_SETTINGS_BASIC_SCOPE),
                ),
                transfer,
            ]
        return [
            StepSpec(
                key="info_domain",
                title="Read the domain with the admin token",
                args=info_domain(DomainName(tenant.primary_domain)),
            ),
            StepSpec(
                key="check_service_account",
                title=f"Check the service account's scopes for {admin}",
                args=check_service_account(admin),
            ),
            transfer,
        ]

    def execute(self, step: JobStep, ctx: StepContext) -> StepOutcome:
        specs = {spec.key: spec for spec in self.plan(HealthParams(), ctx.tenant)}
        outcome = run_gam_step(specs[step.key].args, ctx.cfg_dir)
        if step.key == "directory_role" and outcome.status == StepStatus.succeeded:
            return _check_customer(outcome, ctx.tenant.customer_id or "")
        return outcome

    def on_finished(self, session: Session, job: Job) -> None:
        tenant = session.get(Tenant, job.tenant_id)
        if tenant is None:
            return
        if job.status == JobStatus.succeeded:
            apply_health_result(session, tenant, ok=True, message=PASSED)
            return
        failed = list(session.scalars(
            select(JobStep)
            .where(JobStep.job_id == job.id, JobStep.status == StepStatus.failed)
            .order_by(JobStep.position)
        ))
        if not failed:
            message = "Health check did not complete"
        else:
            dasa = tenant.auth_mode == AuthMode.dasa
            message = "\n\n".join(_failure_block(step, dasa=dasa) for step in failed)
        apply_health_result(session, tenant, ok=False, message=message[:HEALTH_MESSAGE_MAX])


def _check_customer(outcome: StepOutcome, expected: str) -> StepOutcome:
    """The admin account must belong to the tenant's customer id."""

    def failed(text: str) -> StepOutcome:
        return StepOutcome(
            status=StepStatus.failed, output=text, exit_code=outcome.exit_code,
            argv=outcome.argv,
        )

    try:
        info = parse_user_info_json(outcome.output)
    except ValueError:
        return failed("GAM's info user output was not the expected JSON.\n" + outcome.output)
    if info.customer_id is None:
        return failed("GAM's info user output did not include a customer ID.")
    if info.customer_id != expected:
        return failed(
            f"The admin account belongs to customer ID {info.customer_id}, but this tenant is "
            f"set to {expected}. Fix the tenant's customer ID or the admin email."
        )
    return outcome


def _failure_block(step: JobStep, *, dasa: bool) -> str:
    output = step.output or ""
    hint: str | None = None
    if step.key in ("check_service_account", "gmail_delegation") and (
        step.exit_code == SCOPES_NOT_AUTHORIZED_EXIT
    ):
        hint = SCOPES_HINT
    elif step.key == "directory_role" and NOT_AUTHORIZED in output:
        hint = ROLES_HINT
    elif step.key == "data_transfer" and NOT_AUTHORIZED in output:
        hint = DATA_TRANSFER_HINT if dasa else OAUTH_DATA_TRANSFER_HINT
    if step.exit_code is None or (step.exit_code == 0 and hint is None):
        head = f"{step.title}: failed"
    else:
        head = f"{step.title}: failed (GAM exit code {step.exit_code})"
    lines = [head] + ([hint] if hint else []) + ([output[:STEP_OUTPUT_MAX]] if output else [])
    return "\n".join(lines)


register(HealthCheck())
