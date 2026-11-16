# SPDX-License-Identifier: AGPL-3.0-only
"""Offboarding: lock a leaving user out, hand over their Drive, and schedule deletion.

Steps, in this order (ruling R10, docs/decisions.md):

  reset_password   optional  `update user <u> password random`; GAM's output is never
                             stored (it could contain the password)
  signout          optional  `user <u> signout`
  deprovision      optional  `user <u> deprovision` (app passwords, backup codes, OAuth
                             tokens; GAM skips backup codes once the user is suspended)
  auto_reply       optional  `user <u> vacation on subject <s> message <m>` (Gmail
                             settings on a suspended account are unconfirmed)
  suspend          always    `info user <u> quick formatjson` first; no change when the
                             account is already suspended; records the account's
                             Google id (step.data["google_user_id"])
  record_groups    optional  `user <u> print groups` (CSV) into step.data["groups"],
                             committed as its own step; re-runs add to the record
  remove_groups    optional  `user <u> delete groups`, only after record_groups
                             succeeded; shows the recorded list (both are planned when
                             remove_groups is chosen)
  drive_transfer   optional  async; see _drive_transfer
  schedule_delete  optional  a `delete_user` scheduled action N days later. Its handler
                             deletes `uid:<google id>` and refuses unless the Drive
                             transfer succeeded (or was not chosen) and that id still
                             has the offboarded address and is suspended

Every step is safe to run twice. execute() never commits: run_steps commits each
outcome, fenced by the job's claim token.

The auto-reply text is free text the database must not hold in clear: the stored job
parameters carry "[redacted]" in its place and the real text sealed for the worker
(job.params["sealed"], see stored_params); execute() reads it from ctx.sealed.
"""

import uuid
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.envelope import seal_json
from app.gam.commands import (
    REDACTED,
    Email,
    FreeText,
    GoogleUserId,
    create_drive_transfer,
    delete_user,
    delete_user_by_id,
    deprovision,
    info_user,
    info_user_by_id,
    list_transfers,
    print_user_groups,
    remove_from_all_groups,
    reset_password_random,
    signout,
    suspend_user,
    vacation_on,
)
from app.gam.parsers import (
    TransferStatus,
    parse_transfers_csv,
    parse_user_groups_csv,
    parse_user_info_json,
)
from app.gam.runner import GamResult, run_gam
from app.gam.validate import assert_in_tenant
from app.jobs.execute import job_actor
from app.jobs.scheduled import (
    ActionContext,
    ActionResult,
    create_scheduled_action,
    register_action,
)
from app.models import (
    Job,
    JobStatus,
    JobStep,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    Tenant,
)
from app.workflows.base import (
    SEALED_PARAMS_KEY,
    StepContext,
    StepOutcome,
    StepSpec,
    combined_output,
    register,
    run_gam_step,
    sealed_params_aad,
)

OFFBOARDING_WORKFLOW = "offboarding"
DELETE_ACTION = "delete_user"
# GAM exit codes for "this user does not exist" (gam7 7.52.3: entityUnknownWarning gives
# ENTITY_DOES_NOT_EXIST_RC 56, or SERVICE_NOT_APPLICABLE_RC 73 for an address outside
# GAM's configured domain). Used by `info user` and `delete user`.
USER_NOT_FOUND_EXITS = frozenset({56, 73})
# Google's requestTime and our clocks may disagree slightly.
TRANSFER_CLOCK_SKEW = timedelta(seconds=60)
# Checks after creating a transfer before giving up on Google listing it.
MAX_UNLISTED_POLLS = 10
# Step data / scheduled-action params key for the account's immutable Google id.
GOOGLE_ID_KEY = "google_user_id"
RESET_DONE_MESSAGE = "The password was reset to a random value. It is not stored or shown."


# --- Parameters ----------------------------------------------------------------------

EmailField = Annotated[str, AfterValidator(Email)]
TextField = Annotated[str, AfterValidator(FreeText)]


class AutoReply(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: TextField = ""
    message: Annotated[str, Field(min_length=1), AfterValidator(FreeText)]


class OffboardParams(BaseModel):
    """What the technician submits (preview and confirm)."""

    model_config = ConfigDict(extra="forbid")

    user: EmailField
    reset_password: bool = True
    signout: bool = True
    deprovision: bool = True
    remove_groups: bool = True
    auto_reply: AutoReply | None = None
    transfer_drive_to: EmailField | None = None
    delete_after_days: int | None = Field(default=None, ge=1, le=365)
    # The second confirmation for deletion: the user's address typed again.
    confirm_delete_email: EmailField | None = Field(default=None, validate_default=True)

    @field_validator("transfer_drive_to")
    @classmethod
    def _manager_is_someone_else(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and value == info.data.get("user"):
            raise ValueError("the Drive must be transferred to someone other than the user")
        return value

    @field_validator("confirm_delete_email")
    @classmethod
    def _deletion_confirmed(cls, value: str | None, info: ValidationInfo) -> str | None:
        if info.data.get("delete_after_days") is None:
            return value
        if value is None:
            raise ValueError("type the user's email address again to confirm the deletion")
        if value != info.data.get("user"):
            raise ValueError("does not match the user being offboarded")
        return value


class OffboardJobParams(OffboardParams):
    """The stored form (job.params): auto-reply text redacted, the real text sealed."""

    target: EmailField | None = None
    sealed: dict[str, Any] | None = None


def stored_params(
    params: OffboardParams, public_key: X25519PublicKey, tenant_id: Any
) -> dict[str, Any]:
    """job.params for `params`: the auto-reply text is redacted and sealed for the worker."""
    data = params.model_dump(mode="json")
    data["target"] = params.user
    if params.auto_reply is not None:
        data["auto_reply"] = {"subject": REDACTED, "message": REDACTED}
        data[SEALED_PARAMS_KEY] = seal_json(
            {"auto_reply": params.auto_reply.model_dump(mode="json")}, public_key,
            associated_data=sealed_params_aad(tenant_id),
        )
    return data


class FieldError(ValueError):
    """A parameter is unusable for this tenant; `field` names it (for a 422 response)."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def _in_tenant(field: str, email: Email, tenant: Tenant) -> None:
    try:
        assert_in_tenant(email, tenant.domains)
    except ValueError:
        raise FieldError(
            field, f"{email} is not in this tenant's domains ({', '.join(tenant.domains)})"
        ) from None


# Jobs in these states are not finished: a new offboarding of the same user waits.
# `failed` counts, because a failed job stops at a step the operator must retry or skip.
UNFINISHED_JOB = (JobStatus.queued, JobStatus.running, JobStatus.waiting, JobStatus.failed,
                  JobStatus.awaiting_approval)
PENDING_ACTION = (ScheduledStatus.scheduled, ScheduledStatus.running)


def active_offboarding(session: Session, tenant_id: uuid.UUID, user: str) -> str | None:
    """Why `user` cannot be offboarded again now (a 409 message), or None.

    Refused while the tenant has an unfinished offboarding job for that user (queued,
    running, waiting, awaiting approval, or failed and not yet retried or skipped to the
    end) or a scheduled or running deletion of that user.
    """
    job = session.execute(
        select(Job.id, Job.status)
        .where(Job.tenant_id == tenant_id, Job.workflow == OFFBOARDING_WORKFLOW,
               Job.params["target"].astext == user, Job.status.in_(UNFINISHED_JOB))
        .order_by(Job.created_at)
        .limit(1)
    ).first()
    if job is not None:
        if job.status == JobStatus.failed:
            return (f"An offboarding of {user} has failed and is not finished (job {job.id}). "
                    "Open that job and retry or skip its failed step instead of starting "
                    "another.")
        return (f"An offboarding of {user} is already in progress (job {job.id}, "
                f"{job.status.value}). Open that job instead of starting another.")
    action = session.execute(
        select(ScheduledAction.id, ScheduledAction.job_id)
        .where(ScheduledAction.tenant_id == tenant_id,
               ScheduledAction.action == DELETE_ACTION,
               ScheduledAction.params["user"].astext == user,
               ScheduledAction.status.in_(PENDING_ACTION))
        .limit(1)
    ).first()
    if action is not None:
        return (f"A deletion of {user} is already scheduled (job {action.job_id}). Cancel "
                "it in that job before offboarding the user again.")
    return None


# --- Helpers -------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(UTC)


def _output(result: GamResult) -> str:
    output = combined_output(result.stdout, result.stderr)
    if result.timed_out:
        output = combined_output(output, "GAM timed out and was stopped.")
    return output


class _Stop(Exception):
    """Ends a step early with `outcome` (for example a failed GAM read)."""

    def __init__(self, outcome: StepOutcome) -> None:
        super().__init__()
        self.outcome = outcome


def _run_or_stop(args: list[str], ctx: StepContext, data: dict[str, Any]) -> GamResult:
    result = run_gam(args, ctx.cfg_dir)
    if result.exit_code != 0:
        raise _Stop(StepOutcome(
            status=StepStatus.failed, output=_output(result), data=data,
            exit_code=result.exit_code, argv=args,
        ))
    return result


def _hide(text: str, values: Iterable[str]) -> str:
    """Replace free text (and each of its longer lines) in GAM output with [redacted]."""
    pieces: set[str] = set()
    for value in values:
        if value.strip():
            pieces.add(value)
            pieces.update(line for line in value.splitlines() if len(line.strip()) >= 4)
    for piece in sorted(pieces, key=len, reverse=True):
        text = text.replace(piece, REDACTED)
    return text


def _merge_groups(previous: Any, current: list[dict[str, str]]) -> list[dict[str, str]]:
    """Groups recorded earlier (an earlier, partial run) first, then new ones."""
    merged: dict[str, dict[str, str]] = {}
    for group in [*(previous if isinstance(previous, list) else []), *current]:
        if isinstance(group, dict) and group.get("group"):
            merged.setdefault(str(group["group"]), group)
    return list(merged.values())


# --- The workflow --------------------------------------------------------------------

Handler = Callable[[JobStep, StepContext, OffboardJobParams, Email, list[str]], StepOutcome]


class Offboarding:
    name = OFFBOARDING_WORKFLOW
    params_model: type[BaseModel] = OffboardJobParams

    def plan(self, params: OffboardParams, tenant: Tenant) -> list[StepSpec]:
        user = Email(params.user)
        _in_tenant("user", user, tenant)
        if tenant.admin_email and user == tenant.admin_email.strip().lower():
            raise FieldError(
                "user", f"{user} is this tenant's admin account, which GAMUT uses for its "
                "health check; it cannot be offboarded here. Change the tenant's admin "
                "email first.")
        manager: Email | None = None
        if params.transfer_drive_to is not None:
            manager = Email(params.transfer_drive_to)
            _in_tenant("transfer_drive_to", manager, tenant)
        steps: list[StepSpec] = []
        if params.reset_password:
            steps.append(StepSpec(
                "reset_password", "Reset the password to a random value (never stored or shown)",
                reset_password_random(user), optional=True,
            ))
        if params.signout:
            steps.append(StepSpec("signout", "Sign out all sessions", signout(user),
                                  optional=True))
        if params.deprovision:
            steps.append(StepSpec(
                "deprovision", "Revoke app passwords, backup codes and OAuth tokens",
                deprovision(user), optional=True,
            ))
        if params.auto_reply is not None:
            steps.append(StepSpec(
                "auto_reply", "Set an auto-reply",
                vacation_on(user, FreeText(params.auto_reply.subject),
                            FreeText(params.auto_reply.message)),
                optional=True,
            ))
        steps.append(StepSpec("suspend", "Suspend the account", suspend_user(user)))
        if params.remove_groups:
            steps.append(StepSpec(
                "record_groups", "Record group memberships (kept so they can be restored)",
                print_user_groups(user), optional=True,
            ))
            steps.append(StepSpec(
                "remove_groups", "Remove from all groups",
                remove_from_all_groups(user), optional=True,
            ))
        if manager is not None:
            steps.append(StepSpec(
                "drive_transfer", f"Transfer Drive ownership to {manager}",
                create_drive_transfer(user, manager), optional=True, kind="async",
            ))
        if params.delete_after_days is not None:
            steps.append(StepSpec(
                "schedule_delete",
                f"Schedule deletion of the account in {params.delete_after_days} days "
                "(cancellable until it runs)",
                delete_user(user), optional=True, kind="schedule",
            ))
        return steps

    def execute(self, step: JobStep, ctx: StepContext) -> StepOutcome:
        params = OffboardJobParams.model_validate(ctx.job.params)
        try:
            specs = {spec.key: spec for spec in self.plan(params, ctx.tenant)}
        except FieldError as exc:  # the tenant's domains changed since the job was made
            raise ValueError(str(exc)) from None
        handlers: dict[str, Handler] = {
            "reset_password": self._reset_password,
            "signout": self._plain,
            "deprovision": self._plain,
            "auto_reply": self._auto_reply,
            "suspend": self._suspend,
            "record_groups": self._record_groups,
            "remove_groups": self._remove_groups,
            "drive_transfer": self._drive_transfer,
            "schedule_delete": self._schedule_delete,
        }
        if step.key not in specs or step.key not in handlers:
            raise ValueError(f"The step {step.key!r} is not part of this job's parameters.")
        try:
            return handlers[step.key](step, ctx, params, Email(params.user), specs[step.key].args)
        except _Stop as stop:
            return stop.outcome

    def on_finished(self, session: Session, job: Job) -> None:
        return None

    # --- Steps -----------------------------------------------------------------------

    def _plain(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
               user: Email, args: list[str]) -> StepOutcome:
        return run_gam_step(args, ctx.cfg_dir)

    def _reset_password(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                        user: Email, args: list[str]) -> StepOutcome:
        result = run_gam(args, ctx.cfg_dir)
        if result.exit_code == 0:
            return StepOutcome(status=StepStatus.succeeded, output=RESET_DONE_MESSAGE,
                               exit_code=0, argv=args)
        note = "GAM timed out and was stopped. " if result.timed_out else ""
        return StepOutcome(
            status=StepStatus.failed,
            output=(f"{note}GAM exit code {result.exit_code}. GAM's output is not stored "
                    "for this step because it could contain the password."),
            exit_code=result.exit_code, argv=args,
        )

    def _auto_reply(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                    user: Email, args: list[str]) -> StepOutcome:
        text = ctx.sealed.get("auto_reply")
        if not isinstance(text, dict):
            raise ValueError("The auto-reply text is missing from this job. Start a new job.")
        subject = FreeText(str(text.get("subject", "")))
        message = FreeText(str(text.get("message", "")))
        outcome = run_gam_step(vacation_on(user, subject, message), ctx.cfg_dir)
        return replace(outcome, output=_hide(outcome.output, (subject, message)))

    def _suspend(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                 user: Email, args: list[str]) -> StepOutcome:
        """Suspend, and record the account's Google id for the scheduled deletion."""
        check = info_user(user)
        info = parse_user_info_json(_run_or_stop(check, ctx, {}).stdout)
        data: dict[str, Any] = {}
        if info.id is not None:
            data[GOOGLE_ID_KEY] = info.id
        if info.suspended:
            return StepOutcome(status=StepStatus.succeeded, exit_code=0, argv=check, data=data,
                               output=f"{user} is already suspended; no change was made.")
        return replace(run_gam_step(args, ctx.cfg_dir), data=data)

    def _record_groups(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                       user: Email, args: list[str]) -> StepOutcome:
        """List the memberships and add them to the record (never shrinks it)."""
        previous = _merge_groups((step.data or {}).get("groups"), [])
        listing = _run_or_stop(args, ctx, {"groups": previous})
        current = parse_user_groups_csv(listing.stdout)
        groups = _merge_groups(previous, current)
        return StepOutcome(
            status=StepStatus.succeeded, data={"groups": groups}, exit_code=0, argv=args,
            output=(f"{user} is a member of {len(current)} groups; {len(groups)} "
                    "memberships are recorded."),
        )

    def _remove_groups(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                       user: Email, args: list[str]) -> StepOutcome:
        # A separate, short read: ctx.session must not commit, and no transaction may
        # stay open on it while GAM runs.
        with Session(bind=ctx.session.get_bind()) as read:
            record = read.execute(
                select(JobStep.status, JobStep.data)
                .where(JobStep.job_id == ctx.job.id, JobStep.key == "record_groups")
            ).first()
        if record is None or record.status != StepStatus.succeeded:
            raise ValueError("The group list has not been recorded (the record_groups step "
                             "did not succeed), so no group was removed.")
        groups = _merge_groups((record.data or {}).get("groups"), [])
        names = ", ".join(g["group"] for g in groups) or "none"
        outcome = run_gam_step(args, ctx.cfg_dir)
        return replace(outcome, data={"groups": groups}, output=combined_output(
            f"Recorded memberships ({len(groups)}): {names}", outcome.output))

    def _drive_transfer(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                        user: Email, args: list[str]) -> StepOutcome:
        """Create the transfer once, then poll it until Google reports the result.

        step.data: transfer_id (the transfer this job follows), create_requested_at
        (the create ran but Google had not listed the transfer yet) and
        failed_transfer_ids. Without a transfer_id, a non-failed transfer for this pair
        requested since the job was created is adopted (a worker died after creating
        it); older transfers, such as a completed one from an earlier offboarding of
        the same pair, are ignored, so they never block a new transfer.
        """
        if params.transfer_drive_to is None:
            raise ValueError("This job has no Drive transfer target.")
        manager = Email(params.transfer_drive_to)
        old = step.data or {}
        data: dict[str, Any] = {"manager": str(manager)}
        for key in ("transfer_id", "create_requested_at", "failed_transfer_ids"):
            if key in old:
                data[key] = old[key]
        failed_ids = set(data.get("failed_transfer_ids", []))
        listing_args = list_transfers(user, manager)

        def listed() -> list[TransferStatus]:
            return parse_transfers_csv(_run_or_stop(listing_args, ctx, data).stdout)

        transfer_id = data.get("transfer_id")
        if transfer_id:
            found = next((t for t in listed() if t.id == transfer_id), None)
            if found is None:
                return self._transfer_failed(
                    data, str(transfer_id), listing_args,
                    f"Transfer {transfer_id} is no longer listed by Google.")
            return self._transfer_state(found, data, listing_args)

        requested = data.get("create_requested_at")
        if requested is None:
            since = ctx.job.created_at - TRANSFER_CLOCK_SKEW
            mine = [t for t in listed() if not t.failed and t.id not in failed_ids
                    and t.request_time is not None and t.request_time >= since]
            if mine:
                return self._transfer_state(mine[-1], data, listing_args)
            requested_at = _now()
            _run_or_stop(args, ctx, data)
            requested = data["create_requested_at"] = requested_at.isoformat()

        since = datetime.fromisoformat(str(requested)) - TRANSFER_CLOCK_SKEW
        mine = [t for t in listed() if t.id not in failed_ids
                and t.request_time is not None and t.request_time >= since]
        if mine:
            return self._transfer_state(mine[-1], data, listing_args)
        if step.poll_attempts >= MAX_UNLISTED_POLLS:
            return StepOutcome(
                status=StepStatus.failed, data=data, exit_code=0, argv=listing_args,
                output=(f"The transfer was requested at {requested}, but Google has not "
                        f"listed it after {step.poll_attempts} checks. Check the Admin "
                        "console's data transfers, then retry (no new transfer is created)."),
            )
        return StepOutcome(status=StepStatus.waiting, data=data, exit_code=0,
                           argv=listing_args,
                           output="Transfer requested; waiting for Google to list it.")

    @staticmethod
    def _transfer_state(transfer: TransferStatus, data: dict[str, Any],
                        argv: list[str]) -> StepOutcome:
        data = {k: v for k, v in data.items() if k != "create_requested_at"}
        data["transfer_id"] = transfer.id
        if transfer.completed:
            return StepOutcome(status=StepStatus.succeeded, data=data, exit_code=0, argv=argv,
                               output=f"Transfer {transfer.id}: completed.")
        if transfer.failed:
            return Offboarding._transfer_failed(data, transfer.id, argv,
                                                f"Transfer {transfer.id}: failed.")
        return StepOutcome(status=StepStatus.waiting, data=data, exit_code=0, argv=argv,
                           output=f"Transfer {transfer.id}: {transfer.status}; "
                                  "checking again later.")

    @staticmethod
    def _transfer_failed(data: dict[str, Any], transfer_id: str, argv: list[str],
                         message: str) -> StepOutcome:
        """A failed transfer is forgotten, so a retry creates a new one."""
        failed = [*data.get("failed_transfer_ids", []), transfer_id]
        kept = {k: v for k, v in data.items()
                if k not in ("transfer_id", "create_requested_at")}
        return StepOutcome(
            status=StepStatus.failed, data={**kept, "failed_transfer_ids": failed},
            exit_code=0, argv=argv,
            output=f"{message} Retry the step to request a new transfer.",
        )

    def _schedule_delete(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                         user: Email, args: list[str]) -> StepOutcome:
        if params.delete_after_days is None:
            raise ValueError("This job has no deletion delay.")
        row = ctx.session.scalar(
            select(ScheduledAction)
            .where(ScheduledAction.job_id == ctx.job.id,
                   ScheduledAction.action == DELETE_ACTION)
            .order_by(ScheduledAction.created_at.desc())
            .limit(1)
        )
        if row is None:
            # The deletion targets the account suspended by this job, by its Google id.
            suspend_data = ctx.session.scalar(
                select(JobStep.data).where(JobStep.job_id == ctx.job.id,
                                           JobStep.key == "suspend")
            )
            action_params: dict[str, Any] = {"target": str(user), "user": str(user)}
            google_id = (suspend_data or {}).get(GOOGLE_ID_KEY)
            if google_id:
                action_params[GOOGLE_ID_KEY] = str(google_id)
            row = create_scheduled_action(
                ctx.session, tenant_id=ctx.tenant.id, job_id=ctx.job.id, action=DELETE_ACTION,
                run_at=_now() + timedelta(days=params.delete_after_days),
                params=action_params,
                actor=job_actor(ctx.session, ctx.job),
            )
            output = (f"Deletion of {user} is scheduled for {row.run_at:%Y-%m-%d %H:%M} UTC. "
                      "It can be cancelled until it runs.")
        else:
            output = (f"Deletion of {user} was already scheduled for "
                      f"{row.run_at:%Y-%m-%d %H:%M} UTC (status {row.status.value}).")
        return StepOutcome(status=StepStatus.succeeded, output=output,
                           data={"action_id": str(row.id), "run_at": row.run_at.isoformat()})


# --- Scheduled deletion --------------------------------------------------------------

def _refused(message: str, argv: list[str] | None = None,
             exit_code: int | None = None) -> ActionResult:
    return ActionResult(status=ScheduledStatus.refused, result=message, argv=argv or [],
                        exit_code=exit_code)


def run_scheduled_delete(ctx: ActionContext) -> ActionResult:
    """Delete the offboarded account by its Google id, after checking that it is still
    that account, still suspended, and that its Drive transfer completed.

    Refused (nothing is deleted) when:
    - the job has a drive_transfer step that is not `succeeded` (also when skipped);
    - the job's suspend step did not succeed, or no Google id was recorded by it;
    - `info user uid:<id>` shows another id or another primary address (the account was
      renamed, so the address may now belong to someone else), or an account that is
      no longer suspended (it was reactivated).
    An account that no longer exists counts as done (already deleted).
    """
    user = Email(str(ctx.action.params.get("user", "")))
    assert_in_tenant(user, ctx.tenant.domains)
    rows = {row.key: row.status for row in ctx.session.execute(
        select(JobStep.key, JobStep.status).where(
            JobStep.job_id == ctx.job.id, JobStep.key.in_(("suspend", "drive_transfer")))
    )}
    ctx.session.commit()  # end the read; no transaction stays open while GAM runs
    transfer_status = rows.get("drive_transfer")
    if transfer_status is not None and transfer_status != StepStatus.succeeded:
        return _refused(
            f"The Drive transfer step is {transfer_status.value}, not succeeded, so {user} "
            "was not deleted. Complete the transfer and offboard again, or delete the "
            "account by hand.")
    if rows.get("suspend") != StepStatus.succeeded:
        return _refused(f"The job did not suspend {user}, so it was not deleted.")
    raw_id = ctx.action.params.get(GOOGLE_ID_KEY)
    try:
        uid = GoogleUserId(str(raw_id)) if raw_id else None
    except ValueError:
        uid = None
    if uid is None:
        return _refused(
            f"No Google account id was recorded for {user} when it was suspended, so it "
            "was not deleted (GAMUT deletes only the exact account it suspended). Delete "
            "the account by hand if it should go.")
    check = info_user_by_id(uid)
    info = run_gam(check, ctx.cfg_dir)
    if info.exit_code in USER_NOT_FOUND_EXITS:
        return ActionResult(status=ScheduledStatus.done, argv=check, exit_code=info.exit_code,
                            result=f"{user} (id {uid}) does not exist (already deleted); "
                                   "nothing to do.")
    if info.exit_code != 0:
        return ActionResult(status=ScheduledStatus.failed, argv=check,
                            exit_code=info.exit_code, result=_output(info))
    try:
        current = parse_user_info_json(info.stdout)
    except ValueError as exc:
        return ActionResult(status=ScheduledStatus.failed, argv=check, exit_code=0,
                            result=str(exc))
    if current.id != uid or current.primary_email != user:
        return _refused(
            f"The account with id {uid} is no longer {user} (GAM reports id "
            f"{current.id or 'unknown'}, address {current.primary_email or 'unknown'}), so "
            "it was not deleted. Check the account in the Admin console.", check, 0)
    if not current.suspended:
        return _refused(
            f"{user} is not suspended any more (it was reactivated after offboarding), so "
            "it was not deleted.", check, 0)
    args = delete_user_by_id(uid)
    result = run_gam(args, ctx.cfg_dir)
    if result.exit_code == 0:
        return ActionResult(status=ScheduledStatus.done, argv=args, exit_code=0,
                            result=f"{user} (id {uid}) was deleted.")
    if result.exit_code in USER_NOT_FOUND_EXITS:
        return ActionResult(status=ScheduledStatus.done, argv=args, exit_code=result.exit_code,
                            result=f"{user} (id {uid}) does not exist (already deleted); "
                                   "nothing to do.")
    return ActionResult(status=ScheduledStatus.failed, argv=args, exit_code=result.exit_code,
                        result=_output(result))


register(Offboarding())
register_action(DELETE_ACTION, run_scheduled_delete)
