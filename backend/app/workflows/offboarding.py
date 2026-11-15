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
                             account is already suspended
  remove_groups    optional  `user <u> print groups` (CSV) is recorded in step.data
                             ["groups"] first, then `user <u> delete groups`
  drive_transfer   optional  async; see _drive_transfer
  schedule_delete  optional  a `delete_user` scheduled action N days later; its handler
                             refuses unless the Drive transfer succeeded or was not chosen

Every step is safe to run twice. execute() never commits: run_steps commits each
outcome, fenced by the job's claim token.

The auto-reply text is free text the database must not hold in clear: the stored job
parameters carry "[redacted]" in its place and the real text sealed for the worker
(job.params["sealed"], see stored_params); execute() reads it from ctx.sealed.
"""

import json
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
    create_drive_transfer,
    delete_user,
    deprovision,
    info_user,
    list_transfers,
    print_user_groups,
    remove_from_all_groups,
    reset_password_random,
    signout,
    suspend_user,
    vacation_on,
)
from app.gam.parsers import TransferStatus, parse_transfers_csv, parse_user_groups_csv
from app.gam.runner import GamResult, run_gam
from app.gam.validate import assert_in_tenant
from app.jobs.execute import job_actor
from app.jobs.scheduled import (
    ActionContext,
    ActionResult,
    create_scheduled_action,
    register_action,
)
from app.models import Job, JobStep, ScheduledAction, ScheduledStatus, StepStatus, Tenant
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


def _is_suspended(stdout: str) -> bool:
    """Read `suspended` from `info user ... formatjson` (one JSON object)."""
    candidates = [stdout.strip()] + [
        line.strip() for line in stdout.splitlines() if line.strip().startswith("{")
    ]
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value.get("suspended") is True
    raise ValueError("GAM's info user output was not the expected JSON")


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
                "remove_groups", "Remove from all groups (the list is recorded first)",
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
        check = info_user(user)
        info = _run_or_stop(check, ctx, {})
        if _is_suspended(info.stdout):
            return StepOutcome(status=StepStatus.succeeded, exit_code=0, argv=check,
                               output=f"{user} is already suspended; no change was made.")
        return run_gam_step(args, ctx.cfg_dir)

    def _remove_groups(self, step: JobStep, ctx: StepContext, params: OffboardJobParams,
                       user: Email, args: list[str]) -> StepOutcome:
        previous = (step.data or {}).get("groups")
        listing_args = print_user_groups(user)
        listing = _run_or_stop(listing_args, ctx, {"groups": _merge_groups(previous, [])})
        current = parse_user_groups_csv(listing.stdout)
        data = {"groups": _merge_groups(previous, current)}
        if not current:
            return StepOutcome(status=StepStatus.succeeded, data=data, exit_code=0,
                               argv=listing_args,
                               output=f"{user} is not a member of any group.")
        outcome = run_gam_step(args, ctx.cfg_dir)
        recorded = f"Recorded {len(current)} group memberships before removing them."
        return replace(outcome, data=data, output=combined_output(recorded, outcome.output))

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
            row = create_scheduled_action(
                ctx.session, tenant_id=ctx.tenant.id, job_id=ctx.job.id, action=DELETE_ACTION,
                run_at=_now() + timedelta(days=params.delete_after_days),
                params={"target": str(user), "user": str(user)},
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

def run_scheduled_delete(ctx: ActionContext) -> ActionResult:
    """Delete the offboarded account, unless its Drive transfer did not complete.

    Refused when the job has a drive_transfer step that is not `succeeded` (also when it
    was skipped). An account that no longer exists counts as done.
    """
    user = Email(str(ctx.action.params.get("user", "")))
    assert_in_tenant(user, ctx.tenant.domains)
    transfer_status = ctx.session.scalar(
        select(JobStep.status).where(JobStep.job_id == ctx.job.id,
                                     JobStep.key == "drive_transfer")
    )
    ctx.session.commit()  # end the read; no transaction stays open while GAM runs
    if transfer_status is not None and transfer_status != StepStatus.succeeded:
        return ActionResult(
            status=ScheduledStatus.refused,
            result=(f"The Drive transfer step is {transfer_status.value}, not succeeded, so "
                    f"{user} was not deleted. Complete the transfer and offboard again, or "
                    "delete the account by hand."),
        )
    check = info_user(user)
    info = run_gam(check, ctx.cfg_dir)
    if info.exit_code in USER_NOT_FOUND_EXITS:
        return ActionResult(status=ScheduledStatus.done, argv=check, exit_code=info.exit_code,
                            result=f"{user} does not exist (already deleted); nothing to do.")
    if info.exit_code != 0:
        return ActionResult(status=ScheduledStatus.failed, argv=check,
                            exit_code=info.exit_code, result=_output(info))
    args = delete_user(user)
    result = run_gam(args, ctx.cfg_dir)
    if result.exit_code == 0:
        return ActionResult(status=ScheduledStatus.done, argv=args, exit_code=0,
                            result=f"{user} was deleted.")
    if result.exit_code in USER_NOT_FOUND_EXITS:
        return ActionResult(status=ScheduledStatus.done, argv=args, exit_code=result.exit_code,
                            result=f"{user} does not exist (already deleted); nothing to do.")
    return ActionResult(status=ScheduledStatus.failed, argv=args, exit_code=result.exit_code,
                        result=_output(result))


register(Offboarding())
register_action(DELETE_ACTION, run_scheduled_delete)
