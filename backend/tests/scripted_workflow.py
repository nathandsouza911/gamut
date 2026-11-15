# SPDX-License-Identifier: AGPL-3.0-only
"""A test-only workflow whose steps are described by the job's parameters.

Each step is {"key", "args", "optional", "kind", "raise"}:
- a "run" step runs `args` through the fake gam (exit 0 succeeds);
- an "async" step runs `args` and succeeds when stdout contains "done", otherwise it
  returns waiting (the worker polls it again later);
- "raise": "value" raises ValueError("<key>: operator message"), "runtime" raises
  RuntimeError with a message that must never be shown.

PROBES records, per execute() call, whether the session had an open transaction after
reading the tenant, job and step attributes a real workflow reads.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.models import Job, JobStep, StepStatus, Tenant
from app.workflows.base import StepContext, StepOutcome, StepSpec, register, run_gam_step

NAME = "test_scripted"
PROBES: list[dict[str, Any]] = []
FINISHED: list[str] = []


class ScriptedStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    args: list[str] = ["info", "domain"]
    optional: bool = False
    kind: Literal["run", "async", "schedule"] = "run"
    raise_: Literal["value", "runtime"] | None = None


class ScriptedParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str | None = None
    steps: list[ScriptedStep]


class Scripted:
    name = NAME
    params_model: type[BaseModel] = ScriptedParams

    def plan(self, params: ScriptedParams, tenant: Tenant) -> list[StepSpec]:
        if not params.steps:
            raise ValueError("at least one step is needed")
        return [
            StepSpec(key=s.key, title=f"Step {s.key}", args=list(s.args), optional=s.optional,
                     kind=s.kind)
            for s in params.steps
        ]

    def execute(self, step: JobStep, ctx: StepContext) -> StepOutcome:
        # Attributes a workflow reads; none of them may start a DB transaction.
        _ = (ctx.tenant.domains, ctx.tenant.admin_email, ctx.job.params, ctx.step.key)
        PROBES.append({"step": step.key, "in_transaction": ctx.session.in_transaction()})
        params = ScriptedParams.model_validate(ctx.job.params)
        spec = next(s for s in params.steps if s.key == step.key)
        if spec.raise_ == "value":
            raise ValueError(f"{spec.key}: the manager is not in the tenant")
        if spec.raise_ == "runtime":
            raise RuntimeError("internal detail that must not be shown")
        outcome = run_gam_step(list(spec.args), ctx.cfg_dir)
        if spec.kind == "async" and outcome.status == StepStatus.succeeded:
            if "done" not in outcome.output:
                return StepOutcome(
                    status=StepStatus.waiting, output=outcome.output, poll_after_s=None,
                    exit_code=outcome.exit_code, argv=outcome.argv,
                    data={"polled": step.poll_attempts + 1},
                )
        return outcome

    def on_finished(self, session: Session, job: Job) -> None:
        FINISHED.append(f"{job.id}:{job.status.value}")


register(Scripted())


def scripted_params(*steps: dict[str, Any], target: str | None = None) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    for s in steps:
        s = dict(s)
        if "raise" in s:
            s["raise_"] = s.pop("raise")
        out.append(s)
    return {"target": target, "steps": out}
