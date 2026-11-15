# SPDX-License-Identifier: AGPL-3.0-only
"""What a workflow is, and the registry of workflows by name.

A workflow plans a job as an ordered list of steps (StepSpec) and executes one step at
a time (execute -> StepOutcome). app.jobs.execute.run_steps drives the steps, records
results and audit events, and calls the workflow's on_finished hook when the job ends.

execute() must rebuild the step's argument list from the job's parameters and tenant
(for example by calling plan() again) rather than reading JobStep.args: stored args are
redacted (app.gam.commands.redact_argv).
"""

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.gam.runner import run_gam
from app.models import Job, JobStep, StepStatus, Tenant

StepKind = Literal["run", "async", "schedule"]

# Modules that define built-in workflows; each calls register() on import.
BUILTIN_WORKFLOW_MODULES = ("app.workflows.health",)


@dataclass(frozen=True)
class StepSpec:
    key: str
    title: str
    args: list[str]
    optional: bool = False
    kind: StepKind = "run"


@dataclass(frozen=True)
class StepOutcome:
    """The result of executing one step.

    status: succeeded, failed or skipped ends the step; waiting means "poll again after
    poll_after_s seconds" (async steps, handled by the worker loop).
    argv: the argument list actually run (stored and audited only after redact_argv).
    """

    status: StepStatus
    output: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    poll_after_s: int | None = None
    exit_code: int | None = None
    argv: list[str] = field(default_factory=list)


@dataclass
class StepContext:
    session: Session
    tenant: Tenant
    job: Job
    step: JobStep
    cfg_dir: Path  # the job's GAMCFGDIR, holding the tenant's decrypted GAM files


class Workflow(Protocol):
    name: str
    params_model: type[BaseModel]

    def plan(self, params: Any, tenant: Tenant) -> list[StepSpec]:
        """The ordered steps for `params` (an instance of params_model). No side effects.

        Raises ValueError with an operator-readable message when the job cannot run.
        """
        ...

    def execute(self, step: JobStep, ctx: StepContext) -> StepOutcome: ...

    def on_finished(self, session: Session, job: Job) -> None:
        """Called once the job has ended (succeeded or failed), in the same session."""
        ...


class UnknownWorkflow(KeyError):
    pass


_REGISTRY: dict[str, Workflow] = {}


def register(workflow: Workflow) -> Workflow:
    _REGISTRY[workflow.name] = workflow
    return workflow


def get_workflow(name: str) -> Workflow:
    for module in BUILTIN_WORKFLOW_MODULES:
        importlib.import_module(module)
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownWorkflow(name) from None


def combined_output(stdout: str, stderr: str) -> str:
    """stdout then stderr, separated by a newline when both are present."""
    if stdout and stderr:
        return stdout.rstrip("\n") + "\n" + stderr
    return stdout or stderr


def run_gam_step(args: list[str], cfg_dir: Path) -> StepOutcome:
    """Run one GAM command: exit 0 succeeds, anything else fails."""
    result = run_gam(args, cfg_dir)
    output = combined_output(result.stdout, result.stderr)
    if result.timed_out:
        output = combined_output(output, "GAM timed out and was stopped.")
    return StepOutcome(
        status=StepStatus.succeeded if result.exit_code == 0 else StepStatus.failed,
        output=output,
        exit_code=result.exit_code,
        argv=list(args),
    )
