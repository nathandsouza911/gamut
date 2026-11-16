# GAMUT Milestone 2 (Service-Account Credentials, Guided Setup, Tenant Dashboard) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator adds a Google Workspace tenant through a guided page using only a service account key (delegated admin service account, "DASA"), sees each setup check pass or fail separately, and gets a per-tenant dashboard.

**Architecture:** Same three containers as Milestone 1. A tenant gains `auth_mode` (`oauth` | `dasa`) and `customer_id`. In `dasa` mode the worker writes GAM's DASA settings into the per-job gam.cfg itself with `gam config … save` (never an uploaded gam.cfg), the health check runs three independent checks, and the stored files are just `oauth2service.json`. The UI gets a setup page and a dashboard page backed by one new read-only API.

**Tech Stack:** unchanged (Python 3.12, FastAPI, SQLAlchemy 2, Alembic, pytest, ruff, mypy, gam7==7.52.3, React 18 + TypeScript + Vite, Vitest).

**Spec:** [docs/superpowers/specs/2026-11-16-milestone-2-design.md](../specs/2026-11-16-milestone-2-design.md). Background: [docs/spec.md](../../spec.md), Milestone 1 plan [2026-11-15-milestone-1-offboarding.md](2026-11-15-milestone-1-offboarding.md).

## Global Constraints

- All Milestone 1 global constraints still hold (SPDX line on every source file, only `app/gam/runner.py` calls subprocess, builders return `list[str]`, no credential material in logs/output/API responses, tenant routes use `TenantScopedRoute` and answer 404 to users without a role).
- gam.cfg is never accepted from an upload, in either mode.
- DASA delegated scope: exactly `https://www.googleapis.com/auth/gmail.settings.basic`.
- DASA Admin roles to tell operators: built-in **User Management Admin**, built-in **Groups Admin**, and a custom role with the **Data Transfer** privilege, assigned to the service account email.
- GAM `customer_id` for DASA must be the real ID (e.g. `C04jm7qkb`), never `my_customer`.
- `oauth`-mode tenants behave exactly as in Milestone 1 except that their health check gains the data-transfer check.
- Service account files with `key_type` other than absent or `"default"` are refused (no SignJWT/yubikey in M2).
- Key-age warning threshold: 90 days since `uploaded_at`.
- Tests run in Docker: `MSYS_NO_PATHCONV=1 docker compose -f docker-compose.test.yml run --rm tests <cmd>` with `<cmd>` = `pytest -q`, `ruff check .`, `mypy app`, `python scripts/check_spdx.py`; frontend `npm test`, `npm run lint`, `npm run build` in `frontend/`. Run ruff before every commit (Milestone 1 CI failed once on E501).
- Live testing only on the owner's test tenant cloudlocksmith.co, before 2026-11-28 (trial end). Never name the test tenant in committed files.

## Review Focus

1. Customer ID typed with spaces, lowercase `c`, or as `my_customer`. Expected: trimmed; `my_customer` and anything not matching the pattern rejected with a field error. Test: Task 1 `test_customer_id_validation`.
2. Operator uploads the wrong file in DASA mode (an `oauth2.txt`, a `client_secrets.json`, or a service account file with `key_type: signjwt`). Expected: 422 naming the problem, nothing stored. Test: Task 1 `test_dasa_upload_rules`.
3. Service account key belongs to a different Workspace customer than the tenant. Expected: directory check fails with "this service account belongs to customer X, the tenant is set to Y" and the tenant does not become active. Test: Task 3 `test_dasa_directory_check_rejects_other_customer`.
4. One health check fails but the others would pass. Expected: all three still run and report; job ends failed; message lists every failed check. Test: Task 3 `test_dasa_health_runs_every_check`.
5. A user with no role on the tenant calls the dashboard API, or an auditor does. Expected: 404 for no role (automatic in `test_tenant_isolation.py`); auditor gets 200 and no credential contents. Test: Task 4 `test_dashboard_roles_and_no_secrets`.

---

## File Structure

```
backend/app/models.py                  # + AuthMode enum, Tenant.auth_mode/customer_id, TenantCredential.sa_client_email/sa_client_id
backend/migrations/versions/0004_dasa.py
backend/app/gam/validate.py            # + CustomerId
backend/app/gam/commands.py            # + dasa_config(), print_transfer_apps()
backend/app/gam/parsers.py             # UserInfo + customer_id
backend/app/gam/runner.py              # prepare_config_dir(cfg_dir, config_args=None)
backend/app/tenants/service.py         # per-mode file rules, service-account identity
backend/app/tenants/gam_config.py      # NEW: config_args_for(tenant) -> list[str] | None
backend/app/jobs/execute.py            # continue_on_failure; pass config args
backend/app/jobs/scheduled.py          # pass config args
backend/app/workflows/base.py          # Workflow.continue_on_failure (default False)
backend/app/workflows/health.py        # per-mode checks
backend/app/api/tenants.py             # auth_mode/customer_id in create/patch/out; sa identity out
backend/app/api/dashboard.py           # NEW: GET /api/tenants/{tenant_id}/dashboard
frontend/src/api.ts                    # new fields, dashboard()
frontend/src/pages/TenantSetup.tsx     # NEW guided setup
frontend/src/pages/Dashboard.tsx       # NEW
frontend/src/App.tsx                   # routes #/tenants/new, #/t/<id>/setup, #/t/<id>/dashboard
docs/decisions.md docs/gam-setup.md docs/scopes.md docs/threat-model.md README.md
```

---

### Task 1: DASA tenant data and credential rules

**Files:**
- Modify: `backend/app/models.py`, `backend/app/gam/validate.py`, `backend/app/gam/commands.py` (re-export `CustomerId` in `__all__` like `DomainName`), `backend/app/tenants/service.py`, `backend/app/api/tenants.py`
- Create: `backend/migrations/versions/0004_dasa.py`
- Test: `backend/tests/test_validate.py`, `backend/tests/test_tenant_import.py`, `backend/tests/test_schema.py`

**Interfaces:**
- Produces:
  - `class AuthMode(enum.StrEnum): oauth = "oauth"; dasa = "dasa"` in `app.models`.
  - `Tenant.auth_mode: Mapped[AuthMode]` (pg enum `auth_mode`, NOT NULL, server_default `oauth`); `Tenant.customer_id: Mapped[str | None]`.
  - `TenantCredential.sa_client_email: Mapped[str | None]`, `TenantCredential.sa_client_id: Mapped[str | None]`.
  - `class CustomerId(str)` in `app.gam.validate`: strips spaces; must fullmatch `^C[0-9a-z]{6,12}$` (leading capital C, then lowercase letters/digits, as Google shows it); `my_customer` → ValueError; non-str → TypeError.
  - `app.tenants.service.files_for_mode(mode: AuthMode) -> tuple[tuple[str, ...], tuple[str, ...]]` returning (required, optional): oauth → `(("oauth2.txt","oauth2service.json"), ("client_secrets.json",))`; dasa → `(("oauth2service.json",), ())`.
  - `validate_files(files: dict[str, bytes], mode: AuthMode) -> ServiceAccountIdentity` (signature change; callers updated).
  - `@dataclass(frozen=True) class ServiceAccountIdentity: client_email: str; client_id: str`.
  - `store_credentials(...)` sets `sa_client_email`/`sa_client_id` from the identity.
  - API: `TenantCreate.auth_mode: Literal["oauth","dasa"] = "oauth"`, `TenantCreate.customer_id: str | None`; `TenantUpdate.customer_id: str | None`; `TenantOut` adds `auth_mode`, `customer_id`, `sa_client_email`, `sa_client_id`.

- [ ] **Step 1: Write failing tests**
  - `test_validate.py::test_customer_id_validation`: `CustomerId(" C04jm7qkb ") == "C04jm7qkb"`; `ValueError` for `"my_customer"`, `"c04jm7qkb"`, `"C04"`, `"C04jm7qkb;rm"`, `""`; `TypeError` for `123`.
  - `test_tenant_import.py::test_dasa_upload_rules` (owner, tenant created with `auth_mode="dasa"`, `customer_id="C04jm7qkb"`):
    - only `oauth2service.json` with `{"type":"service_account","client_email":"sa@p.iam.gserviceaccount.com","client_id":"1234","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}` → 200; tenant GET shows `sa_client_email == "sa@p.iam.gserviceaccount.com"`, `sa_client_id == "1234"`, and the response text never contains `PRIVATE KEY`.
    - plus `oauth2.txt` → 422 mentioning `oauth2.txt`; `client_secrets.json` → 422; `gam.cfg` → 422 (as today).
    - service account file missing `client_email`, or `"type":"authorized_user"`, or `"key_type":"signjwt"` → 422; message does not echo file contents.
  - `test_tenant_import.py::test_oauth_mode_unchanged`: existing oauth upload tests still pass with no `auth_mode` given; identity fields filled from its `oauth2service.json`.
  - `test_tenant_import.py::test_dasa_tenant_requires_valid_customer_id`: create with `auth_mode="dasa"` and `customer_id="my_customer"` → 422; PATCH `customer_id` on a dasa tenant → 200 and audited (`tenant.update` details include `customer_id`).
  - `test_schema.py::test_tenant_auth_mode_columns`: columns `tenants.auth_mode`, `tenants.customer_id`, `tenant_credentials.sa_client_email`, `tenant_credentials.sa_client_id` exist; existing rows default to `oauth`.
- [ ] **Step 2: Run them; expect failures** (`pytest -q tests/test_validate.py tests/test_tenant_import.py tests/test_schema.py`).
- [ ] **Step 3: Implement** the model fields, migration `0004_dasa` (create enum type, add columns, downgrade drops them), `CustomerId`, per-mode `validate_files` and identity extraction, and API fields. A dasa tenant may be created without `customer_id` (set later by PATCH); the health check plan refuses until it is set (Task 3). `auth_mode` cannot be changed after creation (not in `TenantUpdate`).
- [ ] **Step 4: Run the full backend suite, ruff, mypy, check_spdx; all pass.**
- [ ] **Step 5: Add to `docs/decisions.md`** a section "2026-11-16: Milestone 2 — delegated admin service account" with the live result table from the design doc and the keyless-deferred decision. **Commit** `feat: DASA credential mode for tenants`.

### Task 2: Worker writes DASA settings into the job's gam.cfg

**Files:**
- Create: `backend/app/tenants/gam_config.py`
- Modify: `backend/app/gam/commands.py`, `backend/app/gam/runner.py`, `backend/app/jobs/execute.py`, `backend/app/jobs/scheduled.py`
- Test: `backend/tests/test_gam_commands.py`, `backend/tests/test_gam_runner.py`, `backend/tests/test_offboarding.py`

**Interfaces:**
- Consumes: `AuthMode`, `Tenant.customer_id`, `CustomerId` (Task 1).
- Produces:
  - `commands.dasa_config(admin: Email, customer: CustomerId, domain: DomainName) -> list[str]` = `["config","enable_dasa","true","admin_email",admin,"customer_id",customer,"domain",domain,"save"]` (plain `str` arguments raise TypeError, as other builders).
  - `runner.prepare_config_dir(cfg_dir: Path, config_args: list[str] | None = None) -> None`: runs `config_args` if given, else `["version"]`; raises `RuntimeError("GAM could not write its configuration (exit N)")` on non-zero exit when `config_args` is given (the `version` warm-up keeps ignoring its exit code as today).
  - `gam_config.config_args_for(tenant: Tenant) -> list[str] | None`: `None` for oauth; for dasa builds `dasa_config(Email(tenant.admin_email), CustomerId(tenant.customer_id), DomainName(tenant.primary_domain))`; raises `ValueError("set the tenant's admin email and customer ID first")` if either is missing.
- [ ] **Step 1: Write failing tests**
  - `test_gam_commands.py::test_dasa_config_argv`: exact list above for `Email("admin@acme.test")`, `CustomerId("C04jm7qkb")`, `DomainName("acme.test")`; `TypeError` for plain strings.
  - `test_gam_runner.py::test_prepare_config_dir_runs_config_args`: with fake gam, the recorded call is the dasa argv and `GAMCFGDIR` is the job dir; non-zero exit raises `RuntimeError`.
  - `test_offboarding.py::test_dasa_job_writes_config_before_steps`: a dasa tenant's offboarding job's first recorded GAM call (after `version`) is the `config … save` argv; an oauth tenant's is `version` only (existing test keeps passing).
  - `test_offboarding.py::test_dasa_config_failure_fails_job_readably`: fake gam fails the config call → job failed, first step output contains "could not write its configuration", no step GAM command ran.
  - same for a scheduled action in `test_offboarding.py` (scheduled delete on a dasa tenant runs config first).
- [ ] **Step 2: Run; expect failures.**
- [ ] **Step 3: Implement.** In `_run_steps`, compute `config_args_for(tenant)` before materializing; a `ValueError` goes through `_fail_before_start` with its message; a `RuntimeError` from `prepare_config_dir` likewise (wrap the call). Same pattern in `scheduled._run_one` via its `fail()` helper.
- [ ] **Step 4: Full suite + ruff + mypy pass.**
- [ ] **Step 5: Commit** `feat(worker): write DASA settings into each job's gam.cfg`.

### Task 3: Health check per mode, every check runs

**Files:**
- Modify: `backend/app/workflows/base.py`, `backend/app/jobs/execute.py`, `backend/app/workflows/health.py`, `backend/app/gam/commands.py`, `backend/app/gam/parsers.py`
- Test: `backend/tests/test_tenant_import.py` (health tests live here), `backend/tests/test_gam_parsers.py`, `backend/tests/test_queue.py`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces:
  - `Workflow.continue_on_failure: bool` — read with `getattr(workflow, "continue_on_failure", False)`. When True, `_run_steps` records a failed step and moves to the next; the job ends `failed` if any step failed, else `succeeded`. Offboarding unchanged.
  - `commands.print_transfer_apps() -> list[str]` = `["print","transferapps"]`.
  - `UserInfo.customer_id: str | None` (from JSON `customerId`).
  - Health step keys — oauth: `info_domain`, `check_service_account`, `data_transfer`; dasa: `directory_role`, `gmail_delegation`, `data_transfer`. Titles (dasa): "Directory access (Admin roles on the service account)", "Gmail delegation (gmail.settings.basic)", "Data Transfer role".
  - `health.SETUP_SECTION: dict[str, str]` = `{"directory_role": "roles", "data_transfer": "roles", "gmail_delegation": "delegation", "check_service_account": "delegation", "info_domain": "credentials"}` (the UI links a failed check to that setup section).
- [ ] **Step 1: Write failing tests**
  - `test_dasa_health_plan`: dasa tenant → steps `directory_role` (`info user <admin> quick formatjson`), `gmail_delegation` (`user <admin> check serviceaccount`), `data_transfer` (`print transferapps`); dasa tenant without `customer_id` → plan raises ValueError (health-check POST answers 409/422 as for missing admin_email today — match the existing code path).
  - `test_oauth_health_plan_adds_data_transfer`: oauth tenant steps are `info_domain`, `check_service_account`, `data_transfer`.
  - `test_dasa_health_runs_every_check`: fake gam fails `check serviceaccount` with exit 10 and passes the others → all three steps ran (statuses succeeded/failed/succeeded), job failed, tenant message contains the exit-10 delegation hint, and does not stop after the failure.
  - `test_dasa_directory_check_rejects_other_customer`: fake `info user` JSON with `"customerId":"C0other99"` for a tenant set to `C04jm7qkb` → step failed, output contains `C0other99` and `C04jm7qkb`, tenant stays pending.
  - `test_dasa_directory_403_hint`: exit non-zero with "Not Authorized" → message adds "Assign the Admin roles to the service account; changes can take a few minutes."
  - `test_continue_on_failure_only_for_flagged_workflows` (test_queue.py, scripted workflow): without the flag the job stops at the first failure (existing behavior); with it, later steps run.
  - `test_gam_parsers.py`: `parse_user_info_json` returns `customer_id`.
- [ ] **Step 2: Run; expect failures.**
- [ ] **Step 3: Implement.** `HealthCheck.continue_on_failure = True`. `execute` for `directory_role` runs GAM, then on exit 0 parses JSON and compares `customer_id`; a mismatch returns a failed `StepOutcome` with the message. `on_finished` builds the message from every failed step (one block each: title, hint, capped output), still capped at `HEALTH_MESSAGE_MAX`.
- [ ] **Step 4: Full suite + ruff + mypy pass.**
- [ ] **Step 5: Commit** `feat(health): per-mode checks that all run and report`.

### Task 4: Tenant dashboard API

**Files:**
- Create: `backend/app/api/dashboard.py`; register router in `backend/app/main.py`
- Test: `backend/tests/test_dashboard_api.py`

**Interfaces:**
- Consumes: `JobSummary`, `ScheduledActionOut`, `_summary`, `_action_out` from `app.api.jobs` (import them; do not copy), `TenantOut` builder from `app.api.tenants`.
- Produces: `GET /api/tenants/{tenant_id}/dashboard` (any role) →
  ```
  DashboardOut:
    tenant: TenantOut
    health: HealthOut | None        # latest finished health_check job
      job_id, finished_at, ok: bool, checks: list[{key, title, status, exit_code, section}]
    credentials: CredentialOut | None
      auth_mode, file_names, uploaded_at, age_days: int, rotate_soon: bool (age_days >= 90),
      sa_client_email, sa_client_id
    failed_jobs: list[JobSummary]        # status failed, newest first, max 10, workflow != health_check
    waiting_jobs: list[WaitingJob]       # JobSummary + waiting_since (earliest waiting step's started_at)
    scheduled: list[ScheduledActionOut]  # status scheduled, run_at ascending, max 20
    recent_jobs: list[JobSummary]        # newest first, max 10, all workflows
  ```
- [ ] **Step 1: Write failing tests** in `test_dashboard_api.py`:
  - `test_dashboard_aggregates`: seed a tenant with credentials uploaded 100 days ago, a passed then a failed health job (dashboard shows the failed one, `ok False`, each check with its `section`), one failed offboarding, one waiting offboarding, two scheduled actions (ordered by `run_at`), one cancelled action (absent), 12 jobs (recent_jobs has 10). `credentials.rotate_soon is True`, `age_days == 100`.
  - `test_dashboard_roles_and_no_secrets`: auditor → 200; response text contains no `private_key`, `refresh_token`, `client_secret`.
  - `test_dashboard_empty_tenant`: no credentials, no jobs → `health None`, `credentials None`, empty lists.
  - Isolation is covered automatically by `test_tenant_isolation.py` (confirm it lists the new route).
- [ ] **Step 2: Run; expect failures.**
- [ ] **Step 3: Implement** with one query per list (no N+1; join creator email the way `list_jobs` does).
- [ ] **Step 4: Full suite + ruff + mypy pass.**
- [ ] **Step 5: Commit** `feat(api): tenant dashboard`.

### Task 5: Guided setup page

**Files:**
- Create: `frontend/src/pages/TenantSetup.tsx`, `frontend/src/pages/TenantSetup.test.tsx`
- Modify: `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/pages/Tenants.tsx` (an "Add tenant (guided)" link for owners; the existing form becomes "Advanced: import an existing GAM setup (OAuth)"), `frontend/src/styles.css`, `docs/gam-setup.md`, `docs/scopes.md`
- Test: `frontend/src/pages/TenantSetup.test.tsx`, `frontend/src/App.routing.test.tsx`

**Interfaces:**
- Consumes: API from Tasks 1, 3, 4 (`createTenant` gains `auth_mode`, `customer_id`; `updateTenant` gains `customer_id`; `Tenant` gains `auth_mode`, `customer_id`, `sa_client_email`, `sa_client_id`; `dashboard(id)`).
- Produces: routes `#/tenants/new` (section 1 only) and `#/t/<id>/setup` (all sections, resumable). Section anchors/ids: `details`, `credentials`, `roles`, `delegation`, `check` — matching `SETUP_SECTION` values (`credentials`, `roles`, `delegation`).

Sections (copy is static text in the component; exact wording is the builder's, facts are fixed):
1. **details** — name, primary domain, extra domains, admin email, customer ID ("Admin console → Account → Account settings → Customer ID"). Submit creates a `dasa` tenant and goes to `#/t/<id>/setup#credentials`.
2. **credentials** — how to get a service account key: `gam create project` on any machine with GAM7, or Cloud console (IAM → Service accounts → Keys → Add key → JSON); note that organizations created since May 2024 block key creation (policy `iam.disableServiceAccountKeyCreation`) and an Organization Policy Administrator must allow it for this project. File input for `oauth2service.json` only. After upload, show `sa_client_email` and `sa_client_id` with copy buttons.
3. **roles** — Admin console → Account → Admin roles → (User Management Admin, Groups Admin, and a custom role with Services → Data Transfer) → Assign service accounts → paste the service account email (copy button). "Changes can take a few minutes."
4. **delegation** — Security → Access and data control → API controls → Manage domain-wide delegation → Add new: client ID (copy) and scope `https://www.googleapis.com/auth/gmail.settings.basic` (copy).
5. **check** — "Run checks" button (owner/admin), polls the job (as the existing tenant page does) and shows each check pass/fail with a "Fix in: <section>" link for failures and GAM's output in a collapsible block.

- [ ] **Step 1: Write failing tests** (`TenantSetup.test.tsx`, mocked `api`):
  - `creates a dasa tenant and moves to credentials`: fills details, asserts `createTenant` called with `auth_mode: "dasa"` and the trimmed customer ID; URL hash becomes `#/t/<id>/setup`.
  - `shows service account identity after upload`: tenant with `sa_client_email` renders the email and client ID and the exact scope string.
  - `failed check links to its section`: dashboard/health data with `gmail_delegation` failed shows a link to `#delegation`.
  - `only owners see the setup for a new tenant`: non-owner on `#/tenants/new` sees no form.
  - `App.routing.test.tsx`: `#/tenants/new` and `#/t/<id>/setup` render the setup page.
- [ ] **Step 2: Run `npm test`; expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `npm test`, `npm run lint`, `npm run build` pass.**
- [ ] **Step 5: Docs.** `docs/gam-setup.md`: DASA path first with the same five steps; OAuth path kept under "Advanced". `docs/scopes.md`: DASA = one delegated scope + three roles; OAuth table unchanged. **Commit** `feat(ui): guided tenant setup`.

### Task 6: Dashboard page

**Files:**
- Create: `frontend/src/pages/Dashboard.tsx`, `frontend/src/pages/Dashboard.test.tsx`
- Modify: `frontend/src/App.tsx` (route `#/t/<id>/dashboard`; nav link "Dashboard" first; a tenant whose status is `pending` shows a "Continue setup" link to `#/t/<id>/setup` on the dashboard), `frontend/src/api.ts`, `docs/threat-model.md`, `README.md`

**Interfaces:**
- Consumes: `api.dashboard(id): Promise<Dashboard>` with the Task 4 shape; existing `jobHref`, `api.healthCheck`, `api.cancelScheduled`.

- [ ] **Step 1: Write failing tests** (`Dashboard.test.tsx`):
  - `shows status, checks and key age warning` (age 100 → "rotate" warning text present).
  - `needs attention lists failed and waiting jobs with links to job detail`.
  - `scheduled deletions can be cancelled by admins, not by technicians or auditors`.
  - `run health check button hidden for technicians and auditors`.
  - `pending tenant shows Continue setup`.
- [ ] **Step 2: Run; expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `npm test`, `npm run lint`, `npm run build` pass.**
- [ ] **Step 5: Docs.** `docs/threat-model.md`: in DASA mode the service account key is the only Google secret; its power is bounded by the assigned Admin roles (never super admin) plus one Gmail settings scope; compromise response = delete the key in the Cloud console and unassign the roles. `README.md` status line → Milestone 2. **Commit** `feat(ui): tenant dashboard`.

### Task 7: Live acceptance on the test tenant (owner present)

Before 2026-11-28.

- [ ] **Step 1:** Rebuild the local real-GAM stack (`demo/t10.sh`, git-excluded) on this branch; run migrations.
- [ ] **Step 2:** Through the UI only: add a tenant with the guided setup in DASA mode, upload the existing test service account key, run checks. Expected: three checks pass. Then deliberately remove the Data Transfer role in the Admin console, run checks → only `data_transfer` fails and links to `roles`; restore it.
- [ ] **Step 3:** Create a throwaway user with GAM, add it to a group, offboard it from the UI on the DASA tenant. Expected: all nine steps succeed; scheduled deletion visible on the dashboard; cancel it from the dashboard.
- [ ] **Step 4:** `gamut verify-audit` passes; database dump contains no `PRIVATE KEY`, `refresh_token`.
- [ ] **Step 5:** Record the run in `docs/decisions.md` ("Milestone 2 live acceptance", no tenant names). **Commit** `docs: record Milestone 2 live acceptance`.
