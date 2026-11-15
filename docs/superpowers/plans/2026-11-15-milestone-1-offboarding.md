# GAMUT Milestone 1 (Offboarding, End to End) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A technician can offboard one Google Workspace user from the GAMUT web UI, see every step's result, and find the whole action in a verified, hash-chained audit log.

**Architecture:** Three Docker Compose containers: `web` (FastAPI API that also serves the built React UI), `worker` (same Python image; it alone holds the credential private key and runs GAM7), and `db` (PostgreSQL, which holds all state, the job queue and the audit log). Jobs are rows claimed with `SELECT ... FOR UPDATE SKIP LOCKED`. Every Google call goes through one module, `app/gam/runner.py`, which runs the pinned GAM7 as a subprocess with an argument list and a per-job `GAMCFGDIR` on tmpfs.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 (sync, psycopg 3), Alembic, `cryptography`, Authlib (OIDC), argon2-cffi, pytest, ruff, mypy; `gam7` from PyPI (pinned); React 18 + TypeScript + Vite, Vitest, ESLint; PostgreSQL 16; GitHub Actions CI.

**Spec:** [docs/spec.md](../../spec.md) (copy of https://claude.ai/artifact/A8zMzR3j9ywLMz8JXrCpsm). Read it alongside this plan.

## Global Constraints

- Project name: **GAMUT**. Python package `gamut` lives under `backend/app` (import root `app`). Images `gamut-web`, `gamut-worker`.
- License: AGPL-3.0-only. Full text in `LICENSE`. First line of every source file (py, ts, tsx, js, css, sql, sh, yml, Dockerfile): `SPDX-License-Identifier: AGPL-3.0-only` as a comment.
- UI footer shows a "Source code" link (URL from the `GAMUT_SOURCE_URL` setting, default the repository URL).
- GAM7 is installed with `pip install gam7==<pinned>`. Never vendor its source. Keep its Apache-2.0 license and notices in the image (`/usr/share/doc/gam7/`).
- Only AGPL-compatible dependency licenses. List every runtime dependency in `docs/third-party-licenses.md`.
- Out of scope: hosted/SaaS mode, a free-text GAM box, billing/licensing/reseller, mobile wipe, email forwarding, and anything from Milestones 2–6.
- Only `app/gam/runner.py` may call `subprocess`. `shell=False` always. A CI check enforces this (Task 4).
- No code builds a GAM command from a string. Builders return `list[str]`.
- The API container never receives the credential private key. The worker refuses to start without it, or if it equals the example key.
- No credential material in logs, test output or API responses.
- Every GAM command in the spec was written from memory. Before implementing a builder, check its syntax in the GAM wiki (https://github.com/GAM-team/GAM/wiki) and record the result in `docs/decisions.md`.
- Never run destructive steps against a production user. Real-domain testing happens only in Task 10, against a test tenant the owner provides.
- Open questions are resolved as they come up and recorded in `docs/decisions.md`. wgasuite was **not checked** (owner's choice, 2026-11-15). Record it as unresolved.

## Deliberate changes from the spec (record each in docs/decisions.md)

1. **Asymmetric key wrapping.** The spec says the API encrypts uploads and that the API must not hold the master key. Both can only be true if wrapping uses a public key. The "master key" is an X25519 key pair. The API gets only the public key (`GAMUT_CREDENTIAL_PUBLIC_KEY`). The worker gets the private key (`GAMUT_CREDENTIAL_PRIVATE_KEY_FILE`). Each upload is encrypted with a random AES-256-GCM data key. That key is wrapped with ECIES: an ephemeral X25519 key, HKDF-SHA256 (info `gamut-dek-wrap-v1`), then AES-256-GCM.
2. **The API serves the built UI.** No separate frontend container, so Compose has exactly three services.
3. **A ninth table, `sessions`.** Sessions are stored server-side so they can be revoked. The cookie carries only a random session id.

## Review Focus

1. Offboarding target typed with uppercase letters, surrounding spaces, or a domain not owned by the tenant (including a lookalike such as `acme.com.evil.io`). Expected: normalized to lowercase and trimmed. A domain outside the tenant's list is rejected at preview with a field error. Test: Task 7 `test_preview_rejects_foreign_and_lookalike_domains`.
2. The worker container restarts mid-job. Expected: the job's lease expires, another worker loop reclaims it, and the interrupted step re-runs safely. Test: Task 6 `test_expired_lease_is_reclaimed`.
3. API and worker append audit events at the same moment. Expected: the chain stays linear and `verify-audit` passes. Test: Task 2 `test_concurrent_appends_keep_chain_valid`.
4. The technician double-clicks Confirm, or the browser retries the POST. Expected: exactly one job. Test: Task 7 `test_confirm_is_idempotent_on_preview_token`.
5. Auto-reply text with newlines, quotes, `$(...)`, 10,000 characters, or a leading GAM file-reference keyword such as `file ` or `gdoc `. Expected: passed as one argument verbatim, or rejected by name when it matches a file-reference form. Stored output is capped. Test: Task 4 `test_free_text_is_single_argument_and_file_forms_rejected`.

---

## File Structure

```
LICENSE  README.md  SECURITY.md  docker-compose.yml  .env.example  .github/workflows/ci.yml
scripts/check_spdx.py              # fails if any source file lacks the SPDX line
scripts/check_subprocess.py        # fails if subprocess is imported outside app/gam/runner.py
backend/
  Dockerfile  pyproject.toml  alembic.ini
  app/
    settings.py                    # pydantic-settings; role-specific required vars
    db.py                          # engine, session factory, advisory-lock helper
    models.py                      # SQLAlchemy models for all 9 tables + enums
    main.py                        # FastAPI app factory, middleware, static UI mount
    cli.py                         # `gamut verify-audit`, `gamut worker`, `gamut gen-keys`
    audit/chain.py                 # append_event, verify_chain, canonical hashing, redaction
    auth/oidc.py  auth/sessions.py  auth/bootstrap.py  auth/csrf.py  auth/ratelimit.py
    auth/deps.py                   # current_user, require_tenant_role
    crypto/envelope.py             # seal/open bundle, key loading and guards
    gam/runner.py                  # the ONLY subprocess call site
    gam/commands.py                # typed builders -> list[str]
    gam/validate.py                # Email, tenant domain check, free-text rules
    tenants/service.py             # create, upload/replace/delete credentials, status
    jobs/queue.py                  # create_job, claim, lease, step transitions
    jobs/scheduled.py              # scheduled_actions create/cancel/run
    workflows/base.py              # Workflow protocol, StepSpec, StepOutcome
    workflows/health.py            # health-check workflow
    workflows/offboarding.py       # offboarding workflow
    worker/loop.py                 # main loop: claim, run, poll waiting, run scheduled, daily health
    api/auth.py  api/tenants.py  api/jobs.py  api/workflows.py  api/audit.py  api/users.py
  migrations/versions/0001_initial.py
  tests/
    conftest.py                    # Postgres fixture (TEST_DATABASE_URL), app client, factories
    fake_gam/gam                   # executable; records argv + env, replies from a scenario file
    test_*.py                      # named per task below
frontend/
  package.json  vite.config.ts  index.html  src/main.tsx  src/api.ts  src/App.tsx
  src/components/Footer.tsx  TenantSwitcher.tsx
  src/pages/SignIn.tsx  OffboardForm.tsx  JobDetail.tsx  AuditLog.tsx  Tenants.tsx
docs/ decisions.md  third-party-licenses.md  quick-start.md  gam-setup.md  scopes.md
      threat-model.md  backup-restore.md  spec.md
```

---

### Task 1: Repository skeleton, licensing, Compose, CI

**Files:**
- Create: everything at the top level of the tree above, plus `backend/pyproject.toml`, `backend/Dockerfile`, `frontend/` (Vite React-TS scaffold), `docs/decisions.md`, `docs/third-party-licenses.md`
- Test: `backend/tests/test_repo_hygiene.py`

**Interfaces:**
- Produces: `python scripts/check_spdx.py [root]` (exit 0/1, prints offending paths). `python scripts/check_subprocess.py` (same). Compose service names `web`, `worker`, `db`. Settings env prefix `GAMUT_`.

- [ ] **Step 1: Run `git init`, add `.gitignore` (Python, Node, `.env`, `*.key`), and download the AGPL text into `LICENSE`** from https://www.gnu.org/licenses/agpl-3.0.txt, unmodified.
- [ ] **Step 2: Write the failing test** `test_repo_hygiene.py`:
  - `test_spdx_checker_flags_missing_header(tmp_path)`: write `a.py` without the header and `b.py` with it. Assert `check_spdx.main([str(tmp_path)]) == 1` and the output names `a.py` but not `b.py`.
  - `test_repo_has_spdx_everywhere()`: `check_spdx.main([repo_root]) == 0`.
  - `test_license_is_agpl3()`: `LICENSE` contains `GNU AFFERO GENERAL PUBLIC LICENSE` and `Version 3, 19 November 2007`.
- [ ] **Step 3: Run** `cd backend && pytest tests/test_repo_hygiene.py -v`. Expected: FAIL (module missing).
- [ ] **Step 4: Implement `scripts/check_spdx.py` and `scripts/check_subprocess.py`.** check_spdx scans tracked source extensions, skips `node_modules`, `dist`, `.venv` and `migrations/versions/__pycache__`, and accepts the SPDX line within the first 3 lines (to allow a shebang). check_subprocess greps `backend/app` for `import subprocess` and `from subprocess` outside `app/gam/runner.py`.
- [ ] **Step 5: Write `backend/pyproject.toml`** with `requires-python = ">=3.12"`, the dependencies from Tech Stack, `gam7==<latest stable on PyPI today>` pinned exactly, and a `[project.scripts] gamut = "app.cli:main"` entry. Add ruff and mypy (`strict = true` for `app/`) config.
- [ ] **Step 6: Write `backend/Dockerfile`** (python:3.12-slim). Create a non-root user `gamut` (uid 10001). Install the package. Copy the gam7 license files to `/usr/share/doc/gam7/`. Add a multi-stage Node build of `frontend/` copied to `/app/static`.
- [ ] **Step 7: Write `docker-compose.yml`:**
  - `db`: postgres:16, no `ports:`, named volume, healthcheck.
  - `web`: `command: gamut web`, published on `127.0.0.1:8080`, env file without the private key.
  - `worker`: `command: gamut worker`, `read_only: true`, `tmpfs: /run/gamut-jobs:mode=0700,uid=10001`, private key mounted as a Compose secret, `user: "10001"`.
  - Add `.env.example` with placeholder values. Its example private key is the literal string `EXAMPLE-DO-NOT-USE`.
- [ ] **Step 8: Write `.github/workflows/ci.yml`:**
  - Backend job: Postgres 16 service, `ruff check`, `mypy app`, `pytest`, `check_spdx.py`, `check_subprocess.py`.
  - Frontend job: `npm ci`, `npm run lint`, `npx tsc --noEmit`, `npx vitest run`.
- [ ] **Step 9: Write `README.md`** (stub plus quick-start pointer), `SECURITY.md` (report privately through GitHub Security Advisories on the repository; no public issues), and `docs/decisions.md`. decisions.md seeds: project name GAMUT, wgasuite unchecked, the three deliberate changes above, and the gam7 pin.
- [ ] **Step 10: Run** `pytest tests/test_repo_hygiene.py -v && python scripts/check_spdx.py . && docker compose config -q`. Expected: all pass, no output from compose.
- [ ] **Step 11: Commit** `chore: repository skeleton, AGPL licensing, compose, CI`.

### Task 2: Schema, migrations, audit chain, verify-audit

**Files:**
- Create: `app/settings.py`, `app/db.py`, `app/models.py`, `migrations/versions/0001_initial.py`, `app/audit/chain.py`, `app/cli.py`
- Test: `tests/conftest.py`, `tests/test_audit_chain.py`, `tests/test_schema.py`

**Interfaces:**
- Produces:
  - Models `User, Session, Tenant, TenantCredential, Membership, Job, JobStep, ScheduledAction, AuditEvent`.
  - Enums:
    - `TenantStatus{pending, active, degraded, disabled}`
    - `Role{owner, admin, technician, auditor}` (owner is `users.is_owner`; memberships hold the other three)
    - `JobStatus{queued, running, waiting, failed, succeeded, cancelled, awaiting_approval}`
    - `StepStatus{pending, running, waiting, succeeded, failed, skipped}`
    - `ScheduledStatus{scheduled, cancelled, running, done, refused, failed}`
  - `Job` has a nullable `approved_by`, plus `lease_until`, `idempotency_key UNIQUE` and `gam_version`. `JobStep` has `args jsonb`, `optional bool`, `output text`, `data jsonb`, `next_poll_at` and `poll_attempts`.
  - `append_event(session, *, actor: str, tenant_id: UUID | None, action: str, target: str | None, details: dict) -> AuditEvent`
  - `verify_chain(session) -> VerifyResult(ok: bool, checked: int, first_broken_id: int | None, reason: str | None)`
  - `redact(details: dict) -> dict`
  - CLI `gamut verify-audit` prints `OK <n> events` (exit 0) or `BROKEN at event <id>: <reason>` (exit 1).
  - `db.session_scope()` context manager.
  - Two DB roles: migrations run as owner `gamut_owner`, the app connects as `gamut_app`.

- [ ] **Step 1: Write failing tests** in `test_audit_chain.py`:
  - `test_chain_verifies_after_appends`: append 3 events, then `verify_chain().ok is True` and `checked == 3`.
  - `test_hand_edit_breaks_chain`: as the owner role, `UPDATE audit_events SET target='x' WHERE id=2`. Then `ok is False`, `first_broken_id == 2`, and the CLI exits 1.
  - `test_app_role_cannot_update_or_delete`: as `gamut_app`, UPDATE and DELETE on `audit_events` raise `psycopg.errors.InsufficientPrivilege`.
  - `test_concurrent_appends_keep_chain_valid`: 8 threads × 25 appends on separate sessions, then `ok is True` and `checked == 200`.
  - `test_redact_removes_secrets_and_bodies`: keys matching `password|token|secret|key|message|body` (case-insensitive, nested) become `"[redacted]"`.
- [ ] **Step 2: Write `test_schema.py::test_jobs_has_approval_fields`.** Assert columns `approved_by` (nullable) and status value `awaiting_approval` exist.
- [ ] **Step 3: Run** `pytest tests/test_audit_chain.py tests/test_schema.py -v`. Expected: FAIL.
- [ ] **Step 4: Implement models and migration `0001_initial`.**
  - The migration creates role grants: `gamut_app` gets INSERT and SELECT on `audit_events` (no UPDATE, no DELETE) and full DML on the other tables.
  - Add `REVOKE TRUNCATE`.
  - `tenant_credentials` columns: `ciphertext bytea, nonce bytea, wrapped_key bytea, key_version int, file_names text[], uploaded_by, uploaded_at`.
- [ ] **Step 5: Implement `append_event`.**
  - Take `pg_advisory_xact_lock(0x6A4D5554)`.
  - Read the last row's `hash` (genesis `"0"*64`).
  - Compute `hash = sha256(prev_hash + "\n" + canonical_json(row_fields_without_hash)).hexdigest()`.
  - `canonical_json` = `json.dumps(sort_keys=True, separators=(",",":"), default=str)`, with time in ISO-8601 UTC microseconds.
  - Insert in the caller's transaction.
- [ ] **Step 6: Implement `verify_chain` and the CLI.** verify_chain walks rows in id order and recomputes. The failure reason is either `hash mismatch` or `prev_hash mismatch`.
- [ ] **Step 7: Run** the Step 3 command. Expected: PASS.
- [ ] **Step 8: Commit** `feat: schema, migrations, hash-chained audit log, verify-audit`.

### Task 3: Login, sessions, roles, tenant isolation

**Files:**
- Create: `app/auth/*.py`, `app/api/auth.py`, `app/api/users.py`, `app/api/tenants.py` (list/create/get only), `app/main.py`
- Test: `tests/test_auth.py`, `tests/test_tenant_isolation.py`

**Interfaces:**
- Consumes: `models`, `append_event`.
- Produces:
  - `current_user` dependency → `User` (401 if none).
  - `require_tenant_role(*roles: Role)` dependency factory → `Membership`. It reads the `tenant_id` path param. Owners pass. No membership → **404**. A wrong role on a tenant the user can see → 403.
  - `require_owner`.
  - CSRF header `X-CSRF-Token`, which must equal the `gamut_csrf` cookie on POST/PUT/PATCH/DELETE.
  - `rate_limit(key: str, limit: int, window_s: int)` dependency. Login: 10 per minute per IP. Job creation: 30 per minute per user.
  - Routes:
    - `GET /api/auth/login` → OIDC redirect
    - `GET /api/auth/callback`
    - `POST /api/auth/bootstrap-login` (email + password; only for the bootstrap user)
    - `POST /api/auth/logout`
    - `GET /api/me`
    - `GET/POST /api/tenants`
    - `GET /api/tenants/{tenant_id}`
    - `POST /api/tenants/{tenant_id}/members` (owner or admin)

- [ ] **Step 1: Write failing tests** in `test_auth.py`:
  - `test_bootstrap_owner_created_once`: with `GAMUT_BOOTSTRAP_ADMIN_EMAIL` and `GAMUT_BOOTSTRAP_ADMIN_PASSWORD` set, startup creates one owner (argon2 hash). A second startup does not duplicate it or reset the password.
  - `test_session_cookie_flags`: the login response sets `gamut_session` with `HttpOnly`, `Secure`, `SameSite=Lax`.
  - `test_state_change_without_csrf_is_403`.
  - `test_login_rate_limited`: the 11th attempt within 60 s returns 429.
  - `test_oidc_callback_unknown_email_rejected`: a valid token for an email with no `users` row returns 403. No auto-signup.
  - Use Authlib with a mocked provider metadata and token response.
- [ ] **Step 2: Write `test_tenant_isolation.py::test_user_without_role_gets_404_on_every_tenant_route`.**
  - Enumerate `app.routes` whose path contains `{tenant_id}`.
  - Fill other path params with random UUIDs.
  - For every method, call as a user who is a member of tenant A only, targeting tenant B.
  - Assert 404, never 200, 403 or 5xx.
  - The test must also fail if the enumerated list is empty.
  - The test runs again in each later task as routes are added, so it covers them automatically.
- [ ] **Step 3: Run** `pytest tests/test_auth.py tests/test_tenant_isolation.py -v`. Expected: FAIL.
- [ ] **Step 4: Implement.**
  - Sessions: a random 32-byte id. Store `sha256(id)` in `sessions`, with an absolute expiry of 12 h and an idle expiry of 2 h.
  - Bootstrap password login stays available as a break-glass account, and every use is audited (`auth.bootstrap_login`).
  - Every login and logout is audited.
- [ ] **Step 5: Run** the Step 3 command. Expected: PASS.
- [ ] **Step 6: Commit** `feat: OIDC login, sessions, roles, CSRF, rate limits, tenant isolation`.

### Task 4: GAM runner, command builders, fake gam

**Files:**
- Create: `app/gam/runner.py`, `app/gam/commands.py`, `app/gam/validate.py`, `tests/fake_gam/gam`
- Test: `tests/test_gam_runner.py`, `tests/test_gam_commands.py`, `tests/test_validate.py`

**Interfaces:**
- Produces:
  - `GamResult(exit_code: int, stdout: str, stderr: str, timed_out: bool, truncated: bool)`.
  - `run_gam(args: list[str], cfg_dir: Path, *, timeout_s: int = 300, max_output: int = 256_000) -> GamResult`. It calls the binary named by setting `GAMUT_GAM_BIN` (default `gam`). The environment is exactly `{PATH, HOME=cfg_dir, GAMCFGDIR=cfg_dir, LANG=C.UTF-8}`.
  - `gam_version() -> str`.
  - Builders, each returning `list[str]` without the leading `gam`:
    - `suspend_user(e)`, `reset_password_random(e)`, `signout(e)`, `deprovision(e)`
    - `vacation_on(e, subject: FreeText, message: FreeText)`
    - `print_user_groups(e)` (CSV), `remove_from_all_groups(e)`
    - `create_drive_transfer(e, manager)`, `get_transfer_status(...)`
    - `info_user(e)` (JSON), `delete_user(e)`
    - `info_domain()`, `check_service_account(e)`
  - `Email`: a validated, lowercased, trimmed string type. Strict pattern `^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$`, max 254 characters.
  - `assert_in_tenant(email: Email, domains: list[str])`: exact match on the domain after `@`, or a subdomain of a listed domain only if the domain list says so. No suffix matching.
  - `FreeText`: max 4000 characters. It rejects strings whose first word, case-insensitive, is a GAM file-reference keyword. Start the list with `file`, `gdoc`, `gcsdoc`, `gsheet`, `gcsfile` and `url`, and replace it with the list confirmed in the wiki.
- Fake gam: a Python script on PATH in tests.
  - Appends `{"argv": [...], "env": {"GAMCFGDIR": ..., "files": sorted(listdir(GAMCFGDIR))}}` to `$FAKE_GAM_LOG`.
  - Looks up a reply in `$FAKE_GAM_SCENARIO` (JSON list of `{"match": [argv prefix], "exit": int, "stdout": str, "sleep": float}`; first match wins). The default is exit 0 with empty output.
  - Ignores `version` and replies `GAM 7.x.y - fake`.

- [ ] **Step 1: Verify every builder's syntax in the GAM wiki** for the pinned version. Record each command, the wiki page URL and any changes in `docs/decisions.md`. This resolves these open questions: command syntax, special argument value forms, and which output formats support CSV or JSON.
- [ ] **Step 2: Write failing tests:**
  - `test_runner_passes_args_verbatim_and_isolates_env`: the fake gam log shows the exact argv, `GAMCFGDIR` equal to the given directory, and no parent environment variables such as `GAMUT_DATABASE_URL`.
  - `test_runner_timeout`: a scenario with `sleep` 5 and `timeout_s=1` gives `timed_out is True` and a non-zero exit, and the process is killed.
  - `test_runner_caps_output`: stdout of 1 MB gives `truncated is True` and `len(stdout) <= max_output`.
  - `test_free_text_is_single_argument_and_file_forms_rejected`: a message of `"line1\nline2 \"q\" $(rm -rf /)"` appears as exactly one argv element. `FreeText("file /etc/passwd")` raises `ValueError`. 10,000 characters raises.
  - `test_builders_match_wiki`: one assertion per builder on the exact list confirmed in Step 1. Example for the spec's form: `suspend_user(Email("a@x.com")) == ["update","user","a@x.com","suspended","on"]`.
  - `test_email_validation`: accepts `" A@Acme.com "` → `"a@acme.com"`. Rejects `a@acme`, `a b@acme.com`, `a@acme.com\n`, and a 255-character address.
  - `test_assert_in_tenant_rejects_lookalike`: `acme.com.evil.io` and `evilacme.com` are rejected for `["acme.com"]`.
- [ ] **Step 3: Run** `pytest tests/test_gam_runner.py tests/test_gam_commands.py tests/test_validate.py -v`. Expected: FAIL.
- [ ] **Step 4: Implement.** The runner uses `subprocess.run(..., shell=False, capture_output=True, timeout=...)` and decodes with `errors="replace"`. It never logs `args` at INFO level; argv is stored by the caller after redaction.
- [ ] **Step 5: Run** the Step 3 command plus `python scripts/check_subprocess.py`. Expected: PASS.
- [ ] **Step 6: Commit** `feat: GAM runner, typed command builders, input validation, fake gam`.

### Task 5: Credential encryption, tenant import, health check

**Files:**
- Create: `app/crypto/envelope.py`, `app/tenants/service.py`, `app/workflows/base.py`, `app/workflows/health.py`; extend `app/api/tenants.py` and `app/cli.py` (`gamut gen-keys`)
- Test: `tests/test_envelope.py`, `tests/test_tenant_import.py`, `tests/test_no_secret_leaks.py`

**Interfaces:**
- Consumes: `run_gam`, builders, `append_event`, `require_tenant_role`.
- Produces:
  - `seal_bundle(files: dict[str, bytes], public_key: X25519PublicKey) -> SealedBundle(ciphertext, nonce, wrapped_key, key_version)`.
  - `open_bundle(sealed: SealedBundle, private_key: X25519PrivateKey) -> dict[str, bytes]`.
  - `load_private_key_or_die(settings) -> X25519PrivateKey`. It exits non-zero with `credential private key missing` or `credential private key is the example value`.
  - `materialize(files, base=Path("/run/gamut-jobs")) -> ContextManager[Path]`. It creates a mode-0700 directory, writes the files with mode 0600, and runs `rmtree` in `finally`.
  - `Workflow` protocol: `name: str`, `params_model: type[BaseModel]`, `plan(params, tenant) -> list[StepSpec]`, `execute(step, ctx) -> StepOutcome`.
  - `StepSpec(key: str, title: str, args: list[str], optional: bool, kind: Literal["run","async","schedule"])`.
  - `StepOutcome(status: StepStatus, output: str, data: dict, poll_after_s: int | None)`.
  - Routes:
    - `PUT /api/tenants/{tenant_id}/credentials` (owner; multipart; allowed names from the wiki-confirmed GAM7 config file list)
    - `DELETE /api/tenants/{tenant_id}/credentials`
    - `POST /api/tenants/{tenant_id}/health-check` (owner or admin)
  - Tenant fields `domains text[]` and `admin_email` (used for the service account check).

- [ ] **Step 1: Confirm in the wiki** which files make up a complete GAM7 configuration (`gam.cfg`, `oauth2.txt`, `oauth2service.json`, `client_secrets.json`?), whether `GAMCFGDIR` isolates them fully, and whether a service account alone can run every offboarding step. Record the answers. Set the upload allow-list from them.
- [ ] **Step 2: Write failing tests:**
  - `test_round_trip`.
  - `test_tamper_fails`: flipping one ciphertext byte raises `InvalidTag`.
  - `test_api_settings_have_no_private_key`: `Settings(role="web")` has no private key attribute, and the web app starts with only the public key.
  - `test_worker_refuses_missing_or_example_key`.
  - `test_materialize_permissions_and_cleanup`: the directory is 0700, files are 0600, and the directory is gone after an exception inside the context.
  - `test_upload_never_returned`: a GET of the tenant shows `has_credentials: true` and file names only, never bytes.
  - `test_delete_tenant_keeps_audit`: deleting the tenant removes the `tenant_credentials` row, and its audit events remain.
  - `test_health_check_activates_or_reports`: with fake gam returning 0 for both calls, the tenant becomes `active`. With exit 1 on the service account check and stderr listing a scope, the status stays `pending`, or moves from `active` to `degraded`, and the job output shows that stderr.
  - `test_no_secret_leaks`: run an import plus a health check with known marker secrets in the uploaded files. Scan caplog, captured stdout and stderr, every API response body, and `audit_events.details`. Assert the markers appear nowhere.
- [ ] **Step 3: Run** `pytest tests/test_envelope.py tests/test_tenant_import.py tests/test_no_secret_leaks.py tests/test_tenant_isolation.py -v`. Expected: FAIL.
- [ ] **Step 4: Implement.**
  - The bundle plaintext is a JSON map of `{name: base64}`.
  - The health check is a normal job (Task 6 runs it). Its two steps are `info_domain()` and `check_service_account(tenant.admin_email)`.
  - Only expose missing-scope names if GAM offers a machine-readable form. Otherwise show the capped stderr and record the limitation in decisions.md.
- [ ] **Step 5: Run** the Step 3 command. Expected: PASS.
- [ ] **Step 6: Commit** `feat: envelope-encrypted tenant credentials, import, health check`.

### Task 6: Job queue and worker loop

**Files:**
- Create: `app/jobs/queue.py`, `app/jobs/scheduled.py`, `app/worker/loop.py`; extend `app/cli.py` (`gamut worker`)
- Test: `tests/test_queue.py`, `tests/test_worker.py`

**Interfaces:**
- Consumes: `Workflow`, `StepSpec`, `StepOutcome`, `open_bundle`, `materialize`, `run_gam`, `append_event`.
- Produces:
  - `create_job(session, *, tenant_id, workflow: str, params: dict, steps: list[StepSpec], actor: User, idempotency_key: str) -> Job`. It is one transaction covering the job, its steps and audit event `job.created`. If the idempotency key exists, it returns the existing job.
  - `claim_next(session, worker_id: str, lease_s: int = 120) -> Job | None`. Claims `queued`, `waiting` with `next_poll_at <= now()`, or `running` with `lease_until < now()`, using `FOR UPDATE SKIP LOCKED`.
  - `retry_step(job, step, actor)` and `skip_step(job, step, actor)`. Both are allowed only when the job is `failed`. Skip is allowed only for optional steps. Both are audited.
  - `run_job(job)`: inside a single `materialize` for the whole run, it executes pending steps in order.
    - Failure: step `failed`, job `failed`, stop.
    - `async` outcome: step `waiting`, job `waiting`, `next_poll_at = now + min(30 * 2**attempts, 900)`; release and return.
    - Every step transition appends an audit event with the redacted argv and exit code.
    - Records `gam_version` on the job.
  - `worker.loop.run_forever(stop: Event)`. Each tick: claim and run one job, then run due scheduled actions, then enqueue a health check for any tenant whose last check is older than 24 h. Sleep 2 s when idle. The worker heartbeats the lease every 30 s while a step runs.

- [ ] **Step 1: Write failing tests:**
  - `test_skip_locked_two_workers_one_claim`.
  - `test_expired_lease_is_reclaimed`: set a job `running` with `lease_until` in the past, then `claim_next` returns it.
  - `test_failed_step_stops_job_then_retry_resumes`.
  - `test_skip_only_optional`: skipping a required step raises a `409` error type.
  - `test_waiting_step_does_not_block_other_jobs`: job A waits on an async step and job B, created later, completes in the same test loop.
  - `test_backoff_caps_at_900s`.
  - `test_temp_dir_removed_on_success_and_failure`: the fake gam records the `GAMCFGDIR` path, and afterwards the path does not exist.
  - `test_job_records_gam_version`.
  - `test_every_transition_audited_and_chain_valid`.
- [ ] **Step 2: Run** `pytest tests/test_queue.py tests/test_worker.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** For the rate-limit open question: record the documented Admin SDK and Data Transfer quotas in decisions.md. Add per-tenant concurrency of 1 running job (claim skips tenants that already have a `running` job with a live lease). Retry GAM exits that signal quota errors through the waiting/backoff path, using the exit code or code confirmed in the wiki.
- [ ] **Step 4: Run** the Step 2 command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: Postgres job queue with leases, waiting steps, worker loop`.

### Task 7: Offboarding workflow (preview, run, retry, skip, scheduled deletion)

**Files:**
- Create: `app/workflows/offboarding.py`, `app/api/workflows.py`, `app/api/jobs.py`
- Test: `tests/test_offboarding.py`, `tests/test_offboarding_api.py`

**Interfaces:**
- Consumes: Task 4 builders and validation, Task 6 queue, `jobs/scheduled.py`.
- Produces:
  - `OffboardParams`:
    - `user: Email`
    - `reset_password, signout, deprovision, remove_groups: bool = True`
    - `auto_reply: AutoReply | None` (`subject: FreeText`, `message: FreeText`)
    - `transfer_drive_to: Email | None`
    - `delete_after_days: int | None` (1–365)
    - `confirm_delete_email: Email | None` (must equal `user` when `delete_after_days` is set: the second confirmation)
  - Step keys in order: `suspend, reset_password, signout, deprovision, auto_reply, remove_groups, drive_transfer, schedule_delete`. If the wiki or the test domain shows the auto-reply fails on a suspended account, move `auto_reply` before `suspend` and record why.
  - Routes:
    - `POST /api/tenants/{tenant_id}/workflows/offboarding/preview` (technician or admin) → `{preview_token, steps:[{key,title,args_display}]}`. The token is an HMAC of the canonical params, tenant and user, valid for 10 minutes.
    - `POST /api/tenants/{tenant_id}/jobs` with `{workflow:"offboarding", params, preview_token}` → 201 Job. The token is the idempotency key, and it must match the params.
    - `GET /api/tenants/{tenant_id}/jobs` and `/jobs/{job_id}` (auditor or above).
    - `POST /api/tenants/{tenant_id}/jobs/{job_id}/steps/{step_id}/retry` and `/skip`.
    - `POST /api/tenants/{tenant_id}/scheduled-actions/{action_id}/cancel` (admin or technician).
- Step behaviour:
  - `suspend`: `info_user` JSON first, and skip the GAM call if already suspended.
  - `reset_password`: the output is redacted before storing, and the password is never stored or shown.
  - `remove_groups`: first stores the `print_user_groups` CSV parsed into `step.data["groups"]`, then removes.
  - `drive_transfer`: `async`. Create the transfer and store its id. Later executions poll the status until completed (succeeded) or failed. On a re-run, if `data` already has a transfer id, poll instead of creating a new one.
  - `schedule_delete`: creates a `ScheduledAction(action="delete_user", run_at=now+N days)` and succeeds.
  - Scheduled runner: before deleting, refuse (status `refused`, audited) unless the job's `drive_transfer` step is `succeeded`, or the step was not selected.

- [ ] **Step 1: Write failing tests** (`test_offboarding.py`, run with the worker loop in-process against fake gam):
  - `test_full_run_issues_steps_in_order`: the fake gam log's argv sequence equals the wiki-confirmed lists from Task 4, in key order, with the info/print checks interleaved.
  - `test_unselected_steps_absent`.
  - `test_rerun_is_idempotent`: run all, reset statuses, run again. Already-suspended skips the suspend call, and an existing transfer id is polled, not created twice.
  - `test_password_never_stored`: the fake gam prints `password: S3cr3t!`, and that string is absent from step output, audit events and logs.
  - `test_groups_recorded_before_removal`.
  - `test_drive_transfer_waits_then_completes`.
  - `test_delete_refused_if_transfer_incomplete`.
  - `test_delete_cancellable_until_run`.
  - `test_delete_requires_second_confirmation`: a mismatched `confirm_delete_email` returns 422.
- [ ] **Step 2: Write failing API tests** (`test_offboarding_api.py`):
  - `test_preview_has_no_side_effects`: no jobs, no fake gam calls, and one audit event at most (`workflow.previewed` is not required; assert there is no `job.*` event).
  - `test_preview_rejects_foreign_and_lookalike_domains`: user or manager `x@acme.com.evil.io` returns 422 with the field name.
  - `test_preview_rejects_manager_equal_user`.
  - `test_confirm_is_idempotent_on_preview_token`: two POSTs give the same job id and one job row.
  - `test_confirm_with_altered_params_rejected`: the token does not match, so 400.
  - `test_auditor_cannot_create_job`: 403.
  - Re-run `test_tenant_isolation.py`, which now covers these routes.
- [ ] **Step 3: Run** `pytest tests/test_offboarding.py tests/test_offboarding_api.py tests/test_tenant_isolation.py -v`. Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** the Step 3 command and then the full suite, `pytest -q`. Expected: PASS.
- [ ] **Step 6: Commit** `feat: offboarding workflow with preview, retry, skip, scheduled deletion`.

### Task 8: Audit API and UI

**Files:**
- Create: `app/api/audit.py`; `frontend/src/**` per File Structure; mount `/app/static` in `main.py` with an SPA fallback
- Test: `tests/test_audit_api.py`, `frontend/src/**/*.test.tsx`

**Interfaces:**
- Consumes: all routes above.
- Produces:
  - `GET /api/tenants/{tenant_id}/audit?cursor=&limit=` (auditor or above; newest first; `limit <= 200`).
  - `GET /api/audit/verify` (owner) → `VerifyResult`.
  - Frontend `api.ts` sends cookies and the `X-CSRF-Token` header (read from the `gamut_csrf` cookie) on state-changing calls.

- [ ] **Step 1: Write failing tests:**
  - `test_audit_list_scoped_to_tenant`.
  - Vitest `Footer.test.tsx`: renders a link with text `Source code` and the configured href.
  - `OffboardForm.test.tsx`:
    - Suspend is always checked and disabled.
    - The delete-days field reveals a "type the user's email again" input.
    - Submit calls preview, then shows the steps.
    - Confirm calls create once even on a double click (the button disables).
  - `JobDetail.test.tsx`: polls every 2 s while the status is in `queued, running, waiting`. Shows the step status, and Retry/Skip buttons only on a failed job (Skip only on an optional failed step).
- [ ] **Step 2: Run** `pytest tests/test_audit_api.py -v` and `cd frontend && npx vitest run`. Expected: FAIL.
- [ ] **Step 3: Implement the pages.**
  - SignIn: a "Sign in with Google" button plus a bootstrap admin form.
  - TenantSwitcher.
  - Tenants (owner: create, upload credentials, run the health check, show status and the last check message).
  - OffboardForm, then JobDetail.
  - AuditLog: a table with actor, action, target and time, an expandable details view, and an owner-only "Verify chain" button.
  - Plain CSS. No UI kit, to keep the licence list short.
- [ ] **Step 4: Run** the Step 2 commands, `npm run lint` and `npx tsc --noEmit`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: web UI for sign-in, tenants, offboarding, jobs, audit log`.

### Task 9: Documentation and clean-machine check

**Files:**
- Create or complete: `README.md`, `docs/quick-start.md`, `docs/gam-setup.md`, `docs/scopes.md`, `docs/threat-model.md`, `docs/backup-restore.md`, `docs/third-party-licenses.md`, `docs/decisions.md`

- [ ] **Step 1: Write the docs.**
  - **scopes.md**: the minimum scopes for the health check and the eight offboarding steps, from the wiki. Tell operators to authorize only these.
  - **gam-setup.md**: per-tenant GAM7 setup, then what to upload.
  - **threat-model.md**:
    - Assets, actors and trust boundaries (web vs worker vs db).
    - The audit log is *tamper-evident, not immutable*: a database superuser can rewrite it.
    - TLS is required through a reverse proxy (example Caddy snippet).
    - The key pair split.
  - **backup-restore.md**: `pg_dump`. Back up the private key separately; without it the stored credentials are unrecoverable.
  - **third-party-licenses.md**: generate it with `pip-licenses` and `license-checker`, and confirm every licence is AGPL-compatible.
- [ ] **Step 2: Run the clean-machine check.** From a fresh clone, follow only the README: `cp .env.example .env`, `docker compose run --rm worker gamut gen-keys`, `docker compose up -d`. Expected: `curl -sk http://127.0.0.1:8080/` returns the sign-in page. `docker compose exec worker gamut verify-audit` prints `OK`. Starting the worker with the example key exits with the example-key message.
- [ ] **Step 3: Run** `python scripts/check_spdx.py . && pytest -q && (cd frontend && npx vitest run)`. Expected: all pass.
- [ ] **Step 4: Commit** `docs: quick start, GAM setup, scopes, threat model, backup and restore`.

### Task 10: Acceptance against a real test domain (owner-gated)

- [ ] **Step 1: Ask the owner for a test tenant and a disposable test user.** Do not proceed without them. Never target a production user.
- [ ] **Step 2: Import the tenant, run the health check, and offboard the test user with all eight steps selected** (deletion scheduled for 1 day). Then cancel the deletion or let it run, as the owner chooses. Record which steps failed on a suspended account. If the order must change, change it, re-run Task 7's tests, and record the change.
- [ ] **Step 3: Run the spec's acceptance checklist and record the results in `docs/decisions.md`:**
  - The owner confirms the job.
  - `verify-audit` passes.
  - A hand edit (`psql` as owner) makes it fail.
  - Restore the database from a backup afterwards.
- [ ] **Step 4: Commit** `chore: milestone 1 acceptance results`.
