# Decisions

## 2026-11-15: Project name is GAMUT
Chosen by the owner. Python package `gamut` lives under `backend/app`; images `gamut-web` and `gamut-worker`.

## 2026-11-15: wgasuite NOT checked (unresolved)
The owner chose to skip the prior-art check against wgasuite. This remains an open question and is unresolved.

## 2026-11-15: Deliberate change: asymmetric key wrapping (X25519)
The spec says the API encrypts uploads and that the API must not hold the master key. Both hold only if wrapping uses a public key. The "master key" is an X25519 key pair. The API receives only the public key (`GAMUT_CREDENTIAL_PUBLIC_KEY`); the worker receives the private key (`GAMUT_CREDENTIAL_PRIVATE_KEY_FILE`). Each upload is encrypted with a random AES-256-GCM data key, wrapped with ECIES (ephemeral X25519 key, HKDF-SHA256 with info `gamut-dek-wrap-v1`, then AES-256-GCM).

## 2026-11-15: Deliberate change: the API serves the built UI
No separate frontend container. Compose has exactly three services: `web`, `worker`, `db`.

## 2026-11-15: Deliberate change: a ninth table, `sessions`
Sessions are stored server-side so they can be revoked. The cookie carries only a random session id.

## 2026-11-15: GAM7 pinned to 7.52.3
`gam7==7.52.3`, the latest version on PyPI on 2026-11-15 (checked with `pip index versions gam7`). Installed from PyPI, never vendored. Its Apache-2.0 `LICENSE` is copied into the image at `/usr/share/doc/gam7/`.

## 2026-11-15: Backend tests run in Docker
The development host is Windows with Python 3.10 only; the backend needs Python 3.12 and Linux. Backend verification runs through `docker-compose.test.yml` (`testdb` postgres:16 and a `tests` service built from the Dockerfile `dev` target). CI runs natively on Ubuntu with Python 3.12 and a Postgres service.

## 2026-11-15: Source repository URL is a placeholder
`GAMUT_SOURCE_URL` defaults to `https://github.com/OWNER/gamut` until the owner supplies the real repository.

## 2026-11-15: Panel users are pre-registered; OIDC never creates users
An owner adds a user with `POST /api/users` (email, display name). OIDC sign-in only succeeds for an existing user with a verified email; the first sign-in links the provider subject to the user, and a later sign-in with a different subject for that email is refused. Unknown emails get 403 and an `auth.login_failed` audit event. Tenant admins and owners grant roles with `POST /api/tenants/{tenant_id}/members` (`{email, role}`, role admin, technician or auditor); an unknown email gets 422 telling the caller to have an owner add the user first.

## 2026-11-15: Sessions and CSRF
The session cookie (`gamut_session`, HttpOnly, Secure, SameSite=Lax) holds a random 32-byte id; only its SHA-256 is stored. Sessions end 12 h after creation or after 2 h idle. Each session has a random CSRF token, sent at login in a readable `gamut_csrf` cookie (Secure, SameSite=Lax). POST, PUT, PATCH and DELETE must send `X-CSRF-Token` equal to both the cookie and the session's stored token. The check is part of authentication, so every authenticated state change is covered; a test enumerates the routes to prove it. The login endpoints are exempt and rate-limited instead. The OIDC state and nonce travel in a separate short-lived cookie (`gamut_oidc`, signed with `GAMUT_SECRET_KEY`, path `/api/auth`, 10 minutes).

## 2026-11-15: Tenant isolation is enforced by the route class
Every route with a `{tenant_id}` path parameter uses `TenantScopedRoute`, which checks the session and the caller's membership before FastAPI reads the body. A non-member gets 404 (never 422 or 403), as if the tenant did not exist. `create_app` refuses to start if a `{tenant_id}` route uses another route class, and `tests/test_tenant_isolation.py` enumerates the app's routes so new routes are covered automatically.

## 2026-11-15: Rate limits are per web process (Milestone 1)
Login (10 per minute per client IP) and job creation (30 per minute per user) use an in-memory sliding window. The counts reset on restart and are kept separately by each web process. GAMUT runs one web process; a shared store is needed if that changes. Behind a reverse proxy the client IP comes from `X-Forwarded-For`, trusted only from `GAMUT_FORWARDED_ALLOW_IPS`.

## 2026-11-15: OIDC sign-in is optional; the bootstrap owner always works
OIDC is enabled when `GAMUT_OIDC_CLIENT_ID` and `GAMUT_OIDC_CLIENT_SECRET` are set (then `GAMUT_PUBLIC_BASE_URL` is required). Without it, `/api/auth/login` returns 503 and only the bootstrap owner can sign in. The bootstrap owner is created once from `GAMUT_BOOTSTRAP_ADMIN_EMAIL`/`GAMUT_BOOTSTRAP_ADMIN_PASSWORD` (argon2id); later starts never change it, and every use is audited as `auth.bootstrap_login`.

## 2026-11-15: GAM command syntax verified (Task 4)
Verified against the GAM wiki and, more strictly, against the pinned gam7 7.52.3 source installed in the dev image (`gam/__init__.py`; the usage comment above each command function, and the code). Wiki pages: Users-Gmail-Send-As-Signature-Vacation (https://github.com/GAM-team/GAM/wiki/Users-Gmail-Send-As-Signature-Vacation) and Google-Data-Transfers (https://github.com/GAM-team/GAM/wiki/Google-Data-Transfers) were read directly; for the other commands the other wiki pages were not fetched; the source usage comments and code (which the wiki mirrors) are the evidence. `gam version` was run for real: `GAM 7.52.03 - https://github.com/GAM-team/GAM - pythonsource` (note `7.52.03`).

| Builder | Final argv (after `gam`) | Deviation from the spec form |
|---|---|---|
| suspend_user | `update user <e> suspended on` | none |
| reset_password_random | `update user <e> password random` | none. GAM does not print the password unless `logpassword <file>` is given |
| signout | `user <e> signout` | none (`signoutTurnoff2SVUsers`, no extra arguments allowed) |
| deprovision | `user <e> deprovision` | none. Optional `popimap`, `signout`, `turnoff2sv` are not used. Finding: it deletes app-specific passwords and OAuth tokens, but if the user is already suspended it skips backup verification codes (message "is suspended, no backup codes"). Step 1 (suspend) runs before step 4, so backup codes are not invalidated in the spec order. Task 7 must decide (run deprovision before suspend, or accept). Not confirmable offline whether Google keeps backup codes valid for a suspended user |
| vacation_on | `user <e> vacation on subject <subject> message <message>` | none. Wiki recommends also `start`/`end` dates because a previously expired vacation can keep the responder off; not added (spec form); check in Task 10. `\n` in the text becomes a newline (GAM unescapes). Whether Gmail settings calls work for a suspended account cannot be confirmed offline: it is an open question for Task 10; until then Task 7 should prefer running this step before suspend |
| print_user_groups | `user <e> print groups` | CSV on stdout, columns `User,Group,Role,Status,Delivery` (no `nodetails`, so Role is kept for restore) |
| remove_from_all_groups | `user <e> delete groups` | none. Lists the user's groups (direct memberships) and removes each |
| create_drive_transfer | `create datatransfer <e> gdrive <manager>` | none. `gdrive` is an accepted service alias (also `drive`, `googledrive`). Privacy level is left at Google's default. `create datatransfer` has NO CSV or JSON output (source: it only prints entity lines), so its stdout is not parsed at all: the transfer is found afterwards with `list_transfers`. Rely on the exit code only |
| list_transfers(old, new) (replaces get_transfer_status) | `print datatransfers olduser <old> newuser <new>` | CSV on stdout, one row per application per transfer, columns `id,requestTime,oldOwnerUserEmail,newOwnerUserEmail,overallTransferStatusCode,application,applicationId,status,<params>`; oldest first (GAM sorts by requestTime), so the newest is last. `overallTransferStatusCode` is `completed`, `failed`, `inProgress` or `pending`. `info datatransfer <id>` is text only and is not used. Parsed by `app.gam.parsers.parse_transfers_csv`. Task 7 design: before creating, list and check for an existing non-failed transfer (idempotency); after creating, list and take the newest; poll by listing and reading the status of that id. Optional `status completed|failed|inprogress` filter exists but is unused. `print datatransfers` has no `formatjson` and no id filter |
| info_user | `info user <e> quick formatjson` | `quick` skips group, license, schema, alias lookups; `formatjson` gives one JSON object on stdout |
| delete_user | `delete user <e>` | none. Fails on a user with a Vault hold |
| info_domain | `info domain formatjson` | No domain argument: runs `info instance` (customers.get plus domains.list), a read-only directory call; one JSON object |
| check_service_account | `user <e> check serviceaccount` | Prints PASS/FAIL lines per scope; exit code 10 means scopes not authorized | (no CSV/JSON form exists for `check serviceaccount`; use the exit code, 10 = scopes not authorized, 0 = pass; stdout is for display only)

Special value forms: for `vacation`, `subject` and `message` (also `textmessage`, `htmlmessage`) take the NEXT argument literally; only when the keyword itself is one of `file`, `textfile`, `htmlfile` (local file), `gdoc`, `ghtml` (Google Doc), `gcsdoc`, `gcshtml` (Cloud Storage), or `sig`, `signature`, `textsig`, `htmlsig` for signatures, does GAM read from elsewhere. Because the text is a separate argument, text such as `file /etc/passwd` would be taken literally, so file reading is not reachable through our builder. `FreeText` still rejects text whose first word is one of those keywords (plus `gsheet`, `gcsfile`, `url` as a precaution), by name. Real prose starting with the word "file" or "url" is also rejected (accepted false positive).
Output formats: `formatjson` is supported by `info user`, `info domain`/`info instance`; `print groups` and `print datatransfers` are CSV; `create datatransfer`, `info datatransfer`, `check serviceaccount`, `deprovision`, `signout`, `update user`, `vacation` and `delete` print text only; their exit code and (for steps) a follow-up structured read are the signals, not parsed text.
Not confirmed: behavior against a real domain (Task 10); wiki pages other than the two named above.

## 2026-11-15: Runner design (Task 4)
`run_gam` runs the binary from `GAMUT_GAM_BIN` with an argument list, `shell=False`, no inherited environment: exactly `PATH=/usr/local/bin:/usr/bin:/bin` (fixed: the images keep python3 and gam there), `HOME` and `GAMCFGDIR` set to the config directory, `LANG=C.UTF-8`. It starts GAM in its own session; on timeout the whole process group gets SIGKILL and the result has `timed_out=True`, exit code 124. A missing binary gives exit code 127. Output is read fully and then capped per stream (memory is bounded only by the timeout). `redact_argv` removes `subject` and `message` values and any `password` value except `random`; callers store only redacted argv. Fake gam finds its scenario and log next to the script (the runner's environment cannot carry `FAKE_GAM_*`); the env variables remain as optional overrides.

## 2026-11-15: Tenant domain matching
`assert_in_tenant` needs an exact domain match; subdomains match only for an entry written `*.acme.com` (which does not cover `acme.com`). `Email` trims spaces only, so a trailing newline is rejected.
