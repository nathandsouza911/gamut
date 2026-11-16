# Milestone 2 design: guided tenant setup, service-account-only credentials, tenant dashboard

Date: 2026-11-16. Status: design calls made by Claude after the owner said "just dive in"; owner to review.

## Why

Milestone 1 makes the operator set up GAM7 on their own machine and upload `oauth2.txt` (a refresh
token belonging to a real super admin) plus a service account key with domain-wide delegation. That is
hard to set up, and the stored admin token is the most dangerous secret GAMUT holds. Milestone 2's
spec line is: "Guided tenant setup wizard, keyless credentials if GAM supports them, tenant dashboard."

## What the research and the live test found (2026-11-16, GAM7 7.52.3, test tenant)

**Delegated admin service account (DASA)** — GAM setting `enable_dasa`. The service account holds
Admin console roles itself, so no `oauth2.txt` is needed. GAM requires `admin_email`, `domain` and a
real `customer_id` (not `my_customer`) in gam.cfg. Wiki: "still experimental"; cannot do anything that
needs super admin; does not replace domain-wide delegation for Gmail/Drive/Calendar user data.

Live result with only `oauth2service.json` and these roles assigned to the service account —
built-in **User Management Admin**, built-in **Groups Admin**, and a custom role with the
**Data Transfer** privilege — plus the existing delegation of `gmail.settings.basic`:

| Command (as GAMUT builds it) | Result |
|---|---|
| `user X print groups` | ✅ |
| `update user X password random` | ✅ |
| `user X signout` | ✅ |
| `user X deprovision` | ✅ |
| `user X vacation on subject … message …` (delegation) | ✅ |
| `update user X suspended on` | ✅ |
| `user X delete groups` | ✅ |
| `create datatransfer X gdrive M` / `print datatransfers …` | ✅ (403 until the Data Transfer role was added) |
| `info user uid:N quick formatjson` / `delete user uid:N` | ✅ |
| `info user <admin_email> quick formatjson` | ✅ (returns `customerId`) |
| `user <admin_email> check serviceaccount` | ✅ |
| `print transferapps` | ✅ (403 without Data Transfer) |
| `info domain <domain>`, `info customer`, `print domains` | ❌ 403 (need domain/customer privileges GAMUT does not otherwise need) |

Role changes took 30–75 s to take effect.

**Keyless signing (SignJWT)** — `key_type: signjwt` in `oauth2service.json`; GAM calls the IAM
Credentials `signJwt` API using Application Default Credentials. The GAMUT host must itself have a
Google-trusted identity: a GCE attached service account, or Workload Identity Federation from AWS /
an OIDC issuer (wiki examples: AWS, GitHub Actions). A plain self-hosted Docker box has none, so it
would still store some long-lived secret. Each tenant's Google Cloud project would also need to trust
GAMUT's identity.

## Goals

1. A tenant can be added **without `oauth2.txt`**: a service account key, Admin roles on the service
   account, and delegation of one scope (`gmail.settings.basic`).
2. A **guided setup** in the UI that takes an operator from nothing to a passing health check, telling
   them exactly what to click and paste, and checking each part separately so a failure points at the
   step to fix.
3. A **tenant dashboard**: is this tenant healthy, what is running or waiting, what needs a human.

## Non-goals

- Keyless credentials (SignJWT/WIF). Reason: most self-hosters have no Google-trusted host identity,
  so it moves the secret instead of removing it, and each tenant project would need federation set up.
  Recorded in decisions.md as revisit-later (likely for GCP-hosted installs).
- GAMUT creating Google Cloud projects or service accounts itself (would need the operator's Google
  login inside GAMUT). The wizard guides; it does not act in Google Cloud.
- Approvals, finer roles (Milestone 3), onboarding (Milestone 4).

## Anti-goals

- Accepting operator-supplied gam.cfg again, or any free-text GAM argument.
- Asking operators for super admin rights for the service account when narrower roles work.
- Breaking Milestone 1 tenants (OAuth mode keeps working unchanged).

## Approaches considered

1. **DASA + service account key (chosen).** Removes the admin refresh token; the key's power is
   bounded by Admin roles (never super admin). Works on any host. Cost: GAMUT must write gam.cfg values
   itself; DASA is "experimental" in GAM.
2. **Keep OAuth + key, wizard only.** Easiest, but keeps the riskiest secret and the 6-scope OAuth
   consent dance.
3. **Keyless (SignJWT/WIF).** Best where it fits, but needs host identity and per-tenant federation;
   out of reach for the typical install. Deferred.

## Design

### Credential modes

`tenants.auth_mode`: `oauth` (Milestone 1; default for existing rows) or `dasa` (default for new
tenants). New column `tenants.customer_id` (nullable; required for `dasa`; validated
`^C[0-9a-z]{6,12}$` case-sensitive per Google's format — builder confirms the exact pattern).

Allowed files by mode:
- `oauth`: unchanged (`oauth2.txt`, `oauth2service.json` required; `client_secrets.json` optional).
- `dasa`: `oauth2service.json` only. `oauth2.txt` is refused (it would be ignored and is a needless
  secret).

On upload, GAMUT parses `oauth2service.json` and stores its **non-secret** identifiers in clear on the
credential row: `client_email`, `client_id`, `private_key_id`. They are shown in the wizard (to paste
into the Admin console) and on the dashboard (key id, uploaded date). The private key is never returned.
Upload rejects a service account file without `type == "service_account"`, `client_email`, `client_id`,
`private_key`. A `key_type` other than absent/`default` is rejected (no signjwt/yubikey in M2).

### gam.cfg in DASA mode

The worker still never takes a gam.cfg from anyone. In `dasa` mode, `prepare_config_dir` runs
`gam config enable_dasa true admin_email <Email> customer_id <CustomerId> domain <DomainName> save`
(all three validated types) instead of `gam version`. In `oauth` mode it keeps running `gam version`.
A test asserts the generated gam.cfg has every path setting inside the job directory (same guarantee
as Milestone 1).

### Health check by mode

- `oauth`: unchanged (`info domain`, `check serviceaccount`) plus `print transferapps`.
- `dasa`, three checks, each its own step so the UI can map a failure to a setup step:
  1. **Directory role** — `info user <admin_email> quick formatjson`; parse and require
     `customerId == tenant.customer_id` (wrong tenant = fail with a clear message).
  2. **Gmail delegation** — `user <admin_email> check serviceaccount` (exit 10 → delegation message).
  3. **Data Transfer role** — `print transferapps` (403/exit≠0 → "assign the Data Transfer role").
  A 403 on check 1 means the roles are missing or not yet effective; message says changes can take a
  few minutes.

All checks run with `continue_on_failure` semantics for the health workflow only: every check runs and
reports, so the operator sees all problems at once (builder: add this as a workflow-level flag; offboarding
keeps stop-on-failure).

### Guided setup (UI)

A "Add tenant" flow replacing the bare import form. Owners only (as today). It is a page with numbered
sections; progress is the tenant row itself (status `pending` until a health check passes), so an
operator can leave and come back.

1. **Tenant details** — name, primary domain, extra domains, admin email, customer ID (with "where to
   find it": Admin console → Account → Account settings). Creates the tenant (`dasa`).
2. **Service account** — instructions to create a Cloud project and service account key (GAM's
   `gam create project`, or the Cloud console), including the May-2024 org policy that blocks key
   creation and how to grant the exception (the problem the owner hit in Milestone 1). Upload
   `oauth2service.json`. GAMUT then shows the service account email and client ID with copy buttons.
3. **Admin roles** — assign User Management Admin, Groups Admin, and a custom role with Data Transfer
   to the service account email (Account → Admin roles → Assign service accounts).
4. **Gmail delegation** — Security → API controls → Domain-wide delegation: client ID + the one scope
   `https://www.googleapis.com/auth/gmail.settings.basic`, both with copy buttons.
5. **Check** — run the health check; show each of the three checks with pass/fail and, on failure, a
   link back to the section that fixes it, plus GAM's capped output.

The Milestone 1 OAuth import stays reachable as "Advanced: import an existing GAM setup (OAuth)".
Text in the wizard is static content in the frontend; docs/gam-setup.md gets the same steps.

### Tenant dashboard

Route `#/t/<id>` (tenant home). Visible to every role on the tenant. Shows:
- Status badge, last health check time and per-check results, "Run health check" (admins/owner).
- Credentials: mode, service account email, key id, uploaded date and age (warn ≥ 90 days, Google
  recommends rotation).
- Needs attention: failed jobs (retry/skip pending), jobs waiting (Drive transfers) with how long.
- Upcoming scheduled deletions with dates and a link to cancel (existing cancel route).
- Recent jobs (last 10) linking to job detail.

One new read-only API: `GET /api/tenants/{id}/dashboard` returning those aggregates (tenant-scoped,
404 for no role, as every tenant route).

### Automatic daily health check

The worker enqueues a health check for each `active`/`degraded` tenant whose last check is older than
24 h and that has no health check queued or running. Actor `system`, audited like any job. This makes
the dashboard status meaningful without anyone clicking.

### Docs

decisions.md: "Milestone 2: DASA, keyless deferred" with the live table above. gam-setup.md: DASA path
first, OAuth path as advanced. scopes.md: DASA needs one delegated scope + three roles. threat-model.md:
the key is now the only secret; its power is bounded by Admin roles (not super admin); compromise →
delete the key in Cloud console and unassign roles.

## Acceptance

- Fake-GAM tests cover both modes, upload validation, gam.cfg generation, health check per check,
  dashboard API isolation (404), daily scheduling.
- Live, on the test tenant **before 2026-11-28** (trial end): add a DASA tenant through the wizard from
  scratch, health check passes, then a full offboarding of a throwaway user via the UI succeeds.
- Milestone 1 OAuth tenants keep passing their tests unchanged.

## Left to the builder

Exact customer ID regex; component layout and copy text; dashboard query shapes; migration details;
how "continue on failure" is represented in the workflow base.
