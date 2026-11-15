Source: https://claude.ai/artifact/A8zMzR3j9ywLMz8JXrCpsm (copied 2026-11-15; tables flattened to one cell per line)


Open-source Google Workspace admin panel: architecture and first milestone
 · 
Brief for Claude Code
Build a self-hosted, open-source web admin panel for Google Workspace that runs GAM7 commands behind a UI, with multiple tenants, role-based access and a tamper-evident audit log. The model is CIPP, the community portal MSPs use for Microsoft 365. Nothing equivalent exists for Google Workspace today: admins choose between GAM7 (free, command line only, no audit trail) and paid tools.
The users are MSP technicians who manage several client domains and internal IT admins who manage one. The project is a community tool, not a business. There is no hosted version and no paid tier.
How to use this document:
Treat Decisions already made as fixed. Ask before changing any of them.
Treat the architecture and data model as a strong starting point. Improve details where you find a better way, and say what you changed and why.
Build Milestone 1 only. Do not start later milestones.
Every GAM command in this document was written from memory. Check each one against the GAM wiki (https://github.com/GAM-team/GAM/wiki) before you rely on it.
Resolve the items under Open questions as you reach them, and record the answers in docs/decisions.md.
Before writing code, ask the owner for a project name. This document uses <project> as a placeholder.
Decisions already made
Decision
Choice
Reason
License
AGPL-3.0 (AGPL-3.0-only)
Stops anyone turning the project into a closed hosted product. Same license as CIPP.
Deployment
Self-hosted only, by Docker Compose
A hosted service would need Google's app verification and a yearly security assessment.
Google access
Each tenant's own Google Cloud project and credentials
The operator's credentials never leave their own server.
Engine
Wrap the GAM7 command line tool
GAM already handles pagination, batching, retries and API edge cases.
First workflow
User offboarding
The most repeated, most error-prone admin task, and it exercises every layer.
License requirements:
Add the full AGPL-3.0 text as LICENSE in the repository root.
Put SPDX-License-Identifier: AGPL-3.0-only at the top of every source file.
Show a "Source code" link in the UI footer. AGPL section 13 requires that network users can get the source.
Install GAM7 as a dependency (pip install gam7). Do not copy its source into this repository. GAM7 is Apache-2.0, so keep its license and notices intact in any image you build.
Use only dependencies whose licenses are compatible with AGPL-3.0. List them in docs/third-party-licenses.md.
Out of scope for the whole project:
A hosted or SaaS version.
A free-text box that runs arbitrary GAM commands.
Billing, licensing or reseller functions.
Replacing the Google Admin console. The tool covers repeated workflows, not every setting.
Architecture
Three containers run under Docker Compose: a web app, a worker and PostgreSQL. Only the worker can read tenant credentials or run GAM.
Component
Stack
Responsibility
Web UI
React, TypeScript, Vite
Tenant switcher, workflow forms, job progress, audit log viewer
API
Python, FastAPI
Login, authorization, validation, job creation, read access to jobs and audit events
Worker
Python, same codebase as the API
Claims jobs, decrypts tenant credentials, runs GAM7, records results
Database
PostgreSQL
All state, the job queue and the audit log
Engine
GAM7 (pip install gam7), pinned version
Every call to Google
Python is the backend language because GAM7 is a Python package, so one image carries both. The job queue lives in PostgreSQL (SELECT ... FOR UPDATE SKIP LOCKED), which avoids a separate Redis service.
How a job runs:
A technician picks a tenant, fills in a workflow form and asks for a preview.
The API validates the input and returns the ordered steps the job would run, with no side effects.
The technician confirms. The API writes a job, its steps and an audit event in one transaction.
The worker claims the job and decrypts the tenant's GAM configuration into a private temporary directory.
The worker runs each step as a GAM subprocess, with GAMCFGDIR pointing at that directory.
After each step the worker stores the exit code and output, and appends an audit event.
The worker deletes the temporary directory when the job ends, whether it succeeded or failed.
The UI polls the job and shows each step's status.
Rules for the GAM layer:
One module (gam/runner.py) is the only place that starts a GAM process.
Each workflow step is a typed Python function that returns an argument list. No code builds a command from a string.
Run one tenant per process with its own configuration directory. Never share a GAM configuration directory between tenants.
Pin the GAM7 version and record it on every job, because GAM output formats change between releases.
Ask GAM for CSV or JSON output where a command supports it, and parse that. Do not parse human-readable text.
Suggested repository layout:
</
  LICENSE
  README.md
  docker-compose.yml
  backend/
    app/api/          # FastAPI routes
    app/auth/         # login, sessions, roles
    app/gam/          # runner.py, command builders
    app/workflows/    # offboarding.py
    app/audit/        # append and verify
    app/worker/       # job loop
    migrations/
    tests/
  frontend/
  docs/]]>
Tenant onboarding and Google authentication
In Milestone 1 a tenant is added by importing a working GAM7 configuration that the operator has already set up for that domain. A guided setup wizard comes in Milestone 2.
Google has no partner delegation model like Microsoft's GDAP, so each tenant needs its own credentials. GAM7 normally uses two kinds per domain:
An admin OAuth token (oauth2.txt) for directory actions such as suspending a user.
A service account with domain-wide delegation (oauth2service.json) for acting on user data such as Gmail settings and Drive files.
Milestone 1 import flow:
The operator sets up GAM7 for the domain on their own machine, following GAM's documentation.
In the UI, the operator creates a tenant (name and primary domain) and uploads the GAM configuration files.
The API encrypts the files and stores them. They are never written to disk unencrypted outside a job's temporary directory.
The worker runs a health check job: one read-only directory call and GAM's service account check for one user.
The tenant becomes active only when the health check passes. The UI shows which scopes are missing if it fails.
Requirements:
Document the smallest set of API scopes that offboarding needs, and tell operators to authorize only those.
Re-run the health check on demand and once a day. Mark a tenant as degraded when it fails.
Never return credential contents through the API after upload. Allow replace and delete only.
Deleting a tenant deletes its stored credentials. Its audit events stay.
Google discourages domain-wide delegation except for a critical business need, and Google Cloud organizations created since May 2024 block service account key creation by default. Two GAM7 features may reduce both problems, and both need checking in the GAM wiki before Milestone 2:
A service account that holds an admin role directly, which GAM calls a delegated admin service account.
Keyless signing through Google's signJwt API, which avoids a downloadable key file.
Security requirements
This tool stores credentials that can read every mailbox and file in a tenant, so these requirements are part of Milestone 1, not later hardening.
Credential storage:
Encrypt each tenant's GAM files with a per-tenant data key, and encrypt that key with a master key (envelope encryption, AES-256-GCM).
Load the master key from a file or environment variable that only the worker container receives. The API container must not have it.
Refuse to start if the master key is missing or is the example value.
Decrypt only into a per-job directory on tmpfs with mode 0700, and delete it in a finally block.
Never log credential contents, tokens or the master key. Add a test that scans logs for them.
Running GAM safely:
Start GAM with an argument list and shell=False. Never use a shell.
Build every argument from a typed command builder. User input fills fixed positions only.
Validate email addresses with a strict pattern and confirm they belong to the tenant's domains before use.
Pass free text, such as an auto-reply message, as one argument. Check in the GAM wiki whether any value form (for example a file or gdoc prefix) makes GAM read from elsewhere, and reject those forms.
Set a timeout on every subprocess and cap the stored output size.
Run the worker as a non-root user with a read-only root filesystem.
Audit log:
Store audit events in an append-only table. The application's database role has INSERT and SELECT on it, and no UPDATE or DELETE.
Chain the events: each row stores a SHA-256 hash of its own content plus the previous row's hash.
Provide a verify-audit command that walks the chain and reports the first broken link.
Record the actor, tenant, action, target, parameters, GAM version, argument list, exit code and time. Redact secrets and message bodies.
Describe the log as tamper-evident, not immutable. A database superuser can still rewrite it, and the documentation should say so.
App login and access:
Sign in through OpenID Connect, with Google as the first supported provider. No local passwords except one bootstrap admin created from an environment variable on first start.
Check on every request that the user has a role on the tenant in the URL. Add a test that proves a user of tenant A cannot read or act on tenant B.
Use secure, HTTP-only, same-site session cookies and CSRF protection on every state-changing route.
Rate-limit login and job creation.
Ship secure defaults in docker-compose.yml: no published database port, and documentation that requires TLS through a reverse proxy.
Add SECURITY.md with a private way to report vulnerabilities.
Data model
Eight tables cover Milestone 1. Every query for tenant data filters on tenant_id, directly or through the parent job.
Table
Key fields
Notes
users
id, email, display name, OIDC subject, is_owner
People who sign in to the panel, not Google Workspace users
tenants
id, name, primary domain, status, last health check
Status is pending, active, degraded or disabled
tenant_credentials
tenant_id, encrypted files, wrapped data key, uploaded by, uploaded at
Read by the worker only
memberships
user_id, tenant_id, role
One role per user per tenant
jobs
id, tenant_id, workflow, parameters, status, created by, GAM version, timestamps
Parameters are stored after validation, with secrets removed
job_steps
id, job_id, position, name, argument list, status, exit code, output, timestamps
Status is pending, running, waiting, succeeded, failed or skipped
scheduled_actions
id, tenant_id, job_id, action, run at, status
For delayed steps such as account deletion
audit_events
id, time, actor, tenant_id, action, target, details, previous hash, hash
Append-only and hash-chained
Roles in Milestone 1:
Role
Can do
Owner
Everything, across all tenants, including adding tenants and users
Admin
Run workflows and manage memberships on their tenants
Technician
Run workflows on their tenants
Auditor
Read jobs and audit events on their tenants
Design the jobs table so an approval step can be added later: include a nullable approved_by and an awaiting_approval status now, even though Milestone 1 does not use them.
Milestone 1: offboarding, end to end
Milestone 1 is done when a technician can offboard one Google Workspace user from the UI, see every step's result, and find the whole action in a verified audit log.
The offboarding workflow. Each step is optional in the form except the first, and steps run in this order:
#
Step
GAM command to verify
Notes
1
Suspend the account
gam update user <email> suspended on
Runs first so the user cannot act during the job
2
Reset the password to a random value
gam update user <email> password random
Do not store or display the password
3
Sign out all sessions
gam user <email> signout
4
Revoke app passwords, backup codes and OAuth tokens
gam user <email> deprovision
5
Set an auto-reply
gam user <email> vacation on subject <text> message <text>
Check whether this works on a suspended account. If not, run it before step 1
6
Remove from all groups
gam user <email> delete groups
Record the group list first so it can be restored
7
Transfer Drive ownership to a manager
gam create datatransfer <email> gdrive <manager>
Asynchronous. Poll until Google reports completion
8
Schedule deletion after N days
gam delete user <email>
Stored as a scheduled action. Needs a second confirmation
Workflow behaviour:
Preview shows the exact steps and targets before anything runs.
A failed step stops the job by default. The technician can retry that step or skip it, and both choices are audited.
Every step is safe to run twice. Check current state first where GAM allows it.
The Drive transfer step sits in waiting while Google works. The worker polls with backoff and does not block other jobs.
Scheduled deletion can be cancelled until it runs. It refuses to run if the Drive transfer has not completed.
Mobile device wipe and email forwarding are left for a later milestone.
Build order:
Repository skeleton: license files, Docker Compose, CI with linting, type checks and tests.
Database schema, migrations, and the audit module with its verify-audit command.
Login, sessions, roles and the tenant isolation test.
GAM runner and command builders, tested against a fake gam executable that records its arguments.
Credential encryption, tenant import and the health check job.
Job queue and worker loop, including waiting steps and scheduled actions.
Offboarding workflow: preview, run, retry, skip.
UI: sign-in, tenant switcher, offboarding form, job detail page, audit log viewer.
Documentation: quick start, GAM setup per tenant, minimum scopes, threat model, backup and restore.
Acceptance criteria:
docker compose up on a clean machine gives a working sign-in page, with setup steps in the README.
A tenant can be imported and passes or fails its health check with a clear message.
An offboarding job runs all eight steps against a real test domain, and the owner has confirmed it.
The test suite runs without Google access, using the fake gam executable.
A user with no role on a tenant gets a 404 for every route of that tenant.
No test or log output contains credential material.
verify-audit passes after a job and fails after a row is edited by hand.
Every source file has the SPDX header and the UI footer links to the source.
Testing against Google needs a real Workspace domain. Ask the owner for a test tenant before the final acceptance check, and never run destructive steps against a production user while developing.
Later milestones and open questions
Later milestones are listed for context only. Do not build them yet.
Milestone
Scope
2
Guided tenant setup wizard, keyless credentials if GAM supports them, tenant dashboard
3
Approvals: sensitive actions wait for a second person, plus finer-grained roles
4
Onboarding workflows: user templates, groups, shared drives, Gmail signatures
5
Reports: external Drive sharing, third-party OAuth grants, login anomalies
6
Bulk actions across users and across tenants
Open questions:
Is wgasuite active, and would contributing there beat a new project? The owner should check before work starts. It is Apache-2.0, so its code can be reused here with attribution.
Does each GAM command in the Milestone 1 table exist in the pinned GAM7 version with that exact syntax?
Which files make up a complete GAM7 configuration for one domain, and does GAMCFGDIR isolate them fully?
Can GAM7 run every offboarding step with a service account alone, with no admin OAuth token?
Does GAM7 support keyless service accounts through signJwt, and what does setup look like?
Does GAM treat any argument value specially (file or document references) in the commands used?
Which steps fail on a suspended account, and should the order change?
What are the Admin SDK and Data Transfer API rate limits, and does the worker need per-tenant throttling?
Does a self-hosted tool using the tenant's own Google Cloud project stay outside Google's app verification rules? This is believed true but unconfirmed.
Background research behind these decisions, as of 13 November 2026: no maintained open-source equivalent was found, GAM7 is actively released under Apache-2.0, and Google's guidance on domain-wide delegation is in its best practices page.