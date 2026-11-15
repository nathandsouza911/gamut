# Setting up GAM7 for a tenant

In Milestone 1 GAMUT does not create Google credentials for you. For each Google Workspace domain, an operator sets up GAM7 once on their own machine, following GAM's own documentation, then uploads the resulting files to GAMUT. (A guided wizard is planned for Milestone 2.)

GAM's wiki is the authority on these steps and changes over time: <https://github.com/GAM-team/GAM/wiki> (start with "Authorization" and "GAM7 Install"). This page lists what GAMUT needs from the result.

## 1. Install GAM7 and create a project

On your own computer (not the GAMUT host), install GAM7 and run `gam create project`, which creates a Google Cloud project, enables the APIs and creates the OAuth client and service account. Google Cloud organizations created since May 2024 block service-account key creation by default; if `gam create project` cannot create the key, an organization policy admin has to allow it for the project first.

## 2. Authorize the admin OAuth client with only the needed scopes

Run `gam oauth create` and select only the six scopes in [scopes.md](scopes.md), section 1. Sign in as the admin account that GAMUT should act as (a super admin, or an admin role that can manage users, groups and data transfers).

This produces `oauth2.txt` (and uses `client_secrets.json`).

## 3. Authorize the service account with only the Gmail settings scope

Run `gam user <admin email> update serviceaccount` and select only "Gmail API - Basic Settings". Then authorize the service account's client ID for `https://www.googleapis.com/auth/gmail.settings.basic` under domain-wide delegation in the Admin console, as the command instructs. Keep the recorded scope list in `oauth2service.json` to that one scope (see [scopes.md](scopes.md), section 2).

This produces `oauth2service.json`.

## 4. Check it locally before uploading

```
gam info domain
gam user <admin email> check serviceaccount
```

Both must succeed. GAMUT's health check runs the same two checks.

## 5. Upload to GAMUT

An owner opens the tenant in GAMUT (created with its name, primary domain and the admin email used in step 4) and uploads:

| File | Required | Notes |
| --- | --- | --- |
| `oauth2.txt` | yes | Admin OAuth client and refresh token. |
| `oauth2service.json` | yes | Service account key and recorded scopes. |
| `client_secrets.json` | no | Not used by offboarding. |

Do **not** upload `gam.cfg`: it is refused, because it holds paths from your machine. GAMUT writes its own `gam.cfg` inside each job's private directory. Each file must be a JSON object of at most 256 KB.

GAMUT encrypts the files with the credential public key and stores only the ciphertext; only the worker (private key) can decrypt them, into a temporary directory that exists only while a job runs. The API never returns file contents: after upload you can only replace or delete them, and the UI shows file names. Deleting a tenant deletes its stored credentials; its audit events stay.

Uploading queues a health check. The tenant becomes `active` when it passes. If it fails, the tenant stays `pending` (or becomes `degraded` if it was active) and the message shows GAM's own output. GAM has no machine-readable form of `check serviceaccount`, so GAMUT shows GAM's PASS/FAIL lines for the scopes rather than computing a list of missing scopes itself. The check re-runs daily and on demand ("Run health check").

## Delete the files from your machine

After a successful upload, remove the credential files from your own computer, or store them as carefully as the GAMUT private key. They can read every mailbox and file in the domain within their scopes.

## Known limits

- A service account alone cannot run every offboarding step in this setup: directory actions and data transfers use the admin OAuth client, the Gmail auto-reply uses the service account ([decisions.md](decisions.md), "GAM7 configuration files and GAMCFGDIR"). Google's delegated-admin service accounts and keyless signing may reduce this in Milestone 2.
- Whether the Gmail auto-reply works for a suspended account is unconfirmed; GAMUT runs it before the suspend step for that reason.
