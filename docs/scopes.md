# Google API scopes

Authorize only the scopes below. They are the smallest set that the Milestone 1 health check and the eight offboarding steps need, worked out from the GAM commands GAMUT runs (see [decisions.md](decisions.md), "GAM command syntax verified") and from the scope table in the pinned GAM 7.52.3 source (`gam/gamlib/glapi.py`) and the Google API references. They were checked on a live test domain (2026-11-16, GAM 7.52.3): the health check and all nine offboarding steps ran with exactly these scopes. This page will be corrected if Google answers differently.

## Service account key (guided setup, "dasa" mode)

One credential, `oauth2service.json`, and no OAuth client. Grants:

| Grant | Where | Why |
| --- | --- | --- |
| `https://www.googleapis.com/auth/gmail.settings.basic` (one delegated scope) | Admin console, Security, API controls, Domain-wide delegation | Gmail auto-reply and GAM's `check serviceaccount`. |
| User Management Admin, Groups Admin, and a custom role with Services, Data Transfer | Admin console, Account, Admin roles, Assign service accounts | Directory actions, group removal and Drive data transfers run as the service account. |

Nothing else needs to be authorized.

# Advanced: OAuth client setup

The tables below are for tenants imported with an admin OAuth client (`oauth2.txt`) and are unchanged.

GAM7 uses two kinds of credentials per domain, each with its own scopes.

## 1. Admin OAuth client (`oauth2.txt`)

Acts as the admin account the operator signs in with. Used for directory actions and data transfers. Authorize these when you run `gam oauth create` (or `gam oauth update`) and deselect everything else:

| Scope | Why |
| --- | --- |
| `https://www.googleapis.com/auth/admin.directory.user` | Read, suspend and delete users, reset passwords (`update user`, `info user`, `delete user`). |
| `https://www.googleapis.com/auth/admin.directory.user.security` | Sign out all sessions, deprovision (delete app passwords and OAuth tokens). |
| `https://www.googleapis.com/auth/admin.directory.group` | List the user's groups and remove the user from them. |
| `https://www.googleapis.com/auth/admin.datatransfer` | Create and read the Drive data transfer. |
| `https://www.googleapis.com/auth/admin.directory.customer.readonly` | GAM reads the customer record to turn `my_customer` (its default customer id) into the real id before `info user` and other directory calls. Without it `info user` exits 12 (seen on a live test domain). |
| `https://www.googleapis.com/auth/admin.directory.domain.readonly` | Health check: `info domain <primary domain>`. |

(In GAM's scope menu the last two appear as "Directory API - Customers" and "Directory API - Domains", set to read only. The Reports API is not needed: the health check names the domain, so GAM reads only that domain. Without a domain name, `gam info domain` also reads user counts from the Reports API and fails without that scope.)

The signed-in account also needs the matching Workspace admin privileges (for example a role that can manage users, groups and data transfers, or super admin). OAuth scopes limit what the token can call; the admin role limits what the account may do.

## 2. Service account with domain-wide delegation (`oauth2service.json`)

Acts as individual users. In Milestone 1 it is used for one thing: setting the Gmail auto-reply, and for GAM's `check serviceaccount` in the health check. In the Admin console (Security, API controls, Domain-wide delegation), authorize the service account's client ID for exactly:

| Scope | Why |
| --- | --- |
| `https://www.googleapis.com/auth/gmail.settings.basic` | Turn on the vacation auto-reply for the offboarded user. |

Nothing else, in particular not full Gmail (`https://mail.google.com/`), Drive, Calendar or Directory scopes.

The health check (`gam user <admin email> check serviceaccount`) tests the scopes recorded in `oauth2service.json`. If that file records no scope list, GAM tests its whole default set and the check fails on scopes you correctly did not authorize. When you create the file, record only the scope above, for example by selecting only "Gmail API - Basic Settings" in `gam user <admin email> update serviceaccount` and authorizing it as the command instructs. [gam-setup.md](gam-setup.md) shows the steps.

## Step by step

| Step | GAM command (after `gam`) | Credential and scope |
| --- | --- | --- |
| Health check, domain | `info domain <primary domain> formatjson` | admin OAuth: domain.readonly |
| (any directory call) | GAM's lookup of `my_customer` | admin OAuth: customer.readonly |
| Health check, delegation | `user <admin> check serviceaccount` | service account: the recorded scopes (gmail.settings.basic) |
| 1. Reset password | `update user <u> password random` | admin OAuth: admin.directory.user |
| 2. Sign out | `user <u> signout` | admin OAuth: admin.directory.user.security |
| 3. Deprovision | `user <u> deprovision` | admin OAuth: admin.directory.user.security |
| 4. Auto-reply | `user <u> vacation on subject ... message ...` | service account: gmail.settings.basic |
| 5. Suspend | `info user <u> quick formatjson`, `update user <u> suspended on` | admin OAuth: admin.directory.user |
| 6. Record groups | `user <u> print groups` | admin OAuth: admin.directory.group |
| 7. Remove from groups | `user <u> delete groups` | admin OAuth: admin.directory.group |
| 8. Drive transfer | `create datatransfer <u> gdrive <manager>`, `print datatransfers olduser <u> newuser <m>` | admin OAuth: admin.datatransfer |
| 9. Scheduled delete | `info user <u> quick formatjson`, `delete user <u>` | admin OAuth: admin.directory.user |

The offboarding workflow has nine rows because the group list is recorded in its own step (`record_groups`) before the removal; the spec's "eight steps" count them as one. The order in the table is the order GAMUT runs them (see [decisions.md](decisions.md), "Offboarding step order").

## Notes

- The Drive transfer uses the Admin SDK Data Transfer API through the admin OAuth client, so the service account needs no Drive scope.
- `client_secrets.json` is optional and is not used by offboarding.
- To remove a scope later, re-authorize the client with the smaller list and upload the updated files. Replacing credentials returns the tenant to `pending` until the health check passes again.
