# Threat model

GAMUT stores credentials that can read every mailbox and file in a Google Workspace domain, and drives destructive actions (suspend, delete). This page says what it protects, from whom, and where the limits are.

## Assets

1. **Tenant GAM credentials** (`oauth2.txt`, `oauth2service.json`): the most valuable asset. Stored only as ciphertext in `tenant_credentials`.
2. **The credential private key**: decrypts those credentials. A file on the worker host, mounted into the worker container only.
3. **The audit log**: the record of who did what to which tenant.
4. **Panel sessions and the bootstrap owner password**: access to the UI.
5. **Tenant data reachable through GAM**: protected mainly by what the scopes allow ([scopes.md](scopes.md)).

## Actors

| Actor | Trusted for |
| --- | --- |
| Owner | Everything, including credentials and users. Few people. |
| Tenant admin, technician, auditor | Only the tenants they hold a role on; auditors read only. |
| Anyone on the network | Nothing. Reaches only the reverse proxy. |
| Host administrator and anyone with Docker access on the host | Everything below; they can read the private key and the database. Out of scope to defend against. |
| Database superuser | Can rewrite the audit log (see below). |
| Google | Authenticates users (OIDC) and is the target of the GAM calls. |

## Trust boundaries

```
 browser --TLS--> reverse proxy --http, 127.0.0.1:8080--> web --SQL--> db <--SQL-- worker --> gam --> Google
                                                                                      ^
                                                                    credential private key (file, worker only)
```

- **web** (internet-facing, via the proxy): validates input, enforces roles and tenant isolation, encrypts uploads with the **public** key. It never receives the private key, never runs GAM, and its container has no migration login. If web is compromised, an attacker gets sessions and the ability to enqueue jobs the UI would allow, and can store credentials encrypted for the worker, but cannot decrypt any stored credential.
- **worker** (no inbound port): the only place credentials are decrypted and GAM runs. It receives the private key and the app database login, not the session secret or the OIDC client secret. It runs as non-root uid 10001 with a read-only root filesystem; decrypted files live in a per-job 0700 directory on tmpfs and are deleted in a `finally` block. If the worker host is compromised, the credentials of tenants it processes are exposed; that is inherent to running GAM.
- **db**: reachable only on the Compose network; no published port. The application connects as `gamut_app`, which has no UPDATE or DELETE on the audit table. Schema changes use a different role, `gamut_owner`, only inside the one-shot `migrate` container, so neither long-running service holds that password.

Only `app/gam/runner.py` starts a process: argument lists, `shell=False`, a fixed environment, timeouts and output caps. CI enforces it. Free text (the auto-reply) is one argument and file-reading forms are rejected.

## The key pair split

The "master key" is an X25519 key pair. The API holds only the public key (`GAMUT_CREDENTIAL_PUBLIC_KEY`), so it can encrypt an upload but never decrypt one. The worker holds the private key file (`GAMUT_CREDENTIAL_PRIVATE_KEY_FILE`). Each upload gets a random AES-256-GCM data key, wrapped with ECIES (ephemeral X25519, HKDF-SHA256, AES-256-GCM); the tenant id is authenticated, so a bundle copied to another tenant's row does not decrypt. The web process refuses to start with a missing, example or malformed public key, or if it is given a private key setting; the worker refuses to start without a valid private key or with the example key.

Operating rules: generate the pair once (`gamut gen-keys`), keep the private file mode 0600 owned by uid 10001, back it up separately from database dumps ([backup-restore.md](backup-restore.md)), and never put it in `.env`, the image or git. Losing it makes the stored credentials unrecoverable (re-upload them). Rotating the pair means re-uploading every tenant's credentials; there is no automatic re-wrap in Milestone 1.

Service-level separation is enforced by Compose per-service environments, not by trust: see `docker-compose.yml`.

## The audit log: tamper-evident, not immutable

Every action is stored in an append-only table. Each row holds a SHA-256 hash of its content plus the previous row's hash. `docker compose exec worker gamut verify-audit` (or the owner-only `/api/audit/verify`) walks the chain and reports the first broken link. The application's database role cannot update or delete rows.

This makes tampering **evident**, not impossible. A database superuser (the `postgres` role, or anyone with the host's database volume) can rewrite the whole table and recompute every hash, and nothing inside GAMUT can tell. A truncated tail also verifies as a shorter, valid chain. If the log matters for compliance, copy the latest chain hash (the output of `verify-audit` and the last event) to a place the database administrator cannot change, and back the database up regularly. Secrets and message bodies are redacted from events.

## TLS and the reverse proxy

TLS is required. GAMUT serves plain http on `127.0.0.1:8080`; session and CSRF cookies are `Secure`, so sign-in works only over https (or on localhost for testing). Never publish port 8080 on a public interface.

Example Caddy configuration, with Caddy running on the same host:

```
gamut.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8080
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "same-origin"
    }
}
```

Caddy sets `X-Forwarded-For` itself and replaces any value sent by the client. Set `GAMUT_PUBLIC_BASE_URL=https://gamut.example.com` and use the same address as the Google OIDC redirect host.

### Client address and the login rate limit

Login (10 per minute) is limited per client address, taken from `X-Forwarded-For`, which uvicorn honours only from `GAMUT_FORWARDED_ALLOW_IPS`. The default is `10.78.80.1`, the gateway of the Compose network that `docker-compose.yml` pins to `10.78.80.0/24` (override with `GAMUT_NETWORK_SUBNET` and `GAMUT_NETWORK_GATEWAY`; the trusted address follows the gateway). Because the port is published on `127.0.0.1`, a proxy on the host reaches the web container from that gateway address, and only host processes can connect there. Any local process on the host can therefore send its own `X-Forwarded-For` through that trusted gateway address and choose the client address the rate limit sees. If the setting were left at `127.0.0.1`, the proxy would never be trusted and every client would share the proxy's single bucket, so one attacker's failed logins would lock out everyone. If you run the proxy as another container, trust its address on the Compose network instead and do not publish the port. Never set it to a wide range such as `*`: any client could then forge its address and bypass the limit. The counters are in memory per web process and reset on restart.

## Other controls

- Sign-in: OIDC (Google), with panel users pre-registered by an owner, plus one break-glass bootstrap owner (argon2id), audited on every use. Sessions are server-side, 12 hours maximum and 2 hours idle, revocable. Disabling a user (owner, Users page) deletes all their sessions at once and blocks both sign-in methods.
- Every `/api/tenants/{tenant_id}/...` route checks the caller's role on that tenant; a test enumerates the routes. A caller without a CSRF token on a state-changing request gets 403 before any tenant lookup, the same for every tenant id; an authenticated non-member otherwise gets 404 as if the tenant did not exist.
- CSRF protection (`X-CSRF-Token`) on every state-changing authenticated route; SameSite=Lax HttpOnly cookies.
- Confirmation: offboarding needs a preview and a signed, 10-minute token; account deletion is scheduled and needs a second confirmation. The scheduled deletion deletes the Google account by its immutable id, and only while that account still has the offboarded address and is suspended, so a reactivated account or an address reused by someone else is never deleted. One unfinished offboarding per user and tenant; the tenant's own admin account cannot be offboarded.
- No credential material in logs, test output or API responses; stored GAM output is capped and scrubbed.

## Service-account-only credentials (DASA)

In DASA mode the service account key is the only Google secret GAMUT holds. Its power is bounded by the Admin roles assigned to the service account (never super admin) plus one Gmail settings scope. If the key is compromised, delete it in the Cloud console and unassign the roles; no other Google credential needs to be rotated.

## Known limits (Milestone 1)

- One web process; rate limits are in memory.
- Per-tenant concurrency is one running job, which does not cover scheduled actions: a scheduled account deletion may run while a job for the same tenant is running.
- A compromised host, or anyone who can run `docker` on it, defeats the key split.
- The behaviour of GAM and the scopes was checked on a live test domain (2026-11-16, GAM 7.52.3) only (one tenant, one offboarding).
- GAM's `check serviceaccount` output is shown as GAM prints it; GAMUT does not compute a list of missing scopes.
