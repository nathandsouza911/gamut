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
