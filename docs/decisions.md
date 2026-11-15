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
