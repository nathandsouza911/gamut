# GAMUT

GAMUT is a self-hosted web admin panel for Google Workspace. It runs [GAM7](https://github.com/GAM-team/GAM) behind a web UI so technicians can perform common administration tasks (starting with user offboarding) and review every step in a tamper-evident audit log.

Status: early development (Milestone 1: offboarding, end to end).

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Quick start

1. `cp .env.example .env` and edit the values.
2. Put the worker's credential private key at the path named by `GAMUT_PRIVATE_KEY_PATH` (the shipped example key is a placeholder and is rejected by the worker).
3. `docker compose up -d --build`
4. Open http://127.0.0.1:8080

Three containers run: `web` (API and built UI), `worker` (holds the private key, runs GAM7) and `db` (PostgreSQL).

## Development

Backend tests run in Docker (they need Python 3.12 and Linux):

```
docker compose -f docker-compose.test.yml run --rm tests pytest -v
docker compose -f docker-compose.test.yml run --rm tests ruff check .
docker compose -f docker-compose.test.yml run --rm tests mypy app
```

Frontend (Node 20): `cd frontend && npm ci && npm run lint && npx tsc --noEmit && npx vitest run`.

Design decisions are recorded in [docs/decisions.md](docs/decisions.md). Runtime dependency licenses are listed in [docs/third-party-licenses.md](docs/third-party-licenses.md).
