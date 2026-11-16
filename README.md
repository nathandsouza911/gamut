# GAMUT

GAMUT is a self-hosted web admin panel for Google Workspace. It runs [GAM7](https://github.com/GAM-team/GAM) behind a web UI so technicians can perform common administration tasks (starting with user offboarding) and review every step in a tamper-evident audit log.

Status: early development. Milestone 1 (offboarding, end to end) and Milestone 2 (guided tenant setup, service-account-only credentials, a per-tenant dashboard) are built; it has been run end to end against a test Google Workspace tenant (see [docs/decisions.md](docs/decisions.md), "Live-domain acceptance").

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE). The UI footer links to the source code, as AGPL-3.0 section 13 requires.

## What runs

Four Compose services:

| Service | Role |
| --- | --- |
| `db` | PostgreSQL 16. No published port. |
| `migrate` | One-shot: applies schema migrations as the schema-owner role, then exits. The only container that receives the owner database URL. |
| `web` | API and built UI on `127.0.0.1:8080`. Holds the session secret, the OIDC client secret and the credential **public** key. Never the private key. |
| `worker` | Runs GAM7 jobs. Holds the credential **private** key (a Compose secret) and no other secret except its database login. Non-root, read-only filesystem, per-job decrypted files on tmpfs. |

## Quick start

The short version (full steps, checks and platform notes are in [docs/quick-start.md](docs/quick-start.md)):

```
git clone <this repository> gamut && cd gamut
cp .env.example .env
# fill in the four secrets
for v in POSTGRES_PASSWORD GAMUT_OWNER_DB_PASSWORD GAMUT_APP_DB_PASSWORD GAMUT_SECRET_KEY; do
  sed -i "s|^$v=.*|$v=$(openssl rand -hex 32)|" .env
done
# generate the credential key pair (private key into ./secrets, owned by the worker's uid 10001;
# in Git Bash on Windows prefix this command with MSYS_NO_PATHCONV=1)
mkdir -p secrets
docker compose run --rm --no-deps -T --user root -v ./secrets:/out worker \
  sh -c 'gamut gen-keys /out/credential_private_key && chown 10001:10001 /out/credential_private_key'
# edit .env: paste the printed GAMUT_CREDENTIAL_PUBLIC_KEY line, set
# GAMUT_PRIVATE_KEY_PATH=./secrets/credential_private_key, GAMUT_BOOTSTRAP_ADMIN_PASSWORD,
# GAMUT_PUBLIC_BASE_URL and GAMUT_SOURCE_URL
docker compose up -d --build
docker compose exec worker gamut verify-audit    # prints: OK <n> events
```

Put a TLS reverse proxy in front before real use (see [docs/threat-model.md](docs/threat-model.md)).

## Documentation

- [docs/quick-start.md](docs/quick-start.md): install, key pair, first sign-in, checks, upgrades.
- [docs/gam-setup.md](docs/gam-setup.md): set up GAM7 for a Google domain, then what to upload.
- [docs/scopes.md](docs/scopes.md): the minimum Google API scopes. Authorize only these.
- [docs/threat-model.md](docs/threat-model.md): assets, trust boundaries, TLS, the key pair split, what the audit log does and does not guarantee.
- [docs/backup-restore.md](docs/backup-restore.md): database dump and the separately kept private key.
- [docs/decisions.md](docs/decisions.md): design decisions, GAM command syntax, known limits.
- [docs/third-party-licenses.md](docs/third-party-licenses.md): runtime dependency licenses.
- [SECURITY.md](SECURITY.md): reporting vulnerabilities.

## Development

Backend tests run in Docker (they need Python 3.12 and Linux):

```
docker compose -f docker-compose.test.yml run --rm tests pytest -v
docker compose -f docker-compose.test.yml run --rm tests ruff check .
docker compose -f docker-compose.test.yml run --rm tests mypy app
```

Repository checks: `python scripts/check_spdx.py .` and `python scripts/check_subprocess.py .`.

Frontend (Node 20): `cd frontend && npm ci && npm run lint && npx tsc --noEmit && npx vitest run && npm run build`.
