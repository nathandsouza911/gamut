# Quick start

This sets up GAMUT with Docker Compose on one host. You need Docker with Compose v2, `git`, `openssl` and a POSIX shell (on Windows, use Git Bash or WSL).

## 1. Get the code and create `.env`

```
git clone <this repository> gamut
cd gamut
cp .env.example .env
```

Compose reads `.env` to fill in each service's own environment. The containers do not receive the whole file: `web`, `worker`, `migrate` and `db` each get only the variables listed for them in `docker-compose.yml`.

Generate the four required secrets (hex, so they are safe inside connection URLs):

```
for v in POSTGRES_PASSWORD GAMUT_OWNER_DB_PASSWORD GAMUT_APP_DB_PASSWORD GAMUT_SECRET_KEY; do
  sed -i "s|^$v=.*|$v=$(openssl rand -hex 32)|" .env
done
```

(On macOS use `sed -i ''` instead of `sed -i`.) Compose refuses to start while any of these is empty.

## 2. Generate the credential key pair

GAMUT encrypts each tenant's uploaded GAM credentials with a public key; only the worker holds the private key. Create the pair once with `gamut gen-keys`:

```
mkdir -p secrets
docker compose run --rm --no-deps -T --user root -v "$PWD/secrets:/out" worker \
  sh -c 'gamut gen-keys /out/credential_private_key && chown 10001:10001 /out/credential_private_key'
```

It prints two lines. The first says the private key was written (mode 0600; it never overwrites an existing file). The second is `GAMUT_CREDENTIAL_PUBLIC_KEY=...`. In `.env`:

- replace the `GAMUT_CREDENTIAL_PUBLIC_KEY=EXAMPLE-DO-NOT-USE` line with the printed line;
- set `GAMUT_PRIVATE_KEY_PATH=./secrets/credential_private_key`.

The `chown` matters on Linux. The worker runs as uid 10001 and must read the 0600 file, so 10001 has to own it (then only that user and root can read it). The `secrets/` directory is ignored by git. If you create the key some other way, run `sudo chown 10001:10001 secrets/credential_private_key` yourself.

**Docker Desktop (Windows, macOS):** bind-mounted files do not keep Linux ownership, so the `chown` changes nothing on the host and is harmless. The worker can read the file because Docker Desktop shows it inside the container with open read permission. Check with `docker compose logs worker` after step 4: `credential private key missing` or a permission error means the mount failed (see Troubleshooting). Treat the key file as sensitive on the host regardless.

**Back this key up now, separately from the database** ([backup-restore.md](backup-restore.md)). Without it, stored tenant credentials cannot be decrypted.

## 3. Edit the rest of `.env`

- `GAMUT_BOOTSTRAP_ADMIN_PASSWORD`: a long passphrase for the break-glass owner `GAMUT_BOOTSTRAP_ADMIN_EMAIL`. It is read on first start only. With no password no owner is created, and without OIDC either, nobody can sign in.
- `GAMUT_PUBLIC_BASE_URL`: the external https address of the panel, for example `https://gamut.example.com`.
- `GAMUT_OIDC_CLIENT_ID` and `GAMUT_OIDC_CLIENT_SECRET` (optional): Google sign-in. The authorized redirect URI is `<GAMUT_PUBLIC_BASE_URL>/api/auth/callback`. An owner must add panel users first; OIDC never creates users.
- `GAMUT_SOURCE_URL`: the repository URL shown in the UI footer.

## 4. Start

```
docker compose up -d --build
```

Startup order: `db` becomes healthy, `migrate` applies the schema and exits, then `web` and `worker` start. `docker compose ps -a` shows `migrate` as `Exited (0)`, which is correct.

Only `127.0.0.1:8080` is published, and only for `web`. The database has no published port.

## 5. Check it

```
curl -s http://127.0.0.1:8080/api/meta                 # {"source_url":"...","version":"..."}
curl -s http://127.0.0.1:8080/ | head -n 5              # the sign-in page (HTML)
docker compose ps                                        # db, web, worker: running
docker compose exec worker gamut verify-audit           # OK <n> events
```

`verify-audit` walks the hash chain of the audit log and prints `OK <n> events`, or `BROKEN at event <id>: <reason>` with exit code 1.

The worker refuses to run with the shipped example key. With `GAMUT_PRIVATE_KEY_PATH` pointing at `secrets/credential_private_key.example` it exits with `credential private key is the example value`.

Sign in: open the panel through your reverse proxy (step 6), choose the bootstrap sign-in, and use `GAMUT_BOOTSTRAP_ADMIN_EMAIL` and the password you set. Every use of that account is audited as `auth.bootstrap_login`.

Session cookies are `Secure`. Browsers accept them on `http://127.0.0.1` for local testing, but plain http on any other address will not sign in.

## 6. Put TLS in front

Use a reverse proxy that terminates TLS and forwards to `127.0.0.1:8080`; a Caddy example is in [threat-model.md](threat-model.md). Never publish port 8080 on a public interface.

`GAMUT_FORWARDED_ALLOW_IPS` names the addresses whose `X-Forwarded-For` header GAMUT believes, so the login rate limit counts each real client separately. Compose pins its network to `172.30.80.0/24`. A proxy running on the host reaches the published port from the network gateway `172.30.80.1`, which is the default. Without a trusted proxy address all clients would share one login bucket (10 attempts per minute for everybody). If `172.30.80.0/24` clashes with a network you use, change the subnet and gateway in `docker-compose.yml` and set `GAMUT_FORWARDED_ALLOW_IPS` to the new gateway. A proxy running as another Compose service should be listed by its address on that network instead.

## 7. Add a tenant

An owner creates the tenant in the UI (name, primary domain, admin email for the health check) and uploads the GAM files. [gam-setup.md](gam-setup.md) shows how to produce them and [scopes.md](scopes.md) lists the scopes to authorize. The tenant becomes active when the health check passes.

## Day-to-day

- Stop: `docker compose stop`. The worker finishes the GAM step it is running first (it has up to 120 seconds). If it is killed before that, the job's lease expires and another worker run repeats the interrupted step; steps are idempotent.
- Upgrade: `git pull && docker compose up -d --build`. `migrate` runs again and applies new migrations.
- Logs: `docker compose logs -f web worker`. Credentials, tokens and keys are never logged.

## Troubleshooting

- `required variable ... is missing a value`: a secret in `.env` is empty. Re-run the loop in step 1.
- Worker exits with `credential private key missing`: `GAMUT_PRIVATE_KEY_PATH` points at a missing file, or (Linux) the file is not readable by uid 10001. `ls -ln secrets/` should show owner 10001.
- Worker exits with `credential private key is the example value`: set `GAMUT_PRIVATE_KEY_PATH` to the generated key (step 2) and run `docker compose up -d`.
- Web exits complaining about `GAMUT_CREDENTIAL_PUBLIC_KEY`: paste the public key line from step 2.
- `migrate` fails: read `docker compose logs migrate`. The database passwords in `.env` must match the ones the database was first created with; they are not changed afterwards. On a throwaway install, `docker compose down -v` deletes the volume.
- All clients share one login rate limit: `docker compose logs web` shows the client address of each request. If it is always the proxy's address, set `GAMUT_FORWARDED_ALLOW_IPS` to that address.
