# Backup and restore

GAMUT has two things to back up, and they must be backed up **separately**:

1. The PostgreSQL database (tenants, users, jobs, audit log, and each tenant's credentials as ciphertext).
2. The credential private key file (`secrets/credential_private_key`, or wherever `GAMUT_PRIVATE_KEY_PATH` points).

**Without the private key, the stored tenant credentials cannot be decrypted**, and a database backup cannot restore them. (You can re-upload the GAM files, so this is recoverable but tedious.) Conversely, store the key where a stolen database dump does not also yield it: if someone holds both the dump and the key, they hold the credentials. Keep the key in a password manager or an offline, access-controlled store. Also keep `.env` (it holds the database passwords and `GAMUT_SECRET_KEY`) somewhere safe, and the matching `GAMUT_CREDENTIAL_PUBLIC_KEY` value.

## Back up the database

```
docker compose exec -T db pg_dump -U gamut -d gamut --format=custom > gamut-$(date +%F).dump
```

This runs as the bootstrap superuser inside the `db` container, so no database password is needed on the host. Store the dump encrypted and off the host. Run it on a schedule (cron or a systemd timer).

A running instance can be dumped; the dump is consistent as of the moment it starts.

## Restore

On a new host (or after `docker compose down -v` on the old one):

1. Get the code, `.env` and the private key file back in place (`secrets/credential_private_key`, owner uid 10001 on Linux, `GAMUT_PRIVATE_KEY_PATH` set). Use the same database passwords as in the original `.env`, or any new ones: the dump does not contain role passwords.
2. Start only the database, so the roles are created by the init script on the empty volume:

   ```
   docker compose up -d db
   ```

3. Restore the dump into the empty `gamut` database. The tables are owned by `gamut_owner`, and the grants (including the audit table's no-UPDATE/DELETE rule) are part of the dump:

   ```
   docker compose exec -T db pg_restore -U gamut -d gamut --no-owner --role=gamut_owner --exit-on-error < gamut-YYYY-MM-DD.dump
   ```

   If `pg_restore` complains about existing objects, the database was not empty; recreate the volume (`docker compose down -v`, then step 2) and retry.

4. Start everything. `migrate` finds the schema already at the latest revision and exits:

   ```
   docker compose up -d --build
   ```

5. Verify:

   ```
   docker compose exec worker gamut verify-audit    # OK <n> events
   ```

   Then run a health check on a tenant in the UI. If it fails to decrypt the credentials, the private key is not the one that matches the dump's public key; restore the right key file.

## Notes

- After restoring, the bootstrap owner already exists in the data; `GAMUT_BOOTSTRAP_ADMIN_PASSWORD` is not applied again.
- `verify-audit` after a restore proves the restored log is internally consistent, not that it is the log that existed originally (see [threat-model.md](threat-model.md)).
- Test a restore on a scratch host before you need it.
