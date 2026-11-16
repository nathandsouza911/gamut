# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant credentials (upload, replace, delete), tenant deletion and health status.

Uploaded GAM files are sealed with the credential public key (app.crypto.envelope)
before they touch the database; this module never sees the private key. Audit events
name the files only. Error messages never include file contents.

Allowed files (see docs/decisions.md, "GAM7 configuration files"):
- oauth2.txt          required: the admin OAuth client and refresh token (directory calls)
- oauth2service.json  required: the service account key (domain-wide delegation)
- client_secrets.json optional: only needed to create a new oauth2.txt
In dasa mode (delegated admin service account) only oauth2service.json is allowed.
gam.cfg is refused: its path settings (config_dir, oauth2_txt, cache_dir, ...) are
absolute paths on the operator's machine and could point GAM outside the job directory.
GAM writes a default gam.cfg into the job directory instead.

In dasa mode the stored oauth2service.json gets GAM's `us_scopes` record set to the one
Gmail scope GAMUT uses (see with_gmail_scope_record).
"""

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.crypto.envelope import seal_bundle
from app.models import AuthMode, Tenant, TenantCredential, TenantStatus

REQUIRED_FILES = ("oauth2.txt", "oauth2service.json")
OPTIONAL_FILES = ("client_secrets.json",)
ALLOWED_FILES = REQUIRED_FILES + OPTIONAL_FILES
MAX_FILE_BYTES = 256 * 1024
HEALTH_MESSAGE_MAX = 4000

# GAM 7.52.3 reads the service account's scopes per API from the key's "us_scopes"
# object (gamlib/glapi.py OAUTH2SA_SCOPES; gam/__init__.py _getSvcAcctData). Without it
# GAM uses its default scope set (for Gmail: mail.google.com, gmail.modify,
# gmail.settings.basic, gmail.settings.sharing), which a DASA key is not delegated.
GMAIL_SETTINGS_BASIC_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"
DASA_SCOPE_RECORD: dict[str, list[str]] = {"gmail": [GMAIL_SETTINGS_BASIC_SCOPE]}


class CredentialError(ValueError):
    """The upload is not acceptable. The message is safe to show (no file contents)."""

    def __init__(self, message: str, *, too_large: bool = False) -> None:
        super().__init__(message)
        self.too_large = too_large


def files_for_mode(mode: AuthMode) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(required, optional) file names for the tenant's credential mode."""
    if mode == AuthMode.dasa:
        return (("oauth2service.json",), ())
    return (REQUIRED_FILES, OPTIONAL_FILES)


@dataclass(frozen=True)
class ServiceAccountIdentity:
    """The non-secret identifiers of a service account key (empty when the file lacks them)."""

    client_email: str
    client_id: str


def _service_account_identity(parsed: dict[str, object], mode: AuthMode) -> ServiceAccountIdentity:
    email = parsed.get("client_email")
    client_id = parsed.get("client_id")
    if mode == AuthMode.dasa:
        if parsed.get("type") != "service_account":
            raise CredentialError('oauth2service.json must have "type": "service_account"')
        for field in ("client_email", "client_id", "private_key"):
            value = parsed.get(field)
            if not isinstance(value, str) or not value.strip():
                raise CredentialError(f"oauth2service.json is missing {field}")
        key_type = parsed.get("key_type")
        if key_type not in (None, "default"):
            raise CredentialError(
                'oauth2service.json: only ordinary private keys are supported ("key_type")'
            )
    return ServiceAccountIdentity(
        client_email=email if isinstance(email, str) else "",
        client_id=client_id if isinstance(client_id, str) else "",
    )


def with_gmail_scope_record(content: bytes) -> bytes:
    """The service account key with GAM's `us_scopes` set to exactly gmail.settings.basic.

    Any existing `us_scopes` is replaced; every other field is kept. `content` must be a
    JSON object (validate_files checks that first).
    """
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise CredentialError("oauth2service.json is not a JSON object")
    parsed["us_scopes"] = {api: list(scopes) for api, scopes in DASA_SCOPE_RECORD.items()}
    return json.dumps(parsed, ensure_ascii=False, indent=2).encode()


def validate_files(files: dict[str, bytes], mode: AuthMode) -> ServiceAccountIdentity:
    """Allowed names only (per mode), each at most MAX_FILE_BYTES, required files present,
    JSON. Returns the service account's identifiers; in dasa mode the key must be a
    plain service account key."""
    required, optional = files_for_mode(mode)
    allowed = required + optional
    for name in files:
        if name not in allowed:
            shown = name if name in ("gam.cfg", *ALLOWED_FILES) else "this file name"
            raise CredentialError(f"{shown} is not allowed; upload only {', '.join(allowed)}")
    for name, content in files.items():
        if len(content) > MAX_FILE_BYTES:
            raise CredentialError(
                f"{name} is larger than {MAX_FILE_BYTES // 1024} KB", too_large=True
            )
    missing = [name for name in required if name not in files]
    if missing:
        raise CredentialError(f"missing required file(s): {', '.join(missing)}")
    documents: dict[str, dict[str, object]] = {}
    for name, content in files.items():
        try:
            parsed = json.loads(content)
        except (UnicodeDecodeError, ValueError):
            parsed = None
        if not isinstance(parsed, dict):
            raise CredentialError(f"{name} is not a JSON object")
        documents[name] = parsed
    return _service_account_identity(documents["oauth2service.json"], mode)


def store_credentials(
    session: Session,
    tenant: Tenant,
    files: dict[str, bytes],
    public_key: X25519PublicKey,
    *,
    actor: str,
    actor_id: uuid.UUID | None,
) -> TenantCredential:
    """Seal and store (or replace) the tenant's GAM files; audit the file names.

    New credentials are untested, so an active or degraded tenant goes back to pending
    until a health check passes. A disabled tenant stays disabled.
    """
    identity = validate_files(files, tenant.auth_mode)
    if tenant.auth_mode == AuthMode.dasa:
        files = {
            **files, "oauth2service.json": with_gmail_scope_record(files["oauth2service.json"])
        }
    names = sorted(files)
    sealed = seal_bundle(files, public_key, associated_data=tenant.id.bytes)
    row = session.get(TenantCredential, tenant.id, with_for_update=True)
    previous = list(row.file_names) if row is not None else None
    if row is None:
        row = TenantCredential(tenant_id=tenant.id)
        session.add(row)
    row.ciphertext = sealed.ciphertext
    row.nonce = sealed.nonce
    row.wrapped_key = sealed.wrapped_key
    row.key_version = sealed.key_version
    row.file_names = names
    row.sa_client_email = identity.client_email or None
    row.sa_client_id = identity.client_id or None
    row.uploaded_by = actor_id
    row.uploaded_at = datetime.now(UTC)
    if tenant.status != TenantStatus.disabled:
        tenant.status = TenantStatus.pending
    session.flush()
    details: dict[str, list[str]] = {"file_names": names}
    if previous is not None:
        details["previous_file_names"] = previous
    append_event(
        session,
        actor=actor,
        tenant_id=tenant.id,
        action=f"tenant.credentials.{'replace' if previous is not None else 'upload'}",
        target=tenant.name,
        details=details,
    )
    return row


def delete_credentials(session: Session, tenant: Tenant, *, actor: str) -> bool:
    """Delete the tenant's stored files (False if there were none). Audited."""
    row = session.get(TenantCredential, tenant.id, with_for_update=True)
    if row is None:
        return False
    names = list(row.file_names)
    session.delete(row)
    if tenant.status != TenantStatus.disabled:
        tenant.status = TenantStatus.pending
    session.flush()
    append_event(
        session, actor=actor, tenant_id=tenant.id, action="tenant.credentials.delete",
        target=tenant.name, details={"file_names": names},
    )
    return True


def delete_tenant(session: Session, tenant: Tenant, *, actor: str) -> None:
    """Delete the tenant; credentials, memberships and jobs go with it (FK cascade).

    Audit events have no foreign key and stay.
    """
    append_event(
        session, actor=actor, tenant_id=tenant.id, action="tenant.delete", target=tenant.name,
        details={"name": tenant.name, "primary_domain": tenant.primary_domain},
    )
    session.delete(tenant)
    session.flush()


def credential_summaries(
    session: Session, tenant_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[list[str], datetime, str | None, str | None]]:
    """{tenant_id: (file names, uploaded_at, sa_client_email, sa_client_id)} for tenants
    with stored credentials."""
    if not tenant_ids:
        return {}
    rows = session.execute(
        select(
            TenantCredential.tenant_id, TenantCredential.file_names,
            TenantCredential.uploaded_at, TenantCredential.sa_client_email,
            TenantCredential.sa_client_id,
        ).where(TenantCredential.tenant_id.in_(tenant_ids))
    ).all()
    return {tid: (list(names), at, email, cid) for tid, names, at, email, cid in rows}


def apply_health_result(session: Session, tenant: Tenant, *, ok: bool, message: str) -> None:
    """Record a health check result.

    Pass: the tenant becomes active. Fail: pending stays pending, active becomes
    degraded. A disabled tenant is never changed.
    """
    if tenant.status == TenantStatus.disabled:
        return
    if ok:
        tenant.status = TenantStatus.active
    elif tenant.status == TenantStatus.active:
        tenant.status = TenantStatus.degraded
    tenant.last_health_check_at = datetime.now(UTC)
    tenant.last_health_message = message[:HEALTH_MESSAGE_MAX]
    session.flush()
