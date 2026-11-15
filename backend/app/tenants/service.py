# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant credentials (upload, replace, delete), tenant deletion and health status.

Uploaded GAM files are sealed with the credential public key (app.crypto.envelope)
before they touch the database; this module never sees the private key. Audit events
name the files only. Error messages never include file contents.

Allowed files (see docs/decisions.md, "GAM7 configuration files"):
- oauth2.txt          required: the admin OAuth client and refresh token (directory calls)
- oauth2service.json  required: the service account key (domain-wide delegation)
- client_secrets.json optional: only needed to create a new oauth2.txt
gam.cfg is refused: its path settings (config_dir, oauth2_txt, cache_dir, ...) are
absolute paths on the operator's machine and could point GAM outside the job directory.
GAM writes a default gam.cfg into the job directory instead.
"""

import json
import uuid
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.crypto.envelope import seal_bundle
from app.models import Tenant, TenantCredential, TenantStatus

REQUIRED_FILES = ("oauth2.txt", "oauth2service.json")
OPTIONAL_FILES = ("client_secrets.json",)
ALLOWED_FILES = REQUIRED_FILES + OPTIONAL_FILES
MAX_FILE_BYTES = 256 * 1024
HEALTH_MESSAGE_MAX = 4000


class CredentialError(ValueError):
    """The upload is not acceptable. The message is safe to show (no file contents)."""

    def __init__(self, message: str, *, too_large: bool = False) -> None:
        super().__init__(message)
        self.too_large = too_large


def validate_files(files: dict[str, bytes]) -> None:
    """Allowed names only, each at most MAX_FILE_BYTES, required files present, JSON."""
    for name in files:
        if name not in ALLOWED_FILES:
            shown = name if name == "gam.cfg" else "this file name"
            raise CredentialError(
                f"{shown} is not allowed; upload only {', '.join(ALLOWED_FILES)}"
            )
    for name, content in files.items():
        if len(content) > MAX_FILE_BYTES:
            raise CredentialError(
                f"{name} is larger than {MAX_FILE_BYTES // 1024} KB", too_large=True
            )
    missing = [name for name in REQUIRED_FILES if name not in files]
    if missing:
        raise CredentialError(f"missing required file(s): {', '.join(missing)}")
    for name, content in files.items():
        try:
            parsed = json.loads(content)
        except (UnicodeDecodeError, ValueError):
            parsed = None
        if not isinstance(parsed, dict):
            raise CredentialError(f"{name} is not a JSON object")


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
    validate_files(files)
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
) -> dict[uuid.UUID, tuple[list[str], datetime]]:
    """{tenant_id: (file names, uploaded_at)} for tenants with stored credentials."""
    if not tenant_ids:
        return {}
    rows = session.execute(
        select(
            TenantCredential.tenant_id, TenantCredential.file_names, TenantCredential.uploaded_at
        ).where(TenantCredential.tenant_id.in_(tenant_ids))
    ).all()
    return {tenant_id: (list(names), at) for tenant_id, names, at in rows}


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
