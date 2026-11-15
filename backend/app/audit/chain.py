# SPDX-License-Identifier: AGPL-3.0-only
"""Hash-chained, append-only audit log.

Each row stores prev_hash (the previous row's hash, or GENESIS for the first row) and
    hash = sha256(prev_hash + "\\n" + canonical_json(fields)).hexdigest()
where fields are every column except hash. Appends serialise on one advisory lock, so
the chain stays linear across web and worker processes. The log is tamper-evident, not
immutable: the owner role or a superuser can still rewrite it, but verify_chain will
report the first row that no longer matches.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import advisory_xact_lock
from app.models import AuditEvent

AUDIT_LOCK_KEY = 0x6A4D5554
GENESIS_HASH = "0" * 64
REDACTED = "[redacted]"
_SECRET_KEY = re.compile(r"password|token|secret|key|message|body", re.IGNORECASE)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int  # rows that verified before the walk stopped
    first_broken_id: int | None
    reason: str | None  # "hash mismatch" or "prev_hash mismatch"


def redact(details: dict[str, Any]) -> dict[str, Any]:
    """Copy of `details` with secret-like and message-body keys replaced, at any depth."""
    return {
        k: REDACTED if _SECRET_KEY.search(str(k)) else _redact_value(v)
        for k, v in details.items()
    }


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return redact(value)
    if isinstance(value, list | tuple):
        return [_redact_value(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _iso_utc(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="microseconds")


def compute_hash(
    *,
    id: int,
    time: datetime,
    actor: str,
    tenant_id: uuid.UUID | None,
    action: str,
    target: str | None,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    fields = {
        "id": id,
        "time": _iso_utc(time),
        "actor": actor,
        "tenant_id": None if tenant_id is None else str(tenant_id),
        "action": action,
        "target": target,
        "details": details,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(f"{prev_hash}\n{canonical_json(fields)}".encode()).hexdigest()


def append_event(
    session: Session,
    *,
    actor: str,
    tenant_id: uuid.UUID | None,
    action: str,
    target: str | None,
    details: dict[str, Any],
) -> AuditEvent:
    """Append one event in the caller's transaction (the caller commits).

    `details` is redacted, then normalised through JSON so that what is hashed is
    exactly what jsonb stores and returns.
    """
    advisory_xact_lock(session, AUDIT_LOCK_KEY)
    prev_hash = session.scalar(
        select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)
    ) or GENESIS_HASH
    event_id = session.scalar(
        select(func.nextval(func.pg_get_serial_sequence("audit_events", "id")))
    )
    if event_id is None:  # pragma: no cover - nextval always returns a value
        raise RuntimeError("could not allocate an audit event id")
    fields: dict[str, Any] = {
        "id": int(event_id),
        "time": datetime.now(UTC),
        "actor": actor,
        "tenant_id": tenant_id,
        "action": action,
        "target": target,
        "details": json.loads(canonical_json(redact(details))),
        "prev_hash": prev_hash,
    }
    event = AuditEvent(**fields, hash=compute_hash(**fields))
    session.add(event)
    session.flush()
    return event


def verify_chain(session: Session) -> VerifyResult:
    """Walk every event in id order, recomputing links and hashes; stop at the first break."""
    expected_prev = GENESIS_HASH
    checked = 0
    # Plain column rows, not ORM objects: the session's identity map must not mask
    # what is actually stored.
    rows = session.execute(
        select(
            AuditEvent.id,
            AuditEvent.time,
            AuditEvent.actor,
            AuditEvent.tenant_id,
            AuditEvent.action,
            AuditEvent.target,
            AuditEvent.details,
            AuditEvent.prev_hash,
            AuditEvent.hash,
        )
        .order_by(AuditEvent.id)
        .execution_options(yield_per=500)
    )
    for row in rows:
        fields = row._asdict()
        stored_hash = fields.pop("hash")
        if fields["prev_hash"] != expected_prev:
            return VerifyResult(False, checked, fields["id"], "prev_hash mismatch")
        if compute_hash(**fields) != stored_hash:
            return VerifyResult(False, checked, fields["id"], "hash mismatch")
        expected_prev = stored_hash
        checked += 1
    return VerifyResult(True, checked, None, None)
