# SPDX-License-Identifier: AGPL-3.0-only
"""Parsers for GAM's structured (CSV and JSON) output."""

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

# overallTransferStatusCode values: pending, inProgress, completed, failed.
COMPLETED = "completed"
FAILED = "failed"


@dataclass(frozen=True)
class TransferStatus:
    id: str
    old_owner: str
    new_owner: str
    status: str  # overallTransferStatusCode
    # requestTime as GAM prints it (UTC "...Z", or local time with an offset when GAM is
    # set to convert times); None when missing or unreadable. Not part of equality.
    request_time: datetime | None = field(default=None, compare=False)

    @property
    def completed(self) -> bool:
        return self.status == COMPLETED

    @property
    def failed(self) -> bool:
        return self.status == FAILED


def parse_transfers_csv(stdout: str) -> list[TransferStatus]:
    """Parse `print datatransfers` CSV into one TransferStatus per transfer id.

    GAM writes one row per application of a transfer and sorts transfers by request time,
    oldest first; that order is kept, so the newest transfer is the last element. Raises
    ValueError if the output is not the expected CSV (for example an error message).
    """
    text = stdout.strip()
    if not text:
        return []
    reader = csv.DictReader(io.StringIO(text))
    needed = {"id", "oldOwnerUserEmail", "newOwnerUserEmail", "overallTransferStatusCode"}
    if not needed <= set(reader.fieldnames or []):
        raise ValueError("unexpected output from print datatransfers")
    seen: dict[str, TransferStatus] = {}
    for row in reader:
        tid = row["id"]
        if tid and tid not in seen:
            seen[tid] = TransferStatus(
                id=tid,
                old_owner=row["oldOwnerUserEmail"].lower(),
                new_owner=row["newOwnerUserEmail"].lower(),
                status=row["overallTransferStatusCode"],
                request_time=_parse_time(row.get("requestTime") or ""),
            )
    return list(seen.values())


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


USER_GROUP_COLUMNS = ("User", "Group", "Role", "Status", "Delivery")


def parse_user_groups_csv(stdout: str) -> list[dict[str, str]]:
    """Parse `gam user <e> print groups` CSV: one {group, role, status, delivery} per row.

    Group addresses are lowercased; GAM's order is kept. Empty output or a header alone
    gives []. Raises ValueError if the output is not the expected CSV.
    """
    text = stdout.strip()
    if not text:
        return []
    reader = csv.DictReader(io.StringIO(text))
    if not {"User", "Group", "Role"} <= set(reader.fieldnames or []):
        raise ValueError("unexpected output from print groups")
    return [
        {
            "group": row["Group"].strip().lower(),
            "role": (row.get("Role") or "").strip(),
            "status": (row.get("Status") or "").strip(),
            "delivery": (row.get("Delivery") or "").strip(),
        }
        for row in reader
        if (row.get("Group") or "").strip()
    ]


@dataclass(frozen=True)
class UserInfo:
    """The fields GAMUT reads from `info user ... formatjson`."""

    id: str | None  # Google's immutable user id
    primary_email: str | None  # lowercased
    suspended: bool


def parse_user_info_json(stdout: str) -> UserInfo:
    """Parse `info user <user> quick formatjson` (one JSON object on stdout).

    The whole output is tried first, then each line that starts with "{" (in case GAM
    printed a progress line before it). Raises ValueError when no JSON object is found.
    """
    candidates = [stdout.strip()] + [
        line.strip() for line in stdout.splitlines() if line.strip().startswith("{")
    ]
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            uid, email = value.get("id"), value.get("primaryEmail")
            return UserInfo(
                id=str(uid) if isinstance(uid, str | int) and str(uid) else None,
                primary_email=email.strip().lower() if isinstance(email, str) else None,
                suspended=value.get("suspended") is True,
            )
    raise ValueError("GAM's info user output was not the expected JSON")
