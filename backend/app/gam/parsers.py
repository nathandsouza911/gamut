# SPDX-License-Identifier: AGPL-3.0-only
"""Parsers for GAM's structured (CSV) output."""

import csv
import io
from dataclasses import dataclass

# overallTransferStatusCode values: pending, inProgress, completed, failed.
COMPLETED = "completed"
FAILED = "failed"


@dataclass(frozen=True)
class TransferStatus:
    id: str
    old_owner: str
    new_owner: str
    status: str  # overallTransferStatusCode

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
            )
    return list(seen.values())
