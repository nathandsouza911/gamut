# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from app.gam.commands import Email, list_transfers
from app.gam.parsers import TransferStatus, parse_transfers_csv
from app.gam.runner import run_gam

HEADER = ("id,requestTime,oldOwnerUserEmail,newOwnerUserEmail,overallTransferStatusCode,"
          "application,applicationId,status,PRIVACY_LEVEL\n")
CSV = (
    HEADER
    + "111,2026-11-01T10:00:00,a@x.com,m@x.com,failed,Drive and Docs,55656082996,failed,"
      '"PRIVATE,SHARED"\n'
    + "222,2026-11-02T10:00:00,A@x.com,m@x.com,inProgress,Drive and Docs,55656082996,"
      "inProgress,\n"
    + "222,2026-11-02T10:00:00,A@x.com,m@x.com,inProgress,Calendar,435070579839,pending,\n"
)


def test_parse_transfers_csv_one_entry_per_transfer_in_order():
    got = parse_transfers_csv(CSV)
    assert got == [
        TransferStatus("111", "a@x.com", "m@x.com", "failed"),
        TransferStatus("222", "a@x.com", "m@x.com", "inProgress"),
    ]
    assert got[0].failed and not got[0].completed
    assert got[-1].id == "222"
    done = parse_transfers_csv(HEADER + "9,t,a@x.com,m@x.com,completed,D,1,completed,\n")
    assert done[0].completed


def test_parse_transfers_csv_empty_and_errors():
    assert parse_transfers_csv("") == []
    assert parse_transfers_csv(HEADER) == []
    with pytest.raises(ValueError):
        parse_transfers_csv("ERROR: No Client Access allowed\n")


def test_list_transfers_through_runner(fake_gam, tmp_path):
    argv = list_transfers(Email("a@x.com"), Email("m@x.com"))
    fake_gam.scenario([{"match": ["print", "datatransfers"], "stdout": CSV}])
    result = run_gam(argv, tmp_path)
    assert [t.id for t in parse_transfers_csv(result.stdout)] == ["111", "222"]
