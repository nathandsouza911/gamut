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
    # No transfers: GAM 7.52.3 prints only the `id` column header (seen on a live domain).
    assert parse_transfers_csv("id\n") == []
    assert parse_transfers_csv("id") == []
    with pytest.raises(ValueError):
        parse_transfers_csv("ERROR: No Client Access allowed\n")
    with pytest.raises(ValueError):  # rows without the needed columns are still refused
        parse_transfers_csv("id\n111\n")


def test_list_transfers_through_runner(fake_gam, tmp_path):
    argv = list_transfers(Email("a@x.com"), Email("m@x.com"))
    fake_gam.scenario([{"match": ["print", "datatransfers"], "stdout": CSV}])
    result = run_gam(argv, tmp_path)
    assert [t.id for t in parse_transfers_csv(result.stdout)] == ["111", "222"]


def test_transfer_request_time_is_parsed_as_utc():
    from datetime import UTC, datetime, timedelta, timezone

    got = parse_transfers_csv(
        HEADER
        + "1,2026-11-15T10:00:00Z,a@x.com,m@x.com,pending,D,1,pending,\n"
        + "2,2026-11-15T12:00:00+02:00,a@x.com,m@x.com,pending,D,1,pending,\n"
        + "3,2026-11-15T10:00:00,a@x.com,m@x.com,pending,D,1,pending,\n"
        + "4,never,a@x.com,m@x.com,pending,D,1,pending,\n"
    )
    ten = datetime(2026, 11, 15, 10, tzinfo=UTC)
    assert [t.request_time for t in got] == [ten, ten, ten, None]
    assert got[1].request_time == datetime(2026, 11, 15, 12, tzinfo=timezone(timedelta(hours=2)))


def test_parse_user_groups_csv():
    from app.gam.parsers import parse_user_groups_csv

    csv_text = (
        "User,Group,Role,Status,Delivery\n"
        "a@x.com,Staff@x.com,MEMBER,ACTIVE,ALL_MAIL\n"
        "a@x.com,owners@x.com,OWNER,ACTIVE,\n"
    )
    assert parse_user_groups_csv(csv_text) == [
        {"group": "staff@x.com", "role": "MEMBER", "status": "ACTIVE", "delivery": "ALL_MAIL"},
        {"group": "owners@x.com", "role": "OWNER", "status": "ACTIVE", "delivery": ""},
    ]
    assert parse_user_groups_csv("") == []
    assert parse_user_groups_csv("User,Group,Role,Status,Delivery\n") == []
    with pytest.raises(ValueError):
        parse_user_groups_csv("ERROR: 404: notFound\n")


def test_parse_user_info_json():
    from app.gam.parsers import parse_user_info_json

    info = parse_user_info_json('{"id": "42", "primaryEmail": "A@x.com", "suspended": true}\n')
    assert info.id == "42" and info.primary_email == "a@x.com" and info.suspended is True
    noisy = 'Getting user\n{"primaryEmail": "b@x.com", "suspended": false}\n'
    info = parse_user_info_json(noisy)
    assert info.id is None and info.suspended is False and info.customer_id is None
    with_customer = parse_user_info_json('{"primaryEmail": "c@x.com", "customerId": "C04jm7qkb"}')
    assert with_customer.customer_id == "C04jm7qkb"
    with pytest.raises(ValueError):
        parse_user_info_json("User: a@x.com\n")
