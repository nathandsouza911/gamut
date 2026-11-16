# SPDX-License-Identifier: AGPL-3.0-only
import threading
import uuid

import psycopg.errors
import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from app import cli
from app.audit.chain import append_event, redact, verify_chain
from app.models import AuditEvent


def _append(session: Session, n: int) -> None:
    for i in range(n):
        append_event(
            session,
            actor="tech@example.com",
            tenant_id=uuid.uuid4(),
            action="offboard.step",
            target=f"user{i}@example.com",
            details={"step": i, "argv": ["gam", "info", "user"], "exit_code": 0},
        )


def test_chain_verifies_after_appends(app_session: Session) -> None:
    _append(app_session, 3)
    app_session.commit()

    result = verify_chain(app_session)

    assert result.ok is True
    assert result.checked == 3
    assert result.first_broken_id is None
    assert result.reason is None


def test_first_event_links_to_genesis_and_next_links_to_it(app_session: Session) -> None:
    first = append_event(
        app_session, actor="system", tenant_id=None, action="a", target=None, details={}
    )
    second = append_event(
        app_session, actor="system", tenant_id=None, action="b", target=None, details={}
    )
    app_session.commit()

    assert first.prev_hash == "0" * 64
    assert second.prev_hash == first.hash
    assert len(first.hash) == 64


def test_hand_edit_breaks_chain(
    app_session: Session, owner_engine: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    _append(app_session, 3)
    app_session.commit()
    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE audit_events SET target='x' WHERE id=2"))

    result = verify_chain(app_session)

    assert result.ok is False
    assert result.first_broken_id == 2
    assert result.reason == "hash mismatch"
    assert result.checked == 1
    assert cli.main(["verify-audit"]) == 1
    assert capsys.readouterr().out.strip() == "BROKEN at event 2: hash mismatch"


def test_rewritten_hash_is_caught(app_session: Session, owner_engine: Engine) -> None:
    _append(app_session, 3)
    app_session.commit()
    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE audit_events SET hash=repeat('a', 64) WHERE id=2"))

    result = verify_chain(app_session)

    assert result.ok is False
    assert result.first_broken_id == 2
    assert result.reason == "hash mismatch"


def test_deleted_event_breaks_next_link(app_session: Session, owner_engine: Engine) -> None:
    _append(app_session, 3)
    app_session.commit()
    with owner_engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE id=2"))

    result = verify_chain(app_session)

    assert result.ok is False
    assert result.first_broken_id == 3
    assert result.reason == "prev_hash mismatch"


def test_cli_reports_ok(app_session: Session, capsys: pytest.CaptureFixture[str]) -> None:
    _append(app_session, 2)
    app_session.commit()

    assert cli.main(["verify-audit"]) == 0
    assert capsys.readouterr().out.strip() == "OK 2 events"


@pytest.mark.parametrize(
    "statement", ["UPDATE audit_events SET target='x'", "DELETE FROM audit_events"]
)
def test_app_role_cannot_update_or_delete(app_session: Session, statement: str) -> None:
    _append(app_session, 1)
    app_session.commit()

    with pytest.raises(ProgrammingError) as excinfo:
        app_session.execute(text(statement))
    assert isinstance(excinfo.value.orig, psycopg.errors.InsufficientPrivilege)
    app_session.rollback()


def test_app_role_cannot_truncate_audit_events(app_session: Session) -> None:
    with pytest.raises(ProgrammingError) as excinfo:
        app_session.execute(text("TRUNCATE audit_events"))
    assert isinstance(excinfo.value.orig, psycopg.errors.InsufficientPrivilege)
    app_session.rollback()


def test_concurrent_appends_keep_chain_valid(app_engine: Engine) -> None:
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def worker(n: int) -> None:
        try:
            barrier.wait()
            for i in range(25):
                with Session(app_engine) as session:
                    append_event(
                        session,
                        actor=f"worker-{n}",
                        tenant_id=None,
                        action="concurrent",
                        target=str(i),
                        details={"n": n, "i": i},
                    )
                    session.commit()
        except BaseException as exc:  # re-raised in the main thread via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []

    with Session(app_engine) as session:
        result = verify_chain(session)
        count = session.scalar(select(func.count()).select_from(AuditEvent))
    assert count == 200
    assert result.ok is True
    assert result.checked == 200


def test_redact_removes_secrets_and_bodies() -> None:
    details = {
        "Password": "hunter2",
        "access_TOKEN": "t",
        "client_secret": "s",
        "privateKey": "k",
        "message": "out of office",
        "Body": "<p>hi</p>",
        "target": "a@example.com",
        "nested": {"refresh_token": "r", "keep": 1, "deeper": [{"api_key": "x", "ok": True}]},
        "args": ["gam", "update", "user"],
    }

    assert redact(details) == {
        "Password": "[redacted]",
        "access_TOKEN": "[redacted]",
        "client_secret": "[redacted]",
        "privateKey": "[redacted]",
        "message": "[redacted]",
        "Body": "[redacted]",
        "target": "a@example.com",
        "nested": {
            "refresh_token": "[redacted]",
            "keep": 1,
            "deeper": [{"api_key": "[redacted]", "ok": True}],
        },
        "args": ["gam", "update", "user"],
    }
    assert details["Password"] == "hunter2"  # input is not mutated


def test_append_event_stores_redacted_details(app_session: Session) -> None:
    event = append_event(
        app_session,
        actor="a",
        tenant_id=None,
        action="x",
        target=None,
        details={"password": "hunter2", "step": 1},
    )
    app_session.commit()

    stored = app_session.execute(
        text("SELECT details FROM audit_events WHERE id = :id"), {"id": event.id}
    ).scalar_one()
    assert stored == {"password": "[redacted]", "step": 1}
    assert verify_chain(app_session).ok is True
