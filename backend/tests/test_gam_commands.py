# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from app.gam import commands as c
from app.gam.commands import Email, redact_argv
from app.gam.validate import FreeText

E = Email("a@x.com")


def test_builders_match_wiki():
    assert c.suspend_user(E) == ["update", "user", "a@x.com", "suspended", "on"]
    assert c.reset_password_random(E) == ["update", "user", "a@x.com", "password", "random"]
    assert c.signout(E) == ["user", "a@x.com", "signout"]
    assert c.deprovision(E) == ["user", "a@x.com", "deprovision"]
    assert c.vacation_on(E, FreeText("Away"), FreeText("Back soon")) == [
        "user", "a@x.com", "vacation", "on", "subject", "Away", "message", "Back soon"]
    assert c.print_user_groups(E) == ["user", "a@x.com", "print", "groups"]
    assert c.remove_from_all_groups(E) == ["user", "a@x.com", "delete", "groups"]
    assert c.create_drive_transfer(E, Email("m@x.com")) == [
        "create", "datatransfer", "a@x.com", "gdrive", "m@x.com"]
    assert c.list_transfers(E, Email("m@x.com")) == [
        "print", "datatransfers", "olduser", "a@x.com", "newuser", "m@x.com"]
    assert c.info_user(E) == ["info", "user", "a@x.com", "quick", "formatjson"]
    assert c.delete_user(E) == ["delete", "user", "a@x.com"]
    assert c.info_domain() == ["info", "domain", "formatjson"]
    assert c.check_service_account(E) == ["user", "a@x.com", "check", "serviceaccount"]


def test_builders_reject_plain_strings():
    with pytest.raises(TypeError):
        c.suspend_user("a@x.com")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.vacation_on(E, "s", "m")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.create_drive_transfer(E, "m@x.com")  # type: ignore[arg-type]


def test_vacation_requires_message():
    with pytest.raises(ValueError):
        c.vacation_on(E, FreeText("Away"), FreeText(""))


def test_redact_argv():
    argv = c.vacation_on(E, FreeText("Secret subject"), FreeText("Secret body"))
    assert redact_argv(argv) == [
        "user", "a@x.com", "vacation", "on", "subject", "[redacted]", "message", "[redacted]"]
    assert argv[5] == "Secret subject"  # input untouched
    assert redact_argv(["update", "user", "a@x.com", "password", "hunter2"])[-1] == "[redacted]"
    assert redact_argv(["update", "user", "a@x.com", "password", "RANDOM"])[-1] == "RANDOM"
    assert redact_argv(c.reset_password_random(E)) == c.reset_password_random(E)
    assert redact_argv(["user", "a@x.com", "vacation", "on", "Subject", "s", "MESSAGE", "m"])[
        5::2] == ["[redacted]", "[redacted]"]
    assert redact_argv(["user", "a@x.com", "message"]) == ["user", "a@x.com", "message"]
