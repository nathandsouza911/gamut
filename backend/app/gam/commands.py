# SPDX-License-Identifier: AGPL-3.0-only
"""Typed GAM command builders. Each returns an argument list without the leading `gam`.

Syntax was verified against the GAM wiki and the pinned gam7 7.52.3 source; see
docs/decisions.md. User input fills fixed positions only and never becomes part of a string
that is split later.
"""

from app.gam.validate import Email, FreeText, GoogleUserId

__all__ = [
    "Email", "FreeText", "GoogleUserId", "check_service_account", "create_drive_transfer",
    "delete_user", "delete_user_by_id", "deprovision", "info_domain", "info_user",
    "info_user_by_id", "list_transfers", "print_user_groups",
    "redact_argv", "remove_from_all_groups", "reset_password_random", "signout",
    "suspend_user", "vacation_on",
]

REDACTED = "[redacted]"


def _email(value: Email) -> str:
    if not isinstance(value, Email):
        raise TypeError("expected a validated Email")
    return str(value)


def _text(value: FreeText) -> str:
    if not isinstance(value, FreeText):
        raise TypeError("expected validated FreeText")
    return str(value)


def suspend_user(e: Email) -> list[str]:
    return ["update", "user", _email(e), "suspended", "on"]


def reset_password_random(e: Email) -> list[str]:
    """GAM generates the password; it is not printed unless `logpassword` is given."""
    return ["update", "user", _email(e), "password", "random"]


def signout(e: Email) -> list[str]:
    return ["user", _email(e), "signout"]


def deprovision(e: Email) -> list[str]:
    """Deletes app passwords and OAuth tokens; backup codes only if not suspended."""
    return ["user", _email(e), "deprovision"]


def vacation_on(e: Email, subject: FreeText, message: FreeText) -> list[str]:
    if not message:
        raise ValueError("auto-reply message must not be empty")
    return ["user", _email(e), "vacation", "on", "subject", _text(subject),
            "message", _text(message)]


def print_user_groups(e: Email) -> list[str]:
    """CSV on stdout, columns User,Group,Role,Status,Delivery."""
    return ["user", _email(e), "print", "groups"]


def remove_from_all_groups(e: Email) -> list[str]:
    return ["user", _email(e), "delete", "groups"]


def create_drive_transfer(e: Email, manager: Email) -> list[str]:
    return ["create", "datatransfer", _email(e), "gdrive", _email(manager)]


def list_transfers(old_owner: Email, new_owner: Email) -> list[str]:
    """CSV of data transfers from old_owner to new_owner (see app.gam.parsers).

    One row per application per transfer, oldest request first. Used both to find a
    transfer after `create_drive_transfer` and to poll its overallTransferStatusCode.
    """
    return ["print", "datatransfers", "olduser", _email(old_owner), "newuser", _email(new_owner)]


def info_user(e: Email) -> list[str]:
    """One JSON object on stdout. `quick` skips the group, license and schema lookups."""
    return ["info", "user", _email(e), "quick", "formatjson"]


def delete_user(e: Email) -> list[str]:
    return ["delete", "user", _email(e)]


def _uid(value: GoogleUserId) -> str:
    if not isinstance(value, GoogleUserId):
        raise TypeError("expected a validated GoogleUserId")
    return f"uid:{value}"


def info_user_by_id(uid: GoogleUserId) -> list[str]:
    """`info user uid:<id>`: the account with this immutable id, whatever its address.

    gam7 7.52.3: `<UserItem>` accepts `uid:<id>` (normalizeEmailAddressOrUID strips the
    prefix and passes the id as the Directory API userKey).
    """
    return ["info", "user", _uid(uid), "quick", "formatjson"]


def delete_user_by_id(uid: GoogleUserId) -> list[str]:
    """`delete user uid:<id>`: deletes exactly that account, never whoever has the address."""
    return ["delete", "user", _uid(uid)]


def info_domain() -> list[str]:
    """Read-only customer/domain lookup (one JSON object): the health check's directory call."""
    return ["info", "domain", "formatjson"]


def check_service_account(e: Email) -> list[str]:
    """Prints PASS/FAIL per scope; exit code 10 when scopes are not authorized."""
    return ["user", _email(e), "check", "serviceaccount"]


def redact_argv(args: list[str]) -> list[str]:
    """Copy of `args` safe to store: subject and message values and passwords are removed.

    The value after `subject` or `message` is always replaced; the value after `password`
    is replaced unless it is `random`. Keywords match case-insensitively, as GAM does.
    """
    out = list(args)
    for i in range(len(out) - 1):
        keyword = args[i].lower()
        if keyword in ("subject", "message"):
            out[i + 1] = REDACTED
        elif keyword == "password" and args[i + 1].lower() != "random":
            out[i + 1] = REDACTED
    return out
