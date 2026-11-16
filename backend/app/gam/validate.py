# SPDX-License-Identifier: AGPL-3.0-only
"""Input types for GAM arguments: strict email addresses and safe free text."""

import re
from collections.abc import Iterable
from typing import Self

_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+")
EMAIL_MAX = 254
FREE_TEXT_MAX = 4000

# GAM value forms that read text from somewhere else. Confirmed in the pinned gam7 source
# (SORF_FILE_ARGUMENTS and SORF_SIG_ARGUMENTS in gam/__init__.py): file, textfile,
# htmlfile (local file), gdoc, ghtml (Google Doc), gcsdoc, gcshtml (Cloud Storage).
# gsheet, gcsfile and url are other GAM data-source prefixes, kept as a precaution.
# After `message`/`subject` GAM takes the next argument literally, so these are
# defence in depth: the text is rejected rather than relying on that.
FILE_REFERENCE_KEYWORDS = frozenset({
    "file", "textfile", "htmlfile", "gdoc", "ghtml", "gcsdoc", "gcshtml",
    "gsheet", "gcsfile", "url",
})


class Email(str):
    """A validated email address: trimmed (spaces only), lowercased, strict pattern."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str):
            raise TypeError("email must be a string")
        # Only spaces are trimmed; a trailing newline or tab makes the address invalid.
        cleaned = value.strip(" ").lower()
        if len(cleaned) > EMAIL_MAX or not _EMAIL_RE.fullmatch(cleaned):
            raise ValueError("not a valid email address")
        return super().__new__(cls, cleaned)


_DOMAIN_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


class DomainName(str):
    """A validated DNS domain name: trimmed (spaces only), lowercased, at least one dot."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str):
            raise TypeError("domain must be a string")
        cleaned = value.strip(" ").lower()
        if not _DOMAIN_RE.fullmatch(cleaned):
            raise ValueError("not a valid domain name")
        return super().__new__(cls, cleaned)


_GOOGLE_ID_RE = re.compile(r"[0-9A-Za-z]{1,64}")


_CUSTOMER_ID_RE = re.compile(r"C[0-9a-z]{6,12}")


class CustomerId(str):
    """A Google Workspace customer id as shown in the Admin console (for example C04jm7qkb).

    A capital C, then 6 to 12 lowercase letters or digits. `my_customer` is refused:
    GAM's delegated admin service account mode needs the real id.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str):
            raise TypeError("customer id must be a string")
        # All surrounding whitespace (pasted ids often carry a tab or newline).
        cleaned = value.strip()
        if not _CUSTOMER_ID_RE.fullmatch(cleaned):
            raise ValueError("not a valid customer id (for example C04jm7qkb)")
        return super().__new__(cls, cleaned)


class GoogleUserId(str):
    """A Google Workspace user's immutable id (the `id` of `info user ... formatjson`).

    Google's ids are long digit strings; letters are allowed defensively. Nothing else
    (no spaces, `@`, `:` or newlines), so it can only fill the id in `uid:<id>`.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str):
            raise TypeError("user id must be a string")
        if not _GOOGLE_ID_RE.fullmatch(value):
            raise ValueError("not a valid Google user id")
        return super().__new__(cls, value)


class FreeText(str):
    """Text passed to GAM as exactly one argument (for example an auto-reply message)."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        if not isinstance(value, str):
            raise TypeError("text must be a string")
        if len(value) > FREE_TEXT_MAX:
            raise ValueError(f"text is longer than {FREE_TEXT_MAX} characters")
        if "\x00" in value:
            raise ValueError("text must not contain NUL characters")
        words = value.split(None, 1)
        first = words[0].lower().replace("_", "") if words else ""
        if first in FILE_REFERENCE_KEYWORDS:
            raise ValueError(f"text must not start with the GAM file reference {first!r}")
        return super().__new__(cls, value)


def assert_in_tenant(email: Email, domains: Iterable[str]) -> None:
    """Raise ValueError unless the address's domain is one of the tenant's domains.

    The domain after "@" must equal a listed domain exactly. A subdomain matches only
    when the list says so with a wildcard entry such as "*.acme.com" (which does not
    cover acme.com itself). There is no suffix matching.
    """
    domain = email.rsplit("@", 1)[1]
    for entry in domains:
        listed = entry.strip().lower()
        if listed.startswith("*."):
            if domain.endswith(listed[1:]) and len(domain) > len(listed) - 1:
                return
        elif domain == listed:
            return
    raise ValueError("email domain does not belong to this tenant")
