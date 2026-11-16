# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from app.gam.validate import Email, FreeText, assert_in_tenant


def test_email_validation():
    assert Email(" A@Acme.com ") == "a@acme.com"
    assert isinstance(Email("a@acme.com"), str)
    for bad in ["a@acme", "a b@acme.com", "a@acme.com\n", "\na@acme.com", "a@acme.com,b@acme.com",
                "file@acme.com:x", "", "a@@acme.com", "a" * 246 + "@acme.com"]:
        with pytest.raises(ValueError):
            Email(bad)
    assert len(Email("a" * 245 + "@acme.com")) == 254
    with pytest.raises(ValueError):
        Email("a" * 246 + "@acme.com")  # 255 characters


def test_assert_in_tenant_rejects_lookalike():
    domains = ["acme.com"]
    assert_in_tenant(Email("a@acme.com"), domains)
    for bad in ["a@acme.com.evil.io", "a@evilacme.com", "a@sub.acme.com", "a@evil.io"]:
        with pytest.raises(ValueError):
            assert_in_tenant(Email(bad), domains)


def test_assert_in_tenant_subdomains_only_when_listed():
    assert_in_tenant(Email("a@eu.acme.com"), ["*.acme.com"])
    assert_in_tenant(Email("a@x.eu.acme.com"), ["*.acme.com"])
    with pytest.raises(ValueError):
        assert_in_tenant(Email("a@acme.com"), ["*.acme.com"])  # apex must be listed itself
    with pytest.raises(ValueError):
        assert_in_tenant(Email("a@evilacme.com"), ["*.acme.com"])
    with pytest.raises(ValueError):
        assert_in_tenant(Email("a@acme.com"), [])
    assert_in_tenant(Email("a@acme.com"), [" ACME.com "])


def test_free_text_is_single_argument_and_file_forms_rejected():
    text = 'line1\nline2 "q" $(rm -rf /)'
    assert FreeText(text) == text
    for form in ["file /etc/passwd", "FILE x", "  gdoc a@b.com x", "gcsdoc b/o", "gsheet x",
                 "gcsfile x", "url http://x", "textfile x", "htmlfile x", "ghtml x",
                 "gcshtml x", "file"]:
        with pytest.raises(ValueError):
            FreeText(form)
    FreeText("a" * 4000)
    with pytest.raises(ValueError):
        FreeText("a" * 10_000)
    with pytest.raises(ValueError):
        FreeText("x\x00y")
    ok = "Out of office; file a ticket instead"
    assert FreeText(ok) == ok
