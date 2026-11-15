# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from app.settings import Settings, SettingsError, load_settings

DB = "postgresql+psycopg://gamut_app:pw@db:5432/gamut"
SECRETS = ("ADMINPW-9f3a", "DBPASS-71c2", "SECRETKEY-5e0d")


@pytest.fixture
def secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment full of secret values; no error text may contain any of them."""
    monkeypatch.setenv("GAMUT_DATABASE_URL", f"postgresql+psycopg://gamut_app:{SECRETS[1]}@db/g")
    monkeypatch.setenv(
        "GAMUT_MIGRATE_DATABASE_URL", f"postgresql+psycopg://gamut_owner:{SECRETS[1]}@db/g"
    )
    monkeypatch.setenv("GAMUT_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("GAMUT_BOOTSTRAP_ADMIN_PASSWORD", SECRETS[0])


def _assert_no_secrets(exc: BaseException) -> None:
    text = f"{exc}\n{exc!r}\n{exc.__cause__!r}\n{exc.__context__!r}"
    for secret in SECRETS:
        assert secret not in text


def test_web_requires_secret_key() -> None:
    with pytest.raises(SettingsError, match="GAMUT_SECRET_KEY"):
        Settings(role="web", database_url=DB, credential_public_key="pub")


def test_worker_requires_private_key_file() -> None:
    with pytest.raises(SettingsError, match="GAMUT_CREDENTIAL_PRIVATE_KEY_FILE"):
        Settings(role="worker", database_url=DB)


def test_web_refuses_private_key_file() -> None:
    with pytest.raises(SettingsError, match="GAMUT_CREDENTIAL_PRIVATE_KEY_FILE") as excinfo:
        Settings(
            role="web",
            database_url=DB,
            secret_key=SECRETS[2],
            credential_public_key="pub",
            credential_private_key_file="/run/secrets/credential_private_key",
        )
    _assert_no_secrets(excinfo.value)
    assert "/run/secrets" not in str(excinfo.value)


def test_role_error_does_not_leak_secrets(
    secret_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GAMUT_ROLE", "web")
    monkeypatch.setenv("GAMUT_CREDENTIAL_PUBLIC_KEY", "pub")

    with pytest.raises(SettingsError, match="GAMUT_SECRET_KEY") as excinfo:
        load_settings()
    _assert_no_secrets(excinfo.value)


def test_web_private_key_error_does_not_leak_secrets(
    secret_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GAMUT_ROLE", "web")
    monkeypatch.setenv("GAMUT_SECRET_KEY", SECRETS[2])
    monkeypatch.setenv("GAMUT_CREDENTIAL_PUBLIC_KEY", "pub")
    monkeypatch.setenv("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE", "/run/secrets/k")

    with pytest.raises(SettingsError, match="GAMUT_CREDENTIAL_PRIVATE_KEY_FILE") as excinfo:
        load_settings()
    _assert_no_secrets(excinfo.value)


def test_field_validation_error_does_not_leak_secrets(
    secret_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GAMUT_DATABASE_URL")
    monkeypatch.setenv("GAMUT_ROLE", "bogus")

    with pytest.raises(SettingsError) as excinfo:
        load_settings()
    message = str(excinfo.value)
    assert "GAMUT_DATABASE_URL" in message
    assert "GAMUT_ROLE" in message
    _assert_no_secrets(excinfo.value)


def test_reads_prefixed_env_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAMUT_DATABASE_URL", DB)
    monkeypatch.setenv("GAMUT_ROLE", "cli")

    settings = load_settings()

    assert settings.database_url == DB
    assert settings.role == "cli"
    assert settings.gam_bin == "gam"
    assert settings.source_url == "https://github.com/OWNER/gamut"


def test_web_with_oidc_requires_public_base_url() -> None:
    with pytest.raises(SettingsError, match="GAMUT_PUBLIC_BASE_URL"):
        Settings(
            role="web", database_url=DB, secret_key="k", credential_public_key="pub",
            oidc_client_id="id", oidc_client_secret="SECRETKEY-5e0d",
        )
    without_oidc = Settings(role="web", database_url=DB, secret_key="k", credential_public_key="p")
    assert not without_oidc.oidc_enabled


def test_cli_web_reports_missing_settings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.cli import main

    monkeypatch.setenv("GAMUT_DATABASE_URL", DB)
    monkeypatch.delenv("GAMUT_SECRET_KEY", raising=False)
    assert main(["web"]) == 2
    assert "GAMUT_SECRET_KEY" in capsys.readouterr().err
