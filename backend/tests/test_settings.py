# SPDX-License-Identifier: AGPL-3.0-only
import pytest
from pydantic import ValidationError

from app.settings import Settings

DB = "postgresql+psycopg://gamut_app:pw@db:5432/gamut"


def test_web_requires_secret_key() -> None:
    with pytest.raises(ValidationError, match="GAMUT_SECRET_KEY"):
        Settings(role="web", database_url=DB, credential_public_key="pub")


def test_worker_requires_private_key_file() -> None:
    with pytest.raises(ValidationError, match="GAMUT_CREDENTIAL_PRIVATE_KEY_FILE"):
        Settings(role="worker", database_url=DB)


def test_reads_prefixed_env_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAMUT_DATABASE_URL", DB)
    monkeypatch.setenv("GAMUT_ROLE", "cli")

    settings = Settings()

    assert settings.database_url == DB
    assert settings.role == "cli"
    assert settings.gam_bin == "gam"
    assert settings.source_url == "https://github.com/OWNER/gamut"
