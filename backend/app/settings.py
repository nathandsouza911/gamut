# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration from GAMUT_* environment variables.

Each process has a role. Variables that only one role may hold are required for that
role and nowhere else: the web process never needs the credential private key.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GAMUT_", extra="ignore")

    role: Literal["web", "worker", "cli"] = "cli"

    # App role (gamut_app): what web, worker and CLI connect as.
    database_url: str
    # Owner role (gamut_owner): used by Alembic migrations only.
    migrate_database_url: str | None = None

    # Web: signs sessions, CSRF tokens and preview tokens.
    secret_key: SecretStr | None = None
    # Web: public half of the credential-wrapping key pair (encrypt only).
    credential_public_key: str | None = None
    # Worker only: path of the private key file (mounted as a Compose secret).
    credential_private_key_file: Path | None = None

    source_url: str = "https://github.com/OWNER/gamut"
    gam_bin: str = "gam"

    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: SecretStr | None = None

    @model_validator(mode="after")
    def _role_requirements(self) -> Self:
        missing: list[str] = []
        if self.role == "web":
            if self.secret_key is None or not self.secret_key.get_secret_value():
                missing.append("GAMUT_SECRET_KEY")
            if not self.credential_public_key:
                missing.append("GAMUT_CREDENTIAL_PUBLIC_KEY")
        if self.role == "worker" and self.credential_private_key_file is None:
            missing.append("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE")
        if missing:
            raise ValueError(f"role {self.role!r} requires: {', '.join(missing)}")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings, read once from the environment."""
    return Settings()  # type: ignore[call-arg]  # required fields come from the environment
