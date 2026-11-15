# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration from GAMUT_* environment variables.

Each process has a role. Variables that only one role may hold are required for that
role and refused elsewhere: the web process must never hold the credential private key.

Errors are raised as SettingsError, whose message names variables only. Pydantic's own
ValidationError text can include the raw input (passwords, URLs with credentials), so it
is never allowed to escape from here.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "GAMUT_"


class SettingsError(Exception):
    """Invalid configuration. The message names variables, never their values."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="ignore")

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

    # Worker: where each job decrypts its tenant's GAM files (a tmpfs in Compose).
    job_dir: Path = Path("/run/gamut-jobs")

    source_url: str = "https://github.com/OWNER/gamut"
    gam_bin: str = "gam"

    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: SecretStr | None = None

    # Web: OpenID Connect sign-in (Google by default). Sign-in through OIDC is enabled
    # when the client id and secret are both set; the bootstrap admin works without it.
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_metadata_url: str = "https://accounts.google.com/.well-known/openid-configuration"
    # Web: external https URL of the panel (behind the TLS reverse proxy), for example
    # https://gamut.example.com. The OIDC redirect URI is <public_base_url>/api/auth/callback.
    public_base_url: str | None = None
    # Web: proxy addresses whose X-Forwarded-For is trusted (uvicorn forwarded_allow_ips);
    # the client address feeds the login rate limit.
    forwarded_allow_ips: str = "127.0.0.1"

    @property
    def oidc_enabled(self) -> bool:
        secret = self.oidc_client_secret
        return bool(self.oidc_client_id and secret and secret.get_secret_value())

    @model_validator(mode="after")
    def _role_requirements(self) -> Self:
        # SettingsError is not a ValueError, so pydantic lets it through unwrapped
        # (a wrapped error would print the whole input, secrets included).
        missing: list[str] = []
        if self.role == "web":
            if self.secret_key is None or not self.secret_key.get_secret_value():
                missing.append("GAMUT_SECRET_KEY")
            if not self.credential_public_key:
                missing.append("GAMUT_CREDENTIAL_PUBLIC_KEY")
            if self.credential_private_key_file is not None:
                raise SettingsError(
                    "role 'web' must not have GAMUT_CREDENTIAL_PRIVATE_KEY_FILE set; "
                    "only the worker may hold the credential private key"
                )
            if self.oidc_enabled and not self.public_base_url:
                missing.append("GAMUT_PUBLIC_BASE_URL")
        if self.role == "worker" and self.credential_private_key_file is None:
            missing.append("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE")
        if missing:
            raise SettingsError(f"role {self.role!r} requires: {', '.join(missing)}")
        return self


def load_settings(**overrides: Any) -> Settings:
    """Build Settings from the environment (plus overrides) with value-free errors."""
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        problems = "; ".join(
            f"{ENV_PREFIX}{'.'.join(str(p) for p in err['loc']).upper()}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False, include_context=False)
        )
    # Raised outside the except block so the original error (which holds the raw
    # input) is not kept as __context__ either.
    raise SettingsError(f"invalid configuration: {problems}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings, read once from the environment."""
    return load_settings()
