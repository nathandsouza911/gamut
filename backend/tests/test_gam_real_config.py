# SPDX-License-Identifier: AGPL-3.0-only
"""The real GAM writes a DASA gam.cfg whose every path setting stays inside the job directory.

Runs the installed gam7 (not the fake) through app.gam.runner.prepare_config_dir, with the
runner's environment. Skipped when no gam executable is installed (the dev image has one).
Path resolution follows gam7 7.52.3 (gam/__init__.py _getCfgDirectory / _getCfgFile):
relative directories resolve against the gam.cfg directory (GAMCFGDIR), relative files
against config_dir; an empty gmail_cse_* or input_dir means "not used" / the current
directory (the runner's cwd is the job directory); an empty cacerts_pem means GAM's own
bundled file and an empty cmdlog means no command log.
"""

import configparser
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.gam.commands import CustomerId, DomainName, Email, dasa_config
from app.gam.runner import SAFE_PATH, prepare_config_dir

DIRECTORY_SETTINGS = {
    "cache_dir", "config_dir", "drive_dir", "gmail_cse_incert_dir", "gmail_cse_inkey_dir",
    "input_dir",
}
FILE_SETTINGS = {
    "cacerts_pem", "client_secrets_json", "cmdlog", "extra_args", "oauth2_txt",
    "oauth2service_json",
}
# Empty means "not used" (or GAM's own read-only file for cacerts_pem), never a job path.
MAY_BE_EMPTY = {"cacerts_pem", "cmdlog", "extra_args", "gmail_cse_incert_dir",
                "gmail_cse_inkey_dir"}


def _real_gam() -> str | None:
    configured = os.environ.get("GAMUT_GAM_BIN", "gam")
    return shutil.which(configured, path=SAFE_PATH)


@pytest.fixture
def real_gam(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    from app.settings import get_settings

    binary = _real_gam()
    if binary is None:
        pytest.skip(f"no gam executable on {SAFE_PATH} (GAMUT_GAM_BIN); install gam7 to run")
    monkeypatch.setenv("GAMUT_GAM_BIN", binary)
    monkeypatch.setenv("GAMUT_ROLE", "cli")
    monkeypatch.setenv(
        "GAMUT_DATABASE_URL",
        os.environ.get("GAMUT_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x"),
    )
    get_settings.cache_clear()
    yield binary
    get_settings.cache_clear()


def test_path_setting_list_matches_gam() -> None:
    glcfg = pytest.importorskip("gam.gamlib.glcfg", reason="gam7 is not installed")
    typed = {
        name for name, info in glcfg.VAR_INFO.items()
        if info[glcfg.VAR_TYPE] in (glcfg.TYPE_DIRECTORY, glcfg.TYPE_FILE)
    }
    assert typed == DIRECTORY_SETTINGS | FILE_SETTINGS


def _resolve(name: str, value: str, cfg_dir: Path, config_dir: Path) -> Path | None:
    if not value:
        assert name in MAY_BE_EMPTY or name == "input_dir", f"{name} is empty"
        return None if name != "input_dir" else cfg_dir
    path = Path(value)
    if path.is_absolute():
        return path
    if name in DIRECTORY_SETTINGS:
        return cfg_dir / path  # relative directories: GAMCFGDIR (input_dir "." = cwd too)
    return config_dir / path


def test_dasa_gam_cfg_paths_stay_in_job_dir(real_gam: str, tmp_path: Path) -> None:
    cfg_dir = tmp_path / "job"
    cfg_dir.mkdir()
    prepare_config_dir(cfg_dir, dasa_config(
        Email("admin@acme.test"), CustomerId("C04jm7qkb"), DomainName("acme.test")
    ))

    parser = configparser.ConfigParser(interpolation=None)
    parser.read(cfg_dir / "gam.cfg", encoding="utf-8")
    values = parser["DEFAULT"]
    assert values["enable_dasa"] == "true"
    assert values["customer_id"] == "C04jm7qkb"
    assert values["domain"] == "acme.test"
    assert values["admin_email"] == "admin@acme.test"

    root = cfg_dir.resolve()
    config_dir = Path(values["config_dir"])
    assert config_dir.is_absolute() and config_dir.resolve() == root
    for name in sorted(DIRECTORY_SETTINGS | FILE_SETTINGS):
        assert name in values, f"gam.cfg has no {name}"
        resolved = _resolve(name, values[name].strip("'\""), cfg_dir, config_dir)
        if resolved is not None:
            assert resolved.resolve().is_relative_to(root), f"{name} is outside the job dir"
    for name, value in values.items():  # and any other absolute path GAM wrote
        if value.startswith("/"):
            assert Path(value).resolve().is_relative_to(root), f"{name} is outside the job dir"
