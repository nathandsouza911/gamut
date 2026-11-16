# SPDX-License-Identifier: AGPL-3.0-only
"""The only place GAM is started. Never uses a shell; the environment is not inherited."""

import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.settings import get_settings

# Fixed rather than inherited: the dev and runtime images (python:3.12-slim) keep python3
# and gam under /usr/local/bin.
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
TIMEOUT_EXIT_CODE = 124
NOT_FOUND_EXIT_CODE = 127


@dataclass(frozen=True)
class GamResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool


def _cap(data: bytes | None, limit: int) -> tuple[str, bool]:
    # NUL bytes are dropped: PostgreSQL text and jsonb cannot store them.
    text = (data or b"").decode("utf-8", errors="replace").replace("\x00", "")
    if len(text) > limit:
        return text[:limit], True
    return text, False


def run_gam(
    args: list[str], cfg_dir: Path, *, timeout_s: int = 300, max_output: int = 256_000
) -> GamResult:
    """Run GAM (setting GAMUT_GAM_BIN) with `args`. Never logs the arguments.

    The environment is exactly PATH, HOME, GAMCFGDIR and TMPDIR (all the config
    directory) and LANG. TMPDIR keeps GAM's temporary files inside the job directory,
    which is removed afterwards (the worker's root filesystem is read-only). On timeout
    the process group is killed; the result has timed_out=True and exit code 124.
    Each stream is capped at `max_output` characters.
    """
    binary = get_settings().gam_bin
    cfg = str(cfg_dir)
    env = {"PATH": SAFE_PATH, "HOME": cfg, "GAMCFGDIR": cfg, "TMPDIR": cfg, "LANG": "C.UTF-8"}
    try:
        proc = subprocess.Popen(  # noqa: S603 - argument list, shell=False
            [binary, *args],
            env=env,
            cwd=cfg,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        return GamResult(NOT_FOUND_EXIT_CODE, "", f"cannot start gam: {exc.strerror}", False, False)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    stdout, cut_out = _cap(out, max_output)
    stderr, cut_err = _cap(err, max_output)
    exit_code = TIMEOUT_EXIT_CODE if timed_out else proc.returncode
    return GamResult(exit_code, stdout, stderr, timed_out, cut_out or cut_err)


def prepare_config_dir(cfg_dir: Path) -> None:
    """Let GAM initialise a fresh config directory before any real command runs there.

    In a new GAMCFGDIR, GAM 7.52.3 creates gam.cfg and gamcache and prints "Created: ..."
    and "Config File: ..., Initialized" on stdout, mixed into the first command's output,
    which then no longer parses (seen on a live domain with `print datatransfers`).
    `gam version` makes no API call; its output, and any failure, is discarded: a broken
    GAM fails the real command next.
    """
    run_gam(["version"], cfg_dir, timeout_s=60, max_output=10_000)


_version_cache: dict[str, str] = {}


def clear_gam_version_cache() -> None:
    _version_cache.clear()


def gam_version() -> str:
    """First line of `gam version`, for example `GAM 7.52.03 - https://...`.

    Run once per process and GAM binary (an empty answer is not cached), in a temporary
    directory under GAMUT_JOB_DIR: the worker has no writable default temp directory.
    """
    settings = get_settings()
    cached = _version_cache.get(settings.gam_bin)
    if cached:
        return cached
    base = settings.job_dir
    base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="version-", dir=base))
    try:
        result = run_gam(["version"], tmp, timeout_s=60, max_output=10_000)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    version = next((ln.strip() for ln in result.stdout.splitlines() if ln.strip()), "")
    if version:
        _version_cache[settings.gam_bin] = version
    return version
