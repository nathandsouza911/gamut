# SPDX-License-Identifier: AGPL-3.0-only
"""The only place GAM is started. Never uses a shell; the environment is not inherited."""

import os
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
    text = (data or b"").decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit], True
    return text, False


def run_gam(
    args: list[str], cfg_dir: Path, *, timeout_s: int = 300, max_output: int = 256_000
) -> GamResult:
    """Run GAM (setting GAMUT_GAM_BIN) with `args`. Never logs the arguments.

    The environment is exactly PATH, HOME and GAMCFGDIR (both the config directory) and
    LANG. On timeout the process group is killed; the result has timed_out=True and exit
    code 124. Each stream is capped at `max_output` characters.
    """
    binary = get_settings().gam_bin
    cfg = str(cfg_dir)
    env = {"PATH": SAFE_PATH, "HOME": cfg, "GAMCFGDIR": cfg, "LANG": "C.UTF-8"}
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


def gam_version() -> str:
    """First line of `gam version`, for example `GAM 7.52.3 - https://...`."""
    with tempfile.TemporaryDirectory(prefix="gamut-ver-") as tmp:
        result = run_gam(["version"], Path(tmp), timeout_s=60, max_output=10_000)
    for line in result.stdout.splitlines():
        if line.strip():
            return line.strip()
    return ""
