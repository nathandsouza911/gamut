# SPDX-License-Identifier: AGPL-3.0-only
import time

from app.gam.commands import Email, vacation_on
from app.gam.runner import GamResult, gam_version, prepare_config_dir, run_gam
from app.gam.validate import FreeText


def test_runner_passes_args_verbatim_and_isolates_env(fake_gam, tmp_path, monkeypatch):
    monkeypatch.setenv("GAMUT_SECRET_KEY", "must-not-leak")
    monkeypatch.setenv("SOME_PARENT_VAR", "x")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "oauth2service.json").write_text("{}")
    fake_gam.scenario([{"match": ["info"], "stdout": "hello\n"}])
    args = ["info", "user", "a b@x.com", "--flag=$(x)", "", "é"]
    result = run_gam(args, cfg)
    assert result == GamResult(0, "hello\n", "", False, False)
    (call,) = fake_gam.calls()
    assert call["argv"] == args
    assert call["env"]["GAMCFGDIR"] == str(cfg)
    assert call["env"]["files"] == ["oauth2service.json"]
    keys = set(call["env"]["keys"])
    assert not any(k.startswith("GAMUT_") or k == "SOME_PARENT_VAR" for k in keys)
    assert keys == {"PATH", "HOME", "GAMCFGDIR", "LANG", "TMPDIR"}
    # GAM's temporary files (Python's TemporaryFile) go into the job directory, which
    # is removed afterwards; the worker's root filesystem is read-only.
    assert call["env"]["TMPDIR"] == str(cfg)


def test_runner_reports_nonzero_exit_and_stderr(fake_gam, tmp_path):
    fake_gam.scenario([{"match": [], "exit": 3, "stdout": "o", "stderr": "e"}])
    r = run_gam(["x"], tmp_path)
    assert (r.exit_code, r.stdout, r.stderr, r.timed_out) == (3, "o", "e", False)


def test_runner_timeout(fake_gam, tmp_path):
    fake_gam.scenario([{"match": ["slow"], "sleep": 5}])
    start = time.monotonic()
    r = run_gam(["slow"], tmp_path, timeout_s=1)
    assert time.monotonic() - start < 4
    assert r.timed_out is True
    assert r.exit_code != 0


def test_runner_caps_output(fake_gam, tmp_path):
    fake_gam.scenario([{"match": [], "stdout_bytes": 1_000_000}])
    r = run_gam(["big"], tmp_path, max_output=1000)
    assert r.truncated is True
    assert len(r.stdout) <= 1000


def test_runner_missing_binary(fake_gam, tmp_path, monkeypatch):
    from app.settings import get_settings

    monkeypatch.setenv("GAMUT_GAM_BIN", str(tmp_path / "nope"))
    get_settings.cache_clear()
    r = run_gam(["x"], tmp_path)
    assert r.exit_code == 127 and r.timed_out is False


def test_gam_version(fake_gam, job_dir):
    assert gam_version() == "GAM 7.x.y - fake"
    assert fake_gam.calls() == []
    assert list(job_dir.iterdir()) == []  # its temporary directory is gone


def test_gam_version_uses_job_dir_not_default_tempdir_and_is_cached(
    fake_gam, job_dir, monkeypatch
):
    import tempfile

    from app.gam import runner

    # As in the worker container: no writable default temporary directory.
    monkeypatch.setattr(tempfile, "tempdir", "/nonexistent-tmp")
    seen = []
    real = runner.run_gam

    def counting(args, cfg_dir, **kwargs):
        seen.append(cfg_dir)
        return real(args, cfg_dir, **kwargs)

    monkeypatch.setattr(runner, "run_gam", counting)
    runner.clear_gam_version_cache()
    assert gam_version() == "GAM 7.x.y - fake"
    assert gam_version() == "GAM 7.x.y - fake"
    assert len(seen) == 1  # once per process (per GAM binary)
    assert seen[0].parent == job_dir


def test_free_text_reaches_gam_as_one_argument(fake_gam, tmp_path):
    message = 'line1\nline2 "q" $(rm -rf /)'
    argv = vacation_on(Email("a@x.com"), FreeText("Away"), FreeText(message))
    run_gam(argv, tmp_path)
    (call,) = fake_gam.calls()
    assert call["argv"] == argv
    assert call["argv"].count(message) == 1



def test_prepare_config_dir_runs_version_in_that_dir(fake_gam, tmp_path, monkeypatch):
    # In a fresh config directory GAM 7.52.3 prints "Created: .../gamcache" and
    # "Config File: .../gam.cfg, Initialized" on stdout, mixed into the first command's
    # output (seen on a live domain). `gam version` makes no API call and absorbs them.
    from app.gam import runner

    seen = []
    real = runner.run_gam

    def recording(args, cfg_dir, **kwargs):
        seen.append((args, cfg_dir))
        return real(args, cfg_dir, **kwargs)

    monkeypatch.setattr(runner, "run_gam", recording)
    runner.prepare_config_dir(tmp_path)
    assert seen == [(["version"], tmp_path)]


def test_prepare_config_dir_runs_config_args(fake_gam, tmp_path):
    import pytest

    argv = ["config", "enable_dasa", "true", "save"]
    prepare_config_dir(tmp_path, argv)
    (call,) = fake_gam.calls()
    assert call["argv"] == argv
    assert call["env"]["GAMCFGDIR"] == str(tmp_path)
    fake_gam.scenario([{"match": ["config"], "exit": 5, "stderr": "secret path /x"}])
    with pytest.raises(RuntimeError) as err:
        prepare_config_dir(tmp_path, argv)
    assert str(err.value) == "GAM could not write its configuration (exit 5)"
