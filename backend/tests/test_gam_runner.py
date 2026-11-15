# SPDX-License-Identifier: AGPL-3.0-only
import time

from app.gam.commands import Email, vacation_on
from app.gam.runner import GamResult, gam_version, run_gam
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
    assert {"PATH", "HOME", "GAMCFGDIR", "LANG"} <= keys
    assert not any(k.startswith("GAMUT_") or k == "SOME_PARENT_VAR" for k in keys)
    assert keys == {"PATH", "HOME", "GAMCFGDIR", "LANG"}


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


def test_gam_version(fake_gam):
    assert gam_version() == "GAM 7.x.y - fake"
    assert fake_gam.calls() == []


def test_free_text_reaches_gam_as_one_argument(fake_gam, tmp_path):
    message = 'line1\nline2 "q" $(rm -rf /)'
    argv = vacation_on(Email("a@x.com"), FreeText("Away"), FreeText(message))
    run_gam(argv, tmp_path)
    (call,) = fake_gam.calls()
    assert call["argv"] == argv
    assert call["argv"].count(message) == 1

