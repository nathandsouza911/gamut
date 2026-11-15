# SPDX-License-Identifier: AGPL-3.0-only
"""Envelope encryption of tenant GAM files, key loading guards, materialize."""

import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from fastapi.testclient import TestClient

from app.crypto.envelope import (
    EXAMPLE_KEY_MARKER,
    SealedBundle,
    encode_public_key,
    load_private_key_or_die,
    load_public_key,
    materialize,
    open_bundle,
    seal_bundle,
    write_private_key,
)
from app.settings import Settings, SettingsError

REPO = Path(__file__).resolve().parents[2]
DB = "postgresql+psycopg://gamut_app:pw@db:5432/gamut"
FILES = {"oauth2.txt": b'{"refresh_token": "r"}', "oauth2service.json": b"\x00\xffbinary"}


def _pair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def test_round_trip() -> None:
    private, public = _pair()
    sealed = seal_bundle(FILES, public)
    assert sealed.key_version == 1
    assert len(sealed.nonce) == 12
    assert b"refresh_token" not in sealed.ciphertext
    assert open_bundle(sealed, private) == FILES


def test_each_seal_uses_a_fresh_data_key() -> None:
    _, public = _pair()
    a, b = seal_bundle(FILES, public), seal_bundle(FILES, public)
    assert a.wrapped_key != b.wrapped_key and a.ciphertext != b.ciphertext


def test_tamper_fails() -> None:
    private, public = _pair()
    sealed = seal_bundle(FILES, public)
    flipped = bytearray(sealed.ciphertext)
    flipped[0] ^= 0x01
    with pytest.raises(InvalidTag):
        open_bundle(
            SealedBundle(bytes(flipped), sealed.nonce, sealed.wrapped_key, sealed.key_version),
            private,
        )
    wrapped = bytearray(sealed.wrapped_key)
    wrapped[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        open_bundle(
            SealedBundle(sealed.ciphertext, sealed.nonce, bytes(wrapped), sealed.key_version),
            private,
        )


def test_bundle_is_bound_to_its_tenant_and_key() -> None:
    private, public = _pair()
    sealed = seal_bundle(FILES, public, associated_data=b"tenant-a")
    assert open_bundle(sealed, private, associated_data=b"tenant-a") == FILES
    with pytest.raises(InvalidTag):
        open_bundle(sealed, private, associated_data=b"tenant-b")
    with pytest.raises(InvalidTag):
        open_bundle(sealed, X25519PrivateKey.generate(), associated_data=b"tenant-a")


def test_public_key_encoding_round_trips_and_refuses_example() -> None:
    _, public = _pair()
    encoded = encode_public_key(public)
    assert load_public_key(encoded).public_bytes_raw() == public.public_bytes_raw()
    for bad in (EXAMPLE_KEY_MARKER, "", "not base64!", "c2hvcnQ="):
        with pytest.raises(SettingsError):
            load_public_key(bad)


def test_api_settings_have_no_private_key(
    make_client: Callable[..., TestClient], web_settings: Callable[..., Settings]
) -> None:
    settings = web_settings()
    assert settings.role == "web"
    assert settings.credential_private_key_file is None
    assert not any("private" in name and "file" not in name for name in Settings.model_fields)
    client = make_client(settings=settings)
    state = vars(client.app.state)["_state"]  # type: ignore[attr-defined]
    assert isinstance(state["credential_public_key"], X25519PublicKey)
    assert not any(isinstance(v, X25519PrivateKey) for v in state.values())


def test_web_refuses_example_public_key(web_settings: Callable[..., Settings]) -> None:
    from app.main import create_app

    with pytest.raises(SettingsError, match="GAMUT_CREDENTIAL_PUBLIC_KEY") as excinfo:
        create_app(web_settings(credential_public_key=EXAMPLE_KEY_MARKER))
    assert EXAMPLE_KEY_MARKER not in str(excinfo.value)


def _worker(path: Path | None) -> Settings:
    if path is None:
        return Settings(role="cli", database_url=DB)
    return Settings(role="worker", database_url=DB, credential_private_key_file=path)


def test_worker_refuses_missing_or_example_key(tmp_path: Path) -> None:
    for settings in (_worker(None), _worker(tmp_path / "absent")):
        with pytest.raises(SystemExit) as excinfo:
            load_private_key_or_die(settings)
        assert excinfo.value.code == "credential private key missing"
    example = REPO / "secrets" / "credential_private_key.example"
    with pytest.raises(SystemExit) as excinfo:
        load_private_key_or_die(_worker(example))
    assert excinfo.value.code == "credential private key is the example value"
    garbage = tmp_path / "garbage"
    garbage.write_text("not a key")
    with pytest.raises(SystemExit) as excinfo:
        load_private_key_or_die(_worker(garbage))
    assert excinfo.value.code == "credential private key is not a valid X25519 key"
    assert "not a key" not in str(excinfo.value.code)

    private, public = _pair()
    good = tmp_path / "key"
    write_private_key(private, good)
    loaded = load_private_key_or_die(_worker(good))
    assert loaded.public_key().public_bytes_raw() == public.public_bytes_raw()


def test_worker_command_checks_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.cli import main

    monkeypatch.setenv("GAMUT_DATABASE_URL", DB)
    monkeypatch.setenv("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE", str(tmp_path / "absent"))
    with pytest.raises(SystemExit) as excinfo:
        main(["worker"])
    assert excinfo.value.code == "credential private key missing"
    monkeypatch.delenv("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE")
    assert main(["worker"]) == 2
    assert "GAMUT_CREDENTIAL_PRIVATE_KEY_FILE" in capsys.readouterr().err


def test_gen_keys_writes_private_key_and_prints_public(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from app.cli import main

    target = tmp_path / "credential_private_key"
    assert main(["gen-keys", str(target)]) == 0
    out = capsys.readouterr().out
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    line = next(ln for ln in out.splitlines() if ln.startswith("GAMUT_CREDENTIAL_PUBLIC_KEY="))
    public = load_public_key(line.split("=", 1)[1])
    private = load_private_key_or_die(_worker(target))
    assert private.public_key().public_bytes_raw() == public.public_bytes_raw()
    assert "PRIVATE" not in out
    # Never overwrites an existing key.
    assert main(["gen-keys", str(target)]) == 1
    assert main(["gen-keys"]) == 2


def test_materialize_permissions_and_cleanup(tmp_path: Path) -> None:
    seen: dict[str, int] = {}
    with pytest.raises(RuntimeError, match="boom"), materialize(FILES, base=tmp_path) as cfg:
        assert cfg.parent == tmp_path
        seen["dir"] = stat.S_IMODE(cfg.stat().st_mode)
        for name, content in FILES.items():
            assert (cfg / name).read_bytes() == content
            seen[name] = stat.S_IMODE((cfg / name).stat().st_mode)
        (cfg / "gam.cfg").write_text("written by gam")  # GAM's own files go too
        raise RuntimeError("boom")
    assert seen == {"dir": 0o700, "oauth2.txt": 0o600, "oauth2service.json": 0o600}
    assert os.listdir(tmp_path) == []


def test_materialize_rejects_path_names(tmp_path: Path) -> None:
    for name in ("../x", "a/b", "", ".", ".."):
        with pytest.raises(ValueError), materialize({name: b"x"}, base=tmp_path):
            pass
    assert os.listdir(tmp_path) == []
