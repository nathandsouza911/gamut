# SPDX-License-Identifier: AGPL-3.0-only
"""Envelope encryption of tenant GAM configuration files.

The "master key" is an X25519 key pair (see docs/decisions.md). The web process holds
only the public key, so it can seal uploads but never open them; the worker holds the
private key.

- Each bundle is a JSON map {file name: base64 content}, encrypted with a fresh random
  AES-256-GCM data key (DEK).
- The DEK is wrapped with ECIES: an ephemeral X25519 key agrees a secret with the public
  key, HKDF-SHA256 (info `gamut-dek-wrap-v1`, salt = ephemeral public || recipient
  public) derives a key-encryption key, and AES-256-GCM encrypts the DEK.
  wrapped_key = ephemeral public (32) || wrap nonce (12) || encrypted DEK (32 + 16 tag).
- `associated_data` (the tenant id) is authenticated by both layers, so a bundle copied
  to another tenant's row does not open.

Nothing here logs, and error messages never include key or file contents.
"""

import base64
import binascii
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.settings import Settings, SettingsError

KEY_VERSION = 1
WRAP_INFO = b"gamut-dek-wrap-v1"
BUNDLE_AAD_PREFIX = b"gamut-bundle-v1:"
WRAP_AAD_PREFIX = b"gamut-dek-v1:"
EXAMPLE_KEY_MARKER = "EXAMPLE-DO-NOT-USE"
DEFAULT_JOB_DIR = Path("/run/gamut-jobs")
_NONCE_LEN = 12
_RAW_KEY_LEN = 32


@dataclass(frozen=True)
class SealedBundle:
    ciphertext: bytes
    nonce: bytes
    wrapped_key: bytes
    key_version: int


def _raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _kek(shared: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral + recipient, info=WRAP_INFO)
    return hkdf.derive(shared)


def seal_bundle(
    files: Mapping[str, bytes], public_key: X25519PublicKey, *, associated_data: bytes = b""
) -> SealedBundle:
    """Encrypt `files` for the holder of the private key matching `public_key`."""
    plaintext = json.dumps(
        {name: base64.b64encode(content).decode("ascii") for name, content in files.items()},
        sort_keys=True,
    ).encode("utf-8")
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, BUNDLE_AAD_PREFIX + associated_data)

    ephemeral = X25519PrivateKey.generate()
    ephemeral_raw = _raw(ephemeral.public_key())
    kek = _kek(ephemeral.exchange(public_key), ephemeral_raw, _raw(public_key))
    wrap_nonce = os.urandom(_NONCE_LEN)
    encrypted_dek = AESGCM(kek).encrypt(wrap_nonce, dek, WRAP_AAD_PREFIX + associated_data)
    return SealedBundle(
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_key=ephemeral_raw + wrap_nonce + encrypted_dek,
        key_version=KEY_VERSION,
    )


def open_bundle(
    sealed: SealedBundle, private_key: X25519PrivateKey, *, associated_data: bytes = b""
) -> dict[str, bytes]:
    """Decrypt a bundle. Raises cryptography's InvalidTag on tampering or the wrong key."""
    if sealed.key_version != KEY_VERSION:
        raise ValueError(f"unsupported credential key version {sealed.key_version}")
    head = _RAW_KEY_LEN + _NONCE_LEN
    if len(sealed.wrapped_key) <= head:
        raise ValueError("wrapped key is truncated")
    ephemeral_raw = sealed.wrapped_key[:_RAW_KEY_LEN]
    wrap_nonce = sealed.wrapped_key[_RAW_KEY_LEN:head]
    ephemeral = X25519PublicKey.from_public_bytes(ephemeral_raw)
    kek = _kek(private_key.exchange(ephemeral), ephemeral_raw, _raw(private_key.public_key()))
    dek = AESGCM(kek).decrypt(
        wrap_nonce, sealed.wrapped_key[head:], WRAP_AAD_PREFIX + associated_data
    )
    plaintext = AESGCM(dek).decrypt(
        sealed.nonce, sealed.ciphertext, BUNDLE_AAD_PREFIX + associated_data
    )
    encoded: dict[str, str] = json.loads(plaintext)
    return {name: base64.b64decode(value) for name, value in encoded.items()}


# --- Keys ----------------------------------------------------------------------------

def encode_public_key(public_key: X25519PublicKey) -> str:
    """The value for GAMUT_CREDENTIAL_PUBLIC_KEY: base64 of the raw 32-byte key."""
    return base64.b64encode(_raw(public_key)).decode("ascii")


def load_public_key(value: str | None) -> X25519PublicKey:
    """Parse GAMUT_CREDENTIAL_PUBLIC_KEY. Raises SettingsError (naming the variable only)."""
    if not value or EXAMPLE_KEY_MARKER in value:
        raise SettingsError(
            "GAMUT_CREDENTIAL_PUBLIC_KEY is missing or the example value; run `gamut gen-keys`"
        )
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != _RAW_KEY_LEN:
        raise SettingsError("GAMUT_CREDENTIAL_PUBLIC_KEY is not a base64 X25519 public key")
    return X25519PublicKey.from_public_bytes(raw)


def write_private_key(private_key: X25519PrivateKey, path: Path) -> None:
    """Write the key as unencrypted PKCS#8 PEM, mode 0600. Never overwrites a file."""
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_private_file(path, pem)


def _write_private_file(path: Path, content: bytes) -> None:
    """Create `path` exclusively with mode 0600 and write `content`."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(content)


def _die(message: str) -> NoReturn:
    sys.exit(message)  # non-zero exit; the message goes to stderr


def load_private_key_or_die(settings: Settings) -> X25519PrivateKey:
    """The worker's private key from GAMUT_CREDENTIAL_PRIVATE_KEY_FILE.

    Exits non-zero with `credential private key missing`, `credential private key is the
    example value` or `credential private key is not a valid X25519 key`. The messages
    never include the path or the file's contents.
    """
    path = settings.credential_private_key_file
    if path is None:
        _die("credential private key missing")
    try:
        data = Path(path).read_bytes()
    except OSError:
        _die("credential private key missing")
    if not data.strip():
        _die("credential private key missing")
    if EXAMPLE_KEY_MARKER.encode() in data:
        _die("credential private key is the example value")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        _die("credential private key is not a valid X25519 key")
    if not isinstance(key, X25519PrivateKey):
        _die("credential private key is not a valid X25519 key")
    return key


# --- Materialize ---------------------------------------------------------------------

def _check_name(name: str) -> None:
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise ValueError("credential file names must be plain file names")


@contextmanager
def materialize(files: Mapping[str, bytes], base: Path = DEFAULT_JOB_DIR) -> Iterator[Path]:
    """Write `files` into a fresh mode-0700 directory under `base` (files mode 0600).

    The directory, and anything GAM wrote into it, is removed when the context exits,
    whatever happens inside it.
    """
    for name in files:
        _check_name(name)
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="job-", dir=base))
    try:
        directory.chmod(0o700)
        for name, content in files.items():
            _write_private_file(directory / name, content)
        yield directory
    finally:
        shutil.rmtree(directory)
