# SPDX-License-Identifier: AGPL-3.0-only
"""Command-line entry point (`gamut`)."""

import sys
from collections.abc import Sequence
from pathlib import Path

COMMANDS = ("web", "worker", "verify-audit", "gen-keys")
USAGE = "usage: gamut {" + ",".join(COMMANDS) + "}  (gen-keys PRIVATE_KEY_FILE)"


def verify_audit() -> int:
    """Print `OK <n> events` (exit 0) or `BROKEN at event <id>: <reason>` (exit 1)."""
    from app.audit.chain import verify_chain
    from app.db import session_scope

    with session_scope() as session:
        result = verify_chain(session)
    if result.ok:
        print(f"OK {result.checked} events")
        return 0
    print(f"BROKEN at event {result.first_broken_id}: {result.reason}")
    return 1


def web() -> int:
    """Serve the web app on 0.0.0.0:8080 (TLS terminates at the reverse proxy)."""
    import uvicorn

    from app.main import create_app
    from app.settings import load_settings

    settings = load_settings(role="web")
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",  # noqa: S104 - inside the container; Compose decides what is published
        port=8080,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )
    return 0


def gen_keys(args: list[str]) -> int:
    """Write a new credential private key to PATH (mode 0600, never overwriting) and print
    the matching public key for GAMUT_CREDENTIAL_PUBLIC_KEY."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from app.crypto.envelope import encode_public_key, write_private_key

    if len(args) != 1:
        print("usage: gamut gen-keys PRIVATE_KEY_FILE", file=sys.stderr)
        return 2
    target = Path(args[0])
    private = X25519PrivateKey.generate()
    try:
        write_private_key(private, target)
    except FileExistsError:
        print("gamut gen-keys: the file already exists; not overwritten", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"gamut gen-keys: cannot write the key file: {exc.strerror}", file=sys.stderr)
        return 1
    print(f"Private key written to {target} (mode 0600). Mount it into the worker only.")
    print("Put this line in .env (the web container gets only the public key):")
    print(f"GAMUT_CREDENTIAL_PUBLIC_KEY={encode_public_key(private.public_key())}")
    return 0


def worker() -> int:
    """Check the worker's configuration and credential key. (The job loop is Task 6.)"""
    from app.crypto.envelope import load_private_key_or_die
    from app.settings import load_settings

    settings = load_settings(role="worker")
    load_private_key_or_die(settings)  # exits non-zero when missing or the example
    print("gamut worker: credential private key loaded; the job loop is not implemented yet",
          file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0 if args else 2
    if args[0] == "verify-audit":
        return verify_audit()
    if args[0] == "web":
        from app.settings import SettingsError

        try:
            return web()
        except SettingsError as exc:
            print(f"gamut web: {exc}", file=sys.stderr)
            return 2
    if args[0] == "worker":
        from app.settings import SettingsError

        try:
            return worker()
        except SettingsError as exc:
            print(f"gamut worker: {exc}", file=sys.stderr)
            return 2
    if args[0] == "gen-keys":
        return gen_keys(args[1:])
    print(f"gamut: unknown command {args[0]!r}\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
