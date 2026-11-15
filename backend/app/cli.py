# SPDX-License-Identifier: AGPL-3.0-only
"""Command-line entry point (`gamut`). worker and gen-keys arrive in later tasks."""

import sys
from collections.abc import Sequence

COMMANDS = ("web", "worker", "verify-audit", "gen-keys")
USAGE = "usage: gamut {" + ",".join(COMMANDS) + "}"


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
    if args[0] in COMMANDS:
        print(f"gamut {args[0]}: not implemented yet", file=sys.stderr)
    else:
        print(f"gamut: unknown command {args[0]!r}\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
