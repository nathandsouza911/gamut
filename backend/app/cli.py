# SPDX-License-Identifier: AGPL-3.0-only
"""Command-line entry point (`gamut`). Subcommands are implemented in later tasks."""

import sys
from collections.abc import Sequence

COMMANDS = ("web", "worker", "verify-audit", "gen-keys")
USAGE = "usage: gamut {" + ",".join(COMMANDS) + "}"


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(USAGE)
        return 0 if args else 2
    if args[0] in COMMANDS:
        print(f"gamut {args[0]}: not implemented yet", file=sys.stderr)
    else:
        print(f"gamut: unknown command {args[0]!r}\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
