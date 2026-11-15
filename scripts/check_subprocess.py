# SPDX-License-Identifier: AGPL-3.0-only
"""Fail if `subprocess` is imported anywhere in backend/app except app/gam/runner.py.

Usage: python scripts/check_subprocess.py [root]
"""

import re
import sys
from collections.abc import Sequence
from pathlib import Path

PATTERN = re.compile(r"^\s*(import\s+subprocess\b|from\s+subprocess\b)", re.MULTILINE)
ALLOWED = Path("gam") / "runner.py"


def find_offenders(root: Path) -> list[Path]:
    app_dir = root / "backend" / "app"
    if not app_dir.is_dir():
        return []
    offenders: list[Path] = []
    for path in sorted(app_dir.rglob("*.py")):
        if path.relative_to(app_dir) == ALLOWED:
            continue
        if PATTERN.search(path.read_text(encoding="utf-8", errors="replace")):
            offenders.append(path)
    return offenders


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0] if args else ".").resolve()
    offenders = find_offenders(root)
    for path in offenders:
        print(path.relative_to(root).as_posix())
    return 1 if offenders else 0


if __name__ == "__main__":
    sys.exit(main())
