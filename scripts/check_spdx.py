# SPDX-License-Identifier: AGPL-3.0-only
"""Fail if any source file lacks the SPDX license line in its first 3 lines.

Usage: python scripts/check_spdx.py [root]
"""

import sys
from collections.abc import Sequence
from pathlib import Path

MARKER = "SPDX-License-Identifier: AGPL-3.0-only"
EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".css", ".sql", ".sh", ".yml", ".yaml"}
FILENAMES = {"Dockerfile"}
SKIP_DIRS = {
    "node_modules",
    "dist",
    ".venv",
    "venv",
    ".git",
    ".superpowers",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def _is_source(path: Path) -> bool:
    return path.suffix in EXTENSIONS or path.name in FILENAMES or path.name.endswith(".Dockerfile")


def _has_header(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            head = [fh.readline() for _ in range(3)]
    except OSError:
        return False
    return any(MARKER in line for line in head)


def find_offenders(root: Path) -> list[Path]:
    offenders: list[Path] = []
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.is_file() and _is_source(path) and not _has_header(path):
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
