# SPDX-License-Identifier: AGPL-3.0-only
"""Fail if code in backend/app other than app/gam/runner.py can start a process.

Parses each file with `ast` and flags: any import of `subprocess` (including
`import os, subprocess` and `import subprocess.x`), `__import__("subprocess")`,
`importlib.import_module("subprocess")`, calls to os.system, os.popen, os.exec* and
os.spawn* (also through an `import os as o` alias or `from os import system`), and
files that do not parse (they cannot be checked).

Usage: python scripts/check_subprocess.py [root]
"""

import ast
import sys
from collections.abc import Sequence
from pathlib import Path

ALLOWED = Path("gam") / "runner.py"
OS_PREFIXES = ("exec", "spawn")
OS_NAMES = {"system", "popen"}


def _is_process_func(name: str) -> bool:
    return name in OS_NAMES or name.startswith(OS_PREFIXES)


def _is_subprocess(name: str) -> bool:
    return name == "subprocess" or name.startswith("subprocess.")


def _first_arg_is_subprocess(node: ast.Call) -> bool:
    if not node.args:
        return False
    arg = node.args[0]
    return (
        isinstance(arg, ast.Constant) and isinstance(arg.value, str) and _is_subprocess(arg.value)
    )


def has_violation(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return True
    os_aliases = {"os"}
    import_module_names = {"import_module"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_subprocess(alias.name):
                    return True
                if alias.name == "os":
                    os_aliases.add(alias.asname or "os")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0 and _is_subprocess(module):
                return True
            if node.level == 0 and module == "os":
                if any(_is_process_func(alias.name) for alias in node.names):
                    return True
            if node.level == 0 and module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_names.add(alias.asname or "import_module")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "__import__" and _first_arg_is_subprocess(node):
                return True
            if func.id in import_module_names and _first_arg_is_subprocess(node):
                return True
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in os_aliases and _is_process_func(func.attr):
                return True
            if func.value.id == "importlib" and func.attr == "import_module":
                if _first_arg_is_subprocess(node):
                    return True
    return False


def find_offenders(root: Path) -> list[Path]:
    app_dir = root / "backend" / "app"
    if not app_dir.is_dir():
        return []
    offenders: list[Path] = []
    for path in sorted(app_dir.rglob("*.py")):
        if path.relative_to(app_dir) == ALLOWED:
            continue
        if has_violation(path.read_text(encoding="utf-8", errors="replace")):
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
