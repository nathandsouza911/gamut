# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check_spdx():
    return _load("check_spdx")


@pytest.fixture(scope="module")
def check_subprocess():
    return _load("check_subprocess")


def test_spdx_checker_flags_missing_header(tmp_path, check_spdx, capsys):
    (tmp_path / "a.py").write_text("print('no header')\n")
    (tmp_path / "b.py").write_text("# SPDX-License-Identifier: AGPL-3.0-only\nprint('ok')\n")
    assert check_spdx.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "a.py" in out
    assert "b.py" not in out


def test_spdx_checker_accepts_shebang_and_skips_vendored_dirs(tmp_path, check_spdx):
    (tmp_path / "run.sh").write_text(
        "#!/bin/sh\n# SPDX-License-Identifier: AGPL-3.0-only\necho hi\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("module.exports = 1\n")
    (tmp_path / "Dockerfile").write_text("# SPDX-License-Identifier: AGPL-3.0-only\nFROM scratch\n")
    assert check_spdx.main([str(tmp_path)]) == 0


def test_repo_has_spdx_everywhere(check_spdx):
    assert check_spdx.main([str(REPO_ROOT)]) == 0


def test_subprocess_checker_flags_imports_outside_runner(tmp_path, check_subprocess, capsys):
    app = tmp_path / "backend" / "app"
    (app / "gam").mkdir(parents=True)
    (app / "gam" / "runner.py").write_text("import subprocess\n")
    (app / "bad.py").write_text("from subprocess import run\n")
    (app / "good.py").write_text("import json\n")
    assert check_subprocess.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "bad.py" in out
    assert "good.py" not in out
    assert "runner.py" not in out


BYPASS_SOURCES = [
    "import os, subprocess\n",
    "import subprocess as sp\n",
    "import subprocess.foo\n",
    "from subprocess import run\n",
    "def f():\n    import subprocess\n",
    "m = __import__('subprocess')\n",
    "import importlib\nm = importlib.import_module('subprocess')\n",
    "from importlib import import_module\nm = import_module('subprocess')\n",
    "import os\nos.system('ls')\n",
    "import os\nos.popen('ls')\n",
    "import os\nos.execvp('ls', ['ls'])\n",
    "import os\nos.spawnl(0, 'ls')\n",
    "import os as o\no.system('ls')\n",
    "from os import system\n",
    "from os import popen as p\n",
    "def broken(:\n",
]

HARMLESS_SOURCES = [
    "import os\nprint(os.getcwd())\n",
    "# import subprocess\nx = 'subprocess'\n",
    "import os.path\nos.path.join('a')\n",
    "from os import path, getcwd\n",
    "class A:\n    def system(self): ...\nA().system()\n",
]


@pytest.mark.parametrize("source", BYPASS_SOURCES)
def test_subprocess_checker_flags_every_bypass(tmp_path, check_subprocess, capsys, source):
    app = tmp_path / "backend" / "app"
    app.mkdir(parents=True)
    (app / "bad.py").write_text(source)
    assert check_subprocess.main([str(tmp_path)]) == 1
    assert "bad.py" in capsys.readouterr().out


@pytest.mark.parametrize("source", HARMLESS_SOURCES)
def test_subprocess_checker_accepts_harmless_code(tmp_path, check_subprocess, source):
    app = tmp_path / "backend" / "app"
    app.mkdir(parents=True)
    (app / "ok.py").write_text(source)
    assert check_subprocess.main([str(tmp_path)]) == 0


def test_subprocess_checker_allows_runner(tmp_path, check_subprocess):
    runner = tmp_path / "backend" / "app" / "gam"
    runner.mkdir(parents=True)
    (runner / "runner.py").write_text("import subprocess\nimport os\nos.killpg(1, 9)\n")
    assert check_subprocess.main([str(tmp_path)]) == 0

def test_repo_confines_subprocess_to_runner(check_subprocess):
    assert check_subprocess.main([str(REPO_ROOT)]) == 0


def test_license_is_agpl3():
    text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in text
    assert "Version 3, 19 November 2007" in text
