"""Build small git repositories on disk to probe against.

Synthetic rather than recorded, so the tests need no network, no fixtures directory,
and no pinned upstream that can be rewritten under them. Each builder produces one
history shape the prober has to get right.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

VULNERABLE = 'def load(path):\n    return open(path).read()\n'
FIXED = 'def load(path):\n    if ".." in path:\n        raise ValueError("refused")\n    return open(path).read()\n'
REFACTORED = (
    'import io\n\n\ndef load(path, *, encoding="utf-8"):\n'
    '    """Read a file, refusing traversal."""\n'
    '    if ".." in path:\n        raise ValueError("refused")\n'
    '    with io.open(path, encoding=encoding) as fh:\n        return fh.read()\n'
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} -> exit {result.returncode}\n"
            f"stderr: {result.stderr.strip()}\nstdout: {result.stdout.strip()}"
        )
    return result.stdout.strip()


def _commit(repo: Path, path: str, content: str, message: str, tag: str | None = None) -> str:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", message)
    if tag:
        _git(repo, "tag", tag)
    return _git(repo, "rev-parse", "HEAD")


def init(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    return root


def linear(root: Path) -> tuple[Path, str]:
    """The straightforward case: vulnerable, fixed, then unrelated work on top."""
    repo = init(root)
    _commit(repo, "pkg/loader.py", VULNERABLE, "initial", tag="v1.0")
    _commit(repo, "pkg/util.py", "VERSION = '1.1'\n", "unrelated", tag="v1.1")
    fix = _commit(repo, "pkg/loader.py", FIXED, "reject traversal", tag="v1.2")
    _commit(repo, "pkg/util.py", "VERSION = '1.3'\n", "unrelated after", tag="v1.3")
    return repo, fix


def zero_padded_tags(root: Path) -> tuple[Path, str]:
    """Tags spelled the way a maintainer types them, versions the way PyPI stores them.

    certifi tags `2024.07.04` and ships `2024.7.4`. String matching finds neither in
    the other, and an unresolvable ref cannot be probed at all.
    """
    repo = init(root)
    _commit(repo, "pkg/loader.py", VULNERABLE, "initial", tag="2024.06.02")
    fix = _commit(repo, "pkg/loader.py", FIXED, "reject traversal", tag="2024.07.04")
    return repo, fix


def refactored_after_fix(root: Path) -> tuple[Path, str]:
    """The fix lands, then the file is rewritten around it.

    The vulnerability is gone at v2.0 but the patch no longer applies in either
    direction. The honest answer is indeterminate, not present.
    """
    repo = init(root)
    _commit(repo, "pkg/loader.py", VULNERABLE, "initial", tag="v1.0")
    fix = _commit(repo, "pkg/loader.py", FIXED, "reject traversal", tag="v1.1")
    _commit(repo, "pkg/loader.py", REFACTORED, "rewrite loader", tag="v2.0")
    return repo, fix


def renamed_after_fix(root: Path) -> tuple[Path, str]:
    """The file moves after the fix, so the path no longer exists at the later ref."""
    repo = init(root)
    _commit(repo, "pkg/loader.py", VULNERABLE, "initial", tag="v1.0")
    fix = _commit(repo, "pkg/loader.py", FIXED, "reject traversal", tag="v1.1")
    (repo / "pkg" / "loader.py").unlink()
    _commit(repo, "pkg/io/loader.py", FIXED, "move loader", tag="v2.0")
    return repo, fix


def backported(root: Path) -> tuple[Path, str, str]:
    """The shape the whole project exists for.

    The fix lands on main and is released as 2.0. It is then cherry-picked onto the
    1.x maintenance branch and released as 1.4.7. So 1.4.7 is safe while 1.5, cut from
    the older line, is not -- and the affected set is two intervals, which is exactly
    what the published record cannot express.
    """
    repo = init(root)
    _commit(repo, "pkg/loader.py", VULNERABLE, "initial", tag="v1.0")
    _commit(repo, "pkg/util.py", "VERSION = '1.4.6'\n", "more 1.x work", tag="v1.4.6")
    maintenance = _git(repo, "rev-parse", "HEAD")

    _commit(repo, "pkg/api.py", "def go():\n    pass\n", "main moves on")
    fix = _commit(repo, "pkg/loader.py", FIXED, "reject traversal", tag="v2.0")

    _git(repo, "checkout", "-q", "-b", "maint-1.x", maintenance)
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "cherry-pick", fix)
    _git(repo, "tag", "v1.4.7")
    backport = _git(repo, "rev-parse", "HEAD")

    # 1.5 is cut from the maintenance line BEFORE the cherry-pick, so it carries the
    # vulnerable loader even though it is numbered above the release that was fixed.
    _git(repo, "checkout", "-q", "-b", "rel-1.5", maintenance)
    _commit(repo, "pkg/util.py", "VERSION = '1.5'\n", "1.5 from the old line", tag="v1.5")
    _git(repo, "checkout", "-q", "main")
    return repo, fix, backport
