"""Tree-presence probing, against histories built for the purpose.

Offline and deterministic: the repositories are constructed by the test, so nothing
here depends on an upstream project keeping its tags where they were.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "tests"))

import gitfixture as fx  # noqa: E402
from tree import Presence, Reason, Repo  # noqa: E402

PATH = "pkg/loader.py"


def _repo(path: pathlib.Path) -> Repo:
    """A Repo pointed at a local directory. Nothing is cloned; the fixture is the clone."""
    r = Repo.__new__(Repo)
    r.url = str(path)
    r.path = path
    return r


@pytest.fixture
def linear(tmp_path):
    repo, fix = fx.linear(tmp_path / "linear")
    r = _repo(repo)
    return r, r.patch_for(fix, PATH)


def test_absent_before_the_fix(linear):
    r, patch = linear
    for ref in ("v1.0", "v1.1"):
        assert r.presence(patch, ref, PATH).presence is Presence.ABSENT


def test_present_from_the_fix_onward(linear):
    r, patch = linear
    for ref in ("v1.2", "v1.3"):
        assert r.presence(patch, ref, PATH).presence is Presence.PRESENT


def test_an_unknown_ref_is_indeterminate_not_absent(linear):
    """Absent is a claim about the code. A missing tag is a claim about the clone."""
    probe = r_probe = linear[0].presence(linear[1], "v9.9", PATH)
    assert probe.presence is Presence.INDETERMINATE
    assert r_probe.reason is Reason.REF_UNKNOWN


def test_zero_padded_tags_resolve_through_the_version(tmp_path):
    """PyPI normalises `2024.07.04` to `2024.7.4`; the tag keeps the padding. Resolving
    by spelling finds nothing, and an unresolvable boundary cannot be probed at all."""
    repo, fix = fx.zero_padded_tags(tmp_path / "padded")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    assert r.presence(patch, "2024.6.2", PATH).presence is Presence.ABSENT
    assert r.presence(patch, "2024.7.4", PATH).presence is Presence.PRESENT


def test_a_rewritten_file_is_indeterminate_not_present(tmp_path):
    """The vulnerability really is gone at v2.0, and this prober cannot show it. Saying
    PRESENT here would be right by luck; the evidence layer needs another tier."""
    repo, fix = fx.refactored_after_fix(tmp_path / "refactor")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    assert r.presence(patch, "v1.1", PATH).presence is Presence.PRESENT
    probe = r.presence(patch, "v2.0", PATH)
    assert probe.presence is Presence.INDETERMINATE
    assert probe.reason is Reason.DIVERGED


def test_a_moved_file_reports_the_path_not_the_code(tmp_path):
    repo, fix = fx.renamed_after_fix(tmp_path / "renamed")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    probe = r.presence(patch, "v2.0", PATH)
    assert probe.presence is Presence.INDETERMINATE
    assert probe.reason is Reason.PATH_ABSENT


def test_the_backport_case(tmp_path):
    """The shape the project exists for: 1.4.7 carries the fix, 1.5 does not, and 2.0
    does. The affected set is two intervals -- which is what the published record has
    no way to say."""
    repo, fix, _ = fx.backported(tmp_path / "backport")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    assert r.presence(patch, "v1.4.6", PATH).presence is Presence.ABSENT
    assert r.presence(patch, "v1.4.7", PATH).presence is Presence.PRESENT
    assert r.presence(patch, "v1.5", PATH).presence is Presence.ABSENT
    assert r.presence(patch, "v2.0", PATH).presence is Presence.PRESENT


def test_an_empty_patch_decides_nothing(linear):
    assert linear[0].presence("", "v1.2", PATH).reason is Reason.EMPTY_PATCH


def test_a_traversing_path_is_refused_before_it_is_used(linear):
    """The path comes from an advisory record, not from us. The first version of this
    guard sat after `git show`, which failed on the traversal first and left the check
    unreachable -- so the refusal has to happen before the path is used for anything."""
    r, patch = linear
    for path in ("../../escape.py", "/etc/passwd", "a/../../b.py"):
        probe = r.presence(patch, "v1.2", path)
        assert probe.presence is Presence.INDETERMINATE
        assert probe.reason is Reason.PATH_ESCAPES, path


def test_an_ordinary_nested_path_is_untouched(linear):
    r, patch = linear
    assert r.presence(patch, "v1.2", PATH).presence is Presence.PRESENT
