"""Cherry-pick detection, against histories built for the purpose."""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "tests"))

import gitfixture as fx  # noqa: E402
from backport import find_equivalents, patch_id, patch_ids_for_paths  # noqa: E402

PATH = "pkg/loader.py"


def _tags(repo) -> list[str]:
    return subprocess.run(["git", "-C", str(repo), "tag"],
                          capture_output=True, text=True).stdout.split()


@pytest.fixture
def backported(tmp_path):
    repo, fix, copy = fx.backported(tmp_path / "bp")
    return repo, fix, copy


def test_a_cherry_pick_hashes_the_same_as_its_original(backported):
    """Different commits, different parents, different SHAs -- one change."""
    repo, fix, copy = backported
    assert fix != copy
    assert patch_id(repo, fix) == patch_id(repo, copy)


def test_the_copy_is_found_and_marked_as_a_copy(backported):
    repo, fix, copy = backported
    result = find_equivalents(repo, fix, [PATH])
    assert result.backported is True
    by_sha = {e.sha: e for e in result.equivalents}
    assert by_sha[fix].is_the_fix is True
    assert by_sha[copy].is_the_fix is False


def test_the_fixed_releases_are_reported_in_version_order(backported):
    repo, fix, _ = backported
    assert find_equivalents(repo, fix, [PATH]).release_lines == ("v1.4.7", "v2.0")


def test_the_gap_is_the_finding(backported):
    """1.5 was cut from the old line before the cherry-pick, so it sits between two
    fixed releases without carrying the fix. That hole is what a single published
    interval has no way to express, and it is the reason these records stay wrong."""
    repo, fix, _ = backported
    result = find_equivalents(repo, fix, [PATH])
    assert result.gaps(_tags(repo)) == ("v1.5",)


def test_a_linear_history_reports_no_backport_and_no_gap(tmp_path):
    repo, fix = fx.linear(tmp_path / "linear")
    result = find_equivalents(repo, fix, [PATH])
    assert result.backported is False
    assert result.gaps(_tags(repo)) == ()


def test_patch_ids_come_back_paired_with_their_commits(tmp_path):
    repo, fix = fx.linear(tmp_path / "linear")
    pairs = patch_ids_for_paths(repo, [PATH])
    assert pairs, "the file has history, so it must produce pairs"
    assert all(len(pid) == 40 and len(sha) == 40 for pid, sha in pairs)
    assert fix in {sha for _, sha in pairs}


def test_a_commit_that_changes_nothing_has_no_patch_id(tmp_path):
    """A merge with no changes of its own is not a fix, and must not be matched as one."""
    repo, _ = fx.linear(tmp_path / "linear")
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--allow-empty", "-m", "empty"], check=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    assert patch_id(repo, head) is None


def test_tags_that_are_not_versions_are_kept_not_dropped(tmp_path):
    """`nightly` sorts after the numbered releases rather than vanishing: a reader
    should see every tag that contains the fix, including the odd ones."""
    repo, fix = fx.linear(tmp_path / "linear")
    subprocess.run(["git", "-C", str(repo), "tag", "nightly", fix], check=True)
    lines = find_equivalents(repo, fix, [PATH]).release_lines
    assert "nightly" in lines
    assert lines.index("v1.2") < lines.index("nightly")
