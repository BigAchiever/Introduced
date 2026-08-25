"""Building the shortlist a model chooses from."""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "tests"))

import gitfixture as fx  # noqa: E402
from candidates import (  # noqa: E402
    Source, by_advisory_id, by_release_window, by_touching_paths, shortlist,
)

PATH = "pkg/loader.py"


def _amend_subject(repo, text):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-q", "--amend", "-m", text], check=True)
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


# --- the parsing bug that returned a short list rather than an error ---------------
# git puts a blank line between a commit's header and its file list, so splitting the
# log on blank lines cuts inside a record: the first commit parses and every later one
# is silently dropped. A shortlist quietly missing the right answer is the worst shape
# this bug could have taken.

def test_every_commit_in_the_log_is_parsed(tmp_path):
    repo, fix, backport = fx.backported(tmp_path / "bp")
    shas = {c.sha for c in by_touching_paths(repo, [PATH])}
    assert fix in shas and backport in shas
    assert len(shas) >= 3, "the initial commit touches the file too"


def test_file_lists_survive_parsing(tmp_path):
    repo, fix, _ = fx.backported(tmp_path / "bp")
    found = next(c for c in by_touching_paths(repo, [PATH]) if c.sha == fix)
    assert found.files == (PATH,)


# --- the release window, which is the one that works on real packages --------------

def test_the_window_finds_a_fix_with_no_security_wording(tmp_path):
    """certifi shipped a security fix in 2024.7.4 and called the commit
    "2024.07.04 (#295)" -- no CVE, no advisory id, none of the words a search for
    security language would match. A shortlist built from wording alone was empty for
    exactly the advisories this project selects for."""
    repo, fix = fx.silent_fix(tmp_path / "silent")

    # the wording strategies find nothing at all, which is the point
    assert by_advisory_id(repo, ["CVE-2024-39689"]) == []
    assert shortlist(repo, advisory_ids=["CVE-2024-39689"], paths=[PATH]) == []

    # the window finds it, because the fix is inside it by arithmetic
    found = by_release_window(repo, "v1.1.1", "v1.2.0", [PATH])
    assert fix in {c.sha for c in found}
    assert all("landed in" in c.why for c in found)


def test_the_window_is_bounded_by_the_two_releases(tmp_path):
    repo, fix = fx.linear(tmp_path / "lin")
    found = {c.sha for c in by_release_window(repo, "v1.1", "v1.2", [PATH])}
    assert fix in found
    initial = subprocess.run(["git", "-C", str(repo), "rev-list", "--max-parents=0", "HEAD"],
                             capture_output=True, text=True).stdout.strip()
    assert initial not in found, "commits before the previous release are outside the window"


def test_no_window_without_both_ends(tmp_path):
    repo, _ = fx.linear(tmp_path / "lin")
    assert by_release_window(repo, "", "v1.2", [PATH]) == []
    assert by_release_window(repo, "v1.1", "", [PATH]) == []


# --- where a lead came from travels with it ----------------------------------------

def test_a_commit_naming_the_advisory_is_the_strongest_source(tmp_path):
    repo, _ = fx.zero_padded_tags(tmp_path / "named")
    named = _amend_subject(repo, "fix path traversal (GHSA-x7jh-595q-wq82)")
    found = by_advisory_id(repo, ["GHSA-x7jh-595q-wq82"])
    assert [c.sha for c in found] == [named]
    assert found[0].source is Source.ADVISORY_RECORD
    assert "GHSA-x7jh-595q-wq82" in found[0].why


def test_a_stronger_source_is_not_overwritten_by_a_weaker_one(tmp_path):
    repo, _ = fx.zero_padded_tags(tmp_path / "both")
    named = _amend_subject(repo, "fix traversal (CVE-2020-1234)")
    got = shortlist(repo, advisory_ids=["CVE-2020-1234"], paths=[PATH],
                    previous_release="2024.06.02", fixed_release="HEAD")
    assert next(c for c in got if c.sha == named).source is Source.ADVISORY_RECORD


def test_unrelated_commits_touching_the_file_are_left_out(tmp_path):
    """Most commits touching a file are not fixes. Including them all would make the
    shortlist long enough to hide a wrong answer in."""
    repo, _ = fx.zero_padded_tags(tmp_path / "noise")
    _amend_subject(repo, "bump version")
    got = shortlist(repo, advisory_ids=[], paths=[PATH])
    assert "bump version" not in {c.subject for c in got}


def test_the_shortlist_is_capped(tmp_path):
    repo, _ = fx.linear(tmp_path / "lin")
    got = shortlist(repo, advisory_ids=[], paths=[PATH],
                    previous_release="v1.0", fixed_release="HEAD", cap=1)
    assert len(got) <= 1


def test_candidates_serialise_with_their_reason(tmp_path):
    repo, fix, _ = fx.backported(tmp_path / "bp")
    payload = by_touching_paths(repo, [PATH])[0].to_json()
    assert set(payload) == {"sha", "subject", "committed", "files", "source", "why"}
    assert payload["why"]
