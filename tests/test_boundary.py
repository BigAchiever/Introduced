"""Turning intervals into a correction, in the register's own vocabulary."""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "tests"))

import gitfixture as fx  # noqa: E402
from backport import find_equivalents  # noqa: E402
from boundary import affected_under, emit, translate  # noqa: E402
from evidence import Assessment, Interval, Status, Tier  # noqa: E402
from tree import Repo  # noqa: E402

PATH = "pkg/loader.py"
PUBLISHED = ["1.0", "1.4.6", "1.4.7", "1.5", "2.0"]


def _verdict(version, status, tiers):
    from evidence import ReleaseVerdict
    return ReleaseVerdict(version, status, tuple(tiers), "")


def _assessment(intervals, verdicts=()):
    return Assessment(verdicts=tuple(verdicts), intervals=tuple(intervals))


# --- never invent a version -------------------------------------------------------

def test_a_bound_matching_no_published_version_is_dropped_not_guessed():
    """An open interval says it does not know where the range ends. An invented bound
    looks exactly like a measured one, and nobody downstream is placed to catch it."""
    result = translate([Interval("1.0", "1.9.9")], PUBLISHED)
    assert result == (Interval("1.0", None),)


def test_an_interval_starting_at_an_unreleased_tag_is_dropped():
    assert translate([Interval("0.9", "1.5")], PUBLISHED) == ()


def test_tags_are_translated_to_the_spelling_pypi_uses():
    """certifi tags 2024.07.04 and ships 2024.7.4. The boundary has to carry the
    spelling the advisory uses, not the one the maintainer typed."""
    published = ["2024.6.2", "2024.7.4"]
    assert translate([Interval("2024.06.02", "2024.07.04")], published) == (
        Interval("2024.6.2", "2024.7.4"),
    )


def test_the_v_prefix_survives_translation():
    assert translate([Interval("v1.0", "v1.4.7")], PUBLISHED) == (Interval("1.0", "1.4.7"),)


# --- membership -------------------------------------------------------------------

def test_affected_under_is_half_open():
    hit = affected_under([Interval("1.0", "1.5")], PUBLISHED)
    assert "1.4.7" in hit and "1.5" not in hit


def test_two_intervals_leave_a_hole():
    hit = affected_under([Interval("1.0", "1.4.7"), Interval("1.5", "2.0")], PUBLISHED)
    assert hit == {"1.0", "1.4.6", "1.5"}


# --- the delta ---------------------------------------------------------------------

def test_a_record_that_already_matches_is_a_noop():
    """Arm B of the corpus. Without no-ops there is nothing a false-correction rate
    could be measured against."""
    proposed = _assessment([Interval("1.0", "1.5")])
    correction = emit(proposed, [Interval("1.0", "1.5")], PUBLISHED)
    assert correction.is_noop is True
    assert correction.narrows is False and correction.widens is False


def test_narrowing_is_reported_as_the_versions_it_would_unflag():
    proposed = _assessment([Interval("1.0", "1.4.7"), Interval("1.5", "2.0")])
    correction = emit(proposed, [Interval("0", "2.0")], PUBLISHED)
    assert correction.removed == ("1.4.7",)
    assert correction.narrows is True and correction.widens is False
    assert correction.needs_disjoint_range is True


def test_widening_is_reported_separately_from_narrowing():
    proposed = _assessment([Interval("1.0", None)])
    correction = emit(proposed, [Interval("1.0", "1.5")], PUBLISHED)
    assert correction.added == ("1.5", "2.0")
    assert correction.widens is True and correction.narrows is False


# --- the gate ----------------------------------------------------------------------

def test_an_unresolved_release_blocks_a_narrowing():
    """One release nobody could settle is enough to make a narrowing a guess."""
    proposed = Assessment(
        verdicts=(_verdict("1.4.7", Status.UNKNOWN, [Tier.UNKNOWN]),),
        intervals=(Interval("1.0", "1.4.7"), Interval("1.5", "2.0")),
    )
    correction = emit(proposed, [Interval("0", "2.0")], PUBLISHED)
    assert correction.narrows is True
    assert correction.fileable is False


def test_a_narrowing_backed_by_corroborated_verdicts_is_fileable():
    proposed = Assessment(
        verdicts=(
            _verdict("1.4.7", Status.FIXED, [Tier.EXACT_PATCH, Tier.BACKPORT]),
            _verdict("2.0", Status.FIXED, [Tier.EXACT_PATCH, Tier.COMMIT_CONTAINED]),
        ),
        intervals=(Interval("1.0", "1.4.7"), Interval("1.5", "2.0")),
    )
    assert emit(proposed, [Interval("0", "2.0")], PUBLISHED).fileable is True


# --- end to end ---------------------------------------------------------------------

def test_the_backport_produces_the_correction_this_project_is_for(tmp_path):
    repo, fix, _ = fx.backported(tmp_path / "bp")
    r = Repo.__new__(Repo)
    r.url, r.path = str(repo), repo
    patch = r.patch_for(fix, PATH)
    tags = subprocess.run(["git", "-C", str(repo), "tag"],
                          capture_output=True, text=True).stdout.split()
    from evidence import assess
    assessment = assess(tags, {t: r.presence(patch, t, PATH) for t in tags},
                        find_equivalents(repo, fix, [PATH]))

    correction = emit(assessment, [Interval("0", "2.0")], PUBLISHED)

    assert [(i.introduced, i.fixed) for i in correction.proposed_intervals] == [
        ("1.0", "1.4.7"), ("1.5", "2.0"),
    ]
    assert correction.removed == ("1.4.7",)
    assert correction.needs_disjoint_range is True
    assert correction.fileable is True
