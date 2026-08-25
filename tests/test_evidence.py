"""Weighing probe results, and refusing to weigh them when they say nothing."""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "tests"))

import gitfixture as fx  # noqa: E402
from backport import find_equivalents  # noqa: E402
from evidence import Status, Tier, assess, assess_release, to_intervals  # noqa: E402
from tree import Presence, Probe, Reason, Repo  # noqa: E402

PATH = "pkg/loader.py"


def _repo(path):
    r = Repo.__new__(Repo)
    r.url, r.path = str(path), path
    return r


def _verdict(version, status, tiers):
    from evidence import ReleaseVerdict
    return ReleaseVerdict(version, status, tuple(tiers), "")


# --- the correction that matters ------------------------------------------------
# An earlier version treated any FIXED as not-affected, so one prober could narrow the
# range by itself. Requiring corroboration only at the filing gate was too late: the
# interval is what gets reported and read, and it had already been narrowed.

def test_a_single_tier_does_not_narrow_the_interval():
    verdicts = [
        _verdict("1.0", Status.AFFECTED, [Tier.EXACT_PATCH]),
        _verdict("1.1", Status.FIXED, [Tier.EXACT_PATCH]),        # one observation only
        _verdict("1.2", Status.FIXED, [Tier.EXACT_PATCH, Tier.COMMIT_CONTAINED]),
    ]
    assert to_intervals(verdicts) == (
        __import__("evidence").Interval("1.0", "1.2"),
    ), "1.1 must stay inside the affected set until a second observation agrees"


def test_two_agreeing_observations_do_narrow_it():
    verdicts = [
        _verdict("1.0", Status.AFFECTED, [Tier.EXACT_PATCH]),
        _verdict("1.1", Status.FIXED, [Tier.EXACT_PATCH, Tier.BACKPORT]),
    ]
    assert to_intervals(verdicts)[0].fixed == "1.1"


def test_unknown_counts_as_affected():
    verdicts = [
        _verdict("1.0", Status.UNKNOWN, [Tier.UNKNOWN]),
        _verdict("1.1", Status.FIXED, [Tier.EXACT_PATCH, Tier.COMMIT_CONTAINED]),
    ]
    assert to_intervals(verdicts)[0].introduced == "1.0"


# --- the two probers are independent evidence ------------------------------------

def test_the_original_fix_release_is_corroborated_by_both_probers():
    """Recording both under one tier made two probers agreeing look like one prober
    speaking twice, and corroboration was permanently undercounted."""
    probe = Probe("2.0", PATH, Presence.PRESENT)
    from backport import BackportMap, Equivalent
    bm = BackportMap(fix="a" * 40, patch_id="p",
                     equivalents=(Equivalent("a" * 40, "fix", ("2.0",), True),))
    verdict = assess_release("2.0", probe, bm, frozenset({"2.0"}))
    assert verdict.status is Status.FIXED
    assert set(verdict.tiers) == {Tier.EXACT_PATCH, Tier.COMMIT_CONTAINED}
    assert verdict.corroborated is True


def test_a_cherry_picked_release_is_corroborated_too():
    from backport import BackportMap, Equivalent
    bm = BackportMap(fix="a" * 40, patch_id="p",
                     equivalents=(Equivalent("b" * 40, "fix", ("1.4.7",), False),))
    verdict = assess_release("1.4.7", Probe("1.4.7", PATH, Presence.PRESENT), bm,
                             frozenset({"1.4.7"}))
    assert set(verdict.tiers) == {Tier.EXACT_PATCH, Tier.BACKPORT}
    assert verdict.corroborated is True


# --- affected is safe to conclude alone ------------------------------------------

def test_pre_fix_code_present_is_affected_on_its_own():
    """`git apply` succeeding forward means the vulnerable code is literally there.
    Widening leaves an alert nobody needed; narrowing tells someone that vulnerable
    software is safe. Only one of those deserves corroboration."""
    verdict = assess_release("1.0", Probe("1.0", PATH, Presence.ABSENT), None)
    assert verdict.status is Status.AFFECTED


def test_an_indeterminate_probe_is_unknown_not_affected():
    verdict = assess_release("2.0", Probe("2.0", PATH, Presence.INDETERMINATE, Reason.DIVERGED),
                             None)
    assert verdict.status is Status.UNKNOWN
    assert "diverged" in verdict.reason


# --- end to end, on a real history ------------------------------------------------

def test_the_backport_produces_two_intervals(tmp_path):
    repo, fix, _ = fx.backported(tmp_path / "bp")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    tags = subprocess.run(["git", "-C", str(repo), "tag"],
                          capture_output=True, text=True).stdout.split()
    result = assess(tags, {t: r.presence(patch, t, PATH) for t in tags},
                    find_equivalents(repo, fix, [PATH]))
    assert result.disjoint is True
    assert [(i.introduced, i.fixed) for i in result.intervals] == [
        ("v1.0", "v1.4.7"), ("v1.5", "v2.0"),
    ]
    assert result.fileable is True


def test_a_linear_history_produces_one_interval(tmp_path):
    repo, fix = fx.linear(tmp_path / "lin")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    tags = subprocess.run(["git", "-C", str(repo), "tag"],
                          capture_output=True, text=True).stdout.split()
    result = assess(tags, {t: r.presence(patch, t, PATH) for t in tags},
                    find_equivalents(repo, fix, [PATH]))
    assert result.disjoint is False
    assert result.intervals[0].fixed == "v1.2"


def test_one_unknown_release_makes_the_whole_thing_unfileable(tmp_path):
    repo, fix = fx.linear(tmp_path / "lin")
    r = _repo(repo)
    patch = r.patch_for(fix, PATH)
    tags = subprocess.run(["git", "-C", str(repo), "tag"],
                          capture_output=True, text=True).stdout.split()
    probes = {t: r.presence(patch, t, PATH) for t in tags}
    probes["v1.1"] = Probe("v1.1", PATH, Presence.INDETERMINATE, Reason.DIVERGED)
    result = assess(tags, probes, find_equivalents(repo, fix, [PATH]))
    assert "v1.1" in result.unknowns
    assert result.fileable is False
