"""Tests for the corpus selection rule.

The first two cases are not hypothetical. Both rules they cover were written wrong
first, and both would have silently produced a corpus that measured nothing.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "bench"))

import select_corpus as sc  # noqa: E402


# --- the GIT/ECOSYSTEM conflation ------------------------------------------------
# PYSEC records a GIT range whose events are commit SHAs alongside an ECOSYSTEM range
# whose events are versions. Counting across both types turned an ordinary record into
# a disjoint one: 24.9% became 34.6%, and 6 candidates became 608.

PYSEC_SHAPED = {
    "ranges": [
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "fa1308061802ac7b7d"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.61.1"}]},
    ]
}

def test_eco_events_ignores_git_ranges():
    assert sc.eco_events(PYSEC_SHAPED) == [{"introduced": "0"}, {"fixed": "1.61.1"}]

def test_git_range_alone_is_not_disjoint():
    assert sc.is_disjoint(PYSEC_SHAPED) is False

def test_git_fix_shas_are_kept_as_leads():
    assert sc.git_fix_shas(PYSEC_SHAPED) == ["fa1308061802ac7b7d"]

def test_genuine_two_interval_range_is_disjoint():
    ansible_shaped = {"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "2.7.17"},
        {"introduced": "2.8.0"}, {"fixed": "2.8.9"},
    ]}]}
    assert sc.is_disjoint(ansible_shaped) is True


# --- the reference-type rule -----------------------------------------------------
# `type: FIX` appears zero times in GHSA-reviewed records; 4,854 commit URLs sit under
# `type: WEB`. Matching on type would have caught none of them.

def test_commit_url_is_detected_under_type_web():
    record = {"references": [
        {"type": "WEB", "url": "https://github.com/urllib3/urllib3/commit/01220354d389cd05474713f8c982d05c9b17aafb"},
    ]}
    assert sc.cites_fix_commit(record) is True

def test_plain_web_reference_is_not_a_commit():
    record = {"references": [
        {"type": "WEB", "url": "https://lists.debian.org/debian-lts-announce/2023/10/msg00012.html"},
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-43804"},
    ]}
    assert sc.cites_fix_commit(record) is False

def test_gitlab_commit_url_is_detected():
    record = {"references": [
        {"type": "WEB", "url": "https://gitlab.com/group/proj/-/commit/deadbeef1234567"},
    ]}
    assert sc.cites_fix_commit(record) is True


# --- repository resolution -------------------------------------------------------

def test_package_reference_wins_over_an_incidental_github_link():
    record = {"references": [
        {"type": "WEB", "url": "https://github.com/someone/blog-post"},
        {"type": "PACKAGE", "url": "https://github.com/urllib3/urllib3"},
    ]}
    assert sc.resolve_repo(record) == "https://github.com/urllib3/urllib3"

def test_dot_git_suffix_is_stripped():
    record = {"references": [{"type": "PACKAGE", "url": "https://github.com/a/b.git"}]}
    assert sc.resolve_repo(record) == "https://github.com/a/b"


# --- properties of the committed corpus ------------------------------------------

CORPUS = pathlib.Path(__file__).resolve().parents[1] / "bench" / "corpus.json"

def _corpus():
    return json.loads(CORPUS.read_text())

def test_every_package_appears_once():
    """One project's release conventions must not dominate an arm."""
    packages = [e["package"] for e in _corpus()]
    assert len(packages) == len(set(packages))

def test_the_worked_example_is_never_held_out():
    """The advisory used as the worked example has been studied closely, so holding it
    out would not measure anything."""
    hard = [e for e in _corpus() if e.get("hard_case")]
    assert len(hard) == 1
    assert hard[0]["split"] == "dev"

def test_every_entry_has_an_arm_and_a_split():
    for entry in _corpus():
        assert entry["arm"] in {"A", "B", "C"}
        assert entry["split"] in {"dev", "heldout"}

def test_arm_c_advisories_cite_no_fix_commit():
    """Arm C exists because the archaeology has not been done. If a fix commit is
    already published there is nothing for the agent to establish."""
    for entry in _corpus():
        if entry["arm"] == "C":
            assert entry["cites_commit"] is False, entry["ghsa"]

def test_held_out_set_is_not_empty_in_any_arm():
    seen = {(e["arm"], e["split"]) for e in _corpus()}
    for arm in {e["arm"] for e in _corpus()}:
        assert (arm, "heldout") in seen, f"arm {arm} has no held-out entries"


# --- selection must be deterministic ---------------------------------------------

def _candidate(ghsa, package):
    return sc.Candidate(ghsa=ghsa, package=package, repo=f"https://github.com/x/{package}",
                        n_versions=10, versions=("0.9", "1.0"), introduced=("0",),
                        fixed=("1.0",), cites_commit=False, cves=())

def test_selection_is_order_independent():
    pool = [(_candidate(f"GHSA-{c}", f"pkg{i}"), None, "C")
            for i, c in enumerate("hgfedcba")]
    a, _ = sc.select(list(pool), {"C": 4})
    b, _ = sc.select(list(reversed(pool)), {"C": 4})
    assert [e["ghsa"] for e in a] == [e["ghsa"] for e in b]

def test_split_is_reproducible():
    entries = [{"ghsa": f"GHSA-{i:02d}", "arm": "C"} for i in range(10)]
    other = [dict(e) for e in reversed(entries)]
    sc.split_dev_heldout(entries, hard_case=None)
    sc.split_dev_heldout(other, hard_case=None)
    by_id = {e["ghsa"]: e["split"] for e in other}
    assert all(by_id[e["ghsa"]] == e["split"] for e in entries)


# --- probe eligibility must line up with the corpus it filters ------------------
# The first version of probe_eligibility.py zipped a dict against a differently-sorted
# map, so every verdict was attached to the wrong package: parso, a zero-dependency
# parser, came back with 74 dependencies. Nothing failed. The corpus would simply have
# reserved its probe slots for packages that cannot carry a probe.

ELIGIBLE = pathlib.Path(__file__).resolve().parents[1] / "bench" / "probe_eligible.json"

def test_eligibility_is_keyed_by_package_and_version():
    for key in json.loads(ELIGIBLE.read_text()):
        assert "@" in key, f"{key} is keyed by package alone; eligibility is per release"

def test_every_flagged_entry_is_eligible_at_its_own_fix_version():
    verdicts = json.loads(ELIGIBLE.read_text())
    for entry in _corpus():
        if not entry.get("probe_eligible"):
            continue
        key = f'{entry["package"]}@{entry["fixed"][0]}'
        assert verdicts.get(key, {}).get("eligible") is True, key

def test_enough_probe_capable_entries_to_clear_the_exit_test():
    """make probe-exit needs two differentials. Eligibility is an upper bound -- it is
    checked at the fix version only, and a probe also needs a wheel at the release
    before it -- so the corpus needs headroom, not exactly two."""
    n = sum(1 for e in _corpus() if e.get("probe_eligible"))
    assert n >= 4, f"only {n} probe-capable entries; the behavioural tier has no margin"
