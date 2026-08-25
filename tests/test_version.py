"""PEP 440 ordering, checked against the real thing.

Every boundary this project files rests on this comparison. A wrong answer here does
not fail anywhere downstream -- it produces a well-formed correction that is wrong,
which is the one outcome the whole design exists to prevent.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "rangecore"))

from version import InvalidVersion, V, in_range, parse  # noqa: E402


# --- the trap this module exists for -------------------------------------------
# OSV ECOSYSTEM ranges are PEP 440 ORDERING, not pip's specifier matching. Under
# ordering a pre-release sits below its own release, so "< 1.4.0" contains 1.4.0rc1.
# Under pip's rules it would not. Built on the wrong one, this project would disagree
# with the published record on every advisory whose boundary is a pre-release.

def test_a_prerelease_precedes_its_own_release():
    assert V("1.4.0rc1") < V("1.4.0")

def test_a_prerelease_is_inside_a_range_that_ends_at_its_release():
    assert in_range("1.4.0rc1", "0", "1.4.0") is True

def test_the_release_itself_is_outside_that_range():
    assert in_range("1.4.0", "0", "1.4.0") is False


# --- ordering --------------------------------------------------------------------

@pytest.mark.parametrize("lower,higher", [
    ("1.0.dev1", "1.0a1"),        # a dev release precedes the pre-releases
    ("1.0a1", "1.0a2"),
    ("1.0a2", "1.0b1"),
    ("1.0b1", "1.0rc1"),
    ("1.0rc1", "1.0"),
    ("1.0", "1.0.post1"),         # absent post is lower than any post
    ("1.0.post1.dev1", "1.0.post1"),
    ("1.0", "1.0.1"),
    ("1.9", "1.10"),              # numeric, not lexicographic
    ("99.0", "1!2.0"),            # an epoch outranks everything without one
    ("1.0", "1.0+local"),         # a local version sorts above its plain form
])
def test_ordering(lower, higher):
    assert V(lower) < V(higher), f"{lower} should sort below {higher}"


@pytest.mark.parametrize("a,b", [
    ("1.0", "1.0.0"),             # trailing zeros carry no meaning
    ("1.0", "1.0.0.0"),
    ("1.0a1", "1.0.alpha.1"),     # spelling is normalised
    ("1.0rc1", "1.0.c.1"),
    ("1.0.post1", "1.0-1"),       # the implicit post form
    ("1.0", "v1.0"),
    ("1.0", "  1.0  "),
])
def test_equality_after_normalisation(a, b):
    assert V(a) == V(b), f"{a} and {b} are the same version"


# --- refusal ---------------------------------------------------------------------
# A version this module cannot parse must raise, never sort. Ordering a version wrongly
# produces a boundary; refusing produces an abstention, and abstention is the design.

@pytest.mark.parametrize("bad", ["", "latest", "1.0.x", "not-a-version", "1..0", None])
def test_unparseable_versions_raise(bad):
    with pytest.raises(InvalidVersion):
        parse(bad)


# --- range membership ------------------------------------------------------------

def test_introduced_is_affected_and_fixed_is_not():
    assert in_range("1.0", "1.0", "2.0") is True
    assert in_range("2.0", "1.0", "2.0") is False

def test_below_introduced_is_unaffected():
    assert in_range("0.9", "1.0", "2.0") is False

def test_introduced_zero_means_from_the_beginning():
    assert in_range("0.0.1", "0", "2.0") is True

def test_last_affected_is_inclusive_unlike_fixed():
    assert in_range("2.0", "1.0", None, last_affected="2.0") is True
    assert in_range("2.0.1", "1.0", None, last_affected="2.0") is False

def test_an_unbounded_range_affects_everything_after_introduced():
    assert in_range("99.0", "1.0", None) is True

def test_fixed_and_last_affected_together_are_refused():
    with pytest.raises(ValueError):
        in_range("1.0", "0", "2.0", last_affected="2.0")


# --- the real corpus -------------------------------------------------------------

def test_every_boundary_in_the_corpus_parses():
    """If a published boundary cannot be parsed, that advisory cannot be scored, and
    finding that out here is better than finding it out mid-run."""
    import json
    corpus = json.loads((pathlib.Path(__file__).resolve().parents[1]
                         / "bench" / "corpus.json").read_text())
    for entry in corpus:
        for boundary in entry["introduced"] + entry["fixed"]:
            if boundary == "0":
                continue
            parse(boundary)
