"""Differential test: the hand-rolled PEP 440 against the reference implementation.

rangecore is dependency-free because it runs in a sandbox with no installer. That is a
deployment constraint, not a licence to be approximately right about version ordering,
so the implementation is checked against `packaging` -- which is not a runtime
dependency and is only imported here.

Skipped when `packaging` is absent, and when the pinned snapshot has not been fetched.
Both are ordinary states for a fresh clone, and neither should fail a test run.
"""

import json
import pathlib
import random
import sys
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))

from version import InvalidVersion, V  # noqa: E402

packaging_version = pytest.importorskip("packaging.version")
SNAPSHOT = ROOT / "bench" / ".cache" / "osv-pypi.zip"
pytestmark = pytest.mark.skipif(
    not SNAPSHOT.exists(),
    reason="pinned OSV snapshot not fetched; run bench/select_corpus.py first",
)


def _published_versions() -> list[str]:
    """Every version string OSV publishes for PyPI, from the pinned snapshot."""
    found: set[str] = set()
    with zipfile.ZipFile(SNAPSHOT) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            record = json.loads(zf.read(name))
            for affected in record.get("affected", []):
                if affected.get("package", {}).get("ecosystem") != "PyPI":
                    continue
                found.update(affected.get("versions") or [])
                for rng in affected.get("ranges", []):
                    if rng.get("type") != "ECOSYSTEM":
                        continue
                    for event in rng.get("events", []):
                        found.update(v for v in event.values() if isinstance(v, str))
    found.discard("0")
    return sorted(found)


def _both(raw: str):
    try:
        mine = V(raw)
    except InvalidVersion:
        mine = None
    try:
        ref = packaging_version.Version(raw)
    except packaging_version.InvalidVersion:
        ref = None
    return mine, ref


def test_the_same_strings_are_accepted_and_refused():
    """Disagreeing about what is a version is worse than disagreeing about order: one
    side would score an advisory the other would abstain on."""
    disagreed = [
        raw for raw in _published_versions()
        if (lambda m, r: (m is None) != (r is None))(*_both(raw))
    ]
    assert disagreed == [], f"{len(disagreed)} strings parse differently, e.g. {disagreed[:5]}"


def test_ordering_agrees_across_the_published_corpus():
    """Sampled rather than exhaustive: 41k versions is 850 million pairs. A fixed seed
    keeps a failure reproducible."""
    # Both must be present. Filtering on the local parser alone would let a reference
    # None through, and the comparison below would then raise TypeError instead of
    # failing with the parity assertion that explains what actually diverged. Test order
    # is not guaranteed, so this cannot lean on the parity test running first.
    parsed = [(m, r) for m, r in map(_both, _published_versions())
              if m is not None and r is not None]
    assert len(parsed) > 10_000, "snapshot looks truncated"

    rng = random.Random(0)
    for _ in range(20_000):
        (ma, ra), (mb, rb) = rng.choice(parsed), rng.choice(parsed)
        assert (ma < mb) == (ra < rb), f"order differs: {ma.raw!r} vs {mb.raw!r}"
        assert (ma == mb) == (ra == rb), f"equality differs: {ma.raw!r} vs {mb.raw!r}"
