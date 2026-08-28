"""From probes to a verdict per release, and from verdicts to intervals.

Two probers answer different questions. Tree-presence asks whether the post-fix code
is at a release; cherry-pick detection asks whether the same change was deliberately
applied there. This module decides what those answers are worth, and refuses to decide
when they are worth nothing.

THE ASYMMETRY THAT SHAPES EVERYTHING HERE.

A wrong narrowing and a wrong widening are not the same mistake. Widening leaves a
consumer with an alert they did not need -- annoying, and the status quo. Narrowing
tells a consumer that software carrying a live vulnerability is safe, in a register
their scanner trusts, under our name. Only one of those is worth being careful about,
and it is not the one that looks careless.

So the caution is applied in one direction. Concluding AFFECTED from tree-presence
alone is sound: `git apply` succeeding forward means the pre-fix code is literally
present, byte for byte. Concluding FIXED is where corroboration is demanded, and where
a boundary that removes versions from the affected set needs a second independent
tier before it may be filed at all.

Anything the probers cannot settle becomes UNKNOWN and is then treated as affected for
the purpose of drawing intervals -- deliberately the pessimistic reading. An
abstention is recorded so it stays visible, but it never quietly shrinks a range.
"""

from __future__ import annotations

import dataclasses
import enum

from backport import BackportMap
from tree import Presence, Probe
from version import InvalidVersion, V, VersionSet


class Tier(enum.Enum):
    """What was observed, named by the observation rather than by the conclusion.

    EXACT_PATCH and COMMIT_CONTAINED are genuinely independent: one is a statement
    about the file at a ref, the other about the commit graph reaching it. A squash or
    a rebase can break the second while the first still holds. Recording them under one
    name -- which the first version of this did -- makes two probers agreeing look like
    one prober speaking twice, and corroboration is then permanently undercounted.
    """

    EXACT_PATCH = "exact_patch"            # the fix applies in reverse at this release
    COMMIT_CONTAINED = "commit_contained"  # the fix commit itself is an ancestor
    BACKPORT = "backport"                  # a patch-id equivalent, not the original
    RELEASE_REFERENCE = "release_reference"  # not yet gathered
    TEST_ADDED = "test_added"              # the fix's test is present at this release
    BEHAVIORAL_PROBE = "behavioral_probe"    # a veto only -- never justifies a boundary
    UNKNOWN = "unknown"


class Status(enum.Enum):
    AFFECTED = "affected"
    FIXED = "fixed"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class ReleaseVerdict:
    version: str
    status: Status
    tiers: tuple[Tier, ...]
    reason: str

    @property
    def corroborated(self) -> bool:
        """Two independent tiers agree. Required before a narrowing may be filed."""
        return len({t for t in self.tiers if t is not Tier.UNKNOWN}) >= 2

    def to_json(self) -> dict:
        return {"version": self.version, "status": self.status.value,
                "tiers": [t.value for t in self.tiers], "reason": self.reason,
                "corroborated": self.corroborated}


@dataclasses.dataclass(frozen=True)
class Interval:
    """Half-open, matching how OSV writes a range: `introduced` is affected, `fixed`
    is not. `fixed` is None when the affected set runs to the newest release."""

    introduced: str
    fixed: str | None

    def to_json(self) -> dict:
        return {"introduced": self.introduced, "fixed": self.fixed}


@dataclasses.dataclass(frozen=True)
class Assessment:
    verdicts: tuple[ReleaseVerdict, ...]
    intervals: tuple[Interval, ...]

    @property
    def unknowns(self) -> tuple[str, ...]:
        return tuple(v.version for v in self.verdicts if v.status is Status.UNKNOWN)

    @property
    def disjoint(self) -> bool:
        """More than one interval: the affected set has a hole in it, and a single
        published range has nowhere to put the second piece."""
        return len(self.intervals) > 1

    @property
    def fileable(self) -> bool:
        """May this be filed as a narrowing?

        Every release called FIXED has to be corroborated, and no release may be
        UNKNOWN. One unresolved release is enough to make the boundary a guess, and a
        guess that narrows is the failure this project exists to avoid.

        The intervals are already computed under the same rule, so this is a second
        statement of it rather than the only one -- deliberately, because the interval
        is what a reader sees and the flag is what the write tool consults.
        """
        if self.unknowns:
            return False
        return all(v.corroborated for v in self.verdicts if v.status is Status.FIXED)

    def to_json(self) -> dict:
        return {"intervals": [i.to_json() for i in self.intervals],
                "disjoint": self.disjoint, "fileable": self.fileable,
                "unknowns": list(self.unknowns),
                "verdicts": [v.to_json() for v in self.verdicts]}


def _sortable(version: str):
    try:
        return (0, V(version)._k, "")
    except InvalidVersion:
        return (1, (), version)


def assess_release(version: str, probe: Probe | None, backports: BackportMap | None,
                   containing: VersionSet | None = None,
                   test_probe: Probe | None = None) -> ReleaseVerdict:
    """One release, weighed.

    `containing` is the set of releases that hold a patch-id equivalent of the fix, as
    reported by cherry-pick detection. It is what distinguishes a maintenance release
    that was deliberately patched from one that merely looks similar.

    It is a VersionSet rather than a set of strings, and that is not a detail: the
    releases come from git tags (v2.10.0) and the version being assessed comes from
    PyPI (2.10.0). Comparing them as strings found nothing on every real advisory, so
    the commit-graph tier never fired, nothing was ever corroborated, and no correction
    could ever be filed.
    """
    containing = containing if containing is not None else VersionSet()
    tiers: list[Tier] = []
    notes: list[str] = []

    if backports is not None and version in containing:
        equivalent = next(
            (e for e in backports.equivalents if version in VersionSet(e.releases)), None)
        if equivalent is not None:
            tiers.append(Tier.COMMIT_CONTAINED if equivalent.is_the_fix else Tier.BACKPORT)
            notes.append(
                f"contains {equivalent.sha[:10]}"
                + ("" if equivalent.is_the_fix else " (cherry-picked)"))

    # A test that arrives with a fix is a separate artifact in a separate file, so its
    # presence is an observation the source probe cannot make. This matters most
    # exactly where the commit-graph tier goes silent: a cherry-pick resolved through a
    # conflict is edited, its patch-id stops matching, and the release carrying the fix
    # has only one observation left. On ansible that left 2.8.14 and 2.9.12 detected as
    # fixed and unable to be acted on.
    if test_probe is not None and test_probe.presence is Presence.PRESENT:
        tiers.append(Tier.TEST_ADDED)
        notes.append("the fix's test is present")

    if probe is not None:
        if probe.presence is Presence.PRESENT:
            tiers.append(Tier.EXACT_PATCH)
            notes.append("fix applies in reverse")
        elif probe.presence is Presence.ABSENT:
            # Sound on its own: the pre-fix code applies forward, so it is here. A test
            # present alongside vulnerable code does not rescue it -- the test may have
            # arrived separately, and the code is what runs.
            return ReleaseVerdict(version, Status.AFFECTED, (Tier.EXACT_PATCH,),
                                  "pre-fix code present")
        else:
            notes.append(f"probe indeterminate ({probe.reason.value if probe.reason else '?'})")

    if tiers:
        return ReleaseVerdict(version, Status.FIXED, tuple(tiers), "; ".join(notes))
    return ReleaseVerdict(version, Status.UNKNOWN, (Tier.UNKNOWN,),
                          "; ".join(notes) or "no evidence gathered")


def to_intervals(verdicts) -> tuple[Interval, ...]:
    """Draw the affected set.

    Two things count as affected: UNKNOWN, and FIXED on a single tier.

    The second is the correction that matters. An earlier version treated any FIXED as
    not-affected, so one prober could narrow the range on its own -- which is precisely
    the failure this module's opening paragraph says it exists to prevent. Requiring
    corroboration only at the filing gate was too late: the interval is what gets
    reported, scored, and read, and it had already been narrowed by then.

    So a release leaves the affected set when two independent observations agree, and
    not before. Everything else stays in, which is the pessimistic reading and the
    intended one.
    """
    ordered = sorted(verdicts, key=lambda v: _sortable(v.version))
    intervals: list[Interval] = []
    start: str | None = None
    for verdict in ordered:
        affected = not (verdict.status is Status.FIXED and verdict.corroborated)
        if affected and start is None:
            start = verdict.version
        elif not affected and start is not None:
            intervals.append(Interval(start, verdict.version))
            start = None
    if start is not None:
        intervals.append(Interval(start, None))
    return tuple(intervals)


def assess(releases, probes, backports: BackportMap | None,
           test_probes: dict | None = None) -> Assessment:
    """Every release, weighed and then drawn as intervals."""
    containing = VersionSet(backports.release_lines if backports else ())
    tests = test_probes or {}
    verdicts = tuple(
        assess_release(r, probes.get(r), backports, containing, tests.get(r))
        for r in sorted(releases, key=_sortable)
    )
    return Assessment(verdicts=verdicts, intervals=to_intervals(verdicts))
