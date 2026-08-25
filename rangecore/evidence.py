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
from version import InvalidVersion, V


class Tier(enum.Enum):
    """What justified a verdict, ordered by how much it is worth."""

    EXACT_PATCH = "exact_patch"            # the fix applies in reverse at this release
    BACKPORT = "backport"                  # a patch-id equivalent is contained here
    RELEASE_REFERENCE = "release_reference"  # not yet gathered
    TEST_ADDED = "test_added"                # not yet gathered
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

        Every release we call FIXED has to be corroborated by two independent tiers,
        and no release may be UNKNOWN. One unresolved release is enough to make the
        boundary a guess, and a guess that narrows is the failure this project exists
        to avoid.
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
                   containing: frozenset[str] = frozenset()) -> ReleaseVerdict:
    """One release, weighed.

    `containing` is the set of releases that hold a patch-id equivalent of the fix, as
    reported by cherry-pick detection. It is what distinguishes a maintenance release
    that was deliberately patched from one that merely looks similar.
    """
    tiers: list[Tier] = []
    notes: list[str] = []

    if backports is not None and version in containing:
        equivalent = next(
            (e for e in backports.equivalents if version in e.releases), None)
        if equivalent is not None:
            tiers.append(Tier.EXACT_PATCH if equivalent.is_the_fix else Tier.BACKPORT)
            notes.append(
                f"contains {equivalent.sha[:10]}"
                + ("" if equivalent.is_the_fix else " (cherry-picked)"))

    if probe is not None:
        if probe.presence is Presence.PRESENT:
            if Tier.EXACT_PATCH not in tiers:
                tiers.append(Tier.EXACT_PATCH)
            notes.append("fix applies in reverse")
        elif probe.presence is Presence.ABSENT:
            # Sound on its own: the pre-fix code applies forward, so it is here.
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

    UNKNOWN counts as affected here. That is the pessimistic reading and it is chosen
    on purpose: an unresolved release inside a run must not silently split a range and
    hand a consumer a narrower one than the evidence supports.
    """
    ordered = sorted(verdicts, key=lambda v: _sortable(v.version))
    intervals: list[Interval] = []
    start: str | None = None
    for verdict in ordered:
        affected = verdict.status is not Status.FIXED
        if affected and start is None:
            start = verdict.version
        elif not affected and start is not None:
            intervals.append(Interval(start, verdict.version))
            start = None
    if start is not None:
        intervals.append(Interval(start, None))
    return tuple(intervals)


def assess(releases, probes, backports: BackportMap | None) -> Assessment:
    """Every release, weighed and then drawn as intervals."""
    containing = frozenset(backports.release_lines) if backports else frozenset()
    verdicts = tuple(
        assess_release(r, probes.get(r), backports, containing)
        for r in sorted(releases, key=_sortable)
    )
    return Assessment(verdicts=verdicts, intervals=to_intervals(verdicts))
