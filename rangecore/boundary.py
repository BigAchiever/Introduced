"""From intervals to a correction, expressed in the register's own vocabulary.

The probers work on git tags. A published advisory works on PyPI versions, and the two
are spelled differently often enough that translating between them is a step rather
than a formality: certifi tags `2024.07.04` and ships `2024.7.4`.

So a boundary is never constructed from a tag. Every version this module emits is one
that already appears in the advisory's own published version list -- a boundary naming
a version PyPI never shipped is not a correction, it is a new error, and no reviewer
downstream would be positioned to catch it.

WHAT THE DELTA IS FOR.

A correction is only meaningful next to what it corrects, so the output is not a range
but a difference: which published versions the record currently calls affected, which
ones the evidence calls affected, and the two sets that disagree.

Those two sets are not equally serious. Versions this would ADD to the affected set
widen the alert -- someone is told to look at software they were not told about
before, which is the failure mode of every scanner already. Versions this would REMOVE
tell a consumer that software they are running, which their tooling currently flags,
is safe. That claim goes into a register their scanner trusts, under our name. Removal
is the direction that has to earn it.
"""

from __future__ import annotations

import dataclasses

from evidence import Assessment, Interval
from version import InvalidVersion, V, in_range


def _key(version: str):
    try:
        return (0, V(version)._k, "")
    except InvalidVersion:
        return (1, (), version)


def translate(intervals, published: list[str]) -> tuple[Interval, ...]:
    """Re-express tag-space intervals in the versions the advisory actually lists.

    A bound that matches no published version is dropped to None rather than guessed
    at: an open interval is honest about not knowing where it ends, while an invented
    boundary looks exactly like a measured one.
    """
    lookup: dict = {}
    for candidate in published:
        try:
            lookup.setdefault(V(candidate), candidate)
        except InvalidVersion:
            continue

    def published_form(bound: str | None) -> str | None:
        if bound is None:
            return None
        try:
            return lookup.get(V(bound))
        except InvalidVersion:
            return None

    out = []
    for interval in intervals:
        introduced = published_form(interval.introduced)
        if introduced is None:
            continue          # the interval starts at a tag that was never released
        out.append(Interval(introduced, published_form(interval.fixed)))
    return tuple(out)


def affected_under(intervals, published: list[str]) -> set[str]:
    """Which published versions these intervals call affected."""
    hit = set()
    for version in published:
        for interval in intervals:
            try:
                if in_range(version, interval.introduced, interval.fixed):
                    hit.add(version)
                    break
            except InvalidVersion:
                continue
    return hit


@dataclasses.dataclass(frozen=True)
class Correction:
    published_intervals: tuple[Interval, ...]
    proposed_intervals: tuple[Interval, ...]
    removed: tuple[str, ...]        # currently flagged, evidence says not affected
    added: tuple[str, ...]          # not flagged, evidence says affected
    unknowns: tuple[str, ...]
    fileable: bool

    @property
    def narrows(self) -> bool:
        return bool(self.removed)

    @property
    def widens(self) -> bool:
        return bool(self.added)

    @property
    def is_noop(self) -> bool:
        """The record already matches the evidence. The correct outcome for most
        advisories, and the one that makes a false-correction rate measurable."""
        return not self.removed and not self.added

    @property
    def needs_disjoint_range(self) -> bool:
        """More than one interval, which a single published range cannot hold."""
        return len(self.proposed_intervals) > 1

    def to_json(self) -> dict:
        return {
            "published": [i.to_json() for i in self.published_intervals],
            "proposed": [i.to_json() for i in self.proposed_intervals],
            "removed": list(self.removed),
            "added": list(self.added),
            "narrows": self.narrows,
            "widens": self.widens,
            "is_noop": self.is_noop,
            "needs_disjoint_range": self.needs_disjoint_range,
            "unknowns": list(self.unknowns),
            "fileable": self.fileable,
        }


def emit(assessment: Assessment, published_intervals, published_versions: list[str]) -> Correction:
    """Compare what the record says against what the evidence supports.

    `fileable` carries the assessment's own gate forward and adds one of its own: a
    correction that removes versions is refused unless every release it touches was
    corroborated. Widening needs no such gate. The asymmetry is the whole point --
    telling someone to check software they were not worried about costs them an hour,
    and telling them vulnerable software is safe costs them the thing the advisory
    exists to prevent.
    """
    proposed = translate(assessment.intervals, published_versions)
    now = affected_under(published_intervals, published_versions)
    then = affected_under(proposed, published_versions)

    removed = tuple(sorted(now - then, key=_key))
    added = tuple(sorted(then - now, key=_key))

    fileable = assessment.fileable and not assessment.unknowns
    if removed and not fileable:
        fileable = False

    return Correction(
        published_intervals=tuple(published_intervals),
        proposed_intervals=proposed,
        removed=removed,
        added=added,
        unknowns=assessment.unknowns,
        fileable=fileable,
    )
