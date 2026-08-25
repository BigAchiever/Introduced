"""One advisory, end to end, with a record of every decision.

The pieces are deliberately joined here rather than calling each other, so that the
one step needing judgement -- which of several plausible commits an advisory is
actually describing -- is a parameter rather than a dependency.

`select` is that parameter. The default picks by source strength and is fully
deterministic, which is what lets the whole benchmark run offline with no model, no
key and no network. Supplying a model-backed selector changes which commit is
nominated and nothing else: everything downstream still verifies against the tree, so
a wrong nomination produces an abstention rather than a wrong boundary.

That is the shape the whole design rests on. The model nominates. Nothing trusts it.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Callable

from backport import BackportMap, find_equivalents
from boundary import Correction, emit
from candidates import Candidate, shortlist
from evidence import Assessment, Interval, assess
from tree import GitError, Presence, Repo
from version import InvalidVersion, V


@dataclasses.dataclass(frozen=True)
class Decision:
    """Why one candidate was taken and the others were not.

    Written for a reviewer of the eventual pull request, who has to be able to see the
    rejected commits without re-running anything. A correction that only shows the
    commit it chose is asking to be trusted.
    """

    considered: tuple[Candidate, ...]
    selected: str | None
    rejected: tuple[tuple[str, str], ...]     # (sha, why not)
    note: str = ""

    def to_json(self) -> dict:
        return {"considered": [c.to_json() for c in self.considered],
                "selected": self.selected,
                "rejected": [{"sha": s, "why": w} for s, w in self.rejected],
                "note": self.note}


@dataclasses.dataclass(frozen=True)
class Investigation:
    advisory: str
    package: str
    outcome: str                    # settled | abstained | failed
    decision: Decision
    correction: Correction | None
    assessment: Assessment | None
    error: str = ""

    def to_json(self) -> dict:
        return {"advisory": self.advisory, "package": self.package,
                "outcome": self.outcome, "decision": self.decision.to_json(),
                "correction": self.correction.to_json() if self.correction else None,
                "assessment": self.assessment.to_json() if self.assessment else None,
                "error": self.error}


Selector = Callable[[list[Candidate], dict], Candidate | None]


def first_by_source(candidates: list[Candidate], advisory: dict) -> Candidate | None:
    """The default nomination: strongest source, then earliest.

    Not clever, and deliberately so. It is the baseline a model-backed selector has to
    beat, and having it means the benchmark measures the difference a model makes
    rather than assuming one.
    """
    return candidates[0] if candidates else None


def _released_versions(advisory: dict) -> list[str]:
    return [v for v in advisory.get("versions", []) if v]


def _previous_release(versions: list[str], fixed: str | None) -> str | None:
    """The release immediately before the published fix version.

    The lower edge of the window the fix must be inside. Without a fix version there
    is no window, and the wording strategies are all that remain.
    """
    if not fixed:
        return None
    try:
        target = V(fixed)
    except InvalidVersion:
        return None
    earlier = []
    for candidate in versions:
        try:
            parsed = V(candidate)
        except InvalidVersion:
            continue
        if parsed < target:
            earlier.append((parsed, candidate))
    return max(earlier)[1] if earlier else None


def investigate(advisory: dict, cache: Path, *, select: Selector = first_by_source,
                paths: list[str] | None = None) -> Investigation:
    """Run one advisory. Never raises: a failure is an outcome, not an exception.

    Twenty-five of these run unattended, and one unreachable repository must not take
    the other twenty-four with it.
    """
    ghsa = advisory.get("ghsa", "?")
    package = advisory.get("package", "?")
    empty = Decision(considered=(), selected=None, rejected=())

    try:
        repo = Repo(advisory["repo"], cache)
        repo.clone()
    except (GitError, KeyError) as exc:
        return Investigation(ghsa, package, "failed", empty, None, None, str(exc)[:200])

    versions = _released_versions(advisory)
    fixed = (advisory.get("fixed") or [None])[0]
    previous = _previous_release(versions, fixed)

    # Resolve both ends before building the window. A published version and the tag
    # that carries it are spelled differently often enough that this is the third place
    # the same mistake has been made: checking that a ref resolves and then using the
    # unresolved string anyway. open-webui tags v0.9.6 and ships 0.9.6, so the span
    # "0.9.5..0.9.6" named nothing and the window came back empty.
    window = (repo.resolve(previous) if previous else None,
              repo.resolve(fixed) if fixed else None)

    candidates = shortlist(
        repo.path,
        advisory_ids=[ghsa, *advisory.get("cves", [])],
        paths=paths or [],
        previous_release=window[0],
        fixed_release=window[1],
    )
    if not candidates:
        return Investigation(ghsa, package, "abstained",
                             Decision((), None, (), "no candidate commits found"),
                             None, None)

    chosen = select(candidates, advisory)
    if chosen is None:
        return Investigation(ghsa, package, "abstained",
                             Decision(tuple(candidates), None, (), "selector chose none"),
                             None, None)

    rejected = tuple((c.sha, f"not selected; {c.why}") for c in candidates if c.sha != chosen.sha)
    decision = Decision(tuple(candidates), chosen.sha, rejected)

    try:
        patch = repo.patch_for(chosen.sha, chosen.files[0]) if chosen.files else ""
    except GitError as exc:
        return Investigation(ghsa, package, "failed", decision, None, None, str(exc)[:200])
    if not patch.strip():
        return Investigation(ghsa, package, "abstained",
                             dataclasses.replace(decision, note="candidate changed nothing"),
                             None, None)

    path = chosen.files[0]
    probes = {v: repo.presence(patch, v, path) for v in versions}
    backports: BackportMap = find_equivalents(repo.path, chosen.sha, [path])
    assessment = assess(versions, probes, backports)

    published = [Interval(
        (advisory.get("introduced") or ["0"])[0],
        fixed,
    )]
    correction = emit(assessment, published, versions)

    # Settled means the correction stands on evidence, not that every release in a
    # decade of history could be resolved. A no-op is settled too: agreeing with the
    # record is a result, and it is what makes a false-correction rate measurable.
    settled = correction.fileable
    return Investigation(ghsa, package, "settled" if settled else "abstained",
                         decision, correction, assessment)
