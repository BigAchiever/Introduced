"""Which commits could be the fix, and why each one is on the list.

The model does not search the repository. It chooses from a shortlist that was built
here, deterministically, and every entry carries the reason it qualified.

That split is deliberate and it is the one place this design disagrees with the
obvious approach. The published comparison of twelve tools for this task found that
substituting model-selected commits for heuristic tracing cost 7.3 percentage points
of accuracy, and concluded that heuristic tracing remained more effective. Handing a
model a repository and asking it to find the fix is the version that measured worse.
Handing it a bounded, explained shortlist -- and then verifying whatever it picks
against the tree -- keeps the judgement where a model is genuinely better (reading
prose, weighing which of four plausible commits the advisory is describing) and keeps
the search where determinism is better.

WHERE A CANDIDATE CAME FROM IS PART OF THE CANDIDATE.

A commit whose own message names the advisory is a different kind of evidence from one
that merely touches a file the advisory mentions. The strength of the lead travels
with it, so a boundary can never be justified by something weaker than it looks.
"""

from __future__ import annotations

import dataclasses
import enum
import re
import subprocess
from pathlib import Path


class Source(enum.Enum):
    """How strong the lead is, strongest first.

    These are the values the write tool's schema also accepts, so a nomination that
    only ever appeared in text anyone can write cannot be laundered into a boundary
    by passing through this module.
    """

    ADVISORY_RECORD = "advisory_record"              # the commit names the advisory
    MAINTAINER_AUTHORED = "maintainer_authored"      # a release-tagging author
    DEFAULT_BRANCH_HISTORY = "default_branch_history"  # found by searching history
    LOW_TRUST_TEXT = "low_trust_text"                # an issue or PR comment said so


@dataclasses.dataclass(frozen=True)
class Candidate:
    sha: str
    subject: str
    committed: str                 # ISO date, for ordering against a release
    files: tuple[str, ...]
    source: Source
    why: str                       # the specific reason, not the category

    def to_json(self) -> dict:
        return {"sha": self.sha, "subject": self.subject, "committed": self.committed,
                "files": list(self.files), "source": self.source.value, "why": self.why}


# Ordered strongest first: a commit found by several strategies keeps the best one.
_SECURITY_WORDS = re.compile(
    r"\b(cve|ghsa|security|vulnerab|exploit|traversal|injection|xss|csrf|rce|"
    r"overflow|sanitis|sanitiz|escape|denial of service|dos)\b", re.I)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True, timeout=300)
    return result.stdout if result.returncode == 0 else ""


def _commits(repo: Path, *log_args: str, limit: int = 200) -> list[tuple[str, str, str, tuple[str, ...]]]:
    """(sha, subject, date, files) for a log query.

    Records are separated by an explicit RS byte rather than by blank lines. With
    --name-only git already puts a blank line between a commit's header and its file
    list, so splitting on blank lines cuts inside a record: the first commit parses,
    every later header arrives glued to the previous commit's files and is silently
    skipped. That failure returns a short list rather than an error, which is the worst
    shape a bug can have here -- a shortlist that is quietly missing the right answer.

    Unit separators delimit the fields, because commit subjects contain every printable
    character a person can type, tabs and pipes included.
    """
    out = _git(repo, "log", f"-{limit}", "--format=%x1e%H\x1f%s\x1f%cI",
               "--name-only", *log_args)
    entries = []
    for record in out.split("\x1e"):
        lines = [l for l in record.splitlines() if l.strip()]
        if not lines or "\x1f" not in lines[0]:
            continue
        sha, subject, date = lines[0].split("\x1f", 2)
        entries.append((sha, subject, date, tuple(lines[1:])))
    return entries


def by_advisory_id(repo: Path, ids: list[str], limit: int = 50) -> list[Candidate]:
    """Commits whose own message names the advisory or its CVE.

    The strongest lead there is: the repository is saying, in its own history, that
    this commit is about this vulnerability.
    """
    found: dict[str, Candidate] = {}
    for identifier in ids:
        if not identifier:
            continue
        for sha, subject, date, files in _commits(
                repo, "--all", f"--grep={re.escape(identifier)}", "-i", limit=limit):
            found.setdefault(sha, Candidate(
                sha=sha, subject=subject, committed=date, files=files,
                source=Source.ADVISORY_RECORD,
                why=f"commit message names {identifier}"))
    return list(found.values())


def by_touching_paths(repo: Path, paths: list[str], limit: int = 100) -> list[Candidate]:
    """Commits that changed a file the advisory points at.

    Weak on its own -- most commits touching a file are not security fixes -- which is
    why the security-wording filter is applied by the caller rather than here. The
    unfiltered list is what makes "considered and rejected" honest.
    """
    if not paths:
        return []
    return [
        Candidate(sha=sha, subject=subject, committed=date, files=files,
                  source=Source.DEFAULT_BRANCH_HISTORY,
                  why=f"changed {', '.join(p for p in files if p in paths) or paths[0]}")
        for sha, subject, date, files in _commits(repo, "--all", "--", *paths, limit=limit)
    ]


def by_release_window(repo: Path, previous: str, fixed: str, paths: list[str],
                      limit: int = 60) -> list[Candidate]:
    """Commits between the last affected release and the first fixed one.

    Not a heuristic. The advisory names the release that carries the fix, so the fix
    landed after the release before it and at or before that one; the commit is inside
    that window by arithmetic, whatever anybody wrote in a commit message.

    This exists because the wording strategies find nothing on real packages. certifi
    shipped a security fix in 2024.7.4 and the commit that carries it is called
    "2024.07.04 (#295)" -- no CVE, no advisory id, not one of the words a search for
    security language would match. A shortlist built only from wording would have been
    empty for exactly the advisories this project selects for.
    """
    if not previous or not fixed:
        return []
    span = f"{previous}..{fixed}"
    args = ["--", *paths] if paths else []
    return [
        Candidate(sha=sha, subject=subject, committed=date, files=files,
                  source=Source.DEFAULT_BRANCH_HISTORY,
                  why=f"landed in {span}")
        for sha, subject, date, files in _commits(repo, span, *args, limit=limit)
    ]


def looks_security_related(candidate: Candidate) -> bool:
    return bool(_SECURITY_WORDS.search(candidate.subject))


def shortlist(repo: Path, *, advisory_ids: list[str], paths: list[str],
              previous_release: str | None = None, fixed_release: str | None = None,
              cap: int = 12) -> list[Candidate]:
    """The bounded set a model is asked to choose from.

    Strongest source first, and only as many as a person could read. A shortlist long
    enough to hide a wrong answer in is not a shortlist -- and the cap being small is
    what makes the rejections in the decision log worth writing down.
    """
    ranked: dict[str, Candidate] = {}

    for candidate in by_advisory_id(repo, advisory_ids):
        ranked[candidate.sha] = candidate

    # The release window is where the fix has to be, so it is not filtered on wording.
    # Everything else is, because most commits touching a file are not fixes.
    for candidate in by_release_window(repo, previous_release or "", fixed_release or "", paths):
        ranked.setdefault(candidate.sha, candidate)

    for candidate in by_touching_paths(repo, paths):
        if candidate.sha in ranked:
            continue                       # a stronger source already claimed it
        if looks_security_related(candidate):
            ranked[candidate.sha] = candidate

    order = {s: i for i, s in enumerate(Source)}
    return sorted(ranked.values(),
                  key=lambda c: (order[c.source], c.committed),
                  reverse=False)[:cap]


# Paths whose presence at a release says nothing about whether the fix is there.
# Changelog fragments are the sharpest case: many projects collect them per-change and
# delete them when a release is cut, so the file is absent at every tag by design.
_NOT_SOURCE = re.compile(
    r"(^|/)(changelogs?|newsfragments?|news\.d|docs?|examples?|\.github)/"
    r"|(^|/)(changelog|changes|news|history|readme|contributing|authors)[^/]*$"
    r"|\.(md|rst|txt|po|pot|cfg|ini|toml)$",
    re.I)
_TEST = re.compile(r"(^|/)(tests?|testing|spec)/|(^|/)(test_|conftest)|_test\.py$", re.I)


class FileRole(enum.Enum):
    SOURCE = "source"      # presence here is evidence about the fix
    TEST = "test"          # its own tier; a test arriving is not the fix arriving
    ANCILLARY = "ancillary"  # changelogs, docs -- presence says nothing


def classify_path(path: str) -> FileRole:
    if _TEST.search(path):
        return FileRole.TEST
    if _NOT_SOURCE.search(path):
        return FileRole.ANCILLARY
    return FileRole.SOURCE


def source_paths(candidate: Candidate) -> tuple[str, ...]:
    """The files in a commit whose presence at a release means something.

    Probing the first file a commit touched picks whatever sorts first, and on ansible
    that was `changelogs/fragments/atomic_move_permissions.yml` -- a file deleted when
    the release is cut, so absent at every tag and indeterminate at every ref. All 111
    releases came back unknown from a commit that was correctly identified.

    Every source file is returned rather than one, because a fix spread over two
    modules is ordinary and picking one of them would be another arbitrary choice.
    """
    return tuple(p for p in candidate.files if classify_path(p) is FileRole.SOURCE)


def test_paths(candidate: Candidate) -> tuple[str, ...]:
    return tuple(p for p in candidate.files if classify_path(p) is FileRole.TEST)
