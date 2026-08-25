"""Did this fix reach other release lines, and which ones?

A maintainer fixes something on the development branch, then cherry-picks it onto the
line most people are still running. The two commits make the same change and have
different SHAs, so nothing about the identifier connects them. What connects them is
the change itself.

`git patch-id` hashes a diff independently of line numbers, surrounding context and
commit metadata, so a cherry-pick hashes to the same value as its original. That is a
stronger statement than tree-presence: presence says the post-fix code is here, while
a patch-id match says the same change was deliberately applied here. They fail
differently too -- a cherry-pick resolved through a conflict is edited, so its
patch-id no longer matches while its resulting state still does -- which is why the
evidence layer keeps both and does not treat either as sufficient alone.

Scanning every commit is not affordable: a large project has tens of thousands, and
the corpus has twenty-five of them. Only commits that touched the same paths can be
the same change, and there are rarely more than a few hundred of those.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

from version import InvalidVersion, V

# A file with more history than this is pathological rather than large. The cap is
# applied while reading, so it genuinely bounds the work; applying it to a fully
# materialised list would report a limit it does not enforce.
MAX_CANDIDATES = 5000


@dataclasses.dataclass(frozen=True)
class Equivalent:
    """A commit that makes the same change as the fix, somewhere else in the history."""

    sha: str
    subject: str
    releases: tuple[str, ...]          # tags containing it, ordered by version
    is_the_fix: bool                   # the original rather than a copy of it

    def to_json(self) -> dict:
        return {"sha": self.sha, "subject": self.subject,
                "releases": list(self.releases), "is_the_fix": self.is_the_fix}


@dataclasses.dataclass(frozen=True)
class BackportMap:
    fix: str
    patch_id: str | None
    equivalents: tuple[Equivalent, ...]
    truncated: bool = False            # more candidates than MAX_CANDIDATES

    @property
    def backported(self) -> bool:
        return any(not e.is_the_fix for e in self.equivalents)

    @property
    def release_lines(self) -> tuple[str, ...]:
        """Every release carrying this change, ordered. The shape a boundary is built
        from -- and when these do not form one contiguous run, the affected set has a
        hole in it that a single interval cannot describe."""
        seen: dict[str, None] = {}
        for e in self.equivalents:
            for r in e.releases:
                seen.setdefault(r, None)
        return _by_version(seen)

    def gaps(self, all_releases) -> tuple[str, ...]:
        """Releases that sit between fixed ones and are not themselves fixed.

        This is the whole question. If the fix reaches 1.4.7 and 2.0 but the repository
        also released 1.5 from the older line, then 1.5 sits inside the span of fixed
        releases without carrying the fix, and the affected set has a hole in it.

        A published GHSA range is one interval. A hole cannot be written in one
        interval, which is why these advisories stay wrong rather than getting fixed:
        the person editing the record has nowhere to put the second piece.
        """
        fixed = set(self.release_lines)
        if len(fixed) < 2:
            return ()
        ordered = _by_version(set(all_releases) | fixed)
        first, last = ordered.index(self.release_lines[0]), ordered.index(self.release_lines[-1])
        return tuple(r for r in ordered[first:last] if r not in fixed)

    def to_json(self) -> dict:
        return {"fix": self.fix, "patch_id": self.patch_id,
                "backported": self.backported,
                "release_lines": list(self.release_lines),
                "equivalents": [e.to_json() for e in self.equivalents],
                "truncated": self.truncated}


def _by_version(tags) -> tuple[str, ...]:
    """Version order where possible, name order for the rest, and never a crash.

    Tags that are not versions -- `nightly`, `latest`, a branch tag -- sort after the
    ones that are, rather than being dropped: a reader should see them.
    """
    def key(tag: str):
        candidate = tag[1:] if tag[:1].lower() == "v" and tag[1:2].isdigit() else tag
        try:
            return (0, V(candidate)._k, "")
        except InvalidVersion:
            return (1, (), tag)
    return tuple(sorted(tags, key=key))


def _git(repo: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args],
                          input=stdin, capture_output=True, text=True, timeout=300)


def patch_id(repo: Path, sha: str) -> str | None:
    """A hash of what a commit changed, stable across cherry-picks.

    `--stable` pins the algorithm: without it git may use the historical ordering,
    and two runs of this project could disagree about whether a backport happened.
    """
    diff = _git(repo, "diff-tree", "-p", "--no-commit-id", sha).stdout
    if not diff.strip():
        return None                    # a merge or an empty commit changes nothing
    out = _git(repo, "patch-id", "--stable", stdin=diff).stdout.split()
    return out[0] if out else None


def patch_ids_for_paths(repo: Path, paths: list[str],
                        limit: int = MAX_CANDIDATES) -> list[tuple[str, str]]:
    """(patch_id, commit) for every commit touching these paths, in one pass.

    `git patch-id` reads a stream, so the whole history of a file can be hashed by a
    single pipeline. Computing them one commit at a time costs two subprocess spawns
    each: on certifi that was seventeen seconds for one file, against forty
    milliseconds here. The corpus has twenty-five repositories and the difference is
    the difference between a step and an afternoon.
    """
    log = subprocess.Popen(
        ["git", "-C", str(repo), "log", "--all", "-p", "--no-color", "--", *paths],
        stdout=subprocess.PIPE,
    )
    ids = subprocess.Popen(
        ["git", "-C", str(repo), "patch-id", "--stable"],
        stdin=log.stdout, stdout=subprocess.PIPE, text=True,
    )
    if log.stdout:
        log.stdout.close()          # only `ids` should hold the read end

    pairs: list[tuple[str, str]] = []
    try:
        for line in ids.stdout:      # streamed, so the cap bounds work rather than
            parts = line.split()     # describing a bound it does not apply
            if len(parts) == 2:
                pairs.append((parts[0], parts[1]))
            if len(pairs) >= limit:
                break
    finally:
        # Both ends are killed on every exit path. Leaving `git log` running because
        # the consumer stopped early would hold a pipe open for the rest of the run.
        for process in (ids, log):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if ids.stdout:
            ids.stdout.close()
    return pairs


def releases_containing(repo: Path, sha: str) -> tuple[str, ...]:
    result = _git(repo, "tag", "--contains", sha)
    return _by_version(result.stdout.split()) if result.returncode == 0 else ()


def find_equivalents(repo: Path, fix: str, paths: list[str]) -> BackportMap:
    """Every commit anywhere in the repository that makes the same change as `fix`."""
    # Only commits touching the same files can be the same change, which is what makes
    # an exhaustive scan affordable at all.
    # Resolve to a full SHA first. Comparing by prefix would let an abbreviated id
    # match more than one commit, and the whole point of this module is deciding which
    # commit a change belongs to.
    resolved = _git(repo, "rev-parse", "--verify", "--quiet", f"{fix}^{{commit}}").stdout.strip()
    if not resolved:
        return BackportMap(fix=fix, patch_id=None, equivalents=())
    fix = resolved

    pairs = patch_ids_for_paths(repo, paths, limit=MAX_CANDIDATES + 1)
    truncated = len(pairs) > MAX_CANDIDATES
    if truncated:
        pairs = pairs[:MAX_CANDIDATES]

    # Prefer the fix's patch-id from the same pass, so the comparison is between two
    # values produced by one invocation rather than two.
    target = next((pid for pid, sha in pairs if sha == fix), None) or patch_id(repo, fix)
    if target is None:
        return BackportMap(fix=fix, patch_id=None, equivalents=(), truncated=truncated)

    found: list[Equivalent] = []
    for pid, sha in pairs:
        if pid != target:
            continue
        found.append(Equivalent(
            sha=sha,
            subject=_git(repo, "log", "-1", "--format=%s", sha).stdout.strip(),
            releases=releases_containing(repo, sha),
            is_the_fix=(sha == fix),
        ))

    found.sort(key=lambda e: (not e.is_the_fix, e.sha))
    return BackportMap(fix=fix, patch_id=target, equivalents=tuple(found), truncated=truncated)
