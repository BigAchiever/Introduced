"""Was this fix present at this release?

The question sounds like a string search and is not one. A fix can be reformatted,
have its surrounding code rewritten, be squashed with unrelated edits, or land through
a cherry-pick with different line numbers. Searching for the added lines answers a
different question -- "does this text appear" -- and answers it wrongly often enough
to produce boundaries that are confidently incorrect.

So the fix is treated as a patch and git is asked whether it applies:

    forward applies, reverse does not   ->  the pre-fix code is here.  ABSENT
    reverse applies, forward does not   ->  the post-fix code is here. PRESENT
    neither applies                     ->  the code has diverged.     INDETERMINATE

The third outcome is the one that matters. It is not a failure to be worked around; it
is the honest answer for a file that has been refactored since, and it is what the
abstention rule upstream consumes. A prober that always returns PRESENT or ABSENT is a
prober that guesses.

Everything after the first clone is local. The benchmark has to reproduce with no
network, so probing never reaches out.
"""

from __future__ import annotations

import dataclasses
import enum
import functools
import shutil
import subprocess
import tempfile
from pathlib import Path

from version import InvalidVersion, V


class Presence(enum.Enum):
    PRESENT = "present"
    ABSENT = "absent"
    INDETERMINATE = "indeterminate"


class Reason(enum.Enum):
    """Why a probe could not decide. A closed set: an unexplained indeterminate is a
    bug in this module, not a property of the repository."""

    REF_UNKNOWN = "ref_unknown"              # the tag or commit is not in this clone
    REF_AMBIGUOUS = "ref_ambiguous"          # several tags normalise to the same version
    PATH_ABSENT = "path_absent"              # the file does not exist at that ref
    DIVERGED = "diverged"                    # neither direction applies
    AMBIGUOUS = "ambiguous"                  # both directions apply; the patch says nothing
    EMPTY_PATCH = "empty_patch"              # the commit did not change this file


@dataclasses.dataclass(frozen=True)
class Probe:
    ref: str
    path: str
    presence: Presence
    reason: Reason | None = None

    def to_json(self) -> dict:
        return {"ref": self.ref, "path": self.path, "presence": self.presence.value,
                "reason": self.reason.value if self.reason else None}


class GitError(RuntimeError):
    pass


class Repo:
    """A cached clone. Cloned once, then read-only and offline.

    Blobs are fetched lazily (`--filter=blob:none`): a full clone of every repository in
    the corpus does not fit the disk this runs on, and the trees and tags are what
    resolve a ref. Blobs touched during a run are cached by git, so a second run of the
    same corpus needs no network.
    """

    def __init__(self, url: str, cache: Path) -> None:
        self.url = url.rstrip("/")
        self.path = cache / self.url.rsplit("/", 2)[-2] / self.url.rsplit("/", 1)[-1]

    def _git(self, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True, text=True, timeout=300,
        )
        if check and result.returncode != 0:
            raise GitError(f"git {' '.join(args)}: {result.stderr.strip()}")
        return result

    @property
    def cloned(self) -> bool:
        return (self.path / "HEAD").exists() or (self.path / ".git").exists()

    def clone(self) -> None:
        """Idempotent. An interrupted clone leaves a directory git will not reuse, so
        it is removed rather than repaired -- re-cloning is cheaper than diagnosing."""
        if self.cloned:
            return
        if self.path.exists():
            shutil.rmtree(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", self.url, str(self.path)],
            capture_output=True, text=True, timeout=900,
        )
        if result.returncode != 0:
            if self.path.exists():
                shutil.rmtree(self.path, ignore_errors=True)
            raise GitError(f"clone {self.url}: {result.stderr.strip()[:200]}")

    @functools.cached_property
    def tags(self) -> list[str]:
        result = self._git("tag", "--list")
        return result.stdout.split() if result.returncode == 0 else []

    @functools.cached_property
    def _tags_by_version(self) -> dict[V, list[str]]:
        """Tags indexed by the version they mean, not by how they are spelled.

        This is not a nicety. PyPI publishes PEP 440 NORMALISED versions while a git tag
        keeps whatever the maintainer typed, and the two disagree constantly. certifi
        ships `2024.7.4` to PyPI and tags it `2024.07.04`; string matching finds
        nothing, and an advisory boundary that cannot be resolved to a ref cannot be
        probed at all. Resolving through the version comparison rather than through the
        spelling is what makes most of the corpus reachable.
        """
        index: dict[V, list[str]] = {}
        for tag in self.tags:
            candidate = tag[1:] if tag[:1].lower() == "v" and tag[1:2].isdigit() else tag
            try:
                index.setdefault(V(candidate), []).append(tag)
            except InvalidVersion:
                continue          # release-candidates named by hand, branch tags, junk
        return index

    def resolve(self, ref: str) -> str | None:
        """A ref to a commit SHA, or None.

        Exact spellings first, because they are cheap and unambiguous. Only then the
        version index, which is what catches zero-padding and v-prefixes.
        """
        for candidate in (ref, f"v{ref}", f"release-{ref}"):
            result = self._git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}")
            if result.returncode == 0:
                return result.stdout.strip()
        try:
            matches = self._tags_by_version.get(V(ref), [])
        except InvalidVersion:
            return None
        if len(matches) != 1:
            return None           # nothing, or several spellings -- see resolve_detail
        result = self._git("rev-parse", "--verify", "--quiet", f"{matches[0]}^{{commit}}")
        return result.stdout.strip() if result.returncode == 0 else None

    def resolve_detail(self, ref: str) -> tuple[str | None, Reason | None]:
        """resolve(), but says why it failed. Ambiguity and absence are different
        problems and the ledger should not conflate them."""
        sha = self.resolve(ref)
        if sha:
            return sha, None
        try:
            if len(self._tags_by_version.get(V(ref), [])) > 1:
                return None, Reason.REF_AMBIGUOUS
        except InvalidVersion:
            pass
        return None, Reason.REF_UNKNOWN

    def patch_for(self, commit: str, path: str) -> str:
        """What one commit did to one file, as a patch.

        `--find-renames` so a fix that also moved the file still produces a usable
        patch. First-parent diffing is deliberate: on a merge commit the interesting
        change is what the merge brought in.
        """
        result = self._git("diff", "--find-renames", f"{commit}^", commit, "--", path)
        if result.returncode != 0:
            raise GitError(f"cannot diff {commit} for {path}: {result.stderr.strip()}")
        return result.stdout

    def file_at(self, ref: str, path: str) -> str | None:
        result = self._git("show", f"{ref}:{path}")
        return result.stdout if result.returncode == 0 else None

    def presence(self, patch: str, ref: str, path: str) -> Probe:
        """Does `ref` carry the post-fix code, the pre-fix code, or neither?"""
        if not patch.strip():
            return Probe(ref, path, Presence.INDETERMINATE, Reason.EMPTY_PATCH)
        sha, why = self.resolve_detail(ref)
        if sha is None:
            return Probe(ref, path, Presence.INDETERMINATE, why)
        content = self.file_at(sha, path)
        if content is None:
            return Probe(ref, path, Presence.INDETERMINATE, Reason.PATH_ABSENT)

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            target = work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            patch_file = work / "fix.patch"
            patch_file.write_text(patch)

            def applies(*extra: str) -> bool:
                return subprocess.run(
                    ["git", "apply", "--check", *extra, str(patch_file)],
                    cwd=work, capture_output=True, text=True, timeout=60,
                ).returncode == 0

            forward, reverse = applies(), applies("--reverse")

        if reverse and not forward:
            return Probe(ref, path, Presence.PRESENT)
        if forward and not reverse:
            return Probe(ref, path, Presence.ABSENT)
        if forward and reverse:
            # A patch that applies both ways constrains nothing about this file.
            return Probe(ref, path, Presence.INDETERMINATE, Reason.AMBIGUOUS)
        return Probe(ref, path, Presence.INDETERMINATE, Reason.DIVERGED)
