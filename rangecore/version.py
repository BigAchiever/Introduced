"""PEP 440 versions, and the comparison an advisory range actually means.

Dependency-free on purpose: this runs in a sandbox with no installer, and it is the
foundation every boundary in the project sits on. If this is wrong, every number the
benchmark reports is wrong in a way no test downstream will notice.

THE TRAP, and it is the reason this file exists rather than a one-line import.

There are two different comparisons in the Python packaging world and they disagree:

  * PEP 440 ORDERING places a pre-release BELOW its own release: 1.4.0rc1 < 1.4.0.
    So a range of "< 1.4.0" INCLUDES 1.4.0rc1.

  * pip's SPECIFIER MATCHING excludes pre-releases unless they are asked for, so
    "< 1.4.0" would NOT match 1.4.0rc1 when resolving an install.

OSV ranges of type ECOSYSTEM for PyPI are ordering, not installer semantics -- the
question is "was this published version affected", not "would pip install it". This
module implements ordering. Built on the other one it would disagree with the
published record on every advisory whose boundary is a pre-release, and would look
like a discovery rather than a bug.
"""

from __future__ import annotations

import functools
import re
from typing import NamedTuple

# PEP 440, Appendix: the canonical public-version pattern, minus the surrounding
# whitespace and v-prefix handling done in normalise().
_VERSION = re.compile(
    r"""^
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""",
    re.VERBOSE | re.IGNORECASE,
)

# Spellings that mean the same thing. PEP 440 normalisation, applied before comparison
# so that 1.0a1, 1.0.alpha.1 and 1.0-A-1 do not sort as three different versions.
_PRE_SPELLINGS = {"alpha": "a", "a": "a", "beta": "b", "b": "b",
                  "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}
_POST_SPELLINGS = {"post": "post", "rev": "post", "r": "post"}

# Sorts pre-releases below the release they precede, and a bare release above all of
# its own pre-releases. "" is the marker for "not a pre-release".
_PRE_ORDER = {"a": 0, "b": 1, "rc": 2, "": 3}


class InvalidVersion(ValueError):
    """Raised rather than guessed at. A version this module cannot parse is a version
    it must not silently order, because ordering it wrongly produces a boundary."""


class Version(NamedTuple):
    """A PEP 440 version, in a shape that tuple comparison orders correctly."""

    epoch: int
    release: tuple[int, ...]
    pre_rank: int          # _PRE_ORDER; 3 when this is not a pre-release
    pre_num: int
    post: int              # -1 when absent, so 1.0 < 1.0.post1
    dev: int               # -1 when absent, so 1.0.dev1 < 1.0 needs care -- see below
    local: str             # ordered too: 1.0 < 1.0+local, per PEP 440


def _int(value: str | None, default: int = 0) -> int:
    return default if value is None else int(value)


def parse(raw: str) -> Version:
    """Parse a version string, or raise. Never returns a best guess."""
    if not isinstance(raw, str):
        raise InvalidVersion(f"not a version string: {raw!r}")
    text = raw.strip()
    if text[:1].lower() == "v":
        text = text[1:]
    m = _VERSION.match(text)
    if m is None:
        raise InvalidVersion(f"not a PEP 440 version: {raw!r}")

    release = tuple(int(part) for part in m.group("release").split("."))

    pre_l = m.group("pre_l")
    if pre_l is None:
        pre_rank, pre_num = _PRE_ORDER[""], 0
    else:
        pre_rank, pre_num = _PRE_ORDER[_PRE_SPELLINGS[pre_l.lower()]], _int(m.group("pre_n"))

    if m.group("post") is None:
        post = -1
    elif m.group("post_n1") is not None:      # the implicit "-1" form
        post = int(m.group("post_n1"))
    else:
        post = _int(m.group("post_n2"))

    dev = -1 if m.group("dev") is None else _int(m.group("dev_n"))

    return Version(
        epoch=_int(m.group("epoch")),
        release=release,
        pre_rank=pre_rank,
        pre_num=pre_num,
        post=post,
        dev=dev,
        local=(m.group("local") or "").lower().replace("_", ".").replace("-", "."),
    )


def _local_key(local: str) -> tuple:
    """Local segments: numeric ones sort above alphanumeric ones, per PEP 440.

    Each segment is widened to a same-shaped tuple so that a number is never compared
    against a string, which would raise rather than order.
    """
    if not local:
        return ()
    return tuple(
        (1, int(seg), "") if seg.isdigit() else (0, -1, seg)
        for seg in local.split(".")
    )


def _key(v: Version) -> tuple:
    """The ordering key. Everything subtle about PEP 440 lives here.

    Three cases that a naive tuple comparison gets wrong:

      1.0 == 1.0.0        trailing zeros carry no meaning, so they are stripped.
      1.0.dev1 < 1.0a1    a dev release of a version precedes that version's own
                          pre-releases, so "no pre-release but a dev release" has to
                          sort BELOW every pre-release rather than above.
      1.0 < 1.0.post1     an absent post is lower than any post number, while an
                          absent dev is HIGHER than any dev number, since 1.0.dev1
                          comes before 1.0.
    """
    release = list(v.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()

    has_pre, has_post, has_dev = v.pre_rank != _PRE_ORDER[""], v.post >= 0, v.dev >= 0
    if not has_pre and not has_post and has_dev:
        pre_key: tuple = (-1,)
    elif has_pre:
        pre_key = (0, v.pre_rank, v.pre_num)
    else:
        pre_key = (1,)

    return (
        v.epoch,
        tuple(release),
        pre_key,
        v.post if has_post else -1,
        (0, v.dev) if has_dev else (1,),
        _local_key(v.local),
    )


@functools.total_ordering
class V:
    """A comparable version. `V("1.4.0rc1") < V("1.4.0")` is true, which is the whole
    point -- see the module docstring."""

    __slots__ = ("raw", "parsed", "_k")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.parsed = parse(raw)
        self._k = _key(self.parsed)

    def __repr__(self) -> str:
        return f"V({self.raw!r})"

    def __str__(self) -> str:
        return self.raw

    def __hash__(self) -> int:
        return hash(self._k)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, V) and self._k == other._k

    def __lt__(self, other: "V") -> bool:
        return self._k < other._k

    @property
    def is_prerelease(self) -> bool:
        p = self.parsed
        return p.pre_rank != _PRE_ORDER[""] or p.dev >= 0


def in_range(version: str, introduced: str | None, fixed: str | None,
             last_affected: str | None = None) -> bool:
    """Is `version` inside one OSV ECOSYSTEM interval?

    Half-open at the top: `introduced` is affected, `fixed` is not. `last_affected` is
    the closed-interval alternative OSV allows, and is inclusive.

    Pre-releases are ordered, not filtered. `in_range("1.4.0rc1", "0", "1.4.0")` is
    True: the release candidate was published, it precedes 1.4.0, and the fix landed
    in 1.4.0 -- so it carried the vulnerability. Treating it the way an installer
    would, and excluding it, would silently disagree with the published record.
    """
    if fixed is not None and last_affected is not None:
        raise ValueError("an OSV range carries `fixed` or `last_affected`, never both")
    v = V(version)
    if introduced is not None and introduced != "0" and v < V(introduced):
        return False
    if fixed is not None:
        return v < V(fixed)
    if last_affected is not None:
        return v <= V(last_affected)
    return True   # introduced with no upper bound: everything after it is affected
