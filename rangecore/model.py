"""Asking a model which of several commits an advisory is describing.

This is the only place in the project where judgement is delegated, and the interface
is narrow on purpose: in a shortlist, out one entry of that shortlist, or nothing.

WHAT THE MODEL CANNOT DO HERE, BY CONSTRUCTION.

It cannot name a commit that is not on the list -- a reply naming anything else is
discarded rather than looked up, so a hallucinated SHA cannot become a boundary. It
cannot decide a version range; it picks a commit and every consequence of that pick is
re-derived from the repository. It cannot make a weak lead strong: the source recorded
against a candidate travels with it and is not something the reply can change.

So a wrong answer costs an abstention, which is the outcome this whole design prefers
to a confident one. That is what makes it safe to ask at all.

WHY THE PROSE IS WORTH READING.

The deterministic baseline picks by source strength and date, and on ansible it chose
"stricter permissions on atomic_move when creating new file" over "Change default file
permissions so they are not world readable" -- both real commits, both matching the
advisory id, one of them the fix. Told apart by reading what the advisory says, which
is the thing a model is actually better at than a sort order.
"""

from __future__ import annotations

import json
import re
import textwrap
from typing import Callable

from candidates import Candidate

MAX_DETAILS = 4000        # advisory prose; the long tail is reference lists
MAX_SUBJECT = 120


class Choice:
    """A model's answer, already checked against the shortlist."""

    __slots__ = ("sha", "reason", "rejected")

    def __init__(self, sha: str | None, reason: str = "",
                 rejected: tuple[tuple[str, str], ...] = ()) -> None:
        self.sha = sha
        self.reason = reason
        self.rejected = rejected

    def __repr__(self) -> str:
        return f"Choice({self.sha!r}, {self.reason!r})"


def build_prompt(advisory: dict, candidates: list[Candidate]) -> str:
    """What the model is shown. Everything it may rely on, and nothing else.

    The candidate list is numbered rather than presented by SHA alone, because a reply
    that has to name an index cannot drift into a plausible-looking hash that was never
    offered.
    """
    details = (advisory.get("details") or advisory.get("summary") or "").strip()
    if len(details) > MAX_DETAILS:
        details = details[:MAX_DETAILS] + "\n[truncated]"

    lines = [
        "You are identifying which commit fixed a specific published vulnerability.",
        "",
        f"Advisory: {advisory.get('ghsa', '?')}",
        f"Package: {advisory.get('package', '?')} (PyPI)",
        f"Published as affected: {advisory.get('introduced', ['0'])[0]} "
        f"up to {(advisory.get('fixed') or ['unknown'])[0]}",
        "",
        "What the advisory says:",
        textwrap.indent(details or "(no description published)", "    "),
        "",
        "Candidate commits, already filtered from the repository:",
    ]
    for i, c in enumerate(candidates, 1):
        subject = c.subject[:MAX_SUBJECT]
        lines += [
            f"  [{i}] {c.sha[:12]}  {c.committed[:10]}",
            f"      {subject}",
            f"      files: {', '.join(c.files[:4])}"
            + (f" (+{len(c.files) - 4} more)" if len(c.files) > 4 else ""),
            f"      on this list because: {c.why}",
        ]
    lines += [
        "",
        "Choose the one commit that fixes the vulnerability described above.",
        "",
        "Several candidates may touch the same area or mention the same identifier.",
        "The fix is the commit that changes the behaviour the advisory describes, not a",
        "commit that adds a test for it, adjusts a related permission, or follows up on",
        "it afterwards.",
        "",
        "If none of them is the fix, say so. An honest 'none' is more useful than a",
        "guess: a wrong choice is checked against the repository and discarded, but it",
        "spends the only judgement in this pipeline on the wrong commit.",
        "",
        "Reply with JSON and nothing else:",
        '  {"choice": <number or null>, "reason": "<one sentence>",',
        '   "rejected": [{"number": <n>, "why": "<short>"}]}',
    ]
    return "\n".join(lines)


_JSON = re.compile(r"\{.*\}", re.S)


def parse_reply(reply: str, candidates: list[Candidate]) -> Choice:
    """Read the model's answer, keeping only what the shortlist supports.

    A reply is data, not instruction. Anything it says about which commit to take is
    honoured only if it names a number that was offered; anything else -- a SHA it
    invented, an index out of range, prose with no JSON in it -- resolves to no choice,
    which the caller treats as an abstention.
    """
    match = _JSON.search(reply or "")
    if not match:
        return Choice(None, "no JSON in reply")
    try:
        payload = json.loads(match.group(0))
    except ValueError:
        return Choice(None, "reply was not valid JSON")

    rejected = tuple(
        (candidates[int(r["number"]) - 1].sha, str(r.get("why", ""))[:200])
        for r in (payload.get("rejected") or [])
        if isinstance(r, dict) and str(r.get("number", "")).isdigit()
        and 1 <= int(r["number"]) <= len(candidates)
    )

    number = payload.get("choice")
    reason = str(payload.get("reason", ""))[:400]
    if number is None:
        return Choice(None, reason or "model chose none", rejected)
    if not isinstance(number, int) or not (1 <= number <= len(candidates)):
        return Choice(None, f"choice {number!r} is not one of the offered candidates", rejected)
    return Choice(candidates[number - 1].sha, reason, rejected)


Asker = Callable[[str], str]


def model_selector(ask: Asker):
    """A Selector backed by whatever `ask` talks to.

    `ask` takes a prompt and returns a reply. Keeping the transport out of this module
    is what lets the prompt and the parsing be tested without a model, a key or a
    network, and it is why the benchmark can run either way.
    """
    def select(candidates: list[Candidate], advisory: dict) -> Candidate | None:
        if not candidates:
            return None
        choice = parse_reply(ask(build_prompt(advisory, candidates)), candidates)
        if choice.sha is None:
            return None
        return next((c for c in candidates if c.sha == choice.sha), None)
    return select
