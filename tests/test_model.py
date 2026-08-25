"""The one place judgement is delegated, and the fence around it."""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))

from candidates import Candidate, Source  # noqa: E402
from model import build_prompt, model_selector, parse_reply  # noqa: E402

ADVISORY = {
    "ghsa": "GHSA-x7jh-595q-wq82", "package": "ansible",
    "introduced": ["2.7.0"], "fixed": ["2.10.0"],
    "details": "Ansible created files with world-readable default permissions.",
}


def _c(sha, subject, why="commit message names GHSA-x7jh-595q-wq82"):
    return Candidate(sha=sha, subject=subject, committed="2020-05-01T00:00:00Z",
                     files=("lib/ansible/module_utils/common/file.py",),
                     source=Source.ADVISORY_RECORD, why=why)


CANDIDATES = [
    _c("a" * 40, "stricter permissions on atomic_move when creating new file"),
    _c("b" * 40, "Change default file permissions so they are not world readable"),
    _c("c" * 40, "Fix warning for new default permissions when mode is unset"),
]


# --- the fence -------------------------------------------------------------------
# A reply is data. Anything it says about which commit to take is honoured only if it
# names a number that was offered.

def test_a_sha_the_model_invented_is_not_looked_up():
    """The most dangerous reply is a plausible-looking hash that was never offered."""
    reply = json.dumps({"choice": "deadbeef" * 5, "reason": "this one"})
    assert parse_reply(reply, CANDIDATES).sha is None


def test_an_index_past_the_end_is_refused():
    assert parse_reply(json.dumps({"choice": 9}), CANDIDATES).sha is None


def test_a_reply_with_no_json_is_an_abstention_not_a_crash():
    assert parse_reply("I think the second one, probably.", CANDIDATES).sha is None


def test_malformed_json_is_an_abstention():
    assert parse_reply('{"choice": 2, ', CANDIDATES).sha is None


def test_an_explicit_none_is_honoured():
    choice = parse_reply(json.dumps({"choice": None, "reason": "none of these"}), CANDIDATES)
    assert choice.sha is None
    assert "none" in choice.reason


def test_a_valid_choice_resolves_to_the_candidate_that_was_offered():
    choice = parse_reply(json.dumps({"choice": 2, "reason": "matches the description"}),
                         CANDIDATES)
    assert choice.sha == "b" * 40
    assert choice.reason == "matches the description"


def test_json_embedded_in_prose_is_still_read():
    reply = 'Looking at these, I think:\n{"choice": 2, "reason": "world readable"}\nHope that helps.'
    assert parse_reply(reply, CANDIDATES).sha == "b" * 40


def test_rejections_are_kept_for_the_decision_log():
    reply = json.dumps({"choice": 2, "reason": "x",
                        "rejected": [{"number": 1, "why": "adjusts a different path"},
                                     {"number": 99, "why": "not offered"}]})
    rejected = parse_reply(reply, CANDIDATES).rejected
    assert [sha for sha, _ in rejected] == ["a" * 40]


# --- the prompt --------------------------------------------------------------------

def test_the_prompt_offers_numbers_rather_than_only_hashes():
    """A reply that has to name an index cannot drift into a hash nobody offered."""
    prompt = build_prompt(ADVISORY, CANDIDATES)
    assert "[1]" in prompt and "[2]" in prompt and "[3]" in prompt


def test_the_prompt_carries_the_advisory_prose_and_the_reason_each_candidate_qualified():
    prompt = build_prompt(ADVISORY, CANDIDATES)
    assert "world-readable default permissions" in prompt
    assert "on this list because" in prompt


def test_long_advisory_prose_is_truncated_rather_than_dropped():
    advisory = dict(ADVISORY, details="x" * 20_000)
    prompt = build_prompt(advisory, CANDIDATES)
    assert "[truncated]" in prompt
    assert len(prompt) < 12_000


def test_the_prompt_asks_for_none_as_a_real_answer():
    assert "none" in build_prompt(ADVISORY, CANDIDATES).lower()


# --- the selector -------------------------------------------------------------------

def test_the_selector_returns_the_chosen_candidate():
    select = model_selector(lambda _: json.dumps({"choice": 2, "reason": "r"}))
    assert select(CANDIDATES, ADVISORY).sha == "b" * 40


def test_the_selector_abstains_rather_than_falling_back_to_the_first():
    """Falling back would make a broken model look like a working baseline, and the
    benchmark would then measure the baseline while reporting the model."""
    select = model_selector(lambda _: "nonsense")
    assert select(CANDIDATES, ADVISORY) is None


def test_an_empty_shortlist_is_never_sent_to_a_model():
    asked = []
    select = model_selector(lambda p: asked.append(p) or "{}")
    assert select([], ADVISORY) is None
    assert asked == []
