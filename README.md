# Introduced

**An agent that checks whether a vulnerability's published affected-version range is actually supported by
repository history — and, with human approval, repairs the public record when it isn't.**

Built on [TrueForge](https://github.com/truefoundry/trueforge).

---

## The problem, in one alert

You get a Dependabot alert. You upgrade. Something breaks. You spend three hours fixing it.

Your version was never vulnerable.

The record said `< 2.0`. The truth was more complicated, because the maintainer fixed the bug on `main`,
then cherry-picked the same fix onto the older `1.26` line that most people were still running:

```
1.26.4   affected
1.26.5   fixed        ← the backport landed here
1.27     affected     ← cut from the older line, after the fix
1.28     affected
2.0      fixed
```

The affected set is **two intervals**. Writing that is fiddly, so somebody wrote `< 2.0` and moved on, and
every scanner in the world now reads that one line.

### This is not one careless record

Across the public OSV snapshots, **GHSA has expressed a disjoint affected range exactly once in 53,475
package entries** — and PyPI is a clean zero, 0 of 33,418. PyPA's own advisory database does it in **24.9%**
of its PyPI records. Same format, same ecosystem, same packages.

That single exception, `GHSA-wh77-3x4m-4q9g` on npm `bootstrap`, matters most: it proves the schema and the
curation pipeline both accept a disjoint range. This is not a format limitation. It is a practice gap.

You can check both numbers yourself:

```bash
python3 bench/select_corpus.py --out bench   # downloads the snapshot, prints the funnel
```

And the curators have said publicly that they are past capacity:

> "The system that validates, enriches, and publishes advisory data is functioning; it is now operating
> beyond the volume and complexity it was designed to handle."
>
> — [Inside the Advisory Database and what happens when vulnerability volume breaks
> records](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/), The GitHub Blog

The correction channel — the `github/advisory-database` pull request queue — is public and reviewed.

---

## Ninety seconds, no credentials

Everything scored here runs offline. No API key, no GitHub token, no account.

```bash
git clone https://github.com/BigAchiever/Introduced && cd Introduced
python3 -m pytest tests/ -q
```

**134 pass, 2 skip** in about twenty seconds on a fresh clone. The two skips are a
differential test that compares this project's PEP 440 implementation against `packaging`
over the pinned OSV snapshot; it skips cleanly when either is absent, which is the
ordinary state of a clone that has not downloaded the snapshot yet. Fetch it — step two
below — and the same command reports 136.

To rebuild the corpus from the pinned snapshot and see the selection funnel:

```bash
python3 bench/select_corpus.py --out bench
```

To run the agent over the development split (clones ~17 repositories the first time, then works offline):

```bash
python3 bench/run.py --split dev
```

**Requirements: Python 3.10 or newer, and `git`. Nothing else.**

On macOS the built-in `python3` is 3.9 and will not run this. The entry points check and
say so rather than failing with a `TypeError` from inside an import — use `python3.11`,
`python3.13`, or anything newer.

`rangecore` has no third-party dependencies at all, on purpose: it is written to run in a
sandbox that has no package installer.

---

## What it does

Given an advisory, the agent works out which commit fixed it and which releases carry that commit.

```
advisory prose  →  candidate commits  →  the fix  →  presence at each release  →  intervals  →  a correction
```

Each step is in its own module and each one can be read alone:

| | |
|---|---|
| [`rangecore/version.py`](rangecore/version.py) | PEP 440 ordering, hand-written and checked against `packaging` |
| [`rangecore/candidates.py`](rangecore/candidates.py) | the shortlist a model chooses from |
| [`rangecore/model.py`](rangecore/model.py) | the one delegated judgement: which commit is the fix |
| [`rangecore/tree.py`](rangecore/tree.py) | is the fix present at this release? |
| [`rangecore/backport.py`](rangecore/backport.py) | was it cherry-picked onto another line? |
| [`rangecore/evidence.py`](rangecore/evidence.py) | tiers → verdicts → intervals |
| [`rangecore/boundary.py`](rangecore/boundary.py) | the correction, as a delta against the record |
| [`mcp-introduced/`](mcp-introduced) | the only process holding a token that can write |

### The model nominates. Nothing trusts it.

The model does not search the repository and does not decide a version range. It picks one entry from a
short, numbered list, and every consequence of that pick is re-derived from git. A reply naming anything
that was not offered is discarded rather than looked up, so an invented commit hash cannot become a
boundary.

A wrong answer therefore costs an abstention, not a wrong correction. That is what makes it safe to ask.

This is not a stylistic preference. The published comparison of twelve tools for this task found that
substituting model-selected commits for heuristic tracing cost **7.3 percentage points** and concluded that
heuristic tracing remained more effective. Search where determinism is better; judgement where a model is.

### Refusing is the point

A wrong narrowing and a wrong widening are not the same mistake. Widening leaves someone an alert they did
not need. Narrowing tells them that software they are running, which their tooling currently flags, is safe
— in a register their scanner trusts, under our name.

So the caution is applied in one direction only. A release leaves the affected set when **two independent
observations agree**, and not before. Everything unresolved stays in.

---

## What the harness does

`rangecore` is a calculator and `mcp-introduced` is a token-holder. Everything between them is TrueForge:
which commit gets nominated, whether a write happens at all, what gets a clean context, and what survives a
crash.

**The approval gate is not ours.** TrueForge resolves it entirely from tool annotations — `@write` is
`readOnlyHint === false`, `@destructive` is `destructiveHint === true` — so a tool carrying neither executes
with no approval at all. Both write tools here set both hints, and a test asserts it, because losing an
annotation does not fail loudly: it starts writing without asking.

You can confirm the harness sees them, with no model key:

```bash
curl -s localhost:8790/api/v1/settings/mcp-servers/introduced/tools
```

That is a live connection, not a cached manifest — the same resolution a turn uses.

---

## Honest limits

- **The behavioural evidence tier is not here.** `rangecore/wheel_spike.py` acquires built wheels from PyPI
  and executes a probe against unreviewed third-party code; that needs a container, and no sandbox was
  provisioned in time. 235 of 2,650 candidate releases are eligible for it. The code and the measurement
  are in the repository; the tier is not emitted.
- **The model layer runs against a scripted stand-in.** No API key was available. What is scripted is which
  commit gets picked. What is not scripted: every tool contract, every approval, every piece of evidence
  reasoning, every number below.
- **PyPI and PEP 440 only.** Other ecosystems are future work.
- **`n = 24`.** At this size one error moves a figure by four points, so results are reported as counts.
- **Ground truth is curator judgement**, not physical truth. Disagreement is scored as disagreement.
- **Selection is biased by construction** toward advisories whose fix commit is discoverable — that is what
  makes them scoreable, and it means real-world coverage is lower than the benchmark suggests.

## Trust model

The evidence schema stops **fabrication** — a hallucinated commit, a boundary with no hunk. It does not stop
**misdirection**. Anyone who can post a GitHub comment can point this agent at a real, old commit that is
not the fix; the SHA is real, the hunk is genuinely present, and the schema is satisfied.

So untrusted text may **nominate** a candidate and may never **justify** a boundary. That rule, not the
schema, is what stands between an issue comment and a public correction.

## Related work

Identifying affected version ranges is a studied problem, and this is not the first attempt at it.
["Vulnerability-Affected Versions Identification: How Far Are We?"](https://arxiv.org/abs/2509.03876)
evaluates twelve tools — VCCFinder, V-SZZ, Lifetime, SEM-SZZ, TC-SZZ, LLM4SZZ, ReDeBug, VUDDY, MOVERY,
V1SCAN, FIRE, VULTURE — and reports that **none exceeds 45% accuracy**.

That field is C/C++, it runs *backward* from a known fix commit to find where the bug was introduced, and it
produces a number in a paper. This runs *forward* from an advisory with no fix commit published, on PyPI,
and files the answer back into the public record behind human approval. Commercial scanners — Sonatype,
Black Duck, VulnCheck, Snyk — sell more accurate ranges in a private database. Nobody fixes the public one.

The novelty is that combination, not any single part of it.

## Development

Every change lands through a pull request, reviewed by [Qodo](https://www.qodo.ai) before it merges, with
findings addressed on the same branch. Nine findings across the first three pull requests; the ones worth
reading are in the commit messages, including two where the review was wrong and one where it caught a
security claim the code did not support.

## Licence

MIT — see [LICENSE](LICENSE).
