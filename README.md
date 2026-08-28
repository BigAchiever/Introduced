# Introduced

**An agent that checks whether a vulnerability's published affected-version range is actually
supported by repository history — and, with human approval, repairs the public record when it isn't.**

Built on [TrueForge](https://github.com/truefoundry/trueforge) for The Agent Harness Hackathon, Aug 24–30 2026.

---

## Ninety seconds, no credentials

```bash
git clone https://github.com/BigAchiever/Introduced && cd Introduced
python3 -m pytest tests/ -q                 # 121 passed, 2 skipped
python3 -c "import sys; sys.path.insert(0,'rangecore'); \
  from version import V; print(V('1.4.0rc1') < V('1.4.0'))"
```

No API key, no token, no account, no network.

The two skips are deliberate and worth reading: they are the differential test against `packaging`,
which skips cleanly when that library or the pinned OSV snapshot is absent — as both are in a fresh
clone. `rangecore` is stdlib-only because it has to run in a sandbox with no installer, and that is a
deployment constraint rather than a licence to be approximately right about version ordering. So the
hand-written PEP 440 implementation is checked against the reference one over **43,265 real version
strings** from the snapshot: zero disagreements about which strings are versions, and zero across
200,000 sampled ordering comparisons. Run it yourself with `pip install packaging` and
`python3 bench/select_corpus.py` to fetch the snapshot.

---

## The problem, in one alert

You are running `urllib3 1.26.5`. GitHub tells you it is vulnerable. You upgrade, something breaks,
you lose an afternoon — and your version was never affected. The bug was fixed in exactly the release
you had.

The record said `< 2.0`. The truth was more complicated, because fixes do not land in one place:

```
1.26.4   affected
1.26.5   fixed      ← the fix was backported here
1.27     affected   ← cut from the older line, after the backport
1.28     affected
2.0      fixed
```

Two intervals. Writing that correctly is fiddly, so somebody writes `< 2.0` and moves on.

### And the record often cannot say it at all

Measured across the public OSV snapshots, all seven ecosystems:

| | package entries | expressing a disjoint range |
|---|---|---|
| **GHSA** — what Dependabot reads | 53,475 | **1** |
| **PYSEC** — PyPA's own, PyPI only | 7,266 | **1,811** (24.9%) |

The single exception is [`GHSA-wh77-3x4m-4q9g`](https://github.com/advisories/GHSA-wh77-3x4m-4q9g) on
npm `bootstrap`. It matters: it proves the schema and the curation pipeline both accept a disjoint
range. This is a practice gap, not a format limitation — and PyPA's database, same format, same
ecosystem, does it constantly.

The people who own the record have said publicly that they are past capacity:

> "The system that validates, enriches, and publishes advisory data is functioning; it is now
> operating beyond the volume and complexity it was designed to handle."
>
> — [Inside the Advisory Database and what happens when vulnerability volume breaks records](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/), The GitHub Blog

Their correction channel is a public pull request queue. This agent uses it.

---

## What it does

Given an advisory that does **not** already name its fix commit — the curators' actual backlog:

1. **Shortlist** candidate commits deterministically: commits naming the advisory, and commits inside
   the release window the fix must be in by arithmetic.
2. **Choose one** — the single delegated judgement, and the only place a model is asked anything.
3. **Verify** the choice against the repository: does the fix patch apply in reverse at each release?
   Was the same change cherry-picked onto a maintenance line? Did its tests arrive too?
4. **Emit** the affected set as intervals, and the correction as a *delta* against what is published.
5. **Stop** for a person before anything is filed.

### What it does not do

It does not find vulnerabilities, scan your code, or patch anything. Someone already found the bug
and someone already fixed it. **The record is what is wrong**, and one wrong line is read by every
scanner in the world.

---

## What the harness does, versus what this repository does

`rangecore` is a calculator. `mcp-introduced` is a token-holder. Everything between them is TrueForge:
which commit gets nominated, whether a write happens at all, what gets a clean context, and what
survives a crash.

| | |
|---|---|
| **`rangecore/`** | Python, stdlib only, **holds no credentials**. Version ordering, presence probing, cherry-pick detection, evidence tiers, boundary emission. |
| **`mcp-introduced/`** | TypeScript, stateless. The **only process holding a token that can write**. Two tools, both annotated destructive. |
| **`bench/`** | 24 curator-settled advisories, three arms, a dev/held-out split, reproducible from a pinned snapshot. |

What thinks has no key. What holds the key does not think.

---

## The approval gate shows the consequence, not the command

A gate that says *"about to call `open_boundary_correction` — allow?"* is a consent form. It tells you
a tool is about to run, which you knew.

This one shows **what would change**: the versions that would stop being flagged, the versions that
would start, the commit and the hunk behind each boundary, and every release the evidence could not
settle. You are approving a diff to a public record, so that is what you are shown.

The pause is not a convention. TrueForge resolves its approval policy entirely from tool annotations
(`readOnlyHint` / `destructiveHint`), and a tool carrying neither executes with **no approval at all**.
Both write tools carry both hints, and a test asserts it — against the harness's own view of them, not
against our manifest:

```bash
curl -s localhost:8790/api/v1/settings/mcp-servers/introduced/tools
```

The claim worth checking is not *"I annotated my tools"*. It is *"the harness sees the annotations,
therefore the gate engages."*

### And the write survives being killed

Tool execution is **at-least-once** across a crash inside the write window: one approval was measured
producing two `tools/call`, the second firing before the model was consulted again. So the write path
is idempotent by construction — the branch name is a pure function of the advisory, the existing pull
request is looked for before anything is created, and identical content is never committed twice.

---

## Evidence, and refusing to guess

Every boundary carries typed evidence:

| tier | what was observed |
|---|---|
| `exact_patch` | the fix applies in reverse at this release |
| `commit_contained` | the fix commit itself is an ancestor |
| `backport` | a `git patch-id` equivalent, not the original, is an ancestor |
| `test_added` | the tests the fix brought are present |
| `unknown` | none of the above |

**A release leaves the affected set only when two independent observations agree.** Everything else —
unknown, and single-observation — stays in. That asymmetry is deliberate: widening leaves someone an
alert they did not need, which every scanner already does. Narrowing tells someone that software they
are running, which their tooling currently flags, is safe. Only one of those is worth being careful
about, and it is not the one that looks careless.

---

## The benchmark, and its honest result

24 advisories, chosen by a rule written before any of them were seen and committed as
[`bench/select_corpus.py`](bench/select_corpus.py). Three arms, because a corpus made only of records
already known to be wrong cannot measure how often the agent wrongly corrects something:

| arm | what it is | n |
|---|---|---|
| **A** | PyPA records a disjoint range where GitHub records a single interval | 5 |
| **B** | both agree exactly — the agent should change nothing | 8 |
| **C** | no fix commit published; the answer must come from git | 11 |

Split 17 dev / 7 held-out, round-robin within each arm so it cannot be steered. PyPA's data is a
**held-out second opinion the agent never sees** — a test enforces it. Agreement is only evidence if
the two were arrived at separately.

**Result on the dev split, with the deterministic selector and no model at all:**

- **Zero false corrections.** All six of arm B correctly left alone.
- Zero narrowings, zero disjoint ranges.

And with the correct commit chosen on `ansible` [GHSA-x7jh-595q-wq82](https://github.com/advisories/GHSA-x7jh-595q-wq82):

```
2.8.14     fixed  [test_added, exact_patch]
2.9.12     fixed  [test_added, exact_patch]
2.10.0rc1  fixed  [backport, test_added, exact_patch]
2.10.0     fixed  [backport, test_added, exact_patch]

proposed:  [2.7.0, 2.8.14)   [2.8.15, 2.9.12)   [2.9.13, 2.10.0rc1)
```

Three intervals from a published range that has one, every boundary corroborated. **That gap — one
interval against three — is the entire measured case for asking a model anything.**

Counts, not percentages. At n=24 a single error moves a figure by four points, and on the held-out
seven by fourteen.

---

## Honest limits

- **The delegated choice is the weak point, and it is the only one.** A wrong pick costs an
  abstention, never a wrong boundary — everything downstream re-derives from the repository. But it
  is where the accuracy lives.
- **`2.8.15` still reads as affected after `2.8.14` reads as fixed**, which cannot be true of a
  maintenance line. Unexplained, and stated rather than smoothed over.
- **Our boundaries differ from PyPA's** on the same CVE (2.8.14 against 2.8.9). The shape agrees; the
  edges do not. Unresolved.
- **PyPI and PEP 440 only.** Other ecosystems are future work.
- **Selection is biased by construction** toward advisories whose fix commit is discoverable — that is
  what makes them scoreable, and it means real-world coverage is lower than the benchmark suggests.
- **No behavioural probe tier.** [`rangecore/wheel_spike.py`](rangecore/wheel_spike.py) shows it works
  — certifi 2024.6.2 → 2024.7.4, vulnerable at the first and not the second, from wheels pulled and
  digest-checked at run time — but it needs a sandbox this build never provisioned. 7.4% of candidate
  releases could carry one.

## Related work

This is a studied problem. Twelve tools are surveyed in
[*Vulnerability-Affected Versions Identification: How Far Are We?*](https://arxiv.org/abs/2509.03876) —
including [V-SZZ](https://baolingfeng.github.io/papers/ICSE2022VSZZ.pdf) and **LLM4SZZ**, so "use an LLM
for this" is not a new idea. **None exceeds 45% accuracy.**

They are all C/C++, they all run *backward* from a known fix commit, and none of them writes anything
back. Sonatype, Black Duck, VulnCheck and Snyk all sell more accurate ranges — as a private database.
**Nobody repairs the public one.**

Worth quoting against ourselves: that survey found substituting model-selected commits for heuristic
tracing cost **7.3 percentage points**, and concluded heuristic tracing remained more effective. This
design agrees. The model does not search; it picks from a deterministic shortlist, and everything it
picks is verified against the tree.

## Extending it

`rangecore` knows nothing about MCP, HTTP or GitHub. Add an evidence tier in
[`evidence.py`](rangecore/evidence.py); add an ecosystem by replacing
[`version.py`](rangecore/version.py) and the PyPI-specific parts of
[`select_corpus.py`](bench/select_corpus.py). The corpus rule is code, so a different corpus is a
different run of the same script.

## Development

Every change lands through a pull request, reviewed by [Qodo](https://www.qodo.ai) before it merges,
with findings addressed on the same branch. AI assistance is disclosed in [AI_USAGE.md](AI_USAGE.md).

## Licence

MIT — see [LICENSE](LICENSE).
