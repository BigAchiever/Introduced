# Introduced

**An agent that checks whether a vulnerability's published affected-version range is actually supported by
repository history — and, with human approval, repairs the public record when it isn't.**

Built on [TrueForge](https://github.com/truefoundry/trueforge) for The Agent Harness Hackathon, Aug 24–30 2026.

---

## The problem

When a security bug is found in a package, GitHub's Advisory Database publishes a record. The line that
matters is *which versions are affected* — `< 1.4.2`. Dependabot and every SCA scanner read that one line and
decide whether to alert you.

That line can be wider than the truth. You get an alert on a release that was never vulnerable, you upgrade,
something breaks, and the time is gone. How often that happens across the database is not something this
repository has measured; establishing it one advisory at a time is what the agent is for.

GitHub's own curation team has described the pressure the database is under:

> "The system that validates, enriches, and publishes advisory data is functioning; it is now operating beyond
> the volume and complexity it was designed to handle."
>
> — [Inside the Advisory Database and what happens when vulnerability volume breaks records](https://github.blog/security/supply-chain-security/inside-the-advisory-database-and-what-happens-when-vulnerability-volume-breaks-records/), The GitHub Blog

The correction channel — the `github/advisory-database` pull request queue — is public, and community
contributions are reviewed by the curation team. This agent uses it.

## Why the job is hard

A fix rarely lands in one place. A maintainer patches `main`, then cherry-picks the same fix onto an older
maintenance branch. Now the bug is absent from `1.4.7` and present in `1.5` through `1.9`, which were released
later from a different branch. The affected set is two disjoint intervals, and a human under time pressure
writes `< 2.0`.

Establishing the truth means reading advisory prose, linked issues, pull request discussion and changelogs;
deciding which commit is the fix and which hunk in it is load-bearing; then checking that hunk against every
release the range covers.

## Status

Early. The corpus, the evidence schema and the write path exist; the investigation itself does not yet.

<!-- Still to write here: setup steps someone else can follow, the offline path that needs no credentials,
     the honest limits, the trust model, and what the harness does versus what this repository does. -->

## Development

Every change lands through a pull request. Pull requests are reviewed by
[Qodo](https://www.qodo.ai) before they merge, and findings are addressed on the same branch.

## Licence

MIT — see [LICENSE](LICENSE).
