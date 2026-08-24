"""Which packages could carry a behavioural probe at all.

Separate from corpus selection on purpose: this stage needs the network, and the
selector must stay offline and deterministic. The output is a committed fact the
selector reads.

Eligibility is an upper bound. It is checked at the published fix version only; a
real probe also needs a portable wheel at the release before it, which is not known
until the investigation runs. Report the achieved number, never this one.
"""

from __future__ import annotations

import concurrent.futures
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "bench"))

from wheel_spike import runtime_requirements, wheel_for  # noqa: E402
import select_corpus as sc  # noqa: E402


def eligibility(package: str, version: str) -> dict:
    reqs = runtime_requirements(package, version, timeout=15)
    if reqs is None:
        return {"eligible": False, "reason": "RELEASE_NOT_ON_PYPI"}
    if reqs:
        # No installer means no way to acquire these. A probe cannot import a package
        # whose top-level imports are missing.
        return {"eligible": False, "reason": "HAS_RUNTIME_DEPENDENCIES", "count": len(reqs)}
    if wheel_for(package, version, timeout=15) is None:
        return {"eligible": False, "reason": "NO_PORTABLE_WHEEL"}
    return {"eligible": True, "reason": "ZERO_DEPS_PORTABLE_WHEEL"}


def main() -> int:
    snapshot = pathlib.Path(__file__).parents[1] / "bench" / ".cache" / "osv-pypi.zip"
    out = pathlib.Path(__file__).parents[1] / "bench" / "probe_eligible.json"

    # Keyed by "package@version", not by package. A package can appear in several
    # advisories with different fix versions, and eligibility is a property of the
    # release: metadata on old uploads is not what it is on recent ones.
    targets: dict[str, tuple[str, str]] = {}
    for record in sc.read_records(snapshot):
        cand, _ = sc.build_candidate(record)
        if cand and cand.fixed:
            targets[f"{cand.package}@{cand.fixed[0]}"] = (cand.package, cand.fixed[0])

    keys = sorted(targets)
    print(f"checking {len(keys)} package releases ...", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        # Zip over the SAME sequence the pool consumed. Zipping the dict against a
        # sorted map attaches every verdict to the wrong package, silently — which is
        # how parso, a zero-dependency parser, came back with 74 dependencies.
        ordered = dict(zip(keys, pool.map(lambda k: eligibility(*targets[k]), keys)))
    out.write_text(json.dumps(ordered, indent=1))
    n = sum(1 for v in ordered.values() if v["eligible"])
    print(f"probe-eligible: {n} of {len(ordered)} releases ({100 * n / len(ordered):.1f}%)")
    for k, v in list(ordered.items())[:0]:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
