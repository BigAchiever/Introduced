"""Select the benchmark corpus from a pinned OSV snapshot.

The rule lives here, in code, and it is written before any result is seen. A reader
can run this against the same snapshot and get the same corpus, byte for byte.

Three arms, because a corpus made only of known-wrong records cannot measure the
metric that matters:

    A  PYSEC records a disjoint affected range where GHSA records a single interval.
       A correction is expected. Small and named.
    B  Both databases agree exactly. The agent should change nothing here; this is
       what makes false-correction rate measurable at all.
    C  GHSA advisory with no fix-commit reference. The answer has to be reconstructed
       from repository history. This is the working corpus.

PYSEC is a held-out second opinion. It is written to reference/ and no agent-facing
code path may read it — see tests/test_no_pysec_leakage.py.

Stdlib only, on purpose: this must run anywhere, including a fresh clone with no
virtualenv.

    python3 select_corpus.py --out .            # uses cached snapshot if present
    python3 select_corpus.py --refresh          # re-download the snapshot
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import hashlib
import json
import pathlib
import re
import sys

if sys.version_info < (3, 10):
    # A stranger on macOS gets the built-in python3, which is 3.9, and otherwise sees a
    # TypeError from inside an import -- not a message anyone can act on.
    raise SystemExit(
        f"This needs Python 3.10 or newer; found {sys.version.split()[0]} at {sys.executable}.\n"
        "On macOS the built-in `python3` is 3.9 -- try python3.11 or python3.13 instead."
    )

import urllib.request
import zipfile
from datetime import datetime, timezone
from typing import Any, Iterator

SNAPSHOT_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

# A commit reference disqualifies an advisory from arm C: the archaeology has already
# been done and published, so there is nothing for this agent to add.
#
# Match the URL, never the reference type. `type: FIX` appears zero times in
# GHSA-reviewed records, while 4,854 commit URLs sit under `type: WEB`.
COMMIT_URL = re.compile(
    r"(github\.com|gitlab\.com|bitbucket\.org)/[^/]+/[^/]+/(commit|commits|-/commit)/[0-9a-f]{7,40}",
    re.I,
)
GITHUB_REPO = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+)", re.I)

MIN_VERSIONS = 5

# Every advisory that is considered and not taken is recorded with one of these.
# A closed set, deliberately: free text is where post-hoc rationalisation hides.
class Reason:
    NOT_GHSA = "NOT_GHSA"
    UNREVIEWED = "UNREVIEWED"
    MULTI_PACKAGE = "MULTI_PACKAGE"
    NO_PYPI_PACKAGE = "NO_PYPI_PACKAGE"
    FIX_COMMIT_PRESENT = "FIX_COMMIT_PRESENT"
    NO_RESOLVABLE_BOUNDARY = "NO_RESOLVABLE_BOUNDARY"
    NO_ECOSYSTEM_RANGE = "NO_ECOSYSTEM_RANGE"
    REPO_UNRESOLVED = "REPO_UNRESOLVED"
    TOO_FEW_VERSIONS = "TOO_FEW_VERSIONS"
    ARM_FULL = "ARM_FULL"
    PROBE_QUOTA_ONLY = "PROBE_QUOTA_ONLY"
    PACKAGE_ALREADY_REPRESENTED = "PACKAGE_ALREADY_REPRESENTED"
    NO_ARM = "NO_ARM"


# --------------------------------------------------------------------------------
# Pure functions. No I/O below this line until the loader.
# --------------------------------------------------------------------------------

def eco_events(affected: dict) -> list[dict]:
    """Events from ECOSYSTEM ranges only.

    An OSV record may carry several ranges of different type. PYSEC routinely carries
    a GIT range whose events are commit SHAs alongside an ECOSYSTEM range whose events
    are versions. Counting across both makes an ordinary record look disjoint: doing so
    inflated one measurement from 24.9% to 34.6% and a candidate set from 6 to 608.

    A GIT fix event names a commit. It is a lead, never a boundary.
    """
    return [
        event
        for rng in affected.get("ranges", [])
        if rng.get("type") == "ECOSYSTEM"
        for event in rng.get("events", [])
    ]


def eco_range_count(affected: dict) -> int:
    return sum(1 for r in affected.get("ranges", []) if r.get("type") == "ECOSYSTEM")


def git_fix_shas(affected: dict) -> list[str]:
    """Fix commits PYSEC happens to record. Reference material, never an input."""
    return [
        e["fixed"]
        for r in affected.get("ranges", [])
        if r.get("type") == "GIT"
        for e in r.get("events", [])
        if "fixed" in e
    ]


def is_disjoint(affected: dict) -> bool:
    """True when the affected set is more than one interval, in ECOSYSTEM terms."""
    events = eco_events(affected)
    return (
        sum(1 for e in events if "fixed" in e) > 1
        or sum(1 for e in events if "introduced" in e) > 1
        or eco_range_count(affected) > 1
    )


def cites_fix_commit(record: dict) -> bool:
    return any(COMMIT_URL.search(r.get("url", "")) for r in record.get("references", []))


# Repositories that appear in references but are never the package's source. An
# advisory frequently links the database that carries it, and that link is a github.com
# URL like any other: apache-airflow resolved to pypa/advisory-database, and every
# probe against it would have been meaningless while looking like a real result.
NOT_SOURCE = {
    "pypa/advisory-database", "github/advisory-database", "rustsec/advisory-db",
    "golang/vulndb", "cve-org/cvelist", "cveproject/cvelist",
}


def _package_matches(package: str, repo_name: str) -> bool:
    """Does this repository plausibly hold this package?

    Names differ constantly -- matrix-synapse lives in matrix-org/synapse, elastic-apm
    in elastic/apm-agent-python -- so this is a tiebreaker rather than a requirement.
    """
    a = package.lower().replace("-", "").replace("_", "").replace(".", "")
    b = repo_name.lower().replace("-", "").replace("_", "").replace(".", "")
    return a in b or b in a


def resolve_repo(record: dict, package: str = "") -> str | None:
    """Prefer the reference GitHub itself marks as the package home.

    Then a repository whose name resembles the package, then anything left. A wrong
    repository does not fail loudly -- it produces an investigation that looks ordinary
    and means nothing.
    """
    refs = record.get("references", [])
    ordered = [r for r in refs if r.get("type") == "PACKAGE"] + [
        r for r in refs if r.get("type") != "PACKAGE"
    ]
    fallback: str | None = None
    for ref in ordered:
        m = GITHUB_REPO.match(ref.get("url", ""))
        if not m:
            continue
        owner, name = m.group(1), m.group(2)
        if name.endswith(".git"):
            name = name[:-4]
        slug = f"{owner}/{name}"
        if slug.lower() in NOT_SOURCE:
            continue
        url = f"https://github.com/{slug}"
        if package and _package_matches(package, name):
            return url
        fallback = fallback or url
    return fallback


def sole_pypi_package(record: dict) -> dict | None:
    """Exactly one affected PyPI package, or nothing.

    Multi-package advisories split the unit of work; merging them would make one
    subagent's investigation cover two repositories.
    """
    affected = [
        a for a in record.get("affected", [])
        if a.get("package", {}).get("ecosystem") == "PyPI"
    ]
    return affected[0] if len(affected) == 1 else None


def cve_aliases(record: dict) -> list[str]:
    ids = [record.get("id", "")] + list(record.get("aliases", []))
    return [i for i in ids if i.startswith("CVE-")]


@dataclasses.dataclass(frozen=True)
class Candidate:
    ghsa: str
    package: str
    repo: str
    n_versions: int
    versions: tuple[str, ...]      # every version the advisory lists as affected
    introduced: tuple[str, ...]
    fixed: tuple[str, ...]
    cites_commit: bool
    cves: tuple[str, ...]

    def to_json(self) -> dict:
        d = dataclasses.asdict(self)
        for k in ("introduced", "fixed", "cves", "versions"):
            d[k] = list(d[k])
        return d


def build_candidate(record: dict) -> tuple[Candidate | None, str | None]:
    """Apply the inclusion rule. Returns (candidate, exclusion_reason)."""
    if not record.get("id", "").startswith("GHSA-"):
        return None, Reason.NOT_GHSA
    if not (record.get("database_specific") or {}).get("github_reviewed"):
        return None, Reason.UNREVIEWED

    affected = sole_pypi_package(record)
    if affected is None:
        has_any = any(
            a.get("package", {}).get("ecosystem") == "PyPI"
            for a in record.get("affected", [])
        )
        return None, Reason.MULTI_PACKAGE if has_any else Reason.NO_PYPI_PACKAGE

    events = eco_events(affected)
    if not events:
        return None, Reason.NO_ECOSYSTEM_RANGE

    fixed = tuple(e["fixed"] for e in events if "fixed" in e)
    last_affected = tuple(e["last_affected"] for e in events if "last_affected" in e)
    if not (fixed or last_affected):
        return None, Reason.NO_RESOLVABLE_BOUNDARY

    versions = affected.get("versions", [])
    if len(versions) < MIN_VERSIONS:
        return None, Reason.TOO_FEW_VERSIONS

    repo = resolve_repo(record, affected["package"]["name"])
    if repo is None:
        return None, Reason.REPO_UNRESOLVED

    return (
        Candidate(
            ghsa=record["id"],
            package=affected["package"]["name"].lower(),
            repo=repo,
            n_versions=len(versions),
            # The list itself, not just its length. Every release the assessment walks
            # comes from here, and storing only the count meant the pipeline had
            # nothing to iterate and abstained on every advisory.
            versions=tuple(versions),
            introduced=tuple(e["introduced"] for e in events if "introduced" in e),
            fixed=fixed or last_affected,
            cites_commit=cites_fix_commit(record),
            cves=tuple(cve_aliases(record)),
        ),
        None,
    )


# --------------------------------------------------------------------------------
# Snapshot I/O
# --------------------------------------------------------------------------------

def fetch_snapshot(path: pathlib.Path, refresh: bool) -> dict:
    """Download once, then reuse. Re-running must not re-download."""
    if path.exists() and not refresh:
        blob = path.read_bytes()
        source = "cache"
    else:
        sys.stderr.write(f"downloading {SNAPSHOT_URL} ...\n")
        with urllib.request.urlopen(SNAPSHOT_URL, timeout=180) as resp:
            blob = resp.read()
        path.write_bytes(blob)
        source = "download"
    return {
        "url": SNAPSHOT_URL,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bytes": len(blob),
        "obtained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
    }


def read_records(path: pathlib.Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as zf:
        for name in sorted(zf.namelist()):
            if name.endswith(".json"):
                yield json.loads(zf.read(name))


# --------------------------------------------------------------------------------
# Arm assignment and selection
# --------------------------------------------------------------------------------

def index_pysec(records: list[dict]) -> dict[tuple[str, str], dict]:
    """PYSEC records keyed by (CVE, package). Reference only — never reaches the agent."""
    index: dict[tuple[str, str], dict] = {}
    for record in records:
        if not record.get("id", "").startswith("PYSEC-"):
            continue
        affected = sole_pypi_package(record)
        if affected is None:
            continue
        events = eco_events(affected)
        payload = {
            "pysec": record["id"],
            "introduced": [e["introduced"] for e in events if "introduced" in e],
            "fixed": [e["fixed"] for e in events if "fixed" in e],
            "disjoint": is_disjoint(affected),
            "git_fix_shas": git_fix_shas(affected),
        }
        package = affected["package"]["name"].lower()
        for cve in cve_aliases(record):
            index.setdefault((cve, package), payload)
    return index


def assign_arm(cand: Candidate, pysec: dict | None) -> str | None:
    """A: they disagree in shape.  B: they agree exactly.  C: the archaeology case."""
    if pysec is not None:
        if pysec["disjoint"] and len(cand.fixed) <= 1:
            return "A"
        if not pysec["disjoint"] and pysec["fixed"] and list(cand.fixed) == pysec["fixed"]:
            return "B"
    if not cand.cites_commit:
        return "C"
    return None


def select(
    pool: list[tuple[Candidate, dict | None, str]],
    quotas: dict[str, int],
    probe_eligible: set[str] | None = None,
    probe_reserved: int = 0,
):
    """Deterministic: sort by advisory id and fill each arm in order.

    No sampling, no randomness, no judgement. The same snapshot yields the same
    corpus, and a reader can check that by re-running.

    Arm C reserves `probe_reserved` of its slots for packages that can carry a
    behavioural probe. Only 7% of candidates can: a probe has to import the package,
    there is no installer in the sandbox, and most real Python packages have
    dependencies. Without the reservation the corpus contains one such package by
    chance and the behavioural tier has nothing to run on.

    The reservation biases arm C: dependency-free packages are simpler than average.
    That is a declared stratum, recorded in the ledger, and probe coverage is reported
    on its own and never folded into the headline.
    """
    taken: list[dict] = []
    overflow: list[tuple[str, str]] = []
    counts: collections.Counter[str] = collections.Counter()
    seen_packages: set[str] = set()

    for cand, pysec, arm in sorted(pool, key=lambda t: t[0].ghsa):
        # One advisory per package, corpus-wide. Without this the first eleven ids in
        # alphabetical order gave three `mezzanine` advisories out of eleven slots, and
        # one project's release conventions would dominate an entire arm.
        if cand.package in seen_packages:
            overflow.append((cand.ghsa, Reason.PACKAGE_ALREADY_REPRESENTED))
            continue
        if counts[arm] >= quotas.get(arm, 0):
            overflow.append((cand.ghsa, Reason.ARM_FULL))
            continue
        # Hold the last `probe_reserved` slots of arm C open for probe-capable
        # packages, rather than letting the alphabet spend them first.
        if probe_eligible is not None and arm == "C":
            remaining = quotas["C"] - counts["C"]
            key = f"{cand.package}@{cand.fixed[0]}" if cand.fixed else cand.package
            if remaining <= probe_reserved and key not in probe_eligible:
                overflow.append((cand.ghsa, Reason.PROBE_QUOTA_ONLY))
                continue
        counts[arm] += 1
        seen_packages.add(cand.package)
        entry = cand.to_json()
        entry["arm"] = arm
        entry["probe_eligible"] = (
            probe_eligible is not None
            and bool(cand.fixed)
            and f"{cand.package}@{cand.fixed[0]}" in probe_eligible
        )
        entry["pysec_id"] = pysec["pysec"] if pysec else None
        taken.append(entry)
    return taken, overflow


def split_dev_heldout(entries: list[dict], hard_case: str | None) -> None:
    """Three of every five to dev, two to held-out, within each arm.

    Round-robin rather than a hand-picked split, so the assignment cannot be steered
    toward advisories the implementation happens to handle. One advisory is pinned to
    dev: the worked example used in the documentation has been looked at closely, so it
    must not sit in the held-out measurement.

    At this corpus size the held-out set is small enough that one error moves the
    figure by ten points or more. Report raw counts, never percentages.
    """
    by_arm: dict[str, list[dict]] = collections.defaultdict(list)
    for e in entries:
        by_arm[e["arm"]].append(e)
    for arm in sorted(by_arm):
        for i, entry in enumerate(sorted(by_arm[arm], key=lambda e: e["ghsa"])):
            entry["split"] = "heldout" if i % 5 in (3, 4) else "dev"
            if hard_case and entry["ghsa"] == hard_case:
                entry["split"] = "dev"
                entry["hard_case"] = True


# --------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("."))
    ap.add_argument("--cache", type=pathlib.Path, default=pathlib.Path(".cache/osv-pypi.zip"))
    ap.add_argument("--refresh", action="store_true", help="re-download the snapshot")
    ap.add_argument("--arm-a", type=int, default=6)
    ap.add_argument("--arm-b", type=int, default=8)
    ap.add_argument("--arm-c", type=int, default=11)
    ap.add_argument("--hard-case", default="GHSA-x7jh-595q-wq82",
                    help="worked example; pinned to dev, never held out")
    ap.add_argument("--probe-reserved", type=int, default=4,
                    help="arm C slots held open for probe-capable packages")
    args = ap.parse_args()

    args.cache.parent.mkdir(parents=True, exist_ok=True)
    provenance = fetch_snapshot(args.cache, args.refresh)

    records = list(read_records(args.cache))
    provenance["records_in_snapshot"] = len(records)
    pysec_index = index_pysec(records)

    pool: list[tuple[Candidate, dict | None, str]] = []
    excluded: list[dict] = []
    funnel: collections.Counter[str] = collections.Counter()

    for record in records:
        cand, reason = build_candidate(record)
        if cand is None:
            funnel[reason] += 1
            # Only advisories that cleared the GHSA gate were genuinely considered;
            # recording the other ~19k would bury the ledger in noise.
            if reason not in (Reason.NOT_GHSA, Reason.UNREVIEWED, Reason.NO_PYPI_PACKAGE):
                excluded.append({"id": record.get("id"), "reason": reason})
            continue
        funnel["CANDIDATE"] += 1
        pysec = next(
            (pysec_index[(cve, cand.package)] for cve in cand.cves
             if (cve, cand.package) in pysec_index),
            None,
        )
        arm = assign_arm(cand, pysec)
        if arm is None:
            excluded.append({"id": cand.ghsa, "reason": Reason.NO_ARM})
            continue
        pool.append((cand, pysec, arm))

    quotas = {"A": args.arm_a, "B": args.arm_b, "C": args.arm_c}
    available = collections.Counter(arm for _, _, arm in pool)

    eligible_path = args.out / "probe_eligible.json"
    probe_eligible: set[str] | None = None
    if eligible_path.exists():
        # Keyed "package@version": eligibility is a property of the release, not the
        # project. Old uploads carry different metadata from recent ones.
        probe_eligible = {
            key for key, v in json.loads(eligible_path.read_text()).items() if v["eligible"]
        }

    corpus, overflow = select(pool, quotas, probe_eligible, args.probe_reserved)
    excluded.extend({"id": gid, "reason": r} for gid, r in overflow)
    split_dev_heldout(corpus, args.hard_case)

    out = args.out
    (out / "reference").mkdir(parents=True, exist_ok=True)

    reference = {
        e["ghsa"]: pysec_index[(cve, e["package"])]
        for e in corpus
        for cve in e["cves"]
        if (cve, e["package"]) in pysec_index
    }
    (out / "reference" / "pysec.json").write_text(json.dumps(reference, indent=1, sort_keys=True))
    (out / "corpus.json").write_text(json.dumps(corpus, indent=1, sort_keys=True))
    (out / "EXCLUSIONS.json").write_text(
        json.dumps(sorted(excluded, key=lambda e: (e["reason"], e["id"] or "")), indent=1)
    )
    provenance["funnel"] = dict(sorted(funnel.items()))
    provenance["available_per_arm"] = dict(sorted(available.items()))
    provenance["quotas"] = quotas
    (out / "PROVENANCE.json").write_text(json.dumps(provenance, indent=1, sort_keys=True))

    taken = collections.Counter(e["arm"] for e in corpus)
    split = collections.Counter(e["split"] for e in corpus)
    print(f"snapshot        {provenance['sha256'][:16]}…  {provenance['records_in_snapshot']} records")
    print("funnel")
    for reason, n in sorted(funnel.items(), key=lambda kv: -kv[1]):
        print(f"  {reason:<24} {n:>6}")
    print("arms            " + "  ".join(
        f"{a}: {taken[a]}/{available[a]}" for a in sorted(quotas)))
    print(f"split           dev {split['dev']} · heldout {split['heldout']}")
    n_probe = sum(1 for e in corpus if e.get("probe_eligible"))
    print(f"probe-capable   {n_probe} of {len(corpus)}"
          + ("" if probe_eligible else "   (probe_eligible.json absent — quota not applied)"))
    if any(taken[a] < quotas[a] for a in quotas):
        print("\n!! an arm is short of quota — ship the smaller corpus and report the real number.\n"
              "   Do not pad it to a round figure.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
