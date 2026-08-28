"""Run the corpus and write one record per advisory.

Every result is written as it completes, so an interrupted run keeps what it had and a
second run does not repeat it. Twenty-four repositories are cloned the first time; the
clones are cached and the run is offline afterwards.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

if sys.version_info < (3, 10):
    # A stranger on macOS gets the built-in python3, which is 3.9, and otherwise sees a
    # TypeError from inside an import -- not a message anyone can act on.
    raise SystemExit(
        f"This needs Python 3.10 or newer; found {sys.version.split()[0]} at {sys.executable}.\n"
        "On macOS the built-in `python3` is 3.9 -- try python3.11 or python3.13 instead."
    )

import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "rangecore"))

from investigate import investigate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path, default=ROOT / "corpus.json")
    ap.add_argument("--out", type=pathlib.Path, default=ROOT / "results")
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="dev",
                    help="held-out entries stay unopened until the run that scores them")
    ap.add_argument("--only", default="", help="one advisory id, for debugging")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    cache = ROOT / ".cache" / "repos"
    corpus = json.loads(args.corpus.read_text())

    entries = [e for e in corpus
               if (args.split == "all" or e["split"] == args.split)
               and (not args.only or e["ghsa"] == args.only)]

    for i, entry in enumerate(entries, 1):
        target = args.out / f"{entry['ghsa']}.json"
        if target.exists():
            print(f"[{i}/{len(entries)}] {entry['ghsa']} cached", file=sys.stderr)
            continue
        started = time.time()
        result = investigate(entry, cache)
        payload = result.to_json()
        payload["arm"] = entry["arm"]
        payload["split"] = entry["split"]
        payload["seconds"] = round(time.time() - started, 1)
        target.write_text(json.dumps(payload, indent=1))
        print(f"[{i}/{len(entries)}] {entry['ghsa']:<24} {entry['package']:<22} "
              f"{result.outcome:<10} {payload['seconds']:>6}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
