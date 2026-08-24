"""Can a probe run at two released versions with no package installer?

The sandbox has Python 3.13, git, curl and no way to install anything. If a probe
cannot be made to run there, the behavioural evidence tier does not exist and the
day allocated to it should be reclaimed now rather than discovered on the day.

Acquire from wheels, not from a git checkout. A git tree of a pure-Python project
frequently will not import: src/ layouts need the path pointed elsewhere,
setuptools_scm generates _version.py at build time, parser tables and package_data
are produced during the build. Every one of those is a build-step failure and every
one disappears with a wheel, which is already built. Affected ranges are expressed
over released versions anyway, so an arbitrary commit is never needed.

This is a hand-rolled installer: zip extract plus PYTHONPATH. No dependency
resolution, no site-packages, no entry points, no metadata beyond the digest.
Saying so here is cheaper than being told.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

PYPI = "https://pypi.org/pypi/{name}/{version}/json"

# A wheel that runs anywhere. Anything else needs a compiled extension matching the
# interpreter, and old releases of a package rarely ship one for a current Python.
PORTABLE_TAGS = ("py3-none-any", "py2.py3-none-any")


def runtime_requirements(name: str, version: str, timeout: int = 30) -> list[str] | None:
    """Runtime dependencies, ignoring anything behind an extra.

    This, not wheel availability, is the gate. A package with dependencies needs those
    dependencies acquired too, and acquiring them recursively is dependency resolution
    — which is the installer this design does not have. Probes are for packages that
    stand alone.
    """
    try:
        with urllib.request.urlopen(PYPI.format(name=name, version=version), timeout=timeout) as r:
            info = json.load(r).get("info", {})
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None
    return [d for d in (info.get("requires_dist") or []) if "extra ==" not in d]


def wheel_for(name: str, version: str, timeout: int = 30) -> dict | None:
    """The portable wheel for one release, or None if there isn't one."""
    try:
        with urllib.request.urlopen(PYPI.format(name=name, version=version), timeout=timeout) as r:
            payload = json.load(r)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None
    for f in payload.get("urls", []):
        if f.get("packagetype") != "bdist_wheel":
            continue
        if any(f["filename"].endswith(f"-{tag}.whl") for tag in PORTABLE_TAGS):
            return {
                "url": f["url"],
                "sha256": f["digests"]["sha256"],
                "filename": f["filename"],
                "yanked": f.get("yanked", False),
            }
    return None


def fetch_and_extract(wheel: dict, into: Path, timeout: int = 60) -> Path:
    """Download, verify the digest PyPI published, unzip. Digest first, always."""
    with urllib.request.urlopen(wheel["url"], timeout=timeout) as r:
        blob = r.read()
    got = hashlib.sha256(blob).hexdigest()
    if got != wheel["sha256"]:
        raise ValueError(f"digest mismatch for {wheel['filename']}: {got} != {wheel['sha256']}")
    into.mkdir(parents=True, exist_ok=True)
    archive = into / wheel["filename"]
    archive.write_bytes(blob)
    site = into / "site"
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(site)
    return site


def run_probe(probe: Path, site: Path, timeout: int = 10) -> tuple[str, str]:
    """Run a probe against one extracted release.

    The contract is one line on stdout and nothing else counts. A probe that crashes,
    times out, or prints something unexpected is INCONCLUSIVE — never 'fixed'. That
    single rule removes the whole class of 'the probe fell over and we read it as safe'.
    """
    try:
        p = subprocess.run(
            # -S keeps site-packages out. Without it the host's own copy of a
            # dependency is visible and the probe measures the wrong tree; that is
            # how the first run of this spike produced a false INCONCLUSIVE.
            [sys.executable, "-S", str(probe)],
            env={"PYTHONPATH": str(site), "PYTHONHASHSEED": "0", "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "INCONCLUSIVE", "timeout"
    for line in p.stdout.splitlines():
        if line.startswith("PROBE_VERDICT "):
            try:
                verdict = json.loads(line[len("PROBE_VERDICT "):])["observed"]
            except (ValueError, KeyError):
                return "INCONCLUSIVE", "malformed verdict line"
            if verdict in ("VULNERABLE", "NOT_VULNERABLE"):
                return verdict, ""
            return "INCONCLUSIVE", f"unknown verdict {verdict!r}"
    tail = (p.stderr or p.stdout).strip().splitlines()
    return "INCONCLUSIVE", (tail[-1][:120] if tail else f"no verdict line, exit {p.returncode}")


def differential(name: str, before: str, after: str, probe: Path) -> dict:
    """Run one probe at the last-affected release and at the proposed first-fixed one.

    A probe that does not fire at the release still known to be vulnerable is a broken
    probe, and its answer at the boundary means nothing. The negative control is what
    makes a coverage number worth reporting.
    """
    out = {"package": name, "before": before, "after": after}
    w_before, w_after = wheel_for(name, before), wheel_for(name, after)
    if w_before is None or w_after is None:
        missing = [v for v, w in ((before, w_before), (after, w_after)) if w is None]
        out["eligible"] = False
        out["reason"] = f"no portable wheel at {', '.join(missing)}"
        return out
    reqs_before = runtime_requirements(name, before)
    if reqs_before:
        out["eligible"] = False
        out["reason"] = f"{len(reqs_before)} runtime dependencies; no installer to acquire them"
        out["requires"] = reqs_before[:3]
        return out
    out["eligible"] = True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        try:
            site_b = fetch_and_extract(w_before, root / "before")
            site_a = fetch_and_extract(w_after, root / "after")
        except (ValueError, urllib.error.URLError, zipfile.BadZipFile) as e:
            out["reason"] = f"acquisition failed: {e}"
            return out
        out["control"], out["control_note"] = run_probe(probe, site_b)
        out["boundary"], out["boundary_note"] = run_probe(probe, site_a)
    out["calibrated"] = out["control"] == "VULNERABLE"
    out["differential"] = out["calibrated"] and out["boundary"] == "NOT_VULNERABLE"
    return out
