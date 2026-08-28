"""Every module imports, on the Python this project says it needs.

This exists because it did not. `investigate.py` -- the module that joins every other
one -- had no test of its own, so nothing imported it, so a runtime type alias that
needs Python 3.10 went unnoticed. A stranger on macOS gets the built-in python3, which
is 3.9, and saw a TypeError from inside an import rather than a message they could act
on.

A test that only imports looks like it is testing nothing. It is testing the one thing
every other test assumes.
"""

import importlib
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rangecore"))
sys.path.insert(0, str(ROOT / "bench"))

MODULES = [
    "version", "candidates", "tree", "backport", "evidence", "boundary",
    "model", "investigate", "wheel_spike", "probe_eligibility", "select_corpus",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)


def test_the_declared_floor_is_the_real_floor():
    """The README says 3.10 or newer. If that is wrong in either direction, the README
    is wrong, and a setup step that does not work is worse than no setup step."""
    assert sys.version_info >= (3, 10), (
        "this suite is being run on a Python the project does not support; "
        "the entry points refuse it with a message, but the tests should say so too"
    )


def test_the_pipeline_exposes_what_the_runner_calls():
    """bench/run.py calls investigate() and reads .to_json(). Import alone would not
    catch a rename."""
    investigate = importlib.import_module("investigate")
    assert callable(investigate.investigate)
    assert callable(investigate.first_by_source)
    assert hasattr(investigate.Investigation, "to_json")
