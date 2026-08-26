"""Documentation and coverage audits for the 0.4.0 design (D-13, D-14).

The design document lives outside the repository, so the authoritative list
of test ids is checked in at tests/fixtures/test-ids-0.4.0.txt. When the
design doc is present locally, its id set must match that file.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
ID_FILE = TESTS / "fixtures" / "test-ids-0.4.0.txt"
DESIGN_DOC = ROOT / "docs" / "DESIGN-0.4.0.md"

ID_RE = re.compile(r"\bT-(\d+)-(\d+)\b")
TEST_NAME_RE = re.compile(r"^\s*def (test_\w*?T_(\d+)_(\d+)\w*)\(", re.M)


def _expected_ids() -> set:
    return {m.group(0) for m in ID_RE.finditer(ID_FILE.read_text())}


def _implemented_ids() -> dict:
    found: dict = {}
    for path in TESTS.glob("test_*.py"):
        for m in TEST_NAME_RE.finditer(path.read_text()):
            found.setdefault(f"T-{m.group(2)}-{m.group(3)}", []).append(
                f"{path.name}::{m.group(1)}")
    return found


@pytest.mark.skipif(not DESIGN_DOC.exists(), reason="design doc is local-only")
def test_id_list_matches_design_doc():
    in_doc = {m.group(0) for m in ID_RE.finditer(DESIGN_DOC.read_text())}
    assert in_doc == _expected_ids(), (
        "regenerate tests/fixtures/test-ids-0.4.0.txt from the design doc")


def test_no_test_id_is_implemented_twice():
    dupes = {k: v for k, v in _implemented_ids().items() if len(v) > 1}
    assert not dupes, dupes


def test_no_unknown_test_ids():
    unknown = set(_implemented_ids()) - _expected_ids()
    assert not unknown, unknown


# Flipped to a hard failure in the final 0.4.0 commit (Phase 9); until then it
# reports progress without turning the suite red.
@pytest.mark.xfail(reason="0.4.0 in progress: not every design test id exists yet",
                   strict=False)
def test_every_design_test_id_is_implemented():
    missing = sorted(_expected_ids() - set(_implemented_ids()),
                     key=lambda s: tuple(int(x) for x in s.split("-")[1:]))
    assert not missing, f"{len(missing)} unimplemented: {missing}"
