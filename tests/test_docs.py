"""Documentation and coverage audits for the 0.4.0 design (D-13, D-14).

The design document lives outside the repository, so the authoritative list
of test ids is checked in at tests/fixtures/test-ids-0.4.0.txt. When the
design doc is present locally, its id set must match that file.
"""
import os
import re
import sqlite3
import subprocess
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


def test_every_design_test_id_is_implemented():
    missing = sorted(_expected_ids() - set(_implemented_ids()),
                     key=lambda s: tuple(int(x) for x in s.split("-")[1:]))
    assert not missing, f"{len(missing)} unimplemented: {missing}"


# ── D-13: the threat-model table is in SECURITY.md verbatim ─────────────────

# Fallback copies of the D-13 paragraphs, used when the (local-only) design
# doc is absent; when it is present the test reads the paragraphs from it.
PROTECTS = (
    'secrets at rest (vault), secrets absent from images / `.env` / `docker inspect` '
    "(for the consuming app's own containers), credential material at rest (Argon2id, "
    'encrypted seeds, keyed tags), replay of TOTP codes and recovery codes, offline '
    'brute force of recovery codes and reset tokens, transplant of ciphertext between '
    'rows/stores, stale-index duplicate writes, silent boot without secrets (doctor + '
    'allowlist fail-closed).'
)
DOES_NOT_PROTECT = (
    'a host root that can read the key file; secrets that must be passed to '
    'third-party images via their own env (they are out of `.env`, not out of their '
    "container's `inspect`); build-time constants in a shipped JS bundle "
    "(delivery-model problem, stays deferred); the app's session layer."
)


def _threat_paragraphs() -> tuple:
    if DESIGN_DOC.exists():
        text = DESIGN_DOC.read_text()
        sec = text[text.index("### D-13"):text.index("### D-14")]

        def para(prefix):
            m = re.search(re.escape(prefix) + r"(.*?)\n\n", sec, re.S)
            return " ".join(m.group(1).split())
        return para("Protects: "), para("Does not protect: ")
    return PROTECTS, DOES_NOT_PROTECT


def test_T_13_1_security_md_carries_the_threat_table_and_corrected_decoy_statement():
    text = (ROOT / "SECURITY.md").read_text()
    normalized = " ".join(text.split())
    protects, does_not = _threat_paragraphs()
    assert f"| **Protects** | {protects} |" in normalized
    assert f"| **Does not protect** | {does_not} |" in normalized
    assert "cheapest cost parameters" not in text
    assert "most expensive cost parameters" in text
    assert "timing" in text and "legacy" in text.lower()


# ── D-14: compatibility ──────────────────────────────────────────────────────

#: 0.3.0 tests whose bodies changed for 0.4.0: five asserted the literal
#: schema version 3 (now SCHEMA_VERSION), one greps for messages that moved
#: files. Anything else differing from the v0.3.0 tag is a compatibility
#: break and fails this audit.
ALLOWED_CHANGES = {
    "test_cli_migration.py": {"test_cli_opens_v2_vault_without_losing_entries",
                             "test_cli_opens_v1_vault_without_losing_entries"},
    # `env import` lives in cli_server.py since the pre-argparse command
    # bodies were removed (review finding F21); the messages it greps for
    # moved with it.
    "test_release_review_fixes.py": {"test_t3_partial_env_import_message_is_accurate"},
    "test_security_regressions.py": {
        "test_h3_new_vaults_are_schema_v3",
        "test_h3_v2_vault_upgrades_transparently",
        "test_h6_rollback_plus_mac_delete_plus_version_rollback_is_detected"},
}

_FUNC_RE = re.compile(r"^(?=def test_)", re.M)


def _test_bodies(text: str) -> dict:
    bodies = {}
    for chunk in _FUNC_RE.split(text)[1:]:
        name = chunk.split("(", 1)[0][len("def "):]
        bodies[name] = chunk.rstrip()
    return bodies


def _git_show(ref: str, path: str):
    try:
        out = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT,
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 else None


#: Preamble (everything before the first test) lines that may differ from
#: v0.3.0, per file: (removed lines, added lines). Anything else — including
#: a module-level `pytestmark = pytest.mark.skip` that would silence every
#: 0.3.0 regression test (review finding S3) — fails the audit.
ALLOWED_PREAMBLE_CHANGES = {
    "test_security_regressions.py": (
        {"from sofiavault.storage import get_schema_version"},
        {"from sofiavault.storage import SCHEMA_VERSION, get_schema_version"},
    ),
}


def _preamble(text: str) -> list:
    return text.split("def test_", 1)[0].splitlines()


def test_T_14_1_the_0_3_0_test_suite_is_unmodified_except_for_enumerated_tests():
    listing = _git_show("v0.3.0", "tests")
    if listing is None:
        if os.environ.get("CI"):
            pytest.fail("v0.3.0 tag not available: the 0.3.0 compatibility audit cannot "
                        "run — fetch tags in CI (review finding S2)")
        pytest.skip("v0.3.0 tag not available")
    files = [line for line in listing.splitlines() if line.endswith(".py")]
    assert len(files) > 10
    for name in files:
        old = _git_show("v0.3.0", f"tests/{name}")
        new_path = TESTS / name
        assert new_path.exists(), f"0.3.0 test file removed: {name}"
        new_text = new_path.read_text()
        removed = set(_preamble(old)) - set(_preamble(new_text))
        added = set(_preamble(new_text)) - set(_preamble(old))
        allowed_removed, allowed_added = ALLOWED_PREAMBLE_CHANGES.get(name, (set(), set()))
        assert removed <= allowed_removed and added <= allowed_added, (
            f"{name}: module preamble changed since 0.3.0: -{sorted(removed - allowed_removed)}"
            f" +{sorted(added - allowed_added)}")
        old_bodies, new_bodies = _test_bodies(old), _test_bodies(new_text)
        missing = set(old_bodies) - set(new_bodies)
        assert not missing, f"{name}: 0.3.0 tests removed: {sorted(missing)}"
        changed = {n for n in old_bodies if old_bodies[n] != new_bodies[n]}
        assert changed <= ALLOWED_CHANGES.get(name, set()), (
            f"{name}: 0.3.0 tests changed outside the enumerated set: "
            f"{sorted(changed - ALLOWED_CHANGES.get(name, set()))}")


def test_T_14_2_0_3_0_fixtures_are_checked_in_and_at_the_old_schema():
    fixtures = TESTS / "fixtures" / "0.3.0"
    vault = sqlite3.connect(f"file:{fixtures / 'vault.db'}?mode=ro", uri=True)
    assert vault.execute("SELECT value FROM vault_meta WHERE key='schema_version'"
                         ).fetchone()[0] == "3"
    assert "time_cost" not in {r[1] for r in vault.execute("PRAGMA table_info(master)")}
    users = sqlite3.connect(f"file:{fixtures / 'users.db'}?mode=ro", uri=True)
    assert users.execute("SELECT value FROM auth_meta WHERE key='schema_version'"
                         ).fetchone()[0] == "1"
    assert "totp_enc" not in {r[1] for r in users.execute("PRAGMA table_info(users)")}
    assert (fixtures / "make_fixtures.py").exists()
