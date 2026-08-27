"""Regression tests for the 0.4.0 pre-release security review (F-ids).

Each finding in docs/SECURITY-REVIEW-0.4.0.md has one `test_F_n_…` here,
mirroring the design's T-id convention.
"""

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from sofiavault import envload, storage
from sofiavault.vault import Vault, VaultCorrupted

FIXTURE_V3 = Path(__file__).parent / "fixtures" / "0.3.0" / "vault.db"
FIXTURE_PW = "fixture-master-password-0.3.0"


def _tmp() -> Path:
    return Path(tempfile.mkdtemp())


def _sql(path: Path, stmt: str, params=()):
    conn = sqlite3.connect(str(path))
    conn.execute(stmt, params)
    conn.commit()
    conn.close()


# ── F1: a v3 vault with its MAC stripped must never be re-adopted ───────────

def test_F_1_stripped_mac_on_a_v3_vault_is_tamper_evidence_not_adoption():
    d = _tmp()
    path = d / "v3.db"
    shutil.copy(FIXTURE_V3, path)
    os.chmod(path, 0o600)
    # attacker: roll back a secret (swap blobs is detectable per-entry, so
    # delete a row instead), strip the MAC, keep schema_version = '3'
    _sql(path, "DELETE FROM entries_v2 WHERE id = (SELECT MAX(id) FROM entries_v2)")
    _sql(path, "DELETE FROM vault_meta WHERE key = 'entries_mac'")
    with Vault.open(path, password=FIXTURE_PW) as v:
        assert v.tampered is True
        with pytest.raises(VaultCorrupted):
            v.get("github")
        with pytest.raises(VaultCorrupted):
            envload.load(vault=v, environ={})
    conn = sqlite3.connect(str(path))
    # the migration must not have re-signed it either
    assert conn.execute("SELECT value FROM vault_meta WHERE key='schema_version'"
                        ).fetchone()[0] == "3"
    assert conn.execute("SELECT value FROM vault_meta WHERE key='entries_mac'"
                        ).fetchone() is None
    # same at the storage level, independent of Vault
    key = None
    with Vault.open(path, password=FIXTURE_PW) as v:
        key = v._key
    assert storage.verify_entries_mac(conn, key) is False
    # and an honest v3 vault (MAC intact) still migrates to v4 cleanly
    good = d / "good.db"
    shutil.copy(FIXTURE_V3, good)
    os.chmod(good, 0o600)
    with Vault.open(good, password=FIXTURE_PW) as v:
        assert v.tampered is False and v.get("github") == "hunter2"
    assert sqlite3.connect(str(good)).execute(
        "SELECT value FROM vault_meta WHERE key='schema_version'").fetchone()[0] == "4"
