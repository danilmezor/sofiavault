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


# ── F2/F3/F20: the whole credential row is authenticated, per store ─────────

from sofiavault import totp as _totp  # noqa: E402
from sofiavault.auth import FieldsTampered, UserStore  # noqa: E402

KEY = bytes(range(32))
T0 = 1_800_000_000


def _admin_store(d: Path, name: str = "a.db") -> Path:
    path = d / name
    with UserStore(path, fields_key=KEY) as s:
        s.add_user("root", "root-pw-1", team="ops")
        s.set_admin("root", True)
        s.set_role("root", "admin")
        secret = s.totp_enroll("root")
        assert s.totp_confirm("root", _totp.code_at(secret, T0), now=T0)
        s.add_user("mallory", "mallory-pw-1")
    return path


def test_F_2_rows_do_not_transplant_between_stores_sharing_a_key():
    d = _tmp()
    a = _admin_store(d, "a.db")
    b = d / "b.db"
    with UserStore(b, fields_key=KEY) as s:
        s.add_user("mallory", "mallory-pw-1")
    src = sqlite3.connect(str(a))
    cols = [r[1] for r in src.execute("PRAGMA table_info(users)")]
    row = src.execute("SELECT * FROM users WHERE username='root'").fetchone()
    dst = sqlite3.connect(str(b))
    dst.execute(f"INSERT INTO users ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                row)
    dst.commit()
    dst.close()
    with UserStore(b, fields_key=KEY) as s:
        with pytest.raises(FieldsTampered):
            s.verify("root", "root-pw-1")
        with pytest.raises(FieldsTampered):
            s.get_user("root")
        with pytest.raises(FieldsTampered):
            s.totp_verify("root", "000000", now=T0 + 30)
        assert s.verify("mallory", "mallory-pw-1") is not None
    # the two stores have distinct ids
    ids = {sqlite3.connect(str(p)).execute(
        "SELECT value FROM auth_meta WHERE key='store_id'").fetchone()[0] for p in (a, b)}
    assert len(ids) == 2 and all(len(i) >= 32 for i in ids)


@pytest.mark.parametrize("attack", [
    "UPDATE users SET totp_confirmed = 0 WHERE username = 'root'",
    "UPDATE users SET totp_enc = NULL WHERE username = 'root'",
    "UPDATE users SET totp_counter = -1 WHERE username = 'root'",
    "UPDATE users SET legacy_hash = 'fake$x' WHERE username = 'root'",
    "UPDATE users SET password_changed_at = '1999-01-01' WHERE username = 'root'",
    "UPDATE users SET time_cost = 1, memory_cost = 64 WHERE username = 'root'",
    "UPDATE users SET recovery_enc = X'00' WHERE username = 'root'",
    "UPDATE users SET row_tag = NULL WHERE username = 'root'",
])
def test_F_3_any_edit_to_a_credential_row_is_detected_before_the_password_check(attack):
    d = _tmp()
    path = _admin_store(d)
    _sql(path, attack)
    with UserStore(path, fields_key=KEY) as s:
        with pytest.raises(FieldsTampered):
            s.verify("root", "root-pw-1")
        with pytest.raises(FieldsTampered):      # checked before Argon2, wrong pw too
            s.verify("root", "wrong")
        with pytest.raises(FieldsTampered):
            s.totp_status("root")
        with pytest.raises(FieldsTampered):
            s.set_admin("root", False)           # no laundering through the API
        assert s.verify("mallory", "mallory-pw-1") is not None


def test_F_3_swapping_another_users_password_material_onto_the_admin_is_detected():
    d = _tmp()
    path = _admin_store(d)
    conn = sqlite3.connect(str(path))
    salt, vh, t, m, p = conn.execute(
        "SELECT salt, verify_hash, time_cost, memory_cost, parallelism FROM users "
        "WHERE username='mallory'").fetchone()
    conn.execute("UPDATE users SET salt=?, verify_hash=?, time_cost=?, memory_cost=?, "
                 "parallelism=? WHERE username='root'", (salt, vh, t, m, p))
    conn.commit()
    conn.close()
    with UserStore(path, fields_key=KEY) as s, pytest.raises(FieldsTampered):
        s.verify("root", "mallory-pw-1")


def test_F_3_recovery_and_counter_edits_without_a_matching_tag_are_detected():
    d = _tmp()
    path = _admin_store(d)
    with UserStore(path, fields_key=KEY) as s:
        codes = s.recovery_generate("root", count=2)
        before = sqlite3.connect(str(path)).execute(
            "SELECT recovery_enc FROM users WHERE username='root'").fetchone()[0]
        assert s.recovery_use("root", codes[0]) is True
    # restoring just the blob (the attacker cannot mint the tag) is detected
    _sql(path, "UPDATE users SET recovery_enc = ? WHERE username='root'", (before,))
    with UserStore(path, fields_key=KEY) as s:
        with pytest.raises(FieldsTampered):
            s.recovery_use("root", codes[0])
        with pytest.raises(FieldsTampered):
            s.recovery_remaining("root")
    # Known limit (documented): restoring a whole row *with* its earlier tag
    # is a valid earlier state — a per-row MAC cannot see a rollback, only a
    # forgery. That is the same boundary the vault's entry-set MAC exists for.


def test_F_20_reset_token_expiry_is_authenticated():
    d = _tmp()
    path = _admin_store(d)
    with UserStore(path, fields_key=KEY) as s:
        token = s.reset_token_issue("root", ttl_seconds=1)
    _sql(path, "UPDATE reset_tokens SET expires_at = expires_at + 86400")
    with UserStore(path, fields_key=KEY) as s:
        assert s.reset_token_redeem(token, "new-pw-2") is None
        assert s.verify("root", "root-pw-1") is not None


def test_F_2_3_plaintext_policy_store_is_unchanged_and_documented_unauthenticated():
    d = _tmp()
    path = d / "plain.db"
    with UserStore(path) as s:
        s.add_user("alice", "alice-pw-1")
        s.set_admin("alice", True)
    assert sqlite3.connect(str(path)).execute(
        "SELECT row_tag FROM users").fetchone()[0] is None
    with UserStore(path) as s:
        assert s.verify("alice", "alice-pw-1").is_admin is True
