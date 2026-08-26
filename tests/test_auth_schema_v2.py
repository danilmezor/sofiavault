"""D-7: UserStore schema v2 and the in-place v1 migration."""

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from sofiavault import auth
from sofiavault.auth import AuthStoreError, FieldsTampered, UserStore

FIXTURE = Path(__file__).parent / "fixtures" / "0.3.0" / "users.db"
KEY = bytes(range(32))
V2_COLUMNS = [name for name, _ in auth._V2_COLUMNS]


def _copy_fixture() -> Path:
    d = Path(tempfile.mkdtemp())
    dst = d / "users.db"
    shutil.copy(FIXTURE, dst)
    os.chmod(dst, 0o600)
    return dst


def _columns(path: Path) -> dict:
    conn = sqlite3.connect(str(path))
    try:
        return {r[1]: r for r in conn.execute("PRAGMA table_info(users)")}
    finally:
        conn.close()


def test_T_7_1_v1_fixture_migrates_and_still_verifies():
    path = _copy_fixture()
    assert set(V2_COLUMNS).isdisjoint(_columns(path))
    with UserStore(path) as s:
        r = s.verify("alice", "alice-password")
        assert r is not None and r.fields == {"role": "senior", "is_admin": True}
        assert r.role == "" and r.is_admin is False and r.totp == "off"
        assert s.verify("bob", "wrong") is None
        assert s.list_users(admin_only=True) == []
    conn = sqlite3.connect(str(path))
    assert conn.execute("SELECT value FROM auth_meta WHERE key='schema_version'"
                        ).fetchone()[0] == "2"
    cols = _columns(path)
    assert set(V2_COLUMNS) <= set(cols)
    row = dict(zip([c[1] for c in cols.values()],
                   conn.execute("SELECT * FROM users WHERE username='alice'").fetchone()))
    assert row["role"] == "" and row["is_admin"] == 0 and row["totp_enc"] is None
    assert row["totp_counter"] == -1 and row["totp_confirmed"] == 0
    assert row["recovery_enc"] is None and row["legacy_hash"] is None
    assert row["password_changed_at"] == row["updated_at"] != ""
    assert conn.execute("SELECT COUNT(*) FROM reset_tokens").fetchone()[0] == 0
    # v1 fixture users have a real Argon2 row that verified above; opening
    # again is a no-op migration
    conn.close()
    with UserStore(path) as s:
        assert s.verify("bob", "bob-password") is not None


def test_T_7_2_failed_migration_leaves_the_v1_file_byte_identical(monkeypatch):
    path = _copy_fixture()
    before = path.read_bytes()
    broken = list(auth._V2_COLUMNS)
    broken.insert(4, ("boom", "TEXT UNIQUE"))   # legal in CREATE, illegal in ALTER ADD COLUMN
    monkeypatch.setattr(auth, "_V2_COLUMNS", tuple(broken))
    with pytest.raises(AuthStoreError, match="migration failed"):
        UserStore(path)
    monkeypatch.undo()
    assert path.read_bytes() == before
    assert set(V2_COLUMNS).isdisjoint(_columns(path))
    assert sqlite3.connect(str(path)).execute(
        "SELECT value FROM auth_meta WHERE key='schema_version'").fetchone()[0] == "1"
    # ...and the untouched file still migrates fine afterwards
    with UserStore(path) as s:
        assert s.verify("alice", "alice-password") is not None


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="file modes")
def test_read_only_v1_store_names_the_migration():
    path = _copy_fixture()
    os.chmod(path, 0o400)
    try:
        with pytest.raises(AuthStoreError, match="read-only"):
            UserStore(path)
    finally:
        os.chmod(path, 0o600)


def test_T_7_3_mfa_without_fields_key_is_refused_and_writes_nothing():
    path = Path(tempfile.mkdtemp()) / "users.db"
    with UserStore(path) as s:
        s.add_user("alice", "pw-alice-1")
        for call in (lambda: s.totp_enroll("alice"),
                     lambda: s.recovery_generate("alice"),
                     lambda: s.reset_token_issue("alice"),
                     lambda: s.totp_verify("alice", "000000"),
                     lambda: s.recovery_use("alice", "AAAAA-AAAAA"),
                     lambda: s.reset_token_redeem("x" * 43, "new-pw-123")):
            with pytest.raises(AuthStoreError, match="fields_key required"):
                call()
        assert s.totp_status("alice") == "off"
        assert s.verify("alice", "pw-alice-1") is not None
    conn = sqlite3.connect(str(path))
    assert conn.execute("SELECT totp_enc, recovery_enc FROM users").fetchone() == (None, None)
    assert conn.execute("SELECT COUNT(*) FROM reset_tokens").fetchone()[0] == 0


def test_T_7_4_totp_and_fields_blobs_cannot_be_swapped():
    path = Path(tempfile.mkdtemp()) / "users.db"
    with UserStore(path, fields_key=KEY) as s:
        s.add_user("alice", "pw-alice-1", team="ops")
        s.totp_enroll("alice")
    conn = sqlite3.connect(str(path))
    fields_enc, totp_enc = conn.execute(
        "SELECT fields_enc, totp_enc FROM users WHERE username='alice'").fetchone()
    conn.execute("UPDATE users SET fields_enc = ?, totp_enc = ? WHERE username='alice'",
                 (totp_enc, fields_enc))
    conn.commit()
    conn.close()
    with UserStore(path, fields_key=KEY) as s:
        with pytest.raises(FieldsTampered):
            s.verify("alice", "pw-alice-1")
        with pytest.raises(FieldsTampered):
            s.totp_confirm("alice", "000000")


def test_T_7_5_typed_flags_are_queryable_without_decrypting_fields():
    path = Path(tempfile.mkdtemp()) / "users.db"
    with UserStore(path, fields_key=KEY) as s:
        s.add_user("alice", "pw-alice-1", secret_note="x")
        s.add_user("bob", "pw-bob-1")
        s.add_user("carol", "pw-carol-1")
        assert s.set_role("alice", "senior") and s.set_admin("alice", True)
        assert s.set_role("bob", "senior")
        s.deactivate("carol")
        assert s.list_users(role="senior") == ["alice", "bob"]
        assert s.list_users(admin_only=True) == ["alice"]
        assert s.list_users(role="senior", admin_only=True) == ["alice"]
        assert s.list_users(include_inactive=False) == ["alice", "bob"]
        r = s.verify("alice", "pw-alice-1")
        assert r.role == "senior" and r.is_admin is True
        assert s.get_user("alice")["is_admin"] is True
        assert s.set_role("nobody", "x") is False
    # a store opened WITHOUT the key can still run the policy query
    with UserStore(path) as s2:
        assert s2.list_users(admin_only=True) == ["alice"]
        with pytest.raises(AuthStoreError):
            s2.get_user("alice")     # fields need the key; flags do not
    # sqlite-level: is_admin tampered to the *string* "yes" is not admin
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE users SET is_admin = 'yes' WHERE username='bob'")
    conn.commit()
    with UserStore(path, fields_key=KEY) as s:
        assert s.verify("bob", "pw-bob-1").is_admin is False
