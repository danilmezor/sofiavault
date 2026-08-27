"""D-10: one-time password-reset tokens."""

import base64
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest

from sofiavault.auth import AuthStoreError, UserStore

KEY = bytes(range(32))


def _store():
    path = Path(tempfile.mkdtemp()) / "users.db"
    s = UserStore(path, fields_key=KEY)
    s.add_user("alice", "old-password-1")
    return s, path


def test_T_10_1_issue_then_redeem_once():
    s, path = _store()
    token = s.reset_token_issue("alice")
    assert len(token) >= 43
    assert s.verify("alice", "old-password-1") is not None      # issuing changes nothing
    assert s.reset_token_redeem(token, "new-password-2") == "alice"
    assert s.verify("alice", "old-password-1") is None
    assert s.verify("alice", "new-password-2") is not None
    assert s.reset_token_redeem(token, "third-password-3") is None
    assert s.verify("alice", "third-password-3") is None
    assert s.reset_token_redeem("", "x-password-1") is None
    assert s.reset_token_redeem("not-a-real-token", "x-password-1") is None
    with pytest.raises(AuthStoreError):
        s.reset_token_issue("nobody")
    s.close()


def test_T_10_2_expired_token_is_refused_and_removed():
    s, path = _store()
    token = s.reset_token_issue("alice", ttl_seconds=0.05)
    time.sleep(0.1)
    assert s.reset_token_redeem(token, "new-password-2") is None
    assert s.verify("alice", "old-password-1") is not None
    assert sqlite3.connect(str(path)).execute(
        "SELECT COUNT(*) FROM reset_tokens").fetchone()[0] == 0
    s.close()


def test_T_10_3_second_token_invalidates_the_first():
    s, path = _store()
    first = s.reset_token_issue("alice")
    second = s.reset_token_issue("alice")
    assert s.reset_token_redeem(first, "new-password-2") is None
    assert s.reset_token_redeem(second, "new-password-2") == "alice"
    assert s.reset_token_revoke("alice") is False
    third = s.reset_token_issue("alice")
    assert s.reset_token_revoke("alice") is True
    assert s.reset_token_redeem(third, "x-password-1") is None
    s.close()


def test_T_10_4_redeem_clears_legacy_hash_and_stamps_password_changed_at():
    d = Path(tempfile.mkdtemp())
    src = d / "legacy.db"
    c = sqlite3.connect(str(src))
    c.execute("CREATE TABLE m (username TEXT, password_hash TEXT)")
    c.execute("INSERT INTO m VALUES ('alice', 'abc')")
    c.commit()
    c.close()
    s = UserStore(d / "users.db", fields_key=KEY)
    s.import_sqlite(src, "m", scheme="fake")
    row = sqlite3.connect(str(d / "users.db")).execute(
        "SELECT legacy_hash, password_changed_at FROM users").fetchone()
    assert row[0] == "fake$abc"
    imported_at = row[1]
    time.sleep(1.1)   # timestamps have second resolution
    token = s.reset_token_issue("alice")
    assert s.reset_token_redeem(token, "new-password-2") == "alice"
    row = sqlite3.connect(str(d / "users.db")).execute(
        "SELECT legacy_hash, password_changed_at FROM users").fetchone()
    assert row[0] is None and row[1] != imported_at
    assert s.verify("alice", "new-password-2").password_changed_at == row[1]
    s.close()


def test_T_10_5_token_is_not_recoverable_from_the_file():
    s, path = _store()
    token = s.reset_token_issue("alice")
    s.close()
    data = path.read_bytes()
    assert token.encode() not in data
    # nor any 43-char window of it (no partial leak, no raw hash of it)
    for i in range(len(token) - 42):
        assert token[i:i + 43].encode() not in data
    import hashlib
    assert hashlib.sha256(token.encode()).digest() not in data
    assert base64.urlsafe_b64decode(token + "=") not in data
