"""D-11: pluggable legacy verifiers and import_sqlite."""

import base64
import hashlib
import sqlite3
import statistics
import tempfile
import time
from pathlib import Path

import pytest

from sofiavault.auth import AuthStoreError, LegacyBcryptSha256Pepper, UserStore

bcrypt = pytest.importorskip("bcrypt")
PEPPER = "test-pepper"


def _legacy_hash(password: str) -> str:
    digest = hashlib.sha256((password + PEPPER).encode()).digest()
    return bcrypt.hashpw(base64.b64encode(digest), bcrypt.gensalt(rounds=4)).decode()


def _legacy_db(d: Path, users) -> Path:
    src = d / "auth.db"
    conn = sqlite3.connect(str(src))
    conn.execute("CREATE TABLE managers (id INTEGER PRIMARY KEY, username TEXT, "
                 "password_hash TEXT, role TEXT, is_admin INTEGER, is_active INTEGER)")
    conn.executemany("INSERT INTO managers (username, password_hash, role, is_admin, "
                     "is_active) VALUES (?, ?, ?, ?, ?)", users)
    conn.commit()
    conn.close()
    return src


class CountingVerifier:
    def __init__(self):
        self.calls = 0
        self.inner = LegacyBcryptSha256Pepper(PEPPER)

    def __call__(self, password, payload):
        self.calls += 1
        return self.inner(password, payload)


@pytest.fixture
def migrated():
    d = Path(tempfile.mkdtemp())
    src = _legacy_db(d, [
        ("alice", _legacy_hash("alice-pw"), "senior", 1, 1),
        ("bob", _legacy_hash("bob-pw"), "junior", 0, 0),
    ])
    counting = CountingVerifier()
    store = UserStore(d / "users.db", legacy_verifiers={"bcrypt-sha256-pepper": counting})
    created, skipped = store.import_sqlite(src, "managers", scheme="bcrypt-sha256-pepper")
    return d, store, counting, created, skipped


def test_T_11_1_legacy_user_verifies_once_then_becomes_argon2(migrated):
    d, store, counting, created, skipped = migrated
    assert created == ["alice", "bob"] and skipped == []
    r = store.verify("alice", "alice-pw")
    assert r is not None and r.role == "senior" and r.is_admin is True
    assert counting.calls == 1
    row = sqlite3.connect(str(d / "users.db")).execute(
        "SELECT legacy_hash, time_cost FROM users WHERE username='alice'").fetchone()
    assert row[0] is None and row[1] >= 1
    assert store.verify("alice", "alice-pw") is not None
    assert counting.calls == 1                       # bcrypt never consulted again
    assert store.get_user("alice")["legacy"] is False
    store.close()


def test_T_11_2_wrong_password_leaves_the_legacy_row_untouched(migrated):
    d, store, counting, *_ = migrated
    before = sqlite3.connect(str(d / "users.db")).execute(
        "SELECT * FROM users WHERE username='alice'").fetchone()
    assert store.verify("alice", "nope") is None
    after = sqlite3.connect(str(d / "users.db")).execute(
        "SELECT * FROM users WHERE username='alice'").fetchone()
    assert before == after and counting.calls == 1
    assert store.get_user("alice")["legacy"] is True
    store.close()


def _median_ms(fn, n=7):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples) * 1000


@pytest.mark.slow
def test_T_11_3_unknown_user_and_argon2_user_stay_flat_with_legacy_rows_present(migrated):
    """The weaker claim (see design §9.6): legacy rows add bcrypt on top of
    the Argon2 ceiling and are distinguishable until first login; but their
    presence must not skew unknown-user vs. Argon2-user timing."""
    d, store, *_ = migrated
    store.add_user("carol", "carol-pw")
    unknown = _median_ms(lambda: store.verify("zed", "x"))
    argon = _median_ms(lambda: store.verify("carol", "wrong"))
    legacy = _median_ms(lambda: store.verify("bob", "wrong"))
    assert abs(unknown - argon) < max(unknown, argon) * 0.5
    assert legacy >= argon * 0.6      # pads to the ceiling (advisory: wall-clock is noisy)
    store.close()


def test_T_11_4_import_sqlite_maps_flags_and_skips_existing():
    d = Path(tempfile.mkdtemp())
    src = _legacy_db(d, [
        ("alice", "h1", "senior", 1, 1), ("bob", "h2", None, 0, 0),
        ("alice", "dup", "x", 0, 1), (None, "h", "r", 0, 1), ("eve", "", "r", 0, 1),
        ("bad\nname", "h", "r", 0, 1),
    ])
    with UserStore(d / "users.db") as store:
        store.add_user("existing", "pw-existing-1")
        created, skipped = store.import_sqlite(
            src, "managers", scheme="fake",
            columns={"username": "username", "password_hash": "password_hash"})
        assert created == ["alice", "bob"]
        assert [x.split(" ")[0] for x in skipped] == ["alice", "None", "eve", "bad\nname"]
        assert store.get_user("alice")["role"] == "senior"
        assert store.get_user("alice")["is_admin"] is True
        assert store.get_user("bob")["is_active"] is False
        assert store.get_user("bob")["role"] == ""
        assert store.list_users(admin_only=True) == ["alice"]
        assert store.get_user("existing")["legacy"] is False
        with pytest.raises(AuthStoreError):
            store.import_sqlite(src, "nope", scheme="fake")
        with pytest.raises(AuthStoreError):
            store.import_sqlite(src, "managers", scheme="fake",
                                columns={"password_hash": "missing_col"})
        with pytest.raises(AuthStoreError):
            store.import_sqlite(src, "managers; DROP TABLE users", scheme="fake")


def test_T_11_5_unknown_scheme_raises_never_silent_none():
    d = Path(tempfile.mkdtemp())
    src = _legacy_db(d, [("alice", _legacy_hash("alice-pw"), "r", 0, 1)])
    with UserStore(d / "users.db") as store:          # no verifiers registered
        store.import_sqlite(src, "managers", scheme="bcrypt-sha256-pepper")
        with pytest.raises(AuthStoreError, match="no legacy verifier"):
            store.verify("alice", "alice-pw")
        with pytest.raises(AuthStoreError):
            store.verify("alice", "wrong")
    other = UserStore(d / "users.db", legacy_verifiers={"other": lambda p, h: True})
    with pytest.raises(AuthStoreError, match="bcrypt-sha256-pepper"):
        other.verify("alice", "alice-pw")
    other.close()
    with pytest.raises(AuthStoreError):
        UserStore(d / "users.db", legacy_verifiers={"bad$name": lambda p, h: True})


def test_legacy_verifier_exceptions_and_deactivated_users():
    d = Path(tempfile.mkdtemp())
    src = _legacy_db(d, [("alice", _legacy_hash("alice-pw"), "r", 0, 0)])
    with UserStore(d / "users.db",
                   legacy_verifiers={"bcrypt-sha256-pepper": LegacyBcryptSha256Pepper(PEPPER)}
                   ) as store:
        store.import_sqlite(src, "managers", scheme="bcrypt-sha256-pepper")
        assert store.verify("alice", "alice-pw") is None      # inactive: still denied
        store.activate("alice")
        assert store.verify("alice", "alice-pw") is not None
        assert LegacyBcryptSha256Pepper(PEPPER)("x", "not-a-bcrypt-hash") is False
