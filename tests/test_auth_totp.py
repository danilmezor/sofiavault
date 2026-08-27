"""D-8 (store part): TOTP enrolment, replay-safe verification, disable."""

import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest

from sofiavault import totp
from sofiavault.auth import FieldsTampered, UserStore

KEY = bytes(range(32))
T = 1_800_000_000


def _store() -> tuple[UserStore, Path]:
    path = Path(tempfile.mkdtemp()) / "users.db"
    s = UserStore(path, fields_key=KEY)
    s.add_user("alice", "pw-alice-1")
    return s, path


def test_T_8_3_sixteen_threads_same_code_exactly_one_succeeds():
    """Half the threads use a second UserStore on the same file, so the
    guarantee rests on the database write lock (BEGIN IMMEDIATE), not on
    one instance's in-process RLock (review finding S1)."""
    s, path = _store()
    secret = s.totp_enroll("alice")
    assert s.totp_confirm("alice", totp.code_at(secret, T - 60), now=T - 60)
    code = totp.code_at(secret, T)
    results = []
    start = threading.Barrier(16)
    second = UserStore(path, fields_key=KEY)

    def attempt(store):
        start.wait()
        results.append(store.totp_verify("alice", code, now=T))

    threads = [threading.Thread(target=attempt, args=(s if i % 2 else second,))
               for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1 and len(results) == 16
    second.close()

    # and across *processes*: a second store on the same file sees the counter
    other = UserStore(path, fields_key=KEY)
    assert other.totp_verify("alice", code, now=T) is False
    nxt = totp.code_at(secret, T + 30)
    assert other.totp_verify("alice", nxt, now=T + 30) is True
    assert s.totp_verify("alice", nxt, now=T + 30) is False
    other.close()
    s.close()


def test_T_8_4_pending_enrolment_is_never_accepted_by_verify():
    s, path = _store()
    assert s.totp_status("alice") == "off"
    secret = s.totp_enroll("alice")
    assert s.totp_status("alice") == "pending"
    code = totp.code_at(secret, T)
    assert s.totp_verify("alice", code, now=T) is False
    assert s.totp_confirm("alice", "000000", now=T) is False
    assert s.totp_status("alice") == "pending"
    assert s.totp_confirm("alice", code, now=T) is True
    assert s.totp_status("alice") == "active"
    assert s.verify("alice", "pw-alice-1").totp == "active"
    # confirming again is a no-op, and the confirming code cannot be replayed
    assert s.totp_confirm("alice", code, now=T) is False
    assert s.totp_verify("alice", code, now=T) is False
    assert s.totp_verify("alice", totp.code_at(secret, T + 30), now=T + 30) is True
    # re-enrolling resets to pending with a new secret
    secret2 = s.totp_enroll("alice")
    assert secret2 != secret and s.totp_status("alice") == "pending"
    assert s.totp_verify("alice", totp.code_at(secret2, T + 90), now=T + 90) is False
    s.close()


def test_T_8_5_disable_clears_everything():
    s, path = _store()
    secret = s.totp_enroll("alice")
    s.totp_confirm("alice", totp.code_at(secret, T), now=T)
    s.recovery_generate("alice")
    assert s.totp_disable("alice") is True
    assert s.totp_status("alice") == "off"
    assert s.recovery_remaining("alice") == 0
    row = sqlite3.connect(str(path)).execute(
        "SELECT totp_enc, totp_counter, totp_confirmed, recovery_enc FROM users").fetchone()
    assert row == (None, -1, 0, None)
    assert s.totp_verify("alice", totp.code_at(secret, T + 30), now=T + 30) is False
    assert s.totp_disable("nobody") is False
    s.close()


def test_T_8_7_seed_is_unreadable_without_the_right_key():
    s, path = _store()
    secret = s.totp_enroll("alice")
    s.totp_confirm("alice", totp.code_at(secret, T), now=T)
    s.close()
    blob = sqlite3.connect(str(path)).execute("SELECT totp_enc FROM users").fetchone()[0]
    assert secret.encode() not in blob
    assert secret.encode() not in path.read_bytes()
    with UserStore(path, fields_key=bytes(32)) as other, pytest.raises(FieldsTampered):
        other.totp_verify("alice", totp.code_at(secret, T + 30), now=T + 30)


def test_totp_unknown_user_and_bad_input():
    s, path = _store()
    assert s.totp_verify("nobody", "123456", now=T) is False
    assert s.totp_verify("alice", "123456", now=T) is False        # not enrolled
    assert s.totp_verify("bad\nname", "123456", now=T) is False
    s.close()
