"""D-9: recovery codes."""

import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest

from sofiavault.auth import RECOVERY_ALPHABET, FieldsTampered, UserStore

KEY = bytes(range(32))


def _store():
    path = Path(tempfile.mkdtemp()) / "users.db"
    s = UserStore(path, fields_key=KEY)
    s.add_user("alice", "pw-alice-1")
    return s, path


def test_T_9_1_each_code_works_exactly_once():
    s, path = _store()
    codes = s.recovery_generate("alice", count=8)
    assert len(codes) == 8 and len(set(codes)) == 8
    assert s.recovery_remaining("alice") == 8
    assert s.recovery_use("alice", codes[3]) is True
    assert s.recovery_remaining("alice") == 7
    assert s.recovery_use("alice", codes[3]) is False
    assert s.recovery_use("alice", "ZZZZZ-ZZZZZ") is False
    assert s.recovery_use("nobody", codes[0]) is False
    for c in codes[:3] + codes[4:]:
        assert s.recovery_use("alice", c) is True
    assert s.recovery_remaining("alice") == 0
    s.close()


def test_T_9_2_codes_are_useless_under_a_different_key():
    s, path = _store()
    codes = s.recovery_generate("alice")
    s.close()
    for c in codes:
        assert c.replace("-", "").encode() not in path.read_bytes()
    with UserStore(path, fields_key=bytes(32)) as other, pytest.raises(FieldsTampered):
        other.recovery_use("alice", codes[0])
    with UserStore(path, fields_key=KEY) as again:
        assert again.recovery_use("alice", codes[0]) is True


def test_T_9_3_regenerating_invalidates_the_old_set():
    s, path = _store()
    old = s.recovery_generate("alice")
    new = s.recovery_generate("alice", count=4)
    assert s.recovery_remaining("alice") == 4
    for c in old:
        assert s.recovery_use("alice", c) is False
    assert s.recovery_use("alice", new[0]) is True
    s.close()


def test_T_9_4_concurrent_use_of_one_code_succeeds_once():
    s, path = _store()
    code = s.recovery_generate("alice", count=1)[0]
    results = []
    start = threading.Barrier(8)

    def attempt(store):
        start.wait()
        results.append(store.recovery_use("alice", code))

    # mix in a second connection so the DB-level lock is exercised too
    other = UserStore(path, fields_key=KEY)
    threads = [threading.Thread(target=attempt, args=(s if i % 2 else other,))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    other.close()
    s.close()


def test_T_9_5_alphabet_and_lenient_input():
    assert not set("0O1I") & set(RECOVERY_ALPHABET)
    assert len(RECOVERY_ALPHABET) == 32 and RECOVERY_ALPHABET.isupper()
    s, path = _store()
    codes = s.recovery_generate("alice", count=32)
    for c in codes:
        a, b = c.split("-")
        assert len(a) == len(b) == 5 and set(a + b) <= set(RECOVERY_ALPHABET)
    assert s.recovery_use("alice", codes[0].lower()) is True
    assert s.recovery_use("alice", codes[1].replace("-", "")) is True
    assert s.recovery_use("alice", f"  {codes[2][:5]} {codes[2][6:]} ") is True
    assert s.recovery_use("alice", codes[3].replace("-", "").lower()) is True
    assert s.recovery_use("alice", 12345) is False
    s.close()


def test_recovery_tags_are_keyed_hmacs_not_plain_hashes():
    s, path = _store()
    codes = s.recovery_generate("alice", count=2)
    s.close()
    import hashlib
    blob = sqlite3.connect(str(path)).execute("SELECT recovery_enc FROM users").fetchone()[0]
    for c in codes:
        norm = c.replace("-", "").upper()
        assert hashlib.sha256(norm.encode()).hexdigest().encode() not in blob
