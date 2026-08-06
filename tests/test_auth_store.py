"""Tests for the verify-only user store (sofiavault.auth)."""

import json
import os
import secrets
import sqlite3
import stat
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sofiavault import KEY_SIZE
from sofiavault.auth import (
    AuthStoreError,
    InvalidUsername,
    UserStore,
    _padding_costs,
    normalize_username,
)
from sofiavault.core import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    derive_key,
)


def _store_path() -> Path:
    return Path(tempfile.mkdtemp()) / "users.db"


def test_add_verify_and_fields():
    path = _store_path()
    with UserStore(path) as store:
        assert store.add_user("alice", "hunter2", access_level=3, telegram_id=42)

        result = store.verify("alice", "hunter2")
        assert result is not None
        assert result.username == "alice"
        assert result.fields == {"access_level": 3, "telegram_id": 42}

        assert store.verify("alice", "wrong") is None
        assert store.verify("nobody", "hunter2") is None
    path.unlink()


def test_duplicate_username_rejected():
    path = _store_path()
    with UserStore(path) as store:
        assert store.add_user("alice", "one") is True
        assert store.add_user("alice", "two") is False
        assert store.verify("alice", "one") is not None
    path.unlink()


def test_deactivate_activate():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("bob", "pass1234")
        assert store.deactivate("bob") is True
        assert store.verify("bob", "pass1234") is None  # inactive -> denied
        assert store.activate("bob") is True
        assert store.verify("bob", "pass1234") is not None
    path.unlink()


def test_set_password_rotation():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("carol", "old-pass")
        assert store.set_password("carol", "new-pass") is True
        assert store.verify("carol", "old-pass") is None
        assert store.verify("carol", "new-pass") is not None
        assert store.set_password("ghost", "x") is False
    path.unlink()


def test_update_fields_and_get_user():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("dave", "pass1234", role="junior")
        store.update_fields("dave", role="senior", team="ops")
        user = store.get_user("dave")
        assert user["fields"] == {"role": "senior", "team": "ops"}
        assert user["is_active"] is True
        assert store.get_user("nobody") is None
    path.unlink()


def test_remove_user_and_list():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("a", "pass1234")
        store.add_user("b", "pass1234")
        store.deactivate("b")
        assert store.list_users() == ["a", "b"]
        assert store.list_users(include_inactive=False) == ["a"]
        assert store.remove_user("b") is True
        assert store.list_users() == ["a"]
    path.unlink()


def test_pepper_changes_hashes():
    path = _store_path()
    with UserStore(path, pepper="secret-pepper") as store:
        store.add_user("eve", "pw123456")
        assert store.verify("eve", "pw123456") is not None
    # Same store opened without the pepper must fail verification
    with UserStore(path) as store2:
        assert store2.verify("eve", "pw123456") is None
    path.unlink()


def test_rehash_on_verify_upgrades_parameters():
    path = _store_path()
    store = UserStore(path)
    store.add_user("frank", "pw123456")

    # Simulate a legacy row hashed with weaker parameters
    weak_salt = secrets.token_bytes(16)
    weak_hash = derive_key("pw123456", weak_salt,
                           time_cost=1, memory_cost=1024, parallelism=1)
    store._conn.execute(
        "UPDATE users SET salt=?, verify_hash=?, time_cost=1, memory_cost=1024,"
        " parallelism=1 WHERE username='frank'",
        (weak_salt, weak_hash)
    )
    store._conn.commit()

    assert store.verify("frank", "pw123456") is not None  # verifies + rehashes
    row = store._row("frank")
    assert (row["time_cost"], row["memory_cost"]) != (1, 1024)  # upgraded
    assert store.verify("frank", "pw123456") is not None  # still valid after
    store.close()
    path.unlink()


def test_fields_encryption_at_rest():
    path = _store_path()
    fkey = secrets.token_bytes(KEY_SIZE)
    with UserStore(path, fields_key=fkey) as store:
        store.add_user("grace", "pw123456", email="grace@secret.example")
        result = store.verify("grace", "pw123456")
        assert result.fields == {"email": "grace@secret.example"}

    raw = path.read_bytes()
    assert b"grace@secret.example" not in raw  # encrypted at rest

    # Wrong reader configuration fails loudly, not silently
    with UserStore(path) as no_key_store, pytest.raises(AuthStoreError):
        no_key_store.get_user("grace")
    path.unlink()


def test_fields_key_must_be_correct_size():
    with pytest.raises(AuthStoreError):
        UserStore(_store_path(), fields_key=b"short")


def test_import_json():
    path = _store_path()
    src = path.with_name("legacy.json")
    src.write_text(json.dumps([
        {"name": "alice", "password": "pw-a", "access_level": "senior", "telegram_id": 1},
        {"name": "bob", "password": "pw-b"},
        {"name": "alice", "password": "dupe"},          # duplicate -> skipped
        {"name": "", "password": "x"},                   # missing name
        {"name": "nopass"},                              # missing password
    ]))

    with UserStore(path) as store:
        created, skipped = store.import_json(src)
        assert created == ["alice", "bob"]
        assert len(skipped) == 3

        result = store.verify("alice", "pw-a")
        assert result.fields == {"access_level": "senior", "telegram_id": 1}
        assert store.verify("alice", "dupe") is None  # first entry won
    src.unlink()
    path.unlink()


def test_store_file_permissions():
    if sys.platform == "win32":
        return
    path = _store_path()
    store = UserStore(path)
    store.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.unlink()


def test_verify_rejects_empty_password_and_is_silent(capsys):
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("henry", "pw123456")
        assert store.verify("henry", "") is None
        store.verify("unknown-user", "whatever")  # burns dummy hash, no output
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    path.unlink()


# ── Regressions ──────────────────────────────────────────────────────────────


def _tamper(path: Path, sql: str, params=()):
    """Write to the store the way an attacker with file access would."""
    conn = sqlite3.connect(str(path))
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def test_lone_surrogate_password_denies_instead_of_raising():
    # json.loads('"\\ud800"') hands a web handler a str that cannot be
    # UTF-8 encoded; Argon2 used to raise UnicodeEncodeError out of verify()
    # — a 500 on the login route, and on the unknown-user path too.
    surrogate = json.loads('"\\ud800"')
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("ivan", "pw123456")
        assert store.verify("ivan", surrogate) is None
        assert store.verify("ghost", surrogate) is None

        # Writers hear about it instead of failing at hash time.
        with pytest.raises(AuthStoreError):
            store.add_user("jane", surrogate)
        with pytest.raises(AuthStoreError):
            store.set_password("ivan", surrogate)
        assert store.verify("ivan", "pw123456") is not None  # unchanged
    path.unlink()


def test_dummy_costs_track_the_most_expensive_row():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("alice", "alice-pw")
        # A single legacy cheap row used to price every unknown-user decoy,
        # so probing one username compared it against its own (expensive) row
        # and "exists" fell out of a single measurement.
        _tamper(path, "UPDATE users SET time_cost=1, memory_cost=8192")
        store._dummy_cost_cache = None
        assert store._dummy_costs() == (ARGON2_TIME_COST, ARGON2_MEMORY_COST,
                                        ARGON2_PARALLELISM)

        # A row above the defaults must raise the decoy, not be ignored.
        _tamper(path, "UPDATE users SET time_cost=5 WHERE username='alice'")
        store.add_user("bob", "bob-pw")          # write invalidates the cache
        assert store._dummy_costs()[0] == 5

        # ...and the cache must come back down when the mix gets cheaper.
        store.set_password("alice", "alice-pw2")
        assert store._dummy_costs()[0] == ARGON2_TIME_COST
    path.unlink()


def test_verify_cost_is_flat_across_cheap_rows_and_unknown_users():
    import statistics

    path = _store_path()
    store = UserStore(path)
    store.add_user("alice", "alice-pw")     # dropped to legacy costs below
    store.add_user("carol", "carol-pw")     # current defaults
    store.add_user("dan", "dan-pw")
    store.deactivate("dan")
    _tamper(path, "UPDATE users SET time_cost=1, memory_cost=8192"
                  " WHERE username='alice'")
    store._dummy_cost_cache = None

    def timed(user, password):
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            store.verify(user, password)     # wrong pw: never rehashes
            samples.append(time.perf_counter() - t0)
        return statistics.median(samples)

    # Pricing the decoy at the store minimum made known users slow and
    # unknown ones fast; pricing it at the ceiling alone just flipped that
    # around, because a legacy row still answers at legacy speed. Only
    # levelling the real work up to the ceiling closes it in both directions.
    observed = {
        'unknown': timed("ghost", "wrong-pw"),
        'inactive': timed("dan", "wrong-pw"),
        'known': timed("carol", "wrong-pw"),
        'known-legacy-row': timed("alice", "wrong-pw"),
    }
    ratio = max(observed.values()) / max(min(observed.values()), 1e-9)
    assert ratio < 2.0, f"timing oracle: {observed}"
    store.close()
    path.unlink()


def test_encrypted_fields_cannot_be_downgraded_to_plaintext():
    path = _store_path()
    fkey = secrets.token_bytes(KEY_SIZE)
    with UserStore(path, fields_key=fkey) as store:
        store.add_user("mallory", "mallory-pw", role="junior")

    # Attacker with DB write access drops the ciphertext and writes the
    # profile they want into the unauthenticated column. They keep their own
    # password and never need fields_key.
    _tamper(path, "UPDATE users SET fields_enc=NULL, fields=? "
                  "WHERE username='mallory'", (json.dumps({"role": "admin"}),))
    with UserStore(path, fields_key=fkey) as store2:
        with pytest.raises(AuthStoreError):
            store2.verify("mallory", "mallory-pw")
        with pytest.raises(AuthStoreError):
            store2.get_user("mallory")

    # The empty-looking variant is the same attack with fewer fingerprints.
    _tamper(path, "UPDATE users SET fields_enc=NULL, fields='{}'")
    with UserStore(path, fields_key=fkey) as store3, pytest.raises(AuthStoreError):
        store3.verify("mallory", "mallory-pw")

    # A store whose fields were never encrypted must refuse to half-adopt a
    # key, which would leave exactly the same downgrade hole for old rows.
    plain = _store_path()
    UserStore(plain).close()
    with pytest.raises(AuthStoreError):
        UserStore(plain, fields_key=fkey)
    plain.unlink()
    path.unlink()


def test_rehash_never_downgrades_raised_parameters():
    path = _store_path()
    store = UserStore(path)
    store.add_user("nina", "pw123456")

    # An operator deliberately above the library defaults on one axis and a
    # legacy row below on the other: one login used to flatten both to the
    # defaults, silently undoing the operator's decision.
    strong_t = ARGON2_TIME_COST + 2
    salt = secrets.token_bytes(16)
    mixed = derive_key("pw123456", salt, time_cost=strong_t,
                       memory_cost=1024, parallelism=ARGON2_PARALLELISM)
    store._conn.execute(
        "UPDATE users SET salt=?, verify_hash=?, time_cost=?, memory_cost=1024"
        " WHERE username='nina'", (salt, mixed, strong_t))
    store._conn.commit()

    assert store.verify("nina", "pw123456") is not None
    row = store._row("nina")
    assert row["time_cost"] == strong_t              # not downgraded
    assert row["memory_cost"] == ARGON2_MEMORY_COST  # weak axis raised
    assert store.verify("nina", "pw123456") is not None

    # Already at the defaults on every axis: nothing to rewrite.
    store.add_user("owen", "pw123456")
    before = store._row("owen")
    assert store.verify("owen", "pw123456") is not None
    assert store._row("owen")["verify_hash"] == before["verify_hash"]
    store.close()
    path.unlink()


def test_mutators_take_the_store_lock():
    path = _store_path()
    store = UserStore(path)
    store.add_user("peter", "pw123456")

    # Mutators used to touch the shared connection without the lock: a
    # rotation could commit inside a running verify() (which still returned a
    # valid AuthResult for the retired password), and concurrent writers hit
    # "InterfaceError: bad parameter or other API misuse".
    mutators = [
        lambda: store.add_user("quinn", "pw123456"),
        lambda: store.set_password("peter", "pw-new"),
        lambda: store.update_fields("peter", role="ops"),
        lambda: store.set_active("peter", False),
        lambda: store.remove_user("peter"),
        lambda: store.get_user("peter"),
        lambda: store.list_users(),
    ]
    for call in mutators:
        done = threading.Event()
        worker = threading.Thread(target=lambda c=call, d=done: (c(), d.set()))
        with store._lock:
            worker.start()
            assert not done.wait(0.3), f"{call} ran while the lock was held"
        worker.join(5)
        assert done.is_set()
    store.close()
    path.unlink()


def test_concurrent_add_user_is_serialized():
    path = _store_path()
    store = UserStore(path)
    errors = []
    start = threading.Barrier(4)

    def worker(n):
        try:
            start.wait()
            store.add_user(f"user{n}", "pw123456")
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store.list_users() == ["user0", "user1", "user2", "user3"]

    # A racing writer that wins the name between the check and the INSERT is
    # "already exists", not an IntegrityError out of the API.
    store._row = lambda username: None   # pretend the name is free
    assert store.add_user("user0", "pw123456") is False
    store.close()
    path.unlink()


def test_oversized_username_rejected_before_normalizing():
    # NFKC + strip on the full input ran before the length check and inside
    # the store lock: one 40M-character username stalled every concurrent
    # verify() for two seconds.
    huge = "a" * 40_000_000
    t0 = time.perf_counter()
    with pytest.raises(InvalidUsername):
        normalize_username(huge)
    assert time.perf_counter() - t0 < 0.5

    path = _store_path()
    with UserStore(path) as store:
        store.add_user("rita", "pw123456")
        t0 = time.perf_counter()
        assert store.verify(huge, "pw123456") is None
        assert time.perf_counter() - t0 < 2.0   # decoy hash only, no NFKC pass
    path.unlink()


def test_casefold_expansion_cannot_exceed_max_length():
    # U+1E9E survives NFKC unchanged and only grows when casefolded, so the
    # old order let a 128-character name reach the primary key at 256.
    assert len(normalize_username("ẞ" * 64)) == 128
    with pytest.raises(InvalidUsername):
        normalize_username("ẞ" * 128)


def test_malformed_fields_raise_authstoreerror_not_valueerror():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("sam", "pw123456", role="ops")

    # Both used to escape verify() *after* the password matched: a raw
    # JSONDecodeError, and a str where AuthResult.fields promises a dict —
    # which turns a caller's `'admin' in result.fields` into a substring test.
    for bad in ('{not json', '"pwned-admin"', '[1, 2]'):
        _tamper(path, "UPDATE users SET fields=? WHERE username='sam'", (bad,))
        with UserStore(path) as store2, pytest.raises(AuthStoreError):
            store2.verify("sam", "pw123456")

    # Truncated ciphertext used to reach AESGCM and leak
    # "Nonce must be between 8 and 128 bytes".
    enc_path = _store_path()
    fkey = secrets.token_bytes(KEY_SIZE)
    with UserStore(enc_path, fields_key=fkey) as store3:
        store3.add_user("tara", "pw123456", role="ops")
    _tamper(enc_path, "UPDATE users SET fields_enc=? WHERE username='tara'",
            (b"short",))
    with UserStore(enc_path, fields_key=fkey) as store4, pytest.raises(AuthStoreError):
        store4.verify("tara", "pw123456")
    enc_path.unlink()
    path.unlink()


def test_import_json_refuses_non_string_usernames_and_odd_field_names():
    path = _store_path()
    src = path.with_name("legacy.json")
    src.write_text(json.dumps([
        {"name": 12345, "password": "pw"},
        {"name": {"a": 1}, "password": "pw"},
        {"name": ["x"], "password": "pw"},
        {"name": True, "password": "pw"},
        # A field literally named "self" used to raise TypeError and abort
        # the import halfway through, with the earlier rows already committed.
        {"name": "uma", "password": "pw", "self": 1, "username_hint": "u"},
    ]))
    with UserStore(path) as store:
        created, skipped = store.import_json(src)
        assert created == ["uma"]                 # str() coercion no longer
        assert len(skipped) == 4                  # invents account names
        assert store.list_users() == ["uma"]
        assert store.verify("uma", "pw").fields == {"self": 1, "username_hint": "u"}
    src.unlink()
    path.unlink()


def test_pepper_must_be_a_string():
    # `pepper or ""` accepted these and either silently used no pepper or
    # blew up at the first hash, long after the operator stopped looking.
    for bad in (b"bytes-pepper", 0, 12345, ["p"]):
        with pytest.raises(AuthStoreError):
            UserStore(_store_path(), pepper=bad)
    path = _store_path()
    UserStore(path, pepper="").close()   # explicit "no pepper" stays legal
    path.unlink()


def test_absurd_stored_cost_parameters_are_rejected():
    path = _store_path()
    with UserStore(path) as store:
        store.add_user("vera", "pw123456")

    # memory_cost is in KiB, so this row asks Argon2 for a terabyte: without
    # bounds it wedges (or OOM-kills) every verify() for that user.
    for column, value in (("memory_cost", 1073741824), ("memory_cost", 0),
                          ("time_cost", 0), ("time_cost", 10 ** 9),
                          ("parallelism", 0)):
        _tamper(path, f"UPDATE users SET {column}=? WHERE username='vera'",
                (value,))
        with UserStore(path) as store2:
            t0 = time.perf_counter()
            with pytest.raises(AuthStoreError):
                store2.verify("vera", "pw123456")
            assert time.perf_counter() - t0 < 5.0
        _tamper(path, f"UPDATE users SET {column}=? WHERE username='vera'",
                (ARGON2_MEMORY_COST if column == "memory_cost"
                 else ARGON2_TIME_COST if column == "time_cost"
                 else ARGON2_PARALLELISM,))
    path.unlink()


def test_failed_permission_check_closes_the_connection(monkeypatch):
    if sys.platform == "win32":
        return
    opened = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr("sofiavault.auth.sqlite3.connect", recording_connect)
    monkeypatch.setattr(os, "chmod", _raise_oserror)

    path = _store_path()
    with pytest.raises(AuthStoreError):
        UserStore(path)
    # The store refused to trust the file; leaving an open fd on it was the
    # opposite of that decision.
    assert opened and all(_is_closed(c) for c in opened)
    path.unlink()


def _raise_oserror(*args, **kwargs):
    raise OSError("chmod refused")


def _is_closed(conn) -> bool:
    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


# ── Residual findings from the second audit pass ─────────────────────────────

def _tmp_store_path() -> Path:
    return Path(tempfile.mkdtemp()) / "users.db"


def test_decoy_ceiling_sees_writes_from_another_instance():
    """Each gunicorn/uwsgi worker holds its own UserStore.

    Invalidating the ceiling cache only on the instance's *own* writes left
    every other worker priced at a stale, lower ceiling — an 11x "fast means
    does-not-exist" oracle, the very thing the ceiling exists to close.
    """
    path = _tmp_store_path()
    a = UserStore(path)
    a.add_user("alice", "alice-pw")
    assert a._dummy_costs() == (ARGON2_TIME_COST, ARGON2_MEMORY_COST,
                                ARGON2_PARALLELISM)

    b = UserStore(path)
    b.add_user("heavy", "heavy-pw")
    b._conn.execute("UPDATE users SET time_cost = 8, memory_cost = 262144"
                    " WHERE username = 'heavy'")
    b._conn.commit()

    # a never wrote the heavy row, but must still price its decoy from it
    assert a._dummy_costs() == (8, 262144, ARGON2_PARALLELISM)
    a.close()
    b.close()


@pytest.mark.parametrize("column,value", [
    ("salt", "not-bytes"),
    ("salt", 0),
    ("salt", b"tooshort"),
    ("verify_hash", "not-bytes"),
    ("verify_hash", 7),
    ("verify_hash", b"short"),
])
def test_tampered_binary_columns_raise_the_stores_own_error(column, value):
    """verify() promises a tampered database raises AuthStoreError.

    Cost columns were validated but salt/verify_hash were not, so Argon2
    raised TypeError/HashingError straight past a caller's
    `except AuthStoreError` and became an unhandled 500.
    """
    path = _tmp_store_path()
    store = UserStore(path)
    store.add_user("dave", "dave-pw")
    store._conn.execute(f"UPDATE users SET {column} = ? WHERE username = 'dave'",
                        (value,))
    store._conn.commit()

    with pytest.raises(AuthStoreError):
        store.verify("dave", "dave-pw")
    store.close()


def test_legacy_cost_row_is_not_separable_by_timing():
    """A row still at legacy costs must not be distinguishable from an
    unknown user in a single probe.

    Pricing the level-up deficit in whole Argon2 *passes* could only land on
    multiples of the ceiling's memory, so a row 2.875 passes short rounded up
    to 3 and paid its own hash on top of a full ceiling hash — a stable ~6%
    gap with no distribution overlap. The deficit is spent as memory instead,
    which is granular to the KiB.
    """
    path = _tmp_store_path()
    store = UserStore(path)
    store.add_user("normal", "pw")
    store.add_user("legacy", "pw")
    store._conn.execute("UPDATE users SET time_cost = 1, memory_cost = 8192"
                        " WHERE username = 'legacy'")
    store._conn.commit()

    def samples(user):
        out = []
        for _ in range(15):
            t0 = time.perf_counter()
            store.verify(user, "wrong-pw")
            out.append(time.perf_counter() - t0)
        return out

    # Loose bound only — wall-clock on a shared machine is too noisy to
    # assert a few percent. It still catches the regressions that mattered
    # (the cheapest-row decoy was 7x, the stale cross-instance cache 11x).
    unknown = statistics.median(samples("ghost"))
    legacy = statistics.median(samples("legacy"))
    ratio = max(legacy, unknown) / max(min(legacy, unknown), 1e-9)
    assert ratio < 2.0, (
        f"legacy-row timing tell: legacy={legacy*1000:.2f}ms "
        f"unknown={unknown*1000:.2f}ms"
    )
    store.close()


@pytest.mark.parametrize("row_costs", [
    (1, 8192, ARGON2_PARALLELISM),        # oldest legacy row
    (2, 32768, ARGON2_PARALLELISM),
    (1, ARGON2_MEMORY_COST, ARGON2_PARALLELISM),
    (2, ARGON2_MEMORY_COST, ARGON2_PARALLELISM),
])
def test_levelled_work_lands_on_the_ceiling(row_costs):
    """The deterministic half of the timing property.

    Total Argon2 work for a below-ceiling row must equal the ceiling, so
    that "how long did this take" carries no information about which row
    was hit. Asserted on the cost budget rather than the clock, because
    that is what the padding actually controls.
    """
    ceiling = (ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
    pad = _padding_costs(row_costs, ceiling)
    own = row_costs[0] * row_costs[1]
    total = own + (pad[0] * pad[1] if pad else 0)
    budget = ceiling[0] * ceiling[1]

    assert abs(total - budget) / budget < 0.005, (
        f"row {row_costs[:2]} levels to {total}, ceiling is {budget}"
    )


def test_row_already_at_the_ceiling_is_not_padded():
    """No wasted second hash in the common case."""
    ceiling = (ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
    assert _padding_costs(ceiling, ceiling) is None
    assert _padding_costs((ARGON2_TIME_COST + 1, ARGON2_MEMORY_COST,
                           ARGON2_PARALLELISM), ceiling) is None
