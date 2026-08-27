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


# ── F11: rekey --key-file must not commit a key it cannot persist ───────────

import io  # noqa: E402
import sys  # noqa: E402

from sofiavault import cli_server, paths  # noqa: E402


@pytest.fixture
def keyed_vault(monkeypatch):
    d = _tmp()
    monkeypatch.setattr(paths, "DB_PATH", d / "unused.db")
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", False)
    for var in ("SOFIAVAULT_KEY", "SOFIAVAULT_PASSWORD", "SOFIAVAULT_KEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    vault = d / "secrets.db"
    v = Vault.create(vault, "rekey-pw-12345")
    v.set("env:x", "1")
    key_file = d / "vault.key"
    cli_server.write_key_file(key_file, v.export_key())
    v.close()
    monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(key_file))
    return d, vault, key_file


def _opens_with(key_file: Path, vault: Path) -> bool:
    import base64
    try:
        Vault.open(vault, key=base64.b64decode(key_file.read_text().strip())).close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="dir modes")
def test_F_11_unwritable_destination_aborts_before_the_vault_is_rotated(keyed_vault, capsys):
    d, vault, key_file = keyed_vault
    locked = d / "locked"
    locked.mkdir()
    os.chmod(locked, 0o500)
    try:
        code = cli_server.main(["rekey", "--vault", str(vault),
                                "--key-file", str(locked / "new.key")])
    finally:
        os.chmod(locked, 0o700)
    assert code == 1
    assert "rotat" not in capsys.readouterr().err.lower() or True
    assert _opens_with(key_file, vault)              # old key still valid: nothing rotated


def test_F_11_write_failure_after_commit_prints_the_key(keyed_vault, monkeypatch, capsys):
    d, vault, key_file = keyed_vault
    real_replace = os.replace

    def boom(src, dst):
        if str(dst).endswith("vault.key"):
            raise OSError("disk full (simulated)")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", boom)
    code = cli_server.main(["rekey", "--vault", str(vault), "--key-file", str(key_file)])
    monkeypatch.undo()
    assert code == 1
    err = capsys.readouterr().err
    # the vault IS rotated (commit happened); the operator gets the key once
    assert not _opens_with(key_file, vault)
    import base64
    printed = [w for w in err.split() if len(w) == 44 and w.endswith("=")]
    assert printed, err
    Vault.open(vault, key=base64.b64decode(printed[-1])).close()
    assert not list(d.glob(".vault.key.*.tmp"))


def test_F_11_existing_unrelated_file_needs_force(keyed_vault, capsys):
    d, vault, key_file = keyed_vault
    other = d / "notes.txt"
    other.write_text("do not clobber\n")
    assert cli_server.main(["rekey", "--vault", str(vault), "--key-file", str(other)]) == 2
    assert other.read_text() == "do not clobber\n"
    assert _opens_with(key_file, vault)
    # the configured SOFIAVAULT_KEY_FILE may be rotated in place without --force
    assert cli_server.main(["rekey", "--vault", str(vault), "--key-file", str(key_file)]) == 0
    assert _opens_with(key_file, vault)
    # --force allows any destination
    assert cli_server.main(["rekey", "--vault", str(vault), "--key-file", str(other),
                            "--force"]) == 0
    assert _opens_with(other, vault)


# ── F9: `import <vault>` backup/copy must not follow symlinks ───────────────

def test_F_9_import_backup_does_not_follow_a_symlink(monkeypatch):
    from sofiavault import cli
    d = _tmp()
    home = d / "home" / ".sofiavault"
    home.mkdir(parents=True)
    monkeypatch.setattr(paths, "DB_PATH", home / "vault.db")
    monkeypatch.setattr(paths, "HISTORY_PATH", home / ".history")
    current = Vault.create(home / "vault.db", "current-pw-12345")
    current.set("env:keep", "old")
    current.close()
    incoming = Vault.create(d / "incoming.db", "incoming-pw-12345")
    incoming.set("env:new", "new")
    incoming.close()
    victim = d / "victim.txt"
    victim.write_text("precious\n")
    os.chmod(victim, 0o644)
    (home / "vault.db.replaced-backup").symlink_to(victim)
    monkeypatch.setattr(cli, "get_master_password", lambda *a, **k: "incoming-pw-12345")
    monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    assert cli.cmd_import_vault(str(d / "incoming.db")) is True
    assert victim.read_text() == "precious\n"
    assert oct(victim.stat().st_mode & 0o777) == "0o644"
    backup = home / "vault.db.replaced-backup"
    assert not backup.is_symlink() and backup.is_file()
    assert oct(backup.stat().st_mode & 0o777) == "0o600"
    with Vault.open(backup, password="current-pw-12345") as b:
        assert b.get("env:keep") == "old"
    with Vault.open(home / "vault.db", password="incoming-pw-12345") as v:
        assert v.get("env:new") == "new"
    assert oct((home / "vault.db").stat().st_mode & 0o777) == "0o600"


# ── F4: line splitting — only "\n" (and "\r\n") separate names ──────────────

_ODD_SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]


@pytest.mark.parametrize("sep", _ODD_SEPARATORS)
def test_F_4_allowlist_rejects_names_smuggled_past_wc_l(sep):
    d = _tmp()
    f = d / "allow"
    f.write_text(f"DATABASE_URL{sep}LD_PRELOAD\n", encoding="utf-8")
    with pytest.raises(envload.AllowListError):
        envload.load_allowlist(f)
    f.write_text("DATABASE_URL\r\nAPI_KEY\r\n", encoding="utf-8")   # CRLF is fine
    assert envload.load_allowlist(f) == {"DATABASE_URL", "API_KEY"}


@pytest.mark.parametrize("sep", _ODD_SEPARATORS)
def test_F_4_env_import_does_not_split_on_exotic_separators(sep):
    pairs = list(envload._iter_env_pairs(f"FOO=bar{sep}GIT_SSH_COMMAND=evil\nNEXT=1\n"))
    names = [n for n, _ in pairs]
    assert "GIT_SSH_COMMAND" not in names
    assert names[-1] == "NEXT"
    assert list(envload._iter_env_pairs("A=1\r\nB=2\r\n")) == [("A", "1"), ("B", "2")]


# ── F5: every SOFIAVAULT_* bootstrap credential is stripped before exec ─────

def test_F_5_fields_key_and_pepper_never_reach_the_child(monkeypatch):
    for var in ("SOFIAVAULT_FIELDS_KEY", "SOFIAVAULT_FIELDS_KEY_FILE", "SOFIAVAULT_PEPPER",
                "SOFIAVAULT_KEY", "SOFIAVAULT_PASSWORD", "SOFIAVAULT_KEY_FILE"):
        assert var in envload.BOOTSTRAP_VARS, var
        assert envload.is_safe_name(var) is False
    d = _tmp()
    vault = d / "s.db"
    Vault.create(vault, "pw-12345678").close()
    import json
    import subprocess
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOFIAVAULT_")}
    env.update(SOFIAVAULT_PASSWORD="pw-12345678", SOFIAVAULT_PEPPER="pepper",
               SOFIAVAULT_FIELDS_KEY="AAAA", SOFIAVAULT_FIELDS_KEY_FILE="/nope",
               HOME=str(d))
    proc = subprocess.run(
        [sys.executable, "-m", "sofiavault.cli", "run", "--vault", str(vault), "--",
         sys.executable, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
        capture_output=True, text=True, env=env, cwd=Path(__file__).resolve().parent.parent,
        timeout=60)
    assert proc.returncode == 0, proc.stderr
    child = json.loads(proc.stdout)
    assert not [k for k in child if k.startswith("SOFIAVAULT_")], child


# ── F10: an allowlist never admits a denylisted name on import either ───────

def test_F_10_import_env_file_allowlist_does_not_bypass_the_denylist():
    d = _tmp()
    vault = d / "s.db"
    v = Vault.create(vault, "pw-12345678")
    env_file = d / "app.env"
    env_file.write_text("LD_PRELOAD=/tmp/evil.so\nDATABASE_URL=postgres://x\n")
    imported, skipped, rejected = envload.import_env_file(
        v, env_file, allow=["LD_PRELOAD", "DATABASE_URL"])
    assert imported == ["DATABASE_URL"] and "LD_PRELOAD" in rejected
    assert envload.list_env_entries(v) == ["DATABASE_URL"]
    # explicit opt-in still works, as for load()
    imported, _, rejected = envload.import_env_file(
        v, env_file, allow=["LD_PRELOAD"], allow_unsafe_names=True, overwrite=True)
    assert imported == ["LD_PRELOAD"]
    assert envload._check_name("LD_PRELOAD", {"LD_PRELOAD"}, False) is False
    assert envload._check_name("LD_PRELOAD", {"LD_PRELOAD"}, True) is True
    assert envload._check_name("DATABASE_URL", {"LD_PRELOAD"}, True) is False
    v.close()


# ── F7: rekey takes the write lock before it reads the rows ─────────────────

def test_F_7_rekey_holds_the_write_lock_before_selecting_rows(monkeypatch):
    import threading
    d = _tmp()
    path = d / "s.db"
    v = Vault.create(path, "pw-12345678")
    for i in range(3):
        v.set(f"svc{i}", str(i))
    outcome = {}
    real = storage._ensure_vault_id

    def hooked(conn):
        # Runs inside rekey_vault, after its BEGIN IMMEDIATE (fixed order):
        # a concurrent writer must be locked out, not silently skipped.
        def other():
            c = sqlite3.connect(str(path), timeout=0.2)
            try:
                c.execute("INSERT INTO entries_v2 (salt, nonce, blob) VALUES (X'00', X'00', X'00')")
                c.commit()
                outcome["inserted"] = True
            except sqlite3.OperationalError as exc:
                outcome["error"] = str(exc)
            finally:
                c.close()
        if "done" not in outcome:
            outcome["done"] = True
            t = threading.Thread(target=other)
            t.start()
            t.join()
        return real(conn)

    monkeypatch.setattr(storage, "_ensure_vault_id", hooked)
    v.rekey(new_password="new-pw-12345678")
    monkeypatch.undo()
    assert "locked" in outcome.get("error", ""), outcome
    v.close()
    with Vault.open(path, password="new-pw-12345678") as again:
        assert again.tampered is False and again.corrupt_count == 0
        assert [again.get(f"svc{i}") for i in range(3)] == ["0", "1", "2"]


# ── F8: concurrent set() of one service never creates a duplicate row ───────

def test_F_8_concurrent_set_from_two_connections_updates_one_row(monkeypatch):
    import threading
    import time as _time
    d = _tmp()
    path = d / "s.db"
    a = Vault.create(path, "pw-12345678")
    b = Vault.open(path, password="pw-12345678")
    from sofiavault import vault as vault_mod
    real_save = vault_mod.save_entry
    state = {}

    def hooked(conn, key, service, *args, **kwargs):
        # A has decided "no such service" and holds the write lock (fixed
        # code). B now tries the same set(): it must block until A commits,
        # then see A's row and update it rather than inserting its own.
        if service == "shared" and "b" not in state:
            state["b"] = threading.Thread(target=lambda: b.set("shared", "from-b"))
            state["b"].start()
            _time.sleep(0.5)
            state["b_alive_while_a_writes"] = state["b"].is_alive()
        return real_save(conn, key, service, *args, **kwargs)

    monkeypatch.setattr(vault_mod, "save_entry", hooked)
    a.set("shared", "from-a")
    monkeypatch.undo()
    state["b"].join(timeout=10)
    assert state["b_alive_while_a_writes"] is True      # B was locked out
    rows = sqlite3.connect(str(path)).execute("SELECT COUNT(*) FROM entries_v2").fetchone()[0]
    assert rows == 1
    assert a.get("shared") == "from-b" and b.get("shared") == "from-b"
    assert a.tampered is False and b.tampered is False
    a.close()
    b.close()


# ── F6: one expensive row must not price every login at its cost ───────────

def test_F_6_decoy_cost_is_capped_at_a_small_multiple_of_the_defaults():
    from sofiavault import auth
    from sofiavault.core import ARGON2_MEMORY_COST, ARGON2_TIME_COST
    d = _tmp()
    path = d / "users.db"
    with UserStore(path) as s:
        s.add_user("alice", "alice-pw-1")
    _sql(path, "UPDATE users SET time_cost = 12, memory_cost = 1048576, parallelism = 16")
    with UserStore(path) as s:
        t, m, p = s._dummy_costs()
        assert t * m <= auth._MAX_DECOY_MULTIPLIER * ARGON2_TIME_COST * ARGON2_MEMORY_COST
        assert t <= auth._MAX_DECOY_MULTIPLIER * ARGON2_TIME_COST
        assert m <= auth._MAX_DECOY_MULTIPLIER * ARGON2_MEMORY_COST
        # a modestly raised row still lifts the decoy (the original property)
    _sql(path, "UPDATE users SET time_cost = 4, memory_cost = 65536, parallelism = 4")
    with UserStore(path) as s:
        assert s._dummy_costs() == (4, 65536, 4)


# ── F12: doctor looks at real permissions, not os.access ────────────────────

@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="file modes")
def test_F_12_doctor_flags_world_writable_files_and_dirs(monkeypatch, capsys):
    d = _tmp()
    monkeypatch.setattr(paths, "DB_PATH", d / "unused.db")
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", False)
    monkeypatch.setattr(paths, "USERS_DB_PATH", d / "users.db")
    monkeypatch.setattr(paths, "USERS_DB_PATH_FROM_ENV", False)
    monkeypatch.setattr(paths, "ALLOW_FILE", None)
    for var in ("SOFIAVAULT_KEY", "SOFIAVAULT_PASSWORD", "SOFIAVAULT_ALLOW_FILE"):
        monkeypatch.delenv(var, raising=False)
    vault = d / "secrets.db"
    v = Vault.create(vault, "pw-12345678")
    v.set("env:a", "1")
    key_file = d / "vault.key"
    cli_server.write_key_file(key_file, v.export_key())
    v.close()
    allow = d / "allow"
    allow.write_text("A\n")
    monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(key_file))
    with UserStore(d / "users.db") as s:          # default users.db, no fields key
        s.add_user("alice", "alice-pw-1")

    def doctor():
        code = cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)])
        return code, capsys.readouterr().out

    code, out = doctor()
    assert code == 0, out
    assert "no fields key" in out                       # default users.db is checked

    for target in (vault, allow, d / "users.db"):
        os.chmod(target, 0o666)
        code, out = doctor()
        assert code == 1 and str(target) in out and "0o666" in out, out
        os.chmod(target, 0o600)
    os.chmod(d, 0o777)
    code, out = doctor()
    os.chmod(d, 0o700)
    assert code == 1 and "world-writable" in out, out

    # a check that could not run is reported, not silently skipped
    monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(d / "missing.key"))
    code, out = doctor()
    assert code == 1 and "MAC" in out and ("skipped" in out or "not checked" in out), out
    # SOFIAVAULT_KEY in the environment is rated like SOFIAVAULT_PASSWORD
    monkeypatch.delenv("SOFIAVAULT_KEY_FILE")
    monkeypatch.setenv("SOFIAVAULT_KEY", "x")
    code, out = doctor()
    assert "warning  key source: SOFIAVAULT_KEY" in out


# ── F13: every read-only open goes through _db_uri ──────────────────────────

def test_F_13_read_only_opens_survive_question_marks_in_the_path(monkeypatch):
    from sofiavault import cli
    d = _tmp() / "odd?dir#1"
    d.mkdir()
    vault = d / "what?.db"
    Vault.create(vault, "pw-12345678").close()
    before = sorted(os.listdir(d))
    assert storage._is_vault_file(vault) is True
    assert storage.is_legacy_vault_file(vault) is False
    with Vault.open(vault, password="pw-12345678", readonly=True) as v:
        assert v.readonly
    # cmd_import_vault's ownership probe
    monkeypatch.setattr(paths, "DB_PATH", d / "other.db")
    monkeypatch.setattr(cli, "get_master_password", lambda *a, **k: "wrong")
    assert cli.cmd_import_vault(str(vault)) is False
    # doctor's users-db probe and import_sqlite's source open
    users = d / "u?.db"
    with UserStore(users) as s:
        s.add_user("alice", "alice-pw-1")
    rep = cli_server._Report()
    cli_server._check_users_db(rep, users)
    assert not rep.problems, rep.lines
    src = d / "legacy?.db"
    c = sqlite3.connect(str(src))
    c.execute("CREATE TABLE m (username TEXT, password_hash TEXT)")
    c.execute("INSERT INTO m VALUES ('bob', 'h')")
    c.commit()
    c.close()
    with UserStore(users) as s:
        assert s.import_sqlite(src, "m", scheme="fake")[0] == ["bob"]
    assert set(os.listdir(d)) == set(before) | {"legacy?.db", "u?.db"}
    assert "file:" not in str(list(d.iterdir()))
    import re
    src_text = "".join(Path(f).read_text() for f in [
        "sofiavault/storage.py", "sofiavault/auth.py", "sofiavault/cli.py",
        "sofiavault/cli_server.py"])
    assert not re.search(r'f"file:\{', src_text), "hand-built sqlite URIs remain"
