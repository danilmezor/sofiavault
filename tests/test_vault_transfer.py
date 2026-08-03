"""Tests for vault export, import (device transfer), and secure wipe."""

import base64
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sofiavault import (
    SALT_SIZE,
    VaultSession,
    _is_vault_file,
    _shred_file,
    cmd_export,
    cmd_import_vault,
    cmd_wipe,
    derive_key,
    get_password,
    init_db,
    load_entries,
    save_entry,
    save_master,
)

MASTER_PW = "transfer-test-pw"


def _make_vault(db_path: str, master_password: str = MASTER_PW,
                entries: bool = True):
    """Create a real vault file with a master password and optional entries."""
    with patch("sofiavault.DB_PATH", Path(db_path)):
        conn = init_db()
        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(master_password, salt)
        verify_salt = secrets.token_bytes(SALT_SIZE)
        verify_hash = derive_key(base64.b64encode(key).decode(), verify_salt)
        save_master(conn, salt + verify_salt, verify_hash)
        if entries:
            save_entry(conn, key, "Amazon", "user@test.com", "pass123")
        conn.close()
    return key


# ── _is_vault_file ───────────────────────────────────────────────────────────

def test_is_vault_file_true_for_real_vault():
    tmp = tempfile.mktemp(suffix=".db")
    _make_vault(tmp)
    assert _is_vault_file(Path(tmp)) is True
    Path(tmp).unlink(missing_ok=True)


def test_is_vault_file_false_for_csv():
    tmp = tempfile.mktemp(suffix=".csv")
    Path(tmp).write_text("TITLE,USERNAME,PASSWORD\nAmazon,u,p\n")
    assert _is_vault_file(Path(tmp)) is False
    Path(tmp).unlink(missing_ok=True)


def test_is_vault_file_false_for_garbage_and_missing():
    tmp = tempfile.mktemp(suffix=".db")
    Path(tmp).write_bytes(b"not a database at all")
    assert _is_vault_file(Path(tmp)) is False
    Path(tmp).unlink(missing_ok=True)
    assert _is_vault_file(Path("/nonexistent/vault.db")) is False


def test_is_vault_file_false_for_uninitialized_db():
    tmp = tempfile.mktemp(suffix=".db")
    with patch("sofiavault.DB_PATH", Path(tmp)):
        init_db().close()  # tables exist but no master password set
    assert _is_vault_file(Path(tmp)) is False
    Path(tmp).unlink(missing_ok=True)


# ── export ───────────────────────────────────────────────────────────────────

def test_export_prints_path_and_uri(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    _make_vault(tmp)
    with patch("sofiavault.DB_PATH", Path(tmp)):
        cmd_export()
    out = capsys.readouterr().out
    assert tmp in out
    assert Path(tmp).as_uri() in out
    assert "encrypted" in out.lower()
    Path(tmp).unlink(missing_ok=True)


def test_export_without_vault(capsys):
    with patch("sofiavault.DB_PATH", Path("/nonexistent/vault.db")):
        cmd_export()
    assert "nothing to export" in capsys.readouterr().out.lower()


# ── import (vault transfer) ──────────────────────────────────────────────────

def test_import_vault_to_fresh_device(capsys):
    src = tempfile.mktemp(suffix=".db")
    dest = Path(tempfile.mkdtemp()) / "vault.db"
    key = _make_vault(src)

    with patch("sofiavault.DB_PATH", dest), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = MASTER_PW
        assert cmd_import_vault(src) is True
        assert dest.exists()
        if sys.platform != "win32":
            assert stat.S_IMODE(dest.stat().st_mode) == 0o600

        # imported vault is fully usable
        import sqlite3
        conn = sqlite3.connect(str(dest))
        entries, corrupt = load_entries(conn, key)
        assert corrupt == 0
        assert len(entries) == 1
        assert get_password(conn, key, entries[0].id) == "pass123"
        conn.close()

    Path(src).unlink(missing_ok=True)
    dest.unlink(missing_ok=True)


def test_import_vault_wrong_password_changes_nothing(capsys):
    src = tempfile.mktemp(suffix=".db")
    dest = Path(tempfile.mkdtemp()) / "vault.db"
    _make_vault(src)

    with patch("sofiavault.DB_PATH", dest), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = "wrong password"
        assert cmd_import_vault(src) is False
        assert not dest.exists()

    out = capsys.readouterr().out
    assert "nothing was changed" in out.lower()
    Path(src).unlink(missing_ok=True)


def test_import_vault_over_existing_creates_backup(capsys):
    src = tempfile.mktemp(suffix=".db")
    dest = Path(tempfile.mkdtemp()) / "vault.db"
    _make_vault(src, master_password="new-device-pw")
    _make_vault(str(dest), master_password="old-local-pw")
    old_bytes = dest.read_bytes()

    with patch("sofiavault.DB_PATH", dest), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", return_value="y"):
        gp.getpass.return_value = "new-device-pw"
        assert cmd_import_vault(src) is True

    backup = dest.with_name(dest.name + ".replaced-backup")
    assert backup.exists()
    assert backup.read_bytes() == old_bytes
    assert dest.read_bytes() == Path(src).read_bytes()

    Path(src).unlink(missing_ok=True)
    dest.unlink(missing_ok=True)
    backup.unlink(missing_ok=True)


def test_import_vault_over_existing_declined(capsys):
    src = tempfile.mktemp(suffix=".db")
    dest = Path(tempfile.mkdtemp()) / "vault.db"
    _make_vault(src)
    _make_vault(str(dest), master_password="old-local-pw")
    old_bytes = dest.read_bytes()

    with patch("sofiavault.DB_PATH", dest), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", return_value="n"):
        gp.getpass.return_value = MASTER_PW
        assert cmd_import_vault(src) is False

    assert dest.read_bytes() == old_bytes
    Path(src).unlink(missing_ok=True)
    dest.unlink(missing_ok=True)


def test_import_rejects_non_vault_file(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    Path(tmp).write_bytes(b"garbage")
    with patch("sofiavault.DB_PATH", Path(tempfile.mkdtemp()) / "vault.db"):
        assert cmd_import_vault(tmp) is False
    assert "not a sofiavault vault" in capsys.readouterr().out.lower()
    Path(tmp).unlink(missing_ok=True)


# ── shred / wipe ─────────────────────────────────────────────────────────────

def test_shred_file_removes_file():
    tmp = Path(tempfile.mktemp())
    tmp.write_bytes(b"super secret data" * 1000)
    _shred_file(tmp)
    assert not tmp.exists()


def test_shred_never_follows_symlinks():
    target = Path(tempfile.mktemp())
    target.write_bytes(b"precious unrelated file")
    link = Path(tempfile.mktemp())
    link.symlink_to(target)

    _shred_file(link)

    assert not link.exists()  # link removed...
    assert target.read_bytes() == b"precious unrelated file"  # ...target intact
    target.unlink()


def test_shred_missing_file_is_noop():
    _shred_file(Path("/nonexistent/file"))  # must not raise


def _wipe_session(tmpdir: Path):
    db = tmpdir / "vault.db"
    key = _make_vault(str(db))
    import sqlite3
    conn = sqlite3.connect(str(db))
    return VaultSession(conn, key), db


def test_wipe_destroys_vault_and_exits(capsys):
    tmpdir = Path(tempfile.mkdtemp())
    session, db = _wipe_session(tmpdir)
    history = tmpdir / ".history"
    history.write_text("amazon\n")

    with patch("sofiavault.DB_PATH", db), \
         patch("sofiavault.HISTORY_PATH", history), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", return_value="wipe my vault"), \
         pytest.raises(SystemExit) as exc:
        gp.getpass.return_value = MASTER_PW
        cmd_wipe(session)

    assert exc.value.code == 0
    assert not db.exists()
    assert not history.exists()
    assert session.key is None
    out = capsys.readouterr().out
    assert "wiped" in out.lower()


def test_wipe_wrong_password_aborts(capsys):
    tmpdir = Path(tempfile.mkdtemp())
    session, db = _wipe_session(tmpdir)

    with patch("sofiavault.DB_PATH", db), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", side_effect=AssertionError("must not confirm")):
        gp.getpass.return_value = "wrong password"
        cmd_wipe(session)  # returns, no SystemExit

    assert db.exists()
    out = capsys.readouterr().out
    assert "wrong password" in out.lower()
    session.conn.close()
    db.unlink(missing_ok=True)


def test_wipe_wrong_phrase_aborts(capsys):
    tmpdir = Path(tempfile.mkdtemp())
    session, db = _wipe_session(tmpdir)

    with patch("sofiavault.DB_PATH", db), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", return_value="yes please"):
        gp.getpass.return_value = MASTER_PW
        cmd_wipe(session)

    assert db.exists()
    assert "cancelled" in capsys.readouterr().out.lower()
    session.conn.close()
    db.unlink(missing_ok=True)


def test_wipe_only_touches_allowlisted_files(capsys):
    tmpdir = Path(tempfile.mkdtemp())
    session, db = _wipe_session(tmpdir)
    bystander = tmpdir / "unrelated-file.txt"
    bystander.write_text("do not touch me")

    with patch("sofiavault.DB_PATH", db), \
         patch("sofiavault.HISTORY_PATH", tmpdir / ".history"), \
         patch("sofiavault.getpass") as gp, \
         patch("builtins.input", return_value="wipe my vault"), \
         pytest.raises(SystemExit):
        gp.getpass.return_value = MASTER_PW
        cmd_wipe(session)

    assert not db.exists()
    assert bystander.read_text() == "do not touch me"
    bystander.unlink()
