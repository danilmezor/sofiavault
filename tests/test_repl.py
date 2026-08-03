"""Tests for SofiaVault interactive REPL."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    KEY_SIZE,
    VaultREPL,
    VaultSession,
    init_db,
    save_entry,
)


def _setup_session():
    """Create a temp DB with some entries and an unlocked session."""
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        save_entry(conn, key, "Amazon", "user@test.com", "pass123")
        save_entry(conn, key, "Google", "user2@test.com", "pass456")

    session = VaultSession(conn, key)
    return session, tmp


def test_repl_list_command(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    repl.onecmd("list")

    captured = capsys.readouterr()
    assert "amazon" in captured.out.lower()
    assert "google" in captured.out.lower()

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_ls_alias(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    repl.onecmd("ls")

    captured = capsys.readouterr()
    assert "amazon" in captured.out.lower()

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_exit_returns_true_and_locks():
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    result = repl.onecmd("exit")
    assert result is True
    assert session.key is None
    assert session.entries == []

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_quit_returns_true():
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    result = repl.onecmd("quit")
    assert result is True

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_default_get_hides_password_when_copied(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    with patch("sofiavault.copy_to_clipboard", return_value=True), \
         patch("sofiavault.schedule_clipboard_clear", return_value=True):
        repl.onecmd("amazon")

    captured = capsys.readouterr()
    assert "user@test.com" in captured.out
    assert "pass123" not in captured.out  # hidden by default
    assert "clipboard" in captured.out.lower()

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_show_displays_password(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    with patch("sofiavault.copy_to_clipboard", return_value=True), \
         patch("sofiavault.schedule_clipboard_clear", return_value=True):
        repl.onecmd("show amazon")

    captured = capsys.readouterr()
    assert "pass123" in captured.out

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_get_falls_back_to_display_without_clipboard(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    with patch("sofiavault.copy_to_clipboard", return_value=False):
        repl.onecmd("amazon")

    captured = capsys.readouterr()
    assert "pass123" in captured.out
    assert "clipboard unavailable" in captured.out.lower()

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_emptyline_does_nothing(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    repl.onecmd("")
    captured = capsys.readouterr()
    assert captured.out == ""

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_tab_completion():
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    completions = repl.complete_get("am", "get am", 4, 6)
    assert "amazon" in completions

    completions_all = repl.complete_get("", "get ", 4, 4)
    assert "amazon" in completions_all
    assert "google" in completions_all

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_help_command(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    repl.onecmd("help")

    captured = capsys.readouterr()
    assert "Commands" in captured.out
    assert "add" in captured.out.lower()
    assert "list" in captured.out.lower()
    assert "show" in captured.out.lower()
    assert "exit" in captured.out.lower()

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_vault_session_expiry():
    session, tmp = _setup_session()

    assert session.is_expired() is False

    # Simulate timeout
    session.last_activity = 0
    assert session.is_expired() is True

    session.touch()
    assert session.is_expired() is False

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_expired_session_drops_key_from_memory(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)
    session.last_activity = 0  # force expiry

    # Failed re-auth: key and decrypted index must be gone
    with patch("sofiavault.unlock_vault", return_value=None):
        assert repl._check_lock() is False
    assert session.key is None
    assert session.entries == []

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_expired_session_restored_after_reauth(capsys):
    session, tmp = _setup_session()
    key = session.key
    repl = VaultREPL(session)
    session.last_activity = 0  # force expiry

    with patch("sofiavault.unlock_vault", return_value=key):
        assert repl._check_lock() is True
    assert session.key == key
    assert len(session.entries) == 2
    assert session.is_expired() is False

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)
