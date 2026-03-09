"""Tests for SofiaVault interactive REPL."""

import base64
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    SALT_SIZE,
    VaultREPL,
    VaultSession,
    derive_key,
    encrypt,
    init_db,
    save_entry,
    save_master,
)


def _setup_session():
    """Create a temp DB with a master password and some entries."""
    tmp = tempfile.mktemp(suffix=".db")
    master_password = "testmaster123"

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()

        # Set up master password
        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(master_password, salt)
        verify_salt = secrets.token_bytes(SALT_SIZE)
        verify_hash = derive_key(base64.b64encode(key).decode(), verify_salt)
        save_master(conn, salt + verify_salt, verify_hash)

        # Add some entries
        entry_salt = secrets.token_bytes(SALT_SIZE)
        entry_key = derive_key(base64.b64encode(key).decode(), entry_salt)
        nonce, encrypted = encrypt("pass123", entry_key)
        save_entry(conn, "Amazon", "user@test.com", entry_salt, nonce, encrypted)

        entry_salt2 = secrets.token_bytes(SALT_SIZE)
        entry_key2 = derive_key(base64.b64encode(key).decode(), entry_salt2)
        nonce2, encrypted2 = encrypt("pass456", entry_key2)
        save_entry(conn, "Google", "user2@test.com", entry_salt2, nonce2, encrypted2)

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


def test_repl_exit_returns_true():
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    result = repl.onecmd("exit")
    assert result is True

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_quit_returns_true():
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    result = repl.onecmd("quit")
    assert result is True

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_default_fuzzy_get(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    # Typing "amazon" directly should trigger fuzzy get via default()
    repl.onecmd("amazon")

    captured = capsys.readouterr()
    assert "user@test.com" in captured.out
    assert "pass123" in captured.out

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
