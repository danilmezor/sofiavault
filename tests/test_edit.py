"""Tests for the edit command."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    GEN_CHARSET,
    GEN_DEFAULT_LENGTH,
    KEY_SIZE,
    VaultREPL,
    VaultSession,
    _load_entry_payload,
    cmd_edit,
    get_entry_by_service,
    get_password,
    init_db,
    save_entry,
)


def _setup_session():
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        save_entry(conn, key, "Amazon", "user@test.com", "oldpass",
                   "https://amazon.com")
        save_entry(conn, key, "Google", "user2@test.com", "gpass")
    session = VaultSession(conn, key)
    return session, tmp


def _entry_row(session, entry_id):
    return session.conn.execute(
        "SELECT salt, nonce, blob FROM entries_v2 WHERE id = ?", (entry_id,)
    ).fetchone()


def test_edit_password_only(capsys):
    session, tmp = _setup_session()
    entry = get_entry_by_service(session.entries, "amazon")
    row_before = _entry_row(session, entry.id)
    created_before = _load_entry_payload(session.conn, session.key, entry.id)["created_at"]

    # service, username, url: Enter (keep); generate?: no
    with patch("builtins.input", side_effect=["", "", "", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = "newpass123"
        cmd_edit(session, "amazon")

    updated = get_entry_by_service(session.entries, "amazon")
    assert updated.id == entry.id  # id stable
    assert updated.username == "user@test.com"
    assert updated.url == "https://amazon.com"
    assert get_password(session.conn, session.key, entry.id) == "newpass123"

    payload = _load_entry_payload(session.conn, session.key, entry.id)
    assert payload["created_at"] == created_before  # preserved
    assert payload.get("updated_at")  # stamped

    row_after = _entry_row(session, entry.id)
    assert row_after[0] != row_before[0]  # fresh salt
    assert row_after[1] != row_before[1]  # fresh nonce

    assert "Updated" in capsys.readouterr().out
    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_generate_password(capsys):
    session, tmp = _setup_session()
    entry = get_entry_by_service(session.entries, "amazon")

    with patch("builtins.input", side_effect=["", "", "", "y"]), \
         patch("sofiavault.getpass") as gp, \
         patch("sofiavault.copy_to_clipboard", return_value=True), \
         patch("sofiavault.schedule_clipboard_clear", return_value=True):
        gp.getpass.side_effect = AssertionError("must not prompt for password")
        cmd_edit(session, "amazon")

    new_pw = get_password(session.conn, session.key, entry.id)
    assert new_pw != "oldpass"
    assert len(new_pw) == GEN_DEFAULT_LENGTH
    assert all(c in GEN_CHARSET for c in new_pw)

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_rename_service(capsys):
    session, tmp = _setup_session()
    entry = get_entry_by_service(session.entries, "amazon")

    with patch("builtins.input", side_effect=["AWS", "", "", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = ""
        cmd_edit(session, "amazon")

    assert get_entry_by_service(session.entries, "amazon") is None
    renamed = get_entry_by_service(session.entries, "aws")
    assert renamed is not None
    assert renamed.id == entry.id
    assert get_password(session.conn, session.key, entry.id) == "oldpass"

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_rename_collision_rejected(capsys):
    session, tmp = _setup_session()
    row_before = _entry_row(session, get_entry_by_service(session.entries, "amazon").id)

    with patch("builtins.input", side_effect=["google"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.side_effect = AssertionError("must abort before password")
        cmd_edit(session, "amazon")

    out = capsys.readouterr().out
    assert "already exists" in out
    entry = get_entry_by_service(session.entries, "amazon")
    assert entry is not None
    assert _entry_row(session, entry.id) == row_before  # untouched

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_no_changes(capsys):
    session, tmp = _setup_session()
    entry = get_entry_by_service(session.entries, "amazon")
    row_before = _entry_row(session, entry.id)

    with patch("builtins.input", side_effect=["", "", "", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = ""  # Enter = keep password
        cmd_edit(session, "amazon")

    assert "No changes" in capsys.readouterr().out
    assert _entry_row(session, entry.id) == row_before  # not re-encrypted

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_clear_url(capsys):
    session, tmp = _setup_session()
    entry = get_entry_by_service(session.entries, "amazon")

    with patch("builtins.input", side_effect=["", "", "-", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = ""
        cmd_edit(session, "amazon")

    assert get_entry_by_service(session.entries, "amazon").url == ""
    assert get_password(session.conn, session.key, entry.id) == "oldpass"

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_fuzzy_single_match(capsys):
    session, tmp = _setup_session()

    with patch("builtins.input", side_effect=["", "", "", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = "rotated"
        cmd_edit(session, "amazn")  # typo — fuzzy resolves to amazon

    entry = get_entry_by_service(session.entries, "amazon")
    assert get_password(session.conn, session.key, entry.id) == "rotated"

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_edit_no_match(capsys):
    session, tmp = _setup_session()
    with patch("builtins.input", side_effect=AssertionError("must not prompt")):
        cmd_edit(session, "zzzzzzz")
    assert "No matches" in capsys.readouterr().out
    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_edit_command(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)

    with patch("builtins.input", side_effect=["", "", "", "n"]), \
         patch("sofiavault.getpass") as gp:
        gp.getpass.return_value = "via-repl"
        repl.onecmd("edit amazon")

    entry = get_entry_by_service(session.entries, "amazon")
    assert get_password(session.conn, session.key, entry.id) == "via-repl"

    session.conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_repl_edit_usage(capsys):
    session, tmp = _setup_session()
    repl = VaultREPL(session)
    repl.onecmd("edit")
    assert "Usage" in capsys.readouterr().out
    session.conn.close()
    Path(tmp).unlink(missing_ok=True)
