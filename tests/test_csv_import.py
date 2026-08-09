"""Tests for SofiaVault CSV import functionality."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    KEY_SIZE,
    VaultSession,
    cmd_import,
    get_entry_by_service,
    get_password,
    init_db,
    save_master,
)


def _make_session(db_tmp: str) -> VaultSession:
    key = secrets.token_bytes(KEY_SIZE)
    with patch("sofiavault.paths.DB_PATH", Path(db_tmp)):
        conn = init_db()
    # A session only ever exists for an initialized vault: setup_master (or
    # Vault.create) writes the master record and the first entry-set MAC
    # before anything builds one. Skipping that leaves a v3 vault with no
    # MAC — which the tamper check rightly refuses.
    save_master(conn, b'x' * 16, b'y' * 32, key)
    return VaultSession(conn, key)


def _make_csv(content: str) -> str:
    tmp = tempfile.mktemp(suffix=".csv")
    Path(tmp).write_text(content, encoding="utf-8")
    return tmp


def test_import_basic_csv(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD,URL\n"
        "Amazon,user@test.com,pass123,https://amazon.com\n"
        "Google,user2@test.com,pass456,https://google.com\n"
    )
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)

    assert len(session.entries) == 2
    amazon = get_entry_by_service(session.entries, "amazon")
    assert amazon is not None
    assert amazon.username == "user@test.com"
    assert amazon.url == "https://amazon.com"
    assert get_password(session.conn, session.key, amazon.id) == "pass123"
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_skips_duplicates(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        "Amazon,user@test.com,pass123\n"
    )
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)
    assert len(session.entries) == 1

    # Import again - should skip duplicate
    cmd_import(session, csv_tmp)
    assert len(session.entries) == 1
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_skips_duplicates_within_same_file(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        "Amazon,first@test.com,pass123\n"
        "Amazon,second@test.com,pass456\n"
    )
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)

    assert len(session.entries) == 1
    assert session.entries[0].username == "first@test.com"
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_missing_columns(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv("NAME,PASS\nAmazon,pass123\n")
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)

    # Should import nothing due to missing required columns
    assert len(session.entries) == 0
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_skips_empty_fields(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        ",user@test.com,pass123\n"
        "Google,,pass456\n"
        "Netflix,user3,\n"
    )
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)

    assert len(session.entries) == 0  # All rows should be skipped
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_nonexistent_file(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    session = _make_session(db_tmp)

    cmd_import(session, "/nonexistent/path/file.csv")
    captured = capsys.readouterr()
    assert "not found" in captured.out.lower()
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)


def test_import_without_url_column(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        "Amazon,user@test.com,pass123\n"
    )
    session = _make_session(db_tmp)

    cmd_import(session, csv_tmp)

    entry = get_entry_by_service(session.entries, "amazon")
    assert entry is not None
    assert entry.url == ""  # URL should be empty string
    session.conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)
