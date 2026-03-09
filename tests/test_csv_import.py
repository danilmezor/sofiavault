"""Tests for SofiaVault CSV import functionality."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    SALT_SIZE,
    cmd_import,
    derive_key,
    get_all_services,
    get_entry_by_service,
    init_db,
)


def _make_key():
    salt = secrets.token_bytes(SALT_SIZE)
    return derive_key("testmaster", salt)


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
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        cmd_import(conn, key, csv_tmp)

        services = get_all_services(conn)
        assert len(services) == 2
        conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_skips_duplicates(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        "Amazon,user@test.com,pass123\n"
    )
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        # Import once
        cmd_import(conn, key, csv_tmp)
        assert len(get_all_services(conn)) == 1

        # Import again - should skip duplicate
        cmd_import(conn, key, csv_tmp)
        assert len(get_all_services(conn)) == 1
        conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_missing_columns(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv("NAME,PASS\nAmazon,pass123\n")
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        cmd_import(conn, key, csv_tmp)

        # Should import nothing due to missing required columns
        services = get_all_services(conn)
        assert len(services) == 0
        conn.close()

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
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        cmd_import(conn, key, csv_tmp)

        services = get_all_services(conn)
        assert len(services) == 0  # All rows should be skipped
        conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)


def test_import_nonexistent_file(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        cmd_import(conn, key, "/nonexistent/path/file.csv")
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()
        conn.close()

    Path(db_tmp).unlink(missing_ok=True)


def test_import_without_url_column(capsys):
    db_tmp = tempfile.mktemp(suffix=".db")
    csv_tmp = _make_csv(
        "TITLE,USERNAME,PASSWORD\n"
        "Amazon,user@test.com,pass123\n"
    )
    key = _make_key()

    with patch("sofiavault.DB_PATH", Path(db_tmp)):
        conn = init_db()
        cmd_import(conn, key, csv_tmp)

        entry = get_entry_by_service(conn, "amazon")
        assert entry is not None
        assert entry[3] == ""  # URL should be empty string
        conn.close()

    Path(db_tmp).unlink(missing_ok=True)
    Path(csv_tmp).unlink(missing_ok=True)
