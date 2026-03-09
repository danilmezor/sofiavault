"""Tests for SofiaVault fuzzy matching."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import SALT_SIZE, fuzzy_find_service, init_db, save_entry


def _setup_db_with_entries():
    """Create a temp DB with some entries for fuzzy matching tests."""
    tmp = tempfile.mktemp(suffix=".db")
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(12)

        save_entry(conn, "Amazon", "user1", salt, nonce, b"enc1")
        save_entry(conn, "Google", "user2", salt, nonce, b"enc2")
        save_entry(conn, "Netflix", "user3", salt, nonce, b"enc3")
        save_entry(conn, "GitHub", "user4", salt, nonce, b"enc4")
        save_entry(conn, "Facebook", "user5", salt, nonce, b"enc5")
    return conn, tmp


def test_exact_match_high_score():
    conn, tmp = _setup_db_with_entries()
    results = fuzzy_find_service(conn, "amazon")
    assert len(results) >= 1
    assert results[0][0][1] == "amazon"
    assert results[0][1] == 100
    conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_fuzzy_match_typo():
    conn, tmp = _setup_db_with_entries()
    results = fuzzy_find_service(conn, "amazn")
    assert len(results) >= 1
    assert results[0][0][1] == "amazon"
    assert results[0][1] >= 60
    conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_fuzzy_match_case_insensitive():
    conn, tmp = _setup_db_with_entries()
    results = fuzzy_find_service(conn, "GOOGLE")
    assert len(results) >= 1
    assert results[0][0][1] == "google"
    conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_no_match_below_threshold():
    conn, tmp = _setup_db_with_entries()
    results = fuzzy_find_service(conn, "zzzzzzz", threshold=60)
    assert len(results) == 0
    conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_empty_db_returns_empty():
    tmp = tempfile.mktemp(suffix=".db")
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
    results = fuzzy_find_service(conn, "anything")
    assert results == []
    conn.close()
    Path(tmp).unlink(missing_ok=True)
