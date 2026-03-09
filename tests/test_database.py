"""Tests for SofiaVault database operations."""

import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    SALT_SIZE,
    delete_entry,
    get_all_services,
    get_entry_by_service,
    get_master_data,
    init_db,
    is_vault_initialized,
    save_entry,
    save_master,
)


def _temp_db():
    """Create an in-memory-like temp DB by patching DB_PATH."""
    tmp = tempfile.mktemp(suffix=".db")
    return tmp


def test_init_db_creates_tables():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        # Check tables exist
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cur.fetchall()]
        assert "entries" in tables
        assert "master" in tables
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_vault_not_initialized_initially():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        assert is_vault_initialized(conn) is False
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_save_and_verify_master():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        salt = secrets.token_bytes(32)
        verify_hash = secrets.token_bytes(32)
        save_master(conn, salt, verify_hash)

        assert is_vault_initialized(conn) is True

        got_salt, got_hash = get_master_data(conn)
        assert got_salt == salt
        assert got_hash == verify_hash
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_save_and_retrieve_entry():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(12)
        encrypted = b"encrypted_data"

        save_entry(conn, "Amazon", "user@test.com", salt, nonce, encrypted, "https://amazon.com")

        entry = get_entry_by_service(conn, "amazon")
        assert entry is not None
        assert entry[1] == "amazon"  # stored lowercase
        assert entry[2] == "user@test.com"
        assert entry[3] == "https://amazon.com"
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_get_all_services():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(12)

        save_entry(conn, "Amazon", "u1", salt, nonce, b"enc1")
        save_entry(conn, "Google", "u2", salt, nonce, b"enc2")
        save_entry(conn, "Netflix", "u3", salt, nonce, b"enc3")

        services = get_all_services(conn)
        assert len(services) == 3
        names = [s[1] for s in services]
        assert "amazon" in names
        assert "google" in names
        assert "netflix" in names
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_delete_entry():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(12)

        save_entry(conn, "ToDelete", "user", salt, nonce, b"enc")
        entry = get_entry_by_service(conn, "todelete")
        assert entry is not None

        delete_entry(conn, entry[0])
        assert get_entry_by_service(conn, "todelete") is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_nonexistent_service_returns_none():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        assert get_entry_by_service(conn, "nonexistent") is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)
