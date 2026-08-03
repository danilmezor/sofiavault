"""Tests for SofiaVault database operations (v2 encrypted-blob format)."""

import secrets
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    KEY_SIZE,
    delete_entry,
    get_entry_by_service,
    get_master_data,
    get_password,
    init_db,
    is_vault_initialized,
    load_entries,
    save_entry,
    save_master,
)


def _temp_db():
    """Create a temp DB path for patching DB_PATH."""
    return tempfile.mktemp(suffix=".db")


def _key():
    return secrets.token_bytes(KEY_SIZE)


def test_init_db_creates_tables():
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cur.fetchall()]
        assert "entries_v2" in tables
        assert "master" in tables
        assert "vault_meta" in tables
        # v2 format never creates the legacy plaintext-metadata table
        assert "entries" not in tables
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_db_file_permissions_restricted():
    if sys.platform == "win32":
        return  # POSIX permission bits are not meaningful on Windows
    tmp = _temp_db()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        conn.close()
        mode = stat.S_IMODE(Path(tmp).stat().st_mode)
        assert mode == 0o600
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
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        entry_id = save_entry(
            conn, key, "Amazon", "user@test.com", "pass123", "https://amazon.com"
        )

        entries, corrupt = load_entries(conn, key)
        assert corrupt == 0
        assert len(entries) == 1
        entry = entries[0]
        assert entry.service == "amazon"  # stored lowercase
        assert entry.username == "user@test.com"
        assert entry.url == "https://amazon.com"

        assert get_password(conn, key, entry_id) == "pass123"
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_metadata_is_not_stored_in_plaintext():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        save_entry(conn, key, "amazonsecret", "hidden@user.example",
                   "topsecretpw", "https://hidden.example")
        conn.close()

    raw = Path(tmp).read_bytes()
    assert b"amazonsecret" not in raw
    assert b"hidden@user.example" not in raw
    assert b"topsecretpw" not in raw
    assert b"hidden.example" not in raw
    Path(tmp).unlink(missing_ok=True)


def test_wrong_key_cannot_read_entries():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        entry_id = save_entry(conn, key, "Amazon", "user", "pass123")

        entries, corrupt = load_entries(conn, _key())
        assert entries == []
        assert corrupt == 1
        assert get_password(conn, _key(), entry_id) is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_tampered_entry_fails_decryption():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        entry_id = save_entry(conn, key, "Amazon", "user", "pass123")

        row = conn.execute(
            "SELECT blob FROM entries_v2 WHERE id = ?", (entry_id,)
        ).fetchone()
        tampered = bytearray(row[0])
        tampered[0] ^= 0xFF
        conn.execute(
            "UPDATE entries_v2 SET blob = ? WHERE id = ?", (bytes(tampered), entry_id)
        )
        conn.commit()

        entries, corrupt = load_entries(conn, key)
        assert entries == []
        assert corrupt == 1
        assert get_password(conn, key, entry_id) is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_get_all_entries_sorted():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        save_entry(conn, key, "Netflix", "u3", "p3")
        save_entry(conn, key, "Amazon", "u1", "p1")
        save_entry(conn, key, "Google", "u2", "p2")

        entries, _ = load_entries(conn, key)
        names = [e.service for e in entries]
        assert names == ["amazon", "google", "netflix"]
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_delete_entry():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        save_entry(conn, key, "ToDelete", "user", "pass")

        entries, _ = load_entries(conn, key)
        entry = get_entry_by_service(entries, "todelete")
        assert entry is not None

        delete_entry(conn, entry.id)
        entries, _ = load_entries(conn, key)
        assert get_entry_by_service(entries, "todelete") is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)


def test_nonexistent_service_returns_none():
    tmp = _temp_db()
    key = _key()
    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        entries, _ = load_entries(conn, key)
        assert get_entry_by_service(entries, "nonexistent") is None
        conn.close()
    Path(tmp).unlink(missing_ok=True)
