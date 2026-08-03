"""Tests for automatic v1 -> v2 vault migration.

v1 stored plaintext metadata (service, username, url) alongside a password
encrypted with an Argon2-derived per-entry key and no AAD. Migration must
re-encrypt everything into the v2 blob format without losing a single entry.
"""

import base64
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import (
    KEY_SIZE,
    SALT_SIZE,
    _table_exists,
    derive_key,
    encrypt,
    get_entry_by_service,
    get_password,
    init_db,
    load_entries,
    migrate_legacy_vault,
)

V1_SCHEMA = """
    CREATE TABLE entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        url TEXT DEFAULT '',
        salt BLOB NOT NULL,
        nonce BLOB NOT NULL,
        encrypted_password BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


def _insert_v1_entry(conn, key, service, username, password, url=""):
    """Insert an entry exactly the way SofiaVault v1 did."""
    salt = secrets.token_bytes(SALT_SIZE)
    legacy_key = derive_key(base64.b64encode(key).decode(), salt)
    nonce, enc = encrypt(password, legacy_key)  # v1 used no AAD
    conn.execute(
        "INSERT INTO entries (service, username, url, salt, nonce, encrypted_password) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (service.lower(), username, url, salt, nonce, enc),
    )


def test_migration_preserves_all_entries(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        conn.execute(V1_SCHEMA)
        _insert_v1_entry(conn, key, "Amazon", "user@test.com", "pass123",
                         "https://amazon.com")
        _insert_v1_entry(conn, key, "Google", "user2@test.com", "pass456")
        conn.commit()

        migrate_legacy_vault(conn, key)

        entries, corrupt = load_entries(conn, key)
        assert corrupt == 0
        assert len(entries) == 2

        amazon = get_entry_by_service(entries, "amazon")
        assert amazon.username == "user@test.com"
        assert amazon.url == "https://amazon.com"
        assert get_password(conn, key, amazon.id) == "pass123"

        google = get_entry_by_service(entries, "google")
        assert get_password(conn, key, google.id) == "pass456"

        # Legacy table fully migrated -> dropped
        assert _table_exists(conn, "entries") is False

        # Pre-migration backup exists with restricted permissions
        backup = Path(tmp + ".v1-backup")
        assert backup.exists()
        if sys.platform != "win32":
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        backup.unlink()
        conn.close()

    # After migration + VACUUM, no v1 plaintext may remain in the db file
    raw = Path(tmp).read_bytes()
    assert b"amazon" not in raw
    assert b"user@test.com" not in raw
    assert b"amazon.com" not in raw

    Path(tmp).unlink(missing_ok=True)


def test_migration_keeps_undecryptable_rows(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        conn.execute(V1_SCHEMA)
        _insert_v1_entry(conn, key, "Good", "user", "goodpass")
        # A corrupt row: garbage ciphertext that cannot decrypt
        conn.execute(
            "INSERT INTO entries (service, username, url, salt, nonce, encrypted_password) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("broken", "user", "", secrets.token_bytes(SALT_SIZE),
             secrets.token_bytes(12), b"garbage-ciphertext"),
        )
        conn.commit()

        migrate_legacy_vault(conn, key)

        # Good entry migrated and readable
        entries, _ = load_entries(conn, key)
        assert len(entries) == 1
        assert get_password(conn, key, entries[0].id) == "goodpass"

        # Corrupt row preserved in the legacy table, not silently dropped
        assert _table_exists(conn, "entries") is True
        remaining = conn.execute("SELECT service FROM entries").fetchall()
        assert remaining == [("broken",)]

        Path(tmp + ".v1-backup").unlink(missing_ok=True)
        conn.close()

    Path(tmp).unlink(missing_ok=True)


def test_migration_noop_on_fresh_vault(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        migrate_legacy_vault(conn, key)  # must not raise or create a backup
        assert not Path(tmp + ".v1-backup").exists()
        entries, corrupt = load_entries(conn, key)
        assert entries == []
        assert corrupt == 0
        conn.close()

    Path(tmp).unlink(missing_ok=True)


def test_migration_drops_empty_legacy_table(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        conn.execute(V1_SCHEMA)
        conn.commit()

        migrate_legacy_vault(conn, key)
        assert _table_exists(conn, "entries") is False
        assert not Path(tmp + ".v1-backup").exists()
        conn.close()

    Path(tmp).unlink(missing_ok=True)


def test_migration_is_idempotent(capsys):
    tmp = tempfile.mktemp(suffix=".db")
    key = secrets.token_bytes(KEY_SIZE)

    with patch("sofiavault.DB_PATH", Path(tmp)):
        conn = init_db()
        conn.execute(V1_SCHEMA)
        _insert_v1_entry(conn, key, "Amazon", "user", "pass123")
        conn.commit()

        migrate_legacy_vault(conn, key)
        migrate_legacy_vault(conn, key)  # second run must be a no-op

        entries, corrupt = load_entries(conn, key)
        assert corrupt == 0
        assert len(entries) == 1
        assert get_password(conn, key, entries[0].id) == "pass123"

        Path(tmp + ".v1-backup").unlink(missing_ok=True)
        conn.close()

    Path(tmp).unlink(missing_ok=True)
