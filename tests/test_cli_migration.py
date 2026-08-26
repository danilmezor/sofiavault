"""The CLI must upgrade older vault formats, not show an empty vault.

Regression guard: an early version of the 0.3.0 work applied the v2->v3
re-authentication only in the library path, so opening a 0.2.x vault with
the CLI decrypted nothing and presented as "no passwords saved yet".
"""

import json
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

from sofiavault import cli, paths, storage
from sofiavault.core import (
    ENTRY_CONTEXT,
    SALT_SIZE,
    create_master_record,
    derive_entry_key,
    encrypt,
)

PW = "cli-migration-pw"


def _build_v2_vault(db: Path, entries: dict) -> bytes:
    """Write a genuine 0.2.x vault: v2 blobs with the old constant AAD."""
    conn = storage.init_db(db)
    combined_salt, verify_hash, key = create_master_record(PW)
    storage.save_master(conn, combined_salt, verify_hash)
    for service, password in entries.items():
        payload = json.dumps({
            "service": service, "username": "danil", "url": "",
            "password": password, "created_at": "2026-01-01",
        })
        salt = secrets.token_bytes(SALT_SIZE)
        nonce, blob = encrypt(payload, derive_entry_key(key, salt),
                              aad=ENTRY_CONTEXT)
        conn.execute("INSERT INTO entries_v2 (salt, nonce, blob) VALUES (?,?,?)",
                     (salt, nonce, blob))
    conn.execute("UPDATE vault_meta SET value='2' WHERE key='schema_version'")
    conn.execute("DELETE FROM vault_meta WHERE key='entries_mac'")
    conn.commit()
    conn.close()
    return key


def _open_via_cli(db: Path):
    with patch.object(paths, "DB_PATH", db), \
         patch("sofiavault.cli.getpass") as gp, \
         patch("sofiavault.cli.check_for_updates"):
        gp.getpass.return_value = PW
        conn, key = cli._open_vault(show_banner_on_setup=False)
    return conn, key


def test_cli_opens_v2_vault_without_losing_entries():
    db = Path(tempfile.mkdtemp()) / "vault.db"
    _build_v2_vault(db, {"github": "gh-secret", "bank": "bank-secret"})

    conn, key = _open_via_cli(db)
    session = cli.VaultSession(conn, key)

    assert sorted(e.service for e in session.entries) == ["bank", "github"]
    assert session.corrupt_count == 0
    assert storage.get_schema_version(conn) == storage.SCHEMA_VERSION
    by_name = {e.service: e.id for e in session.entries}
    assert storage.get_password(conn, key, by_name["github"]) == "gh-secret"
    assert storage.get_password(conn, key, by_name["bank"]) == "bank-secret"
    conn.close()


def test_cli_v2_vault_stays_consistent_across_restarts():
    db = Path(tempfile.mkdtemp()) / "vault.db"
    _build_v2_vault(db, {"github": "gh-secret"})

    conn, key = _open_via_cli(db)
    storage.save_entry(conn, key, "newsite", "danil", "new-secret")
    assert storage.verify_entries_mac(conn, key) is True
    conn.close()

    conn2, key2 = _open_via_cli(db)
    session = cli.VaultSession(conn2, key2)
    assert sorted(e.service for e in session.entries) == ["github", "newsite"]
    assert session.corrupt_count == 0
    assert storage.verify_entries_mac(conn2, key2) is True
    conn2.close()


def test_cli_delete_keeps_entry_mac_valid():
    db = Path(tempfile.mkdtemp()) / "vault.db"
    _build_v2_vault(db, {"a": "1", "b": "2"})

    conn, key = _open_via_cli(db)
    session = cli.VaultSession(conn, key)
    target = next(e for e in session.entries if e.service == "a")
    storage.delete_entry(conn, target.id, key)
    assert storage.verify_entries_mac(conn, key) is True
    conn.close()

    conn2, key2 = _open_via_cli(db)
    session2 = cli.VaultSession(conn2, key2)
    assert [e.service for e in session2.entries] == ["b"]
    conn2.close()


def _build_v1_vault(db: Path, entries: dict) -> bytes:
    """Write a genuine 0.1.x vault: plaintext metadata, Argon2 entry keys."""
    import base64
    import sqlite3 as _sq

    from sofiavault.core import derive_key

    combined_salt, verify_hash, key = create_master_record(PW)
    conn = _sq.connect(str(db))
    conn.execute("CREATE TABLE master (id INTEGER PRIMARY KEY CHECK (id = 1),"
                 " salt BLOB NOT NULL, verify_hash BLOB NOT NULL)")
    conn.execute("INSERT INTO master VALUES (1, ?, ?)", (combined_salt, verify_hash))
    conn.execute("""CREATE TABLE entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL,
        username TEXT NOT NULL, url TEXT DEFAULT '', salt BLOB NOT NULL,
        nonce BLOB NOT NULL, encrypted_password BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    for service, password in entries.items():
        salt = secrets.token_bytes(SALT_SIZE)
        legacy_key = derive_key(base64.b64encode(key).decode(), salt)
        nonce, enc = encrypt(password, legacy_key)   # v1 used no AAD
        conn.execute(
            "INSERT INTO entries (service, username, url, salt, nonce,"
            " encrypted_password) VALUES (?,?,?,?,?,?)",
            (service, "danil", "", salt, nonce, enc))
    conn.commit()
    conn.close()
    return key


def test_cli_opens_v1_vault_without_losing_entries():
    """0.1.x vaults must still open through the CLI after the v3 MAC work.

    The MAC now binds schema_version and vault_id, and a v3 vault is
    required to carry one — neither of which a v1 file has. The migration
    has to establish both without tripping the tamper check.
    """
    db = Path(tempfile.mkdtemp()) / "vault.db"
    _build_v1_vault(db, {"github": "gh-secret", "bank": "bank-secret"})

    conn, key = _open_via_cli(db)
    session = cli.VaultSession(conn, key)

    assert sorted(e.service for e in session.entries) == ["bank", "github"]
    assert session.corrupt_count == 0
    assert storage.get_schema_version(conn) == storage.SCHEMA_VERSION
    assert storage.verify_entries_mac(conn, key) is True
    by_name = {e.service: e.id for e in session.entries}
    assert storage.get_password(conn, key, by_name["github"]) == "gh-secret"
    assert storage.get_password(conn, key, by_name["bank"]) == "bank-secret"
    # the legacy table is gone and the untouched original was preserved
    assert not storage._table_exists(conn, "entries")
    assert db.with_name(db.name + ".v1-backup").exists()
    conn.close()


def test_cli_v1_vault_stays_consistent_across_restarts():
    db = Path(tempfile.mkdtemp()) / "vault.db"
    _build_v1_vault(db, {"github": "gh-secret"})

    conn, key = _open_via_cli(db)
    storage.save_entry(conn, key, "newsite", "danil", "new-secret")
    conn.close()

    conn2, key2 = _open_via_cli(db)
    session = cli.VaultSession(conn2, key2)
    assert sorted(e.service for e in session.entries) == ["github", "newsite"]
    assert session.corrupt_count == 0
    assert storage.verify_entries_mac(conn2, key2) is True
    conn2.close()
