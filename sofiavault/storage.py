"""SofiaVault storage layer: SQLite schema, entry blobs, migration, shredding.

Silent by contract — no prints, no prompts. Progress reporting for the
legacy migration goes through an optional callback.
"""

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from rapidfuzz import fuzz, process

from . import paths
from .core import ENTRY_CONTEXT, SALT_SIZE, decrypt, derive_entry_key, derive_key, encrypt

#: Bumped when the on-disk entry format changes. v3 binds each entry blob
#: to its row id and vault id via AES-GCM associated data.
SCHEMA_VERSION = 3


def _harden_storage_perms(db_path: Path):
    """Restrict vault directory/files to the owning user (POSIX).

    Also repairs permissions of vaults created by older versions.
    The directory is only touched when it is a `.sofiavault` dir, so
    library consumers pointing at app-owned directories (and tests using
    temp dirs) never chmod shared locations.
    """
    with contextlib.suppress(OSError):
        if db_path.parent.name == '.sofiavault':
            os.chmod(db_path.parent, 0o700)
    with contextlib.suppress(OSError):
        if db_path.exists():
            os.chmod(db_path, 0o600)
    with contextlib.suppress(OSError):
        if paths.HISTORY_PATH.exists():
            os.chmod(paths.HISTORY_PATH, 0o600)


def _create_private_file(path: Path):
    """Create `path` with mode 0600 before anything can open it.

    sqlite3.connect() would create the file under the process umask
    (typically 0644) and our chmod would land afterwards — an attacker who
    opens the file during that window keeps a readable descriptor even
    after the mode is tightened. Creating it O_EXCL at 0600 closes that.
    """
    if path.exists():
        return
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    except OSError:
        return  # fall back to connect() + chmod
    os.close(fd)


def init_db(db_path: Optional[Path] = None,
            check_same_thread: bool = True) -> sqlite3.Connection:
    """Initialize database and return connection.

    `check_same_thread=False` is used by the library Vault, which serializes
    all access behind its own lock so a single instance can be shared by a
    threaded server.
    """
    db_path = Path(db_path) if db_path is not None else paths.DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _create_private_file(db_path)
    _harden_storage_perms(db_path)
    conn = sqlite3.connect(str(db_path), check_same_thread=check_same_thread)
    # Overwrite deleted content with zeros so removed entries (and migrated
    # legacy plaintext) don't linger in the database file's free pages.
    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verify_hash BLOB NOT NULL
        )
    """)
    # v2 entries: all fields (service, username, url, password, created_at)
    # live inside one authenticated AES-GCM blob. No plaintext metadata,
    # and nothing an attacker can relabel or swap between rows.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            blob BLOB NOT NULL
        )
    """)
    conn.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value TEXT)")
    # A brand-new database starts at the current schema version; existing
    # ones keep theirs until migrate_* upgrades them.
    if conn.execute("SELECT COUNT(*) FROM entries_v2").fetchone()[0] == 0 and \
            conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='entries'"
            ).fetchone()[0] == 0:
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),)
        )
    else:
        conn.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('schema_version', '2')"
        )
    _ensure_vault_id(conn)
    conn.commit()
    _harden_storage_perms(db_path)
    return conn


def get_schema_version(conn: sqlite3.Connection) -> int:
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'schema_version'")
    row = cur.fetchone()
    try:
        return int(row[0]) if row else 2
    except (TypeError, ValueError):
        return 2


def _ensure_vault_id(conn: sqlite3.Connection) -> str:
    """Return this vault's identifier, creating it if absent.

    The id is not secret. It exists so an entry blob authenticated under
    one vault cannot be transplanted into another vault that happens to
    share a master key (the documented export_key/SOFIAVAULT_KEY setup).
    """
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'vault_id'")
    row = cur.fetchone()
    if row and row[0]:
        return row[0]
    vault_id = secrets.token_hex(16)
    conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('vault_id', ?)",
                 (vault_id,))
    conn.commit()
    return vault_id


def _read_vault_id(conn: sqlite3.Connection) -> str:
    """Current vault id without creating one. '' when absent.

    _entries_mac() must not write: it runs mid-transaction during migration
    and from the read-only verify path.
    """
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'vault_id'")
    row = cur.fetchone()
    return row[0] if row and row[0] else ''


def _entries_mac(conn: sqlite3.Connection, key: bytes) -> bytes:
    """Authenticate the *set* of entries, not just each entry individually.

    Per-entry AAD stops a blob being moved to another row or vault, but a
    blob restored into its own row re-authenticates perfectly — that's a
    rollback of a rotated secret. Deleting or duplicating rows is likewise
    invisible per-entry.

    This MAC covers every (row id, nonce) pair. Nonces are freshly random
    on every write, so any stale blob, extra row, or missing row changes
    the digest.

    It also covers the two vault_meta values that decide how those rows are
    *interpreted*. Both are plain unauthenticated text, so leaving them out
    let an attacker change the reading of the vault without changing the
    digest: `vault_id` feeds every entry's AAD, and `schema_version`
    selects the migration path — rolling it back to '2' used to re-enter
    migrate_v2_to_v3(), which re-signed whatever the rows then held.
    """
    mac_key = derive_entry_key(key, b"sofiavault-entries-mac-salt")
    h = hmac.new(mac_key, b"sofiavault-entries-v3", hashlib.sha256)
    h.update(b"schema=%d;" % get_schema_version(conn))
    h.update(b"vault=%s;" % _read_vault_id(conn).encode('ascii'))
    for row_id, nonce in conn.execute(
            "SELECT id, nonce FROM entries_v2 ORDER BY id"):
        h.update(b"%d:" % row_id)
        h.update(nonce)
        h.update(b";")
    return h.digest()


def refresh_entries_mac(conn: sqlite3.Connection, key: bytes, commit: bool = True):
    """Recompute and store the entry-set MAC after a mutation."""
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('entries_mac', ?)",
        (_entries_mac(conn, key).hex(),)
    )
    if commit:
        conn.commit()


def verify_entries_mac(conn: sqlite3.Connection, key: bytes) -> bool:
    """True if the entry set matches its stored MAC.

    A vault written before this MAC existed has none; it is adopted on
    first open (there is nothing to compare against yet).

    Adoption is only safe for pre-v3 vaults. Every v3 vault writes a MAC —
    at master creation, on every mutation, and at the end of migration — so
    a v3 vault with no MAC is one an attacker stripped it from, which is
    exactly how you would erase the evidence before rolling a secret back.
    """
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'entries_mac'")
    row = cur.fetchone()
    if row is None or not row[0]:
        if get_schema_version(conn) >= SCHEMA_VERSION:
            return False
        refresh_entries_mac(conn, key)
        return True
    try:
        stored = bytes.fromhex(row[0])
    except ValueError:
        return False
    return hmac.compare_digest(stored, _entries_mac(conn, key))


def _entry_aad(vault_id: str, row_id: int) -> bytes:
    """Associated data binding a blob to one row of one vault.

    Without this, any (salt, nonce, blob) triple produced under a master
    key stays valid in any row of any vault using that key — enabling
    rollback of a rotated secret, duplicate-row shadowing, and cross-vault
    transplant. All three are authenticated-decryption failures now.
    """
    return b"%s|%s|%d" % (ENTRY_CONTEXT, vault_id.encode('ascii'), row_id)


def is_vault_initialized(conn: sqlite3.Connection) -> bool:
    """Check if master password has been set"""
    cur = conn.execute("SELECT COUNT(*) FROM master")
    return cur.fetchone()[0] > 0


def save_master(conn: sqlite3.Connection, salt: bytes, verify_hash: bytes,
                key: Optional[bytes] = None):
    """Save master password verification data.

    Pass `key` when initializing a new vault so the entry-set MAC exists
    from the very first moment. A v3 vault is required to carry a MAC, so
    one that reaches disk without it cannot be told apart from one whose
    MAC an attacker deleted.
    """
    conn.execute(
        "INSERT OR REPLACE INTO master (id, salt, verify_hash) VALUES (1, ?, ?)",
        (salt, verify_hash)
    )
    if key is not None:
        refresh_entries_mac(conn, key, commit=False)
    conn.commit()


def get_master_data(conn: sqlite3.Connection) -> tuple[bytes, bytes]:
    """Get master salt and verify hash"""
    cur = conn.execute("SELECT salt, verify_hash FROM master WHERE id = 1")
    row = cur.fetchone()
    return row[0], row[1]


@dataclass
class VaultEntry:
    """Decrypted entry metadata held in memory while the vault is unlocked."""
    id: int
    service: str
    username: str
    url: str


def save_entry(conn: sqlite3.Connection, key: bytes, service: str, username: str,
               password: str, url: str = '', created_at: Optional[str] = None,
               commit: bool = True) -> int:
    """Encrypt and save a password entry. Returns the new row id.

    The blob is authenticated against its final row id, so the row is
    inserted first to allocate the id, then filled in.
    """
    if created_at is None:
        created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    payload = json.dumps({
        'service': service.lower().strip(),
        'username': username,
        'url': url,
        'password': password,
        'created_at': created_at,
    }, ensure_ascii=False)

    vault_id = _ensure_vault_id(conn)
    cur = conn.execute(
        "INSERT INTO entries_v2 (salt, nonce, blob) VALUES (?, ?, ?)",
        (b'', b'', b'')
    )
    row_id = cur.lastrowid

    entry_salt = secrets.token_bytes(SALT_SIZE)
    entry_key = derive_entry_key(key, entry_salt)
    nonce, blob = encrypt(payload, entry_key, aad=_entry_aad(vault_id, row_id))
    conn.execute(
        "UPDATE entries_v2 SET salt = ?, nonce = ?, blob = ? WHERE id = ?",
        (entry_salt, nonce, blob, row_id)
    )
    if commit:
        refresh_entries_mac(conn, key, commit=False)
        conn.commit()
    return row_id


def _decrypt_entry_row(key: bytes, salt: bytes, nonce: bytes, blob: bytes,
                       aad: bytes) -> dict:
    """Decrypt one entry blob to its dict payload. Raises on tampering/corruption."""
    entry_key = derive_entry_key(key, salt)
    return json.loads(decrypt(nonce, blob, entry_key, aad=aad))


def load_entries(conn: sqlite3.Connection, key: bytes) -> tuple[list[VaultEntry], int]:
    """Decrypt metadata for all entries. Returns (entries, corrupt_count).

    `corrupt_count` is not cosmetic: an entry that fails authenticated
    decryption is absent from the index, so callers must treat a non-zero
    count as "this vault may be missing secrets" rather than "that key was
    never configured". Vault.get() enforces this.
    """
    vault_id = _ensure_vault_id(conn)
    entries = []
    corrupt = 0
    cur = conn.execute("SELECT id, salt, nonce, blob FROM entries_v2 ORDER BY id")
    for row_id, salt, nonce, blob in cur.fetchall():
        try:
            data = _decrypt_entry_row(key, salt, nonce, blob,
                                      _entry_aad(vault_id, row_id))
            entries.append(VaultEntry(
                id=row_id,
                service=data.get('service', ''),
                username=data.get('username', ''),
                url=data.get('url', ''),
            ))
        except Exception:
            corrupt += 1
    entries.sort(key=lambda e: e.service)
    return entries, corrupt


def _load_entry_payload(conn: sqlite3.Connection, key: bytes,
                        entry_id: int) -> Optional[dict]:
    """Decrypt one entry's full payload dict, or None on failure."""
    cur = conn.execute("SELECT salt, nonce, blob FROM entries_v2 WHERE id = ?", (entry_id,))
    row = cur.fetchone()
    if row is None:
        return None
    vault_id = _ensure_vault_id(conn)
    try:
        return _decrypt_entry_row(key, row[0], row[1], row[2],
                                  _entry_aad(vault_id, entry_id))
    except Exception:
        return None


def get_password(conn: sqlite3.Connection, key: bytes, entry_id: int) -> Optional[str]:
    """Decrypt and return the password for one entry, or None on failure."""
    data = _load_entry_payload(conn, key, entry_id)
    if data is None:
        return None
    return data.get('password')


def update_entry(conn: sqlite3.Connection, key: bytes, entry_id: int,
                 service: str, username: str, url: str, password: str,
                 created_at: str):
    """Re-encrypt an entry in place with a fresh salt and nonce."""
    payload = json.dumps({
        'service': service.lower().strip(),
        'username': username,
        'url': url,
        'password': password,
        'created_at': created_at,
        'updated_at': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
    }, ensure_ascii=False)

    vault_id = _ensure_vault_id(conn)
    entry_salt = secrets.token_bytes(SALT_SIZE)
    entry_key = derive_entry_key(key, entry_salt)
    nonce, blob = encrypt(payload, entry_key, aad=_entry_aad(vault_id, entry_id))

    conn.execute(
        "UPDATE entries_v2 SET salt = ?, nonce = ?, blob = ? WHERE id = ?",
        (entry_salt, nonce, blob, entry_id)
    )
    refresh_entries_mac(conn, key, commit=False)
    conn.commit()


def get_entry_by_service(entries: list[VaultEntry], service: str) -> Optional[VaultEntry]:
    """Find an entry by exact service name in the decrypted index."""
    target = service.lower().strip()
    for entry in entries:
        if entry.service == target:
            return entry
    return None


def delete_entry(conn: sqlite3.Connection, entry_id: int, key: bytes):
    """Delete entry by ID and re-sign the remaining set.

    `key` is required: the previous behaviour of clearing the MAC when no
    key was supplied handed any caller a one-line way to strip the vault's
    tamper evidence, which is indistinguishable from an attacker doing the
    same thing deliberately.
    """
    if key is None:
        raise ValueError("delete_entry requires the master key to re-sign the entry set")
    conn.execute("DELETE FROM entries_v2 WHERE id = ?", (entry_id,))
    refresh_entries_mac(conn, key, commit=False)
    conn.commit()


def fuzzy_find_service(
    entries: list[VaultEntry], query: str, threshold: int = 60
) -> list[tuple[VaultEntry, int]]:
    """Find entries matching query using fuzzy matching on the decrypted index."""
    if not entries:
        return []

    names = [e.service for e in entries]
    matches = process.extract(query.lower(), names, scorer=fuzz.ratio, limit=5)

    results = [
        (entries[idx], score)
        for _name, score, idx in matches
        if score >= threshold
    ]
    return sorted(results, key=lambda x: x[1], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Vault file identification
# ─────────────────────────────────────────────────────────────────────────────

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    )
    return cur.fetchone()[0] > 0


def _is_vault_file(path: Path) -> bool:
    """True if the file looks like a SofiaVault database (v1 or v2)."""
    try:
        with open(path, 'rb') as f:
            if not f.read(16).startswith(b"SQLite format 3"):
                return False
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='master'"
            )
            if cur.fetchone()[0] == 0:
                return False
            return conn.execute("SELECT COUNT(*) FROM master").fetchone()[0] > 0
        finally:
            conn.close()
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Legacy (v1) migration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MigrationResult:
    total: int
    migrated: int
    failed: list
    backup: Optional[Path]


def migrate_v2_to_v3(conn: sqlite3.Connection, key: bytes) -> int:
    """Re-authenticate v2 entry blobs against their row and vault id.

    v2 blobs used a constant AAD, so a blob was valid in any row of any
    vault sharing the master key. Returns the number of rows upgraded.
    Rows that fail to decrypt under the old scheme are left untouched and
    reported through the usual corrupt-entry path.
    """
    if get_schema_version(conn) >= 3:
        return 0

    # A genuine v2 vault predates the entry-set MAC and carries none. A MAC
    # that is present but does not verify means this vault was already v3 and
    # its schema_version — plain, unauthenticated text — was rolled back to
    # re-enter this path. Migrating would rewrite every blob and re-sign
    # whatever the rows now hold, laundering the tampering into a valid MAC.
    # Leave the stale MAC in place so verify_entries_mac reports it.
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'entries_mac'")
    row = cur.fetchone()
    if row is not None and row[0]:
        try:
            stored = bytes.fromhex(row[0])
        except ValueError:
            return 0
        if not hmac.compare_digest(stored, _entries_mac(conn, key)):
            return 0

    vault_id = _ensure_vault_id(conn)
    rows = conn.execute("SELECT id, salt, nonce, blob FROM entries_v2").fetchall()

    # The MAC check above only fires when a MAC is *present*. entries_mac and
    # schema_version are both unauthenticated text, so an attacker with
    # file-write access can delete the MAC row and roll schema_version back to
    # '2' together: no MAC to fail the check, yet this path would migrate and
    # re-sign whatever the rows now hold — laundering a rolled-back, deleted, or
    # shadow-inserted row set into a fresh, valid MAC.
    #
    # The rows themselves are the authenticated witness the metadata is not. A
    # genuine v2 blob authenticates only under the constant ENTRY_CONTEXT AAD; a
    # v3 blob authenticates under _entry_aad(vault_id, row_id). If any row still
    # decrypts as v3, this "v2" vault is a rolled-back v3 one. Restore the true
    # schema_version and refuse to migrate or re-sign, leaving verify_entries_mac
    # to judge the rows against the real schema and the (possibly stripped) MAC.
    for row_id, salt, nonce, blob in rows:
        try:
            decrypt(nonce, blob, derive_entry_key(key, salt),
                    aad=_entry_aad(vault_id, row_id))
        except Exception:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),)
        )
        conn.commit()
        return 0

    upgraded = 0
    try:
        for row_id, salt, nonce, blob in rows:
            try:
                payload = decrypt(nonce, blob, derive_entry_key(key, salt),
                                  aad=ENTRY_CONTEXT)
            except Exception:
                continue  # not decryptable under v2 either; leave as-is
            new_salt = secrets.token_bytes(SALT_SIZE)
            new_nonce, new_blob = encrypt(
                payload, derive_entry_key(key, new_salt),
                aad=_entry_aad(vault_id, row_id)
            )
            conn.execute(
                "UPDATE entries_v2 SET salt = ?, nonce = ?, blob = ? WHERE id = ?",
                (new_salt, new_nonce, new_blob, row_id)
            )
            upgraded += 1
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),)
        )
        refresh_entries_mac(conn, key, commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return upgraded


def is_legacy_vault_file(db_path: Path) -> bool:
    """True if the file on disk still has a v1 `entries` table.

    Read-only: checked before init_db() so a backup can be taken before
    anything writes to the file.
    """
    try:
        if not db_path.exists():
            return False
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return _table_exists(conn, 'entries')
        finally:
            conn.close()
    except Exception:
        return False


def backup_legacy_vault(db_path: Optional[Path] = None) -> Optional[Path]:
    """Copy a v1 vault aside before any migration touches it.

    Must be called BEFORE init_db(), which creates the v2 tables and so
    would otherwise be part of the "original" we claim to have preserved.
    Returns the backup path, or None if there was nothing to back up.
    """
    db_path = Path(db_path) if db_path is not None else paths.DB_PATH
    if not is_legacy_vault_file(db_path):
        return None
    backup = db_path.with_name(db_path.name + ".v1-backup")
    if backup.exists():
        return backup
    _create_private_file(backup)
    shutil.copy2(db_path, backup)
    with contextlib.suppress(OSError):
        os.chmod(backup, 0o600)
    return backup


def _failed_legacy_ids(conn: sqlite3.Connection) -> set:
    cur = conn.execute("SELECT value FROM vault_meta WHERE key = 'v1_failed_ids'")
    row = cur.fetchone()
    if not row or not row[0]:
        return set()
    return {int(x) for x in row[0].split(',') if x.strip().isdigit()}


def migrate_legacy_vault(conn: sqlite3.Connection, key: bytes,
                         db_path: Optional[Path] = None,
                         on_progress: Optional[Callable[[int, int], None]] = None,
                         ) -> MigrationResult:
    """Upgrade a v1 vault (plaintext metadata, Argon2 entry keys) to v2/v3.

    Safety properties:
      - `backup_legacy_vault()` must have been called first (before
        init_db) so the untouched original is preserved.
      - All re-encryption happens in a single transaction; a crash or error
        rolls back and leaves the vault exactly as it was.
      - Entries that fail to decrypt (already corrupt in v1) are left in the
        legacy table untouched and reported — never silently dropped. Their
        ids are recorded so later opens don't retry them forever.

    `on_progress(done, total)` is called at the start (0, total) and every
    20 entries; the CLI uses it for user feedback.
    """
    db_path = Path(db_path) if db_path is not None else paths.DB_PATH

    if not _table_exists(conn, 'entries'):
        return MigrationResult(0, 0, [], None)

    # Very old v1 databases may lack the url column
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute("ALTER TABLE entries ADD COLUMN url TEXT DEFAULT ''")

    already_failed = _failed_legacy_ids(conn)
    all_rows = conn.execute(
        "SELECT id, service, username, url, salt, nonce, encrypted_password, created_at "
        "FROM entries"
    ).fetchall()
    rows = [r for r in all_rows if r[0] not in already_failed]

    if not all_rows:
        conn.execute("DROP TABLE entries")
        conn.commit()
        return MigrationResult(0, 0, [], None)

    if not rows:
        # Everything left over already failed on a previous run; don't
        # re-run Argon2 over them (or VACUUM) on every open.
        return MigrationResult(0, 0, [], db_path.with_name(db_path.name + ".v1-backup"))

    backup = backup_legacy_vault(db_path)

    if on_progress:
        on_progress(0, len(rows))

    failed = []
    failed_ids = set(already_failed)
    try:
        for i, (row_id, service, username, url, salt, nonce, enc, created_at) in enumerate(
            rows, 1
        ):
            legacy_key = derive_key(base64.b64encode(key).decode(), salt)
            try:
                password = decrypt(nonce, enc, legacy_key)  # v1: no AAD
            except Exception:
                failed.append(service)
                failed_ids.add(row_id)
                continue
            save_entry(conn, key, service, username, password, url or '',
                       created_at=str(created_at or ''), commit=False)
            conn.execute("DELETE FROM entries WHERE id = ?", (row_id,))
            if on_progress and i % 20 == 0:
                on_progress(i, len(rows))
        if not failed_ids:
            conn.execute("DROP TABLE entries")
        else:
            conn.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value)"
                " VALUES ('v1_failed_ids', ?)",
                (','.join(str(i) for i in sorted(failed_ids)),)
            )
        # v1 rows are written straight into the current format
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),)
        )
        refresh_entries_mac(conn, key, commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    # Rewrite the database file so freed pages holding v1 plaintext metadata
    # are physically removed, not just marked unused.
    conn.execute("VACUUM")

    return MigrationResult(len(rows), len(rows) - len(failed), failed, backup)


# ─────────────────────────────────────────────────────────────────────────────
# Secure file shredding
# ─────────────────────────────────────────────────────────────────────────────

def _shred_file(path: Path, passes: int = 3):
    """Overwrite a file with random data, then delete it.

    Symlinks are unlinked without following, so a wipe can never scramble
    a file outside the vault directory.
    """
    try:
        if path.is_symlink():
            path.unlink()
            return
        if not path.is_file():
            return
        size = path.stat().st_size
        if size:
            # O_NOFOLLOW closes the window between the is_symlink() check
            # above and the open: with a writable parent directory the
            # target could otherwise be swapped for a link to another file.
            flags = os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
            with os.fdopen(os.open(str(path), flags), 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    remaining = size
                    while remaining:
                        chunk = min(1 << 20, remaining)
                        f.write(secrets.token_bytes(chunk))
                        remaining -= chunk
                    f.flush()
                    os.fsync(f.fileno())
                f.seek(0)
                f.truncate()
                f.flush()
                os.fsync(f.fileno())
        # Hide the original filename as well
        tmp = path.with_name(secrets.token_hex(8))
        try:
            path.rename(tmp)
            tmp.unlink()
        except OSError:
            path.unlink()
    except OSError:
        with contextlib.suppress(OSError):
            path.unlink()
