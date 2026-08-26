"""The Vault class — SofiaVault's library API.

Silent by contract: never prompts, never prints, never touches the network.
All failures raise typed exceptions. The CLI is a consumer of this API.
"""

import base64
import binascii
import contextlib
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from .core import KEY_SIZE, verify_master_key, verify_master_password
from .core import create_master_record as _create_master_record
from .core import create_master_record_for_key as _create_master_record_for_key
from .storage import (
    MigrationResult,
    ReadOnlyDatabase,
    VaultEntry,
    _load_entry_payload,
    _read_vault_id,
    backup_legacy_vault,
    connect_db,
    default_costs,
    delete_entry,
    entry_row_exists,
    fuzzy_find_service,
    get_entry_by_service,
    get_master_costs,
    get_master_data,
    get_schema_version,
    init_db,
    is_vault_initialized,
    load_entries,
    migrate_legacy_vault,
    migrate_v2_to_v3,
    migrate_v3_to_v4,
    rekey_vault,
    save_entry,
    save_master,
    update_entry,
    verify_entries_mac,
)


class VaultError(Exception):
    """Base class for all SofiaVault library errors."""


class VaultNotInitialized(VaultError):
    """The vault file has no master password set."""


class VaultAlreadyInitialized(VaultError):
    """Vault.create() was called on an already-initialized vault."""


class WrongPassword(VaultError):
    """The supplied password or key does not match this vault."""


class VaultLocked(VaultError):
    """open_auto() exhausted every key source. The library never prompts."""


class EntryNotFound(VaultError, KeyError):
    """No entry with that service name."""


class VaultReadOnly(VaultError):
    """The vault file (or its directory) cannot be written.

    Raised by open() on the writable path, and by every mutating method of a
    vault opened with readonly=True.
    """


class VaultCorrupted(VaultError):
    """An entry failed authenticated decryption."""


@dataclass
class Entry:
    """A fully decrypted entry, including the password."""
    id: int
    service: str
    username: str
    url: str
    password: str
    created_at: str
    updated_at: str


class Vault:
    """An unlocked SofiaVault database.

    Use the classmethods to obtain an instance:

        with Vault.open("/srv/app/secrets.db", password="...") as v:
            token = v.get("telegram-bot")

        v = Vault.open_auto("/srv/app/secrets.db")   # server boot

    One Vault per process is the intended pattern. Reads are cheap
    (HKDF + one AES-GCM per get); the decrypted metadata index is
    kept in memory while unlocked, passwords are decrypted on demand.
    """

    def __init__(self, conn: sqlite3.Connection, key: bytes, path: Path,
                 migration: Optional[MigrationResult] = None,
                 readonly: bool = False):
        self._conn = conn
        self._key: Optional[bytes] = key
        self.path = path
        self.migration = migration
        self.readonly = readonly
        self._entries: list[VaultEntry] = []
        self.corrupt_count = 0
        self.tampered = False
        self._data_version: Optional[int] = None
        # Serializes access to the connection and the decrypted index so a
        # module-level Vault can be shared by a threaded server.
        self._lock = threading.RLock()
        self._reload()

    # ── Construction ─────────────────────────────────────────────────────

    @classmethod
    def create(cls, path: Union[str, Path], password: str) -> "Vault":
        """Initialize a brand-new vault at `path` with a master password."""
        path = Path(path)
        conn = init_db(path, check_same_thread=False)
        if is_vault_initialized(conn):
            conn.close()
            raise VaultAlreadyInitialized(f"vault already initialized: {path}")
        costs = default_costs()
        combined_salt, verify_hash, key = _create_master_record(password, costs)
        save_master(conn, combined_salt, verify_hash, key, costs=costs)
        return cls(conn, key, path)

    @classmethod
    def open(cls, path: Union[str, Path], password: Optional[str] = None,
             key: Optional[bytes] = None, *, readonly: bool = False) -> "Vault":
        """Unlock an existing vault with an explicit password or raw key.

        `readonly=True` opens the file with sqlite's `mode=ro`: nothing is
        created, migrated, or re-signed, so a vault on a read-only mount (the
        natural Docker configuration) works as-is. Every mutating method then
        raises VaultReadOnly. Without it, a vault that cannot be written
        raises VaultReadOnly from here — never a raw sqlite error.
        """
        if (password is None) == (key is None):
            raise ValueError("provide exactly one of password= or key=")
        path = Path(path)
        if not path.exists():
            raise VaultNotInitialized(f"no vault at {path}")
        if key is not None and not isinstance(key, (bytes, bytearray)):
            raise WrongPassword("key must be bytes")

        if readonly:
            try:
                conn = connect_db(path, readonly=True, check_same_thread=False)
            except (FileNotFoundError, sqlite3.Error) as exc:
                raise VaultNotInitialized(f"cannot open {path}: {exc}") from exc
            try:
                if get_schema_version(conn) < 3:
                    raise VaultReadOnly(
                        f"{path} predates the tamper-evident format; open it "
                        "writable once so it can be migrated"
                    )
                if not is_vault_initialized(conn):
                    raise VaultNotInitialized(f"vault has no master password: {path}")
                _read_vault_id(conn)
            except VaultError:
                conn.close()
                raise
            except Exception as exc:
                conn.close()
                raise VaultNotInitialized(f"{path} is not a vault: {exc}") from exc
        else:
            if not os.access(path, os.W_OK) or not os.access(path.parent, os.W_OK):
                raise VaultReadOnly(
                    f"{path} is not writable; pass readonly=True to open it anyway"
                )
            # Preserve a genuinely untouched copy before init_db() writes.
            backup_legacy_vault(path)
            try:
                conn = init_db(path, check_same_thread=False)
            except ReadOnlyDatabase as exc:
                raise VaultReadOnly(str(exc)) from exc
            if not is_vault_initialized(conn):
                conn.close()
                raise VaultNotInitialized(f"vault has no master password: {path}")

        try:
            combined_salt, stored_hash = get_master_data(conn)
            costs = get_master_costs(conn)
            if password is not None:
                master_key = verify_master_password(password, combined_salt,
                                                    stored_hash, costs=costs)
                if master_key is None:
                    raise WrongPassword("wrong master password")
            else:
                if len(key) != KEY_SIZE:
                    raise WrongPassword(f"key must be {KEY_SIZE} bytes")
                if not verify_master_key(key, combined_salt, stored_hash, costs=costs):
                    raise WrongPassword("key does not match this vault")
                master_key = bytes(key)
        except VaultError:
            conn.close()
            raise
        except Exception as exc:
            # Malformed master record (truncated salt, wrong types, ...) must
            # surface as a VaultError, not a raw crypto-library exception.
            conn.close()
            raise VaultCorrupted(f"master record is unreadable: {exc}") from exc

        # Migration and the first index load read attacker-influenced metadata
        # (vault_id, schema_version, entry blobs). The contract is that every
        # failure here is a typed VaultError with the connection closed — a raw
        # library exception escaping open() would leave a live fd on a file we
        # already distrust.
        try:
            if readonly:
                return cls(conn, master_key, path, readonly=True)
            migration = migrate_legacy_vault(conn, master_key, path)
            migrate_v2_to_v3(conn, master_key)
            migrate_v3_to_v4(conn, master_key)
            return cls(conn, master_key, path, migration=migration)
        except VaultError:
            conn.close()
            raise
        except sqlite3.OperationalError as exc:
            conn.close()
            if 'readonly' in str(exc).lower():
                raise VaultReadOnly(f"{path} is read-only: {exc}") from exc
            raise VaultCorrupted(f"vault metadata is unreadable: {exc}") from exc
        except Exception as exc:
            conn.close()
            raise VaultCorrupted(f"vault metadata is unreadable: {exc}") from exc

    @classmethod
    def open_auto(cls, path: Union[str, Path],
                  environ: Optional[dict] = None) -> "Vault":
        """Non-interactive unlock. Key sources, first hit wins:

        1. SOFIAVAULT_KEY        — base64-encoded raw 32-byte master key
        2. SOFIAVAULT_PASSWORD   — master password
        3. SOFIAVAULT_KEY_FILE   — path to a file containing the base64 key
        4. OS keyring            — service "sofiavault", username = str(path),
                                   value treated as the master password
                                   (requires the optional `keyring` package)

        Raises VaultLocked when every source is exhausted — this method
        never prompts.
        """
        env = environ if environ is not None else os.environ

        raw = env.get("SOFIAVAULT_KEY")
        if raw:
            return cls.open(path, key=_decode_key(raw, "SOFIAVAULT_KEY"))

        password = env.get("SOFIAVAULT_PASSWORD")
        if password:
            return cls.open(path, password=password)

        key_file = env.get("SOFIAVAULT_KEY_FILE")
        if key_file:
            key_path = Path(key_file)
            try:
                content = key_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise VaultLocked(f"cannot read SOFIAVAULT_KEY_FILE: {exc}") from exc
            if os.name == 'posix':
                try:
                    mode = key_path.stat().st_mode
                except OSError:
                    mode = 0
                if mode & 0o077:
                    raise VaultLocked(
                        f"SOFIAVAULT_KEY_FILE {key_path} is accessible to other "
                        f"users (mode {oct(mode & 0o777)}); run "
                        f"'chmod 600 {key_path}'"
                    )
            return cls.open(path, key=_decode_key(content, "SOFIAVAULT_KEY_FILE"))

        try:
            import keyring  # optional extra
            secret = keyring.get_password("sofiavault", str(path))
        except Exception:
            secret = None
        if secret:
            return cls.open(path, password=secret)

        raise VaultLocked(
            "no key source available: set SOFIAVAULT_KEY, SOFIAVAULT_PASSWORD, "
            "or SOFIAVAULT_KEY_FILE (see docs)"
        )

    # ── Entry access ─────────────────────────────────────────────────────

    def get(self, service: str) -> str:
        """Return the secret value (password field) for a service."""
        return self.get_entry(service).password

    def get_entry(self, service: str) -> Entry:
        """Return the fully decrypted entry for a service.

        Fails closed: if any entry in this vault failed authenticated
        decryption, a missing service raises VaultCorrupted rather than
        EntryNotFound — a tampered blob must never be indistinguishable
        from "never configured" (EntryNotFound is a KeyError, and callers
        legitimately treat that as "fall back to a default").
        """
        with self._lock:
            self._require_unlocked()
            self._sync()
            self._require_untampered()
            meta = get_entry_by_service(self._entries, service)
            if meta is None:
                if self.corrupt_count:
                    raise VaultCorrupted(
                        f"'{service}' is not in the index and {self.corrupt_count} "
                        "entries failed authenticated decryption — the vault may "
                        "have been tampered with"
                    )
                raise EntryNotFound(service)
            payload = _load_entry_payload(self._conn, self._key, meta.id)
            if payload is None:
                raise VaultCorrupted(f"entry '{service}' failed authenticated decryption")
            return Entry(
                id=meta.id,
                service=payload.get('service', ''),
                username=payload.get('username', ''),
                url=payload.get('url', ''),
                password=payload.get('password', ''),
                created_at=payload.get('created_at', ''),
                updated_at=payload.get('updated_at', ''),
            )

    def set(self, service: str, password: str, username: str = '',
            url: str = '') -> int:
        """Add or update an entry. Returns its row id.

        Refuses on a tampered vault: every write re-signs the current row
        set, so writing here would launder a detected rollback, insertion,
        or deletion into a fresh valid MAC.
        """
        with self._lock:
            self._require_unlocked()
            self._require_writable()
            self._sync()
            self._require_untampered(live=True)
            existing = get_entry_by_service(self._entries, service)
            if existing is not None and not entry_row_exists(self._conn, existing.id):
                # The row went away after this index was built (another
                # writer deleted it). UPDATE-ing it would match nothing and
                # silently lose the secret the caller asked us to store.
                existing = None
            if existing is None:
                row_id = save_entry(self._conn, self._key, service, username,
                                    password, url)
            else:
                payload = _load_entry_payload(self._conn, self._key, existing.id)
                if payload is None:
                    raise VaultCorrupted(
                        f"entry '{service}' failed authenticated decryption; "
                        "refusing to overwrite it"
                    )
                update_entry(self._conn, self._key, existing.id, service, username,
                             url, password, payload.get('created_at', ''))
                row_id = existing.id
            self._reload()
            return row_id

    def delete(self, service: str):
        """Delete an entry. Raises EntryNotFound if absent.

        Refuses on a tampered vault, for the same reason as set().
        """
        with self._lock:
            self._require_unlocked()
            self._require_writable()
            self._sync()
            self._require_untampered(live=True)
            meta = get_entry_by_service(self._entries, service)
            if meta is None:
                raise EntryNotFound(service)
            delete_entry(self._conn, meta.id, self._key)
            self._reload()

    def list_entries(self) -> list[VaultEntry]:
        """Decrypted metadata (service, username, url) — no passwords."""
        with self._lock:
            self._require_unlocked()
            self._sync()
            return list(self._entries)

    def search(self, query: str, threshold: int = 60) -> list[tuple[VaultEntry, int]]:
        """Fuzzy-match services. Returns (entry, score) pairs, best first."""
        with self._lock:
            self._require_unlocked()
            self._sync()
            return fuzzy_find_service(self._entries, query, threshold)

    # ── Key management / lifecycle ───────────────────────────────────────

    def export_key(self) -> str:
        """Base64 master key, for provisioning SOFIAVAULT_KEY.

        Handle with the same care as the master password.
        """
        with self._lock:
            self._require_unlocked()
            return base64.b64encode(self._key).decode('ascii')

    def reload(self):
        """Re-read the entry index and MAC from disk.

        get/set/delete/list_entries/search already do this automatically
        when another connection has committed (one `PRAGMA data_version`
        per call); reload() forces it. A tamper detected here latches
        `tampered` exactly as at open — the flag only ever goes up.
        """
        with self._lock:
            self._require_unlocked()
            self._reload()

    def rekey(self, new_password: Optional[str] = None,
              new_key: Optional[bytes] = None) -> str:
        """Rotate the master key. Returns the new key, base64-encoded.

        Exactly one of `new_password` / `new_key` (32 raw bytes). Every entry
        is re-encrypted and the master record and MAC replaced in one
        transaction: if anything fails the file is untouched and the current
        key stays valid. Refuses on a tampered or partly corrupt vault, since
        re-signing would launder the damage.
        """
        if (new_password is None) == (new_key is None):
            raise ValueError("provide exactly one of new_password= or new_key=")
        if new_key is not None:
            if not isinstance(new_key, (bytes, bytearray)) or len(new_key) != KEY_SIZE:
                raise ValueError(f"new_key must be {KEY_SIZE} bytes")
            new_key = bytes(new_key)
        with self._lock:
            self._require_unlocked()
            self._require_writable()
            self._sync()
            self._require_untampered(live=True)
            if self.corrupt_count:
                raise VaultCorrupted(
                    f"{self.corrupt_count} entries fail authenticated decryption; "
                    "refusing to rekey a partly corrupt vault"
                )
            costs = default_costs()
            if new_password is not None:
                combined_salt, verify_hash, new_key = _create_master_record(
                    new_password, costs)
            else:
                combined_salt, verify_hash = _create_master_record_for_key(new_key, costs)
            try:
                rekey_vault(self._conn, self._key, new_key, combined_salt,
                            verify_hash, costs)
            except sqlite3.OperationalError as exc:
                if 'readonly' in str(exc).lower():
                    raise VaultReadOnly(f"{self.path} is read-only: {exc}") from exc
                raise VaultCorrupted(f"rekey failed: {exc}") from exc
            except ValueError as exc:
                raise VaultCorrupted(str(exc)) from exc
            self._key = new_key
            self._reload()
            return base64.b64encode(new_key).decode('ascii')

    def close(self):
        """Drop the key and decrypted index, close the connection."""
        with self._lock:
            self._key = None
            self._entries = []
            with contextlib.suppress(Exception):
                self._conn.close()

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Internals ────────────────────────────────────────────────────────

    def _reload(self):
        self._data_version = self._conn.execute("PRAGMA data_version").fetchone()[0]
        self._entries, self.corrupt_count = load_entries(self._conn, self._key)
        # Detects whole-blob rollback, row insertion, and row deletion —
        # none of which per-entry authentication can see on its own. Raises
        # the flag only; __init__ establishes the initial False, and nothing
        # afterwards may lower it (see _require_untampered).
        if not verify_entries_mac(self._conn, self._key):
            self.tampered = True

    def _sync(self):
        """Reload if another connection has committed since the last load.

        `PRAGMA data_version` changes only for *other* connections' commits,
        so our own writes (which already reload) never trigger a second
        decrypt pass. One cheap pragma per call is what keeps a long-lived
        Vault from serving stale misses or inserting a duplicate row.
        """
        version = self._conn.execute("PRAGMA data_version").fetchone()[0]
        if version != self._data_version:
            self._reload()

    def _require_unlocked(self):
        if self._key is None:
            raise VaultLocked("vault is closed")

    def _require_writable(self):
        if self.readonly:
            raise VaultReadOnly(f"{self.path} was opened read-only")

    def _require_untampered(self, live: bool = False):
        # Writes pass live=True: they re-sign whatever the database holds
        # *now*, so the flag cached at the last reload is not enough — a
        # file rewritten mid-session would be laundered into a valid MAC.
        # The check is one HMAC over (id, nonce) pairs; no decryption.
        # Only ever raises the flag: another writer re-signing the set does
        # not undo the edit this instance already observed.
        if live and not verify_entries_mac(self._conn, self._key):
            self.tampered = True
        if self.tampered:
            raise VaultCorrupted(
                "the set of entries does not match its authentication tag — "
                "a secret may have been rolled back, added, or removed"
            )


def _decode_key(value: str, source: str) -> bytes:
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultLocked(f"{source} is not valid base64") from exc
    if len(key) != KEY_SIZE:
        raise VaultLocked(f"{source} must decode to {KEY_SIZE} bytes")
    return key
