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
from .storage import (
    MigrationResult,
    VaultEntry,
    _load_entry_payload,
    backup_legacy_vault,
    delete_entry,
    fuzzy_find_service,
    get_entry_by_service,
    get_master_data,
    init_db,
    is_vault_initialized,
    load_entries,
    migrate_legacy_vault,
    migrate_v2_to_v3,
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
                 migration: Optional[MigrationResult] = None):
        self._conn = conn
        self._key: Optional[bytes] = key
        self.path = path
        self.migration = migration
        self._entries: list[VaultEntry] = []
        self.corrupt_count = 0
        self.tampered = False
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
        combined_salt, verify_hash, key = _create_master_record(password)
        save_master(conn, combined_salt, verify_hash, key)
        return cls(conn, key, path)

    @classmethod
    def open(cls, path: Union[str, Path], password: Optional[str] = None,
             key: Optional[bytes] = None) -> "Vault":
        """Unlock an existing vault with an explicit password or raw key."""
        if (password is None) == (key is None):
            raise ValueError("provide exactly one of password= or key=")
        path = Path(path)
        if not path.exists():
            raise VaultNotInitialized(f"no vault at {path}")
        if key is not None and not isinstance(key, (bytes, bytearray)):
            raise WrongPassword("key must be bytes")

        # Preserve a genuinely untouched copy before init_db() writes.
        backup_legacy_vault(path)
        conn = init_db(path, check_same_thread=False)
        if not is_vault_initialized(conn):
            conn.close()
            raise VaultNotInitialized(f"vault has no master password: {path}")

        try:
            combined_salt, stored_hash = get_master_data(conn)
            if password is not None:
                master_key = verify_master_password(password, combined_salt, stored_hash)
                if master_key is None:
                    raise WrongPassword("wrong master password")
            else:
                if len(key) != KEY_SIZE:
                    raise WrongPassword(f"key must be {KEY_SIZE} bytes")
                if not verify_master_key(key, combined_salt, stored_hash):
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
            migration = migrate_legacy_vault(conn, master_key, path)
            migrate_v2_to_v3(conn, master_key)
            return cls(conn, master_key, path, migration=migration)
        except VaultError:
            conn.close()
            raise
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
            if self.tampered:
                raise VaultCorrupted(
                    "the set of entries does not match its authentication tag — "
                    "a secret may have been rolled back, added, or removed"
                )
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
        """Add or update an entry. Returns its row id."""
        with self._lock:
            self._require_unlocked()
            existing = get_entry_by_service(self._entries, service)
            if existing is None:
                row_id = save_entry(self._conn, self._key, service, username,
                                    password, url)
            else:
                payload = _load_entry_payload(self._conn, self._key, existing.id) or {}
                update_entry(self._conn, self._key, existing.id, service, username,
                             url, password, payload.get('created_at', ''))
                row_id = existing.id
            self._reload()
            return row_id

    def delete(self, service: str):
        """Delete an entry. Raises EntryNotFound if absent."""
        with self._lock:
            self._require_unlocked()
            meta = get_entry_by_service(self._entries, service)
            if meta is None:
                raise EntryNotFound(service)
            delete_entry(self._conn, meta.id, self._key)
            self._reload()

    def list_entries(self) -> list[VaultEntry]:
        """Decrypted metadata (service, username, url) — no passwords."""
        with self._lock:
            self._require_unlocked()
            return list(self._entries)

    def search(self, query: str, threshold: int = 60) -> list[tuple[VaultEntry, int]]:
        """Fuzzy-match services. Returns (entry, score) pairs, best first."""
        with self._lock:
            self._require_unlocked()
            return fuzzy_find_service(self._entries, query, threshold)

    # ── Key management / lifecycle ───────────────────────────────────────

    def export_key(self) -> str:
        """Base64 master key, for provisioning SOFIAVAULT_KEY.

        Handle with the same care as the master password.
        """
        with self._lock:
            self._require_unlocked()
            return base64.b64encode(self._key).decode('ascii')

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
        self._entries, self.corrupt_count = load_entries(self._conn, self._key)
        # Detects whole-blob rollback, row insertion, and row deletion —
        # none of which per-entry authentication can see on its own.
        self.tampered = not verify_entries_mac(self._conn, self._key)

    def _require_unlocked(self):
        if self._key is None:
            raise VaultLocked("vault is closed")


def _decode_key(value: str, source: str) -> bytes:
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultLocked(f"{source} is not valid base64") from exc
    if len(key) != KEY_SIZE:
        raise VaultLocked(f"{source} must decode to {KEY_SIZE} bytes")
    return key
