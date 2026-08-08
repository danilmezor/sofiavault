"""Verify-only user credential store.

For applications that authenticate their own users (managers, admins,
operators). The store holds Argon2id verifiers — it can never produce a
plaintext password, and needs no master key to verify.

    from sofiavault.auth import UserStore

    store = UserStore("/srv/app/users.db")
    store.add_user("alice", "hunter2", access_level=3)
    result = store.verify("alice", submitted)   # AuthResult or None

Never use the retrievable Vault for end-user credentials — a breached
server must yield slow hashes, not decryptable passwords.

Out of scope by design (the caller's job): sessions/JWT, TOTP, rate
limiting, lockout. This module only answers "is this password correct,
and who is this user".
"""

import contextlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    derive_key,
)

AUTH_CONTEXT = b"sofiavault-auth-v1"

#: Characters that must never appear in a username: C0/C1 controls, NUL,
#: bidi/zero-width marks, and other format characters. They enable log
#: forging, C-string truncation, and visually identical shadow accounts.
#: Zl/Zp are the Unicode line/paragraph separators (U+2028/U+2029): not
#: control or format characters, but str.splitlines(), JSON-in-JS, and many
#: log viewers treat them as newlines, so they smuggle exactly the log-forged
#: second record that rejecting '\n' (a Cc control) is meant to prevent.
_FORBIDDEN_CATEGORIES = {'Cc', 'Cf', 'Co', 'Cs', 'Cn', 'Zl', 'Zp'}

#: How much longer than `max_length` a raw username may be before it is
#: rejected unnormalized. NFKC can expand (U+FDFA alone becomes 18 characters)
#: so some slack is required, but only some — see normalize_username.
_RAW_LENGTH_FACTOR = 8

#: Bounds for cost parameters read back out of the database. SQLite is
#: dynamically typed and the file is only as trustworthy as its permissions:
#: a single UPDATE setting memory_cost to 1 TiB turns every verify() into an
#: out-of-memory kill, and a value below the floor is a cracking discount.
_MAX_TIME_COST = 32
_MAX_MEMORY_COST = 1 << 20  # KiB, i.e. 1 GiB
_MAX_PARALLELISM = 64

#: Shortest possible fields_enc blob: nonce + GCM tag. Anything shorter is
#: truncated, and slicing it would reach AESGCM with a stub nonce, which
#: reports "Nonce must be between 8 and 128 bytes" — a raw ValueError out of
#: an authentication call that has already succeeded.
_MIN_FIELDS_ENC = NONCE_SIZE + 16

#: Stand-in secret used when the submitted password cannot be UTF-8 encoded,
#: so the decoy hash still runs and an unencodable password is not itself a
#: timing tell for "this user does not exist".
_DECOY_PASSWORD = "sofiavault-unencodable-decoy"


class AuthStoreError(Exception):
    """UserStore configuration or data error."""


class InvalidUsername(AuthStoreError):
    """The username is empty, too long, or contains unsafe characters."""


class FieldsTampered(AuthStoreError, InvalidTag):
    """Encrypted profile fields failed authentication.

    Also an InvalidTag so callers that already catch cryptographic tampering
    keep working, and an AuthStoreError so callers that guard the store's own
    API surface do not have to import cryptography.
    """


def normalize_username(username: str, *, max_length: int = 128) -> str:
    """Canonicalize and validate a username.

    NFKC-normalizes and casefolds so `Admin`, `ADMIN`, and the fullwidth
    `ａdmin` all resolve to one account instead of silently becoming
    separate rows that an application comparing loosely would confuse.
    Rejects control/format characters outright.
    """
    if not isinstance(username, str):
        raise InvalidUsername("username must be a string")
    # Length is checked on the raw input first: NFKC + strip on a 40M-character
    # username costs seconds of CPU and hundreds of megabytes before any limit
    # could reject it, and callers hold the store lock while they wait.
    if len(username) > max_length * _RAW_LENGTH_FACTOR:
        raise InvalidUsername(f"username exceeds {max_length} characters")
    candidate = unicodedata.normalize('NFKC', username).strip()
    if not candidate:
        raise InvalidUsername("username must not be empty")
    if len(candidate) > max_length:
        raise InvalidUsername(f"username exceeds {max_length} characters")
    for ch in candidate:
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise InvalidUsername(
                f"username contains a control or format character "
                f"(U+{ord(ch):04X})"
            )
    if re.search(r'\s\s', candidate):
        raise InvalidUsername("username contains repeated whitespace")
    folded = candidate.casefold()
    # Casefolding expands (ﬄ → ffl, ẞ → ss), so a name that passed the check
    # above can still land in the primary key at up to three times the limit.
    if len(folded) > max_length:
        raise InvalidUsername(f"username exceeds {max_length} characters")
    return folded


@dataclass
class AuthResult:
    """Successful verification: who authenticated and their profile fields."""
    username: str
    fields: dict


class UserStore:
    """SQLite-backed Argon2id credential verifier.

    - Per-user salt; cost parameters stored per row so they can be raised
      later; verify() transparently rehashes when a row is weaker than the
      current defaults, and never when it is stronger.
    - Unknown/inactive usernames burn a dummy Argon2 pass so response
      timing does not reveal which usernames exist.
    - `pepper` is optional and has NO default — a missing pepper means
      "no pepper", never a known constant.
    - Profile fields are arbitrary JSON per user; pass `fields_key`
      (32 bytes, e.g. from a Vault entry) to encrypt them at rest. Whether
      a store encrypts fields is a store-level policy, not a per-row one.
    """

    def __init__(self, path: Union[str, Path], pepper: Optional[str] = None,
                 fields_key: Optional[bytes] = None):
        # `pepper or ""` accepted b"pep" and 0 and turned them into "no
        # pepper" or a TypeError at the first hash — either way the operator
        # believed the store was peppered when it was not.
        if pepper is not None and not isinstance(pepper, str):
            raise AuthStoreError("pepper must be a string or None")
        if fields_key is not None and (
                not isinstance(fields_key, (bytes, bytearray))
                or len(fields_key) != KEY_SIZE):
            raise AuthStoreError(f"fields_key must be {KEY_SIZE} bytes")
        self.path = Path(path)
        self._pepper = pepper if pepper is not None else ""
        self._fields_key = bytes(fields_key) if fields_key is not None else None
        self._fields_encrypted = self._fields_key is not None
        self._dummy_cost_cache: Optional[tuple[int, int, int]] = None
        self._dummy_cost_version: Optional[int] = None
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create at 0600 before sqlite opens it: a file created under the
        # umask is briefly world-readable, and an fd opened in that window
        # survives a later chmod.
        if not self.path.exists():
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except OSError:
                pass
        # Serializes access so one store can back a threaded server.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        # Anything that fails from here on must not leave the connection (and
        # its fd on a file we just refused to trust) open behind the exception.
        try:
            self._conn.execute("PRAGMA secure_delete = ON")
            self._init_schema()
            try:
                os.chmod(self.path, 0o600)
            except OSError as exc:
                if os.name == 'posix':
                    raise AuthStoreError(
                        f"cannot restrict permissions on {self.path}: {exc}"
                    ) from exc
        except BaseException:
            self.close()
            raise

    def _init_schema(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                verify_hash BLOB NOT NULL,
                time_cost INTEGER NOT NULL,
                memory_cost INTEGER NOT NULL,
                parallelism INTEGER NOT NULL,
                fields TEXT NOT NULL DEFAULT '{}',
                fields_enc BLOB,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('schema_version', '1')"
        )
        # A per-store random salt for the anti-enumeration dummy hash, so
        # unknown-user verification cost matches real verification cost.
        cur = self._conn.execute("SELECT value FROM auth_meta WHERE key = 'dummy_salt'")
        row = cur.fetchone()
        if row is None:
            self._dummy_salt = secrets.token_bytes(SALT_SIZE)
            self._conn.execute(
                "INSERT INTO auth_meta (key, value) VALUES ('dummy_salt', ?)",
                (self._dummy_salt.hex(),)
            )
        else:
            self._dummy_salt = bytes.fromhex(row[0])
        self._init_fields_policy()
        self._conn.commit()

    def _init_fields_policy(self):
        """Decide, once per store, whether profile fields must be encrypted.

        `fields_enc IS NULL` is not a policy. Without a store-level record,
        anyone with write access to the database could null the ciphertext,
        drop `{"role": "admin"}` into the unauthenticated `fields` column,
        keep their own password, and log in with a profile they were never
        issued — never needing fields_key at all. A constructor that was
        given the key is the stronger authority (a tampered meta row cannot
        talk it out of enforcing), so the two are OR-ed.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('fields_encrypted', ?)",
            ('1' if self._fields_key is not None else '0',)
        )
        row = self._conn.execute(
            "SELECT value FROM auth_meta WHERE key = 'fields_encrypted'"
        ).fetchone()
        stored = row is not None and row[0] == '1'
        self._fields_encrypted = stored or self._fields_key is not None
        if self._fields_key is not None and not stored:
            raise AuthStoreError(
                "this store was created without fields_key and its existing profile "
                "fields are plaintext; create a new store to encrypt fields"
            )

    def _dummy_costs(self) -> tuple[int, int, int]:
        """Cost parameters for the unknown-user decoy hash.

        Priced at the most expensive parameters any real row uses, floored at
        the current defaults. The cheapest row is exactly the wrong choice:
        an attacker probing one username is timed against *that* row, so a
        decoy priced at the store minimum makes a single legacy cheap row
        enough to separate "exists" from "does not exist" in one probe.
        Over-paying only costs the attacker time; under-paying is the oracle.
        This ceiling is also what verify() levels cheap rows up to, so that
        "fast" cannot come to mean "exists, with a legacy row" instead.

        Cached because this is on the unknown-user path — the one an attacker
        drives — and invalidated by every write that can change the cost mix.

        Our own writes clear the cache directly; `PRAGMA data_version` catches
        everybody else's. Invalidating on our own writes alone is not enough:
        each gunicorn/uwsgi worker holds its own UserStore, so a cost raised
        by one worker would leave every other worker priced at a stale, lower
        ceiling — which is exactly the "fast means does-not-exist" oracle this
        ceiling exists to close.
        """
        version = self._conn.execute("PRAGMA data_version").fetchone()[0]
        if self._dummy_cost_cache is None or self._dummy_cost_version != version:
            t, m, p = ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM
            cur = self._conn.execute(
                "SELECT DISTINCT time_cost, memory_cost, parallelism FROM users"
            )
            for row in cur:
                try:
                    rt, rm, rp = _validated_costs(*row)
                except AuthStoreError:
                    # A tampered row must not get to price the decoy: that is
                    # how a 1 TiB memory_cost would become a store-wide DoS.
                    continue
                t, m, p = max(t, rt), max(m, rm), max(p, rp)
            self._dummy_cost_cache = (t, m, p)
            self._dummy_cost_version = version
        return self._dummy_cost_cache

    # ── Hashing ──────────────────────────────────────────────────────────

    def _secret(self, password: str) -> str:
        return password + self._pepper

    def _hash(self, password: str, salt: bytes,
              time_cost: int = ARGON2_TIME_COST,
              memory_cost: int = ARGON2_MEMORY_COST,
              parallelism: int = ARGON2_PARALLELISM) -> bytes:
        return derive_key(self._secret(password), salt, time_cost=time_cost,
                          memory_cost=memory_cost, parallelism=parallelism)

    def _burn_dummy_hash(self, password: str):
        """Matched-cost decoy for unknown/inactive users (anti-enumeration)."""
        if not _utf8_encodable(password):
            password = _DECOY_PASSWORD
        t, m, p = self._dummy_costs()
        self._hash(password, self._dummy_salt, t, m, p)

    # ── Field encryption ─────────────────────────────────────────────────

    @staticmethod
    def _fields_aad(username: str) -> bytes:
        """Bind an encrypted field blob to the row that owns it.

        With a constant AAD, any user's blob decrypts in any user's row —
        so someone with only DB write access could paste the admin's
        profile onto their own account, keep their own password, and log in
        with elevated fields while nothing looks amiss.
        """
        return AUTH_CONTEXT + b"|" + username.encode('utf-8')

    def _encode_fields(self, fields: dict, username: str) -> tuple[str, Optional[bytes]]:
        if self._fields_encrypted and self._fields_key is None:
            raise AuthStoreError(
                "this store encrypts profile fields; construct UserStore with fields_key"
            )
        payload = json.dumps(fields, ensure_ascii=False)
        if self._fields_key is None:
            return payload, None
        nonce = secrets.token_bytes(NONCE_SIZE)
        ct = AESGCM(self._fields_key).encrypt(nonce, payload.encode('utf-8'),
                                              self._fields_aad(username))
        return '{}', nonce + ct

    def _decode_fields(self, fields_text: str, fields_enc: Optional[bytes],
                       username: str) -> dict:
        if self._fields_encrypted:
            # The policy, not the row, decides. A row presenting plaintext in
            # an encrypting store is a downgrade attempt, not a legacy row —
            # including the empty-looking fields_enc=NULL, fields='{}'.
            if fields_enc is None:
                raise AuthStoreError(
                    f"profile fields for {username!r} are unencrypted in a store "
                    "that requires encrypted fields"
                )
            if self._fields_key is None:
                raise AuthStoreError(
                    "profile fields are encrypted; construct UserStore with fields_key"
                )
            if not isinstance(fields_enc, (bytes, bytearray)) or len(fields_enc) < _MIN_FIELDS_ENC:
                raise AuthStoreError(
                    f"encrypted profile fields for {username!r} are truncated"
                )
            fields_enc = bytes(fields_enc)
            try:
                payload = AESGCM(self._fields_key).decrypt(
                    fields_enc[:NONCE_SIZE], fields_enc[NONCE_SIZE:],
                    self._fields_aad(username)
                )
            except InvalidTag as exc:
                raise FieldsTampered(
                    f"profile fields for {username!r} failed authentication"
                ) from exc
            try:
                text = payload.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise AuthStoreError(
                    f"profile fields for {username!r} are not valid UTF-8"
                ) from exc
        else:
            if fields_enc is not None:
                raise AuthStoreError(
                    f"profile fields for {username!r} are encrypted; construct "
                    "UserStore with fields_key"
                )
            text = fields_text or '{}'
        try:
            decoded = json.loads(text)
        except (ValueError, TypeError) as exc:
            # Raised after the password already matched, so an unwrapped
            # JSONDecodeError surfaces as a 500 on a successful login.
            raise AuthStoreError(
                f"profile fields for {username!r} are not valid JSON"
            ) from exc
        if not isinstance(decoded, dict):
            # AuthResult.fields is documented as a mapping; a str would turn a
            # caller's `'admin' in result.fields` into a substring test that
            # any value containing "admin" passes.
            raise AuthStoreError(
                f"profile fields for {username!r} are {type(decoded).__name__}, "
                "not a JSON object"
            )
        return decoded

    # ── CRUD ─────────────────────────────────────────────────────────────

    def add_user(self, username: str, password: str, /, **fields) -> bool:
        """Create a user. Returns False if the username already exists.

        `username`/`password` are positional-only so that a profile field may
        be named "username", "password" or "self" without colliding with this
        signature and aborting an import with a TypeError.
        """
        return self._create_user(username, password, fields)

    def _create_user(self, username: str, password: str, fields: dict) -> bool:
        username = normalize_username(username)
        _require_password(password)
        with self._lock:
            if self._row(username) is not None:
                return False
            salt = secrets.token_bytes(SALT_SIZE)
            verify_hash = self._hash(password, salt)
            fields_text, fields_enc = self._encode_fields(fields, username)
            now = _utcnow()
            try:
                self._conn.execute(
                    "INSERT INTO users (username, salt, verify_hash, time_cost, memory_cost,"
                    " parallelism, fields, fields_enc, is_active, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (username, salt, verify_hash, ARGON2_TIME_COST, ARGON2_MEMORY_COST,
                     ARGON2_PARALLELISM, fields_text, fields_enc, now, now)
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                # Another writer took the name between the check and the
                # insert. "Already exists" is the answer, not a stack trace.
                with contextlib.suppress(sqlite3.Error):
                    self._conn.rollback()
                return False
            self._dummy_cost_cache = None
            return True

    def set_password(self, username: str, password: str) -> bool:
        """Rotate a user's password. Returns False if the user is unknown."""
        _require_password(password)
        username = normalize_username(username)
        with self._lock:
            if self._row(username) is None:
                return False
            self._write_password(username, password, (ARGON2_TIME_COST,
                                                      ARGON2_MEMORY_COST,
                                                      ARGON2_PARALLELISM))
            return True

    def _write_password(self, username: str, password: str,
                        costs: tuple[int, int, int]):
        """Re-salt and re-hash an existing row at the given cost parameters."""
        time_cost, memory_cost, parallelism = costs
        salt = secrets.token_bytes(SALT_SIZE)
        verify_hash = self._hash(password, salt, time_cost, memory_cost, parallelism)
        self._conn.execute(
            "UPDATE users SET salt = ?, verify_hash = ?, time_cost = ?,"
            " memory_cost = ?, parallelism = ?, updated_at = ? WHERE username = ?",
            (salt, verify_hash, time_cost, memory_cost, parallelism,
             _utcnow(), username)
        )
        self._conn.commit()
        self._dummy_cost_cache = None

    def update_fields(self, username: str, /, **fields) -> bool:
        """Replace a user's profile fields. Returns False if unknown."""
        username = normalize_username(username)
        with self._lock:
            if self._row(username) is None:
                return False
            fields_text, fields_enc = self._encode_fields(fields, username)
            self._conn.execute(
                "UPDATE users SET fields = ?, fields_enc = ?, updated_at = ?"
                " WHERE username = ?",
                (fields_text, fields_enc, _utcnow(), username)
            )
            self._conn.commit()
            return True

    def set_active(self, username: str, active: bool) -> bool:
        """Activate/deactivate (soft-delete) a user."""
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET is_active = ?, updated_at = ? WHERE username = ?",
                (1 if active else 0, _utcnow(), username)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def deactivate(self, username: str) -> bool:
        return self.set_active(username, False)

    def activate(self, username: str) -> bool:
        return self.set_active(username, True)

    def remove_user(self, username: str) -> bool:
        """Hard-delete a user row (secure_delete zeroes the freed pages)."""
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM users WHERE username = ?", (username,)
            )
            self._conn.commit()
            self._dummy_cost_cache = None
            return cur.rowcount > 0

    def get_user(self, username: str) -> Optional[dict]:
        """Profile view (no hash material): fields + is_active + timestamps."""
        try:
            username = normalize_username(username)
        except InvalidUsername:
            return None
        with self._lock:
            row = self._row(username)
            if row is None:
                return None
            return {
                'username': row['username'],
                'fields': self._decode_fields(row['fields'], row['fields_enc'],
                                              row['username']),
                'is_active': bool(row['is_active']),
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
            }

    def list_users(self, include_inactive: bool = True) -> list[str]:
        sql = "SELECT username FROM users"
        if not include_inactive:
            sql += " WHERE is_active = 1"
        with self._lock:
            return [r[0] for r in self._conn.execute(sql + " ORDER BY username")]

    # ── Verification ─────────────────────────────────────────────────────

    def verify(self, username: str, password: str) -> Optional[AuthResult]:
        """The single question this store answers.

        Returns AuthResult(username, fields) on success; None for wrong
        password, unknown username, deactivated user, or malformed input —
        with a dummy hash burned in the unknown/inactive cases so timing
        stays flat. Never raises for bad input: a handler passing
        JSON-decoded values should get a clean auth failure, not a 500.
        (A tampered *database* is not input: that still raises
        AuthStoreError, because silently authenticating past it is worse.)
        """
        if not isinstance(password, str) or not password:
            return None
        # A lone surrogate — trivially delivered by json.loads('"\\ud800"') —
        # cannot be UTF-8 encoded, and Argon2 would raise UnicodeEncodeError
        # from inside the derivation, including on the unknown-user path.
        encodable = _utf8_encodable(password)
        # Normalized before the lock: NFKC on a hostile 40M-character username
        # must not stall every other thread's verify() behind it.
        try:
            name: Optional[str] = normalize_username(username)
        except InvalidUsername:
            name = None
        with self._lock:
            if name is None or not encodable:
                self._burn_dummy_hash(password)
                return None
            row = self._row(name)
            if row is None or not _is_truthy_active(row['is_active']):
                self._burn_dummy_hash(password)
                return None

            costs = _validated_costs(row['time_cost'], row['memory_cost'],
                                     row['parallelism'])
            salt = _validated_blob(row['salt'], 'salt', SALT_SIZE)
            stored_hash = _validated_blob(row['verify_hash'], 'verify_hash',
                                          KEY_SIZE)
            computed = self._hash(password, salt, *costs)
            # Pricing only the decoy at the ceiling does not close the
            # enumeration oracle, it inverts it: a user whose row is still at
            # legacy costs answers in 2ms where an unknown user costs 34ms, so
            # "fast" becomes the tell. Top the cheap row's work back up to the
            # ceiling. Before the comparison, so the wrong-password and
            # correct-password paths both pay it — padding only the failures
            # would be an oracle of its own.
            pad = _padding_costs(costs, self._dummy_costs())
            if pad is not None:
                self._hash(password, self._dummy_salt, *pad)
            if not hmac.compare_digest(computed, stored_hash):
                return None

            # Rehash only upward. Comparing `!=` to the defaults *lowered*
            # parameters an operator had deliberately raised — one successful
            # login silently took t=6/m=128MiB back down to the library
            # defaults — so each parameter moves to the stronger of the two.
            target = (max(costs[0], ARGON2_TIME_COST),
                      max(costs[1], ARGON2_MEMORY_COST),
                      max(costs[2], ARGON2_PARALLELISM))
            if target != costs:
                self._write_password(row['username'], password, target)

            return AuthResult(
                username=row['username'],
                fields=self._decode_fields(row['fields'], row['fields_enc'],
                                           row['username']),
            )

    # ── Bulk import ──────────────────────────────────────────────────────

    def import_json(self, path: Union[str, Path]) -> tuple[list[str], list[str]]:
        """One-shot ingest of a legacy plaintext credentials file.

        Accepts a JSON array of objects with `username` (or `name`) and
        `password`; all other keys become profile fields. Existing users
        are skipped. Returns (created, skipped).

        The source file held plaintext passwords — after importing, delete
        it, purge it from version control history, and rotate every
        imported password.
        """
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise AuthStoreError("expected a JSON array of user objects")
        created = []
        skipped = []
        for entry in data:
            if not isinstance(entry, dict):
                skipped.append("<malformed entry>")
                continue
            raw_name = entry.get('username') or entry.get('name') or ''
            password = entry.get('password')

            if not isinstance(raw_name, str):
                # str() used to turn objects, arrays and booleans into account
                # names via repr — the import created users called "{'a': 1}"
                # and "true". A non-string name is corrupt data, not a user.
                skipped.append(f"<non-string username ({type(raw_name).__name__})>")
                continue
            label = raw_name.strip() or '<missing username>'

            if not isinstance(password, str) or not password:
                # Coercing 12345 -> "12345" would "succeed" while locking
                # the user out, because it isn't what the old system stored.
                reason = ("missing password" if password in (None, '', False)
                          else f"non-string password ({type(password).__name__})")
                skipped.append(f"{label} ({reason})")
                continue
            try:
                username = normalize_username(raw_name)
            except InvalidUsername as exc:
                skipped.append(f"{label} ({exc})")
                continue

            fields = {k: v for k, v in entry.items()
                      if k not in ('username', 'name', 'password')}
            try:
                # Fields travel as one dict, never as **kwargs: a legacy
                # record with a field named "self" or "username" used to raise
                # TypeError and abort the import halfway through, uncommitted
                # rows already written and no rollback.
                ok = self._create_user(username, password, fields)
            except AuthStoreError as exc:
                skipped.append(f"{label} ({exc})")
                continue
            if ok:
                created.append(username)
            else:
                skipped.append(f"{username} (already exists)")
        return created, skipped

    # ── Lifecycle / internals ────────────────────────────────────────────

    def close(self):
        with contextlib.suppress(Exception):
            self._conn.close()

    def __enter__(self) -> "UserStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _row(self, username: str) -> Optional[dict]:
        cur = self._conn.execute(
            "SELECT username, salt, verify_hash, time_cost, memory_cost,"
            " parallelism, fields, fields_enc, is_active, created_at, updated_at"
            " FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        keys = ('username', 'salt', 'verify_hash', 'time_cost', 'memory_cost',
                'parallelism', 'fields', 'fields_enc', 'is_active',
                'created_at', 'updated_at')
        return dict(zip(keys, row))


def _utf8_encodable(value: str) -> bool:
    """Whether Argon2 can accept this secret at all.

    Surrogates survive json.loads but not .encode('utf-8'), and the store's
    contract is that bad input produces a denial, never an exception.
    """
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _require_password(password) -> None:
    """Validate a password the caller is asking the store to *write*.

    Writers get a typed error where verify() gets a silent denial: an
    operator setting an unstorable password must hear about it.
    """
    if not isinstance(password, str) or not password:
        raise AuthStoreError("password must be a non-empty string")
    if not _utf8_encodable(password):
        raise AuthStoreError("password is not UTF-8 encodable (lone surrogate)")


def _validated_costs(time_cost, memory_cost, parallelism) -> tuple[int, int, int]:
    """Bounds-check cost parameters read back out of a row.

    SQLite stores whatever it is handed, so these are attacker-controlled the
    moment the file is writable: memory_cost = 1 TiB hangs or OOM-kills every
    verify() for that user, and a floor-less value is a free cracking
    discount. Reject rather than clamp — a row this wrong is not a row to
    authenticate against.
    """
    try:
        t, m, p = int(time_cost), int(memory_cost), int(parallelism)
    except (TypeError, ValueError) as exc:
        raise AuthStoreError("stored cost parameters are not integers") from exc
    if not 1 <= p <= _MAX_PARALLELISM:
        raise AuthStoreError(f"stored parallelism {p} is out of range")
    if not 1 <= t <= _MAX_TIME_COST:
        raise AuthStoreError(f"stored time_cost {t} is out of range")
    if not 8 * p <= m <= _MAX_MEMORY_COST:
        raise AuthStoreError(f"stored memory_cost {m} is out of range")
    return t, m, p


def _validated_blob(value, column: str, size: int) -> bytes:
    """Type/length-check a binary column read back out of a row.

    SQLite's dynamic typing means `salt` can come back as TEXT or an INTEGER
    once the file is writable, and Argon2 then raises TypeError/HashingError
    straight past verify()'s "a tampered database raises AuthStoreError"
    contract — a caller guarding `except AuthStoreError` gets an unhandled
    500 instead of a clean failure.
    """
    if not isinstance(value, (bytes, bytearray)):
        raise AuthStoreError(
            f"stored {column} is {type(value).__name__}, not bytes"
        )
    if len(value) != size:
        raise AuthStoreError(
            f"stored {column} is {len(value)} bytes, expected {size}"
        )
    return bytes(value)


def _padding_costs(costs: tuple[int, int, int],
                   ceiling: tuple[int, int, int]) -> Optional[tuple[int, int, int]]:
    """Extra Argon2 work that levels a below-ceiling row up to the ceiling.

    Argon2id's cost is essentially `time_cost` passes over `memory_cost`
    bytes. Spending the deficit as whole *passes* at the ceiling's memory —
    the obvious reading — can only land on multiples of `ceil_m`: a legacy
    row 2.875 passes short rounds up to 3, so it pays its own hash on top of
    a full ceiling hash and answers a measurable ~6% slower than an unknown
    user. That is a stable, non-overlapping tell for "this account exists on
    a legacy row", and it never expires, because the upward rehash only fires
    on a *successful* login and an attacker probes with wrong passwords.

    `memory_cost` is granular to the KiB, so the same budget is spent as
    `ceil_t` passes over whatever memory that works out to, and the total
    lands within noise of the ceiling. Returns None when the row already
    pays ceiling cost — the common case, and no wasted work.
    """
    ceil_t, ceil_m, ceil_p = ceiling
    deficit = ceil_t * ceil_m - costs[0] * costs[1]
    if deficit <= 0:
        return None
    memory = deficit // ceil_t
    # Argon2 requires at least 8 KiB per lane; a deficit below that is
    # already too small to be worth a second hash.
    if memory < 8 * ceil_p:
        return None
    return (ceil_t, min(memory, _MAX_MEMORY_COST), ceil_p)


def _is_truthy_active(value) -> bool:
    """Strict reading of the is_active column.

    SQLite has dynamic typing, so a tampered row can hold the *string*
    'no', which Python considers truthy — reviving a revoked account.
    Only the integer 1 (or True) counts as active.
    """
    return value is True or (isinstance(value, int) and value == 1)


def _utcnow() -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
