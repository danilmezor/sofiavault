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

Since 0.4.0 the store is a complete *credential* store for humans:
Argon2id passwords, TOTP with an atomic replay guard, single-use recovery
codes, one-time password-reset tokens, typed role/admin/active flags, and a
legacy-verifier path that migrates bcrypt-style hashes on first login. What
stays the caller's job: sessions/JWT, rate limiting, lockout — policy, not
credentials.

TOTP seeds, recovery-code tags and reset-token tags are only ever stored
under `fields_key`; a store created without one can hold password-only users
and nothing else.
"""

import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import totp as _totp
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
AUTH_SCHEMA_VERSION = 2

#: Columns added by schema v2, in ALTER order. Module-level so a test can
#: inject a failure mid-migration and prove the transaction rolls back.
_V2_COLUMNS = (
    ("role", "TEXT NOT NULL DEFAULT ''"),
    ("is_admin", "INTEGER NOT NULL DEFAULT 0"),
    ("totp_enc", "BLOB"),
    ("totp_counter", "INTEGER NOT NULL DEFAULT -1"),
    ("totp_confirmed", "INTEGER NOT NULL DEFAULT 0"),
    ("recovery_enc", "BLOB"),
    ("legacy_hash", "TEXT"),
    ("password_changed_at", "TEXT NOT NULL DEFAULT ''"),
)

_ROW_COLUMNS = (
    'username', 'salt', 'verify_hash', 'time_cost', 'memory_cost', 'parallelism',
    'fields', 'fields_enc', 'is_active', 'created_at', 'updated_at',
) + tuple(name for name, _ in _V2_COLUMNS)

#: Recovery codes: 10 symbols from a 32-symbol alphabet (50 bits). 0/O and
#: 1/I are excluded as visually ambiguous; input is case-folded so `l` reads
#: as L and hyphens/spaces are ignored.
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_CODE_LENGTH = 10
_MFA_KEY_REQUIRED = (
    "fields_key required for MFA/reset tokens; this store was created without one "
    "— create a new store with a key and import-sqlite from this one"
)

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
#:
#: The ceilings are also the blast radius of a tampered row, not just its own
#: cost: _dummy_costs() prices every unknown-user probe at the most expensive
#: row in the store, so one row at the maximum makes *every* login attempt pay
#: it. time_cost and parallelism have no interactive-auth reason to reach the
#: old 32/64 — a value that high is tampering, not tuning — so they are held to
#: values that still clear any sane operator config (defaults are 3/4) while
#: keeping the amplified worst case bounded. memory stays at 1 GiB, a defensible
#: high-security ceiling.
_MAX_TIME_COST = 12
_MAX_MEMORY_COST = 1 << 20  # KiB, i.e. 1 GiB
_MAX_PARALLELISM = 16

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
    """What a successful verify() tells the application.

    `totp` is "off", "pending" or "active": an app that gates on MFA should
    demand a code only when it is "active" (a pending enrolment was never
    confirmed by the user and must not lock them out).
    """
    username: str
    fields: dict = field(default_factory=dict)
    role: str = ''
    is_admin: bool = False
    is_active: bool = True
    totp: str = "off"
    password_changed_at: str = ''


LegacyVerifier = Callable[[str, str], bool]


class LegacyBcryptSha256Pepper:
    """`bcrypt(base64(sha256(password + pepper)))` — the pre-hash-then-bcrypt
    scheme some apps use to dodge bcrypt's 72-byte limit. Needs the
    `sofiavault[legacy-bcrypt]` extra.
    """

    scheme = "bcrypt-sha256-pepper"

    def __init__(self, pepper: str = ""):
        if not isinstance(pepper, str):
            raise AuthStoreError("pepper must be a string")
        self._pepper = pepper

    def __call__(self, password: str, payload: str) -> bool:
        try:
            import bcrypt
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise AuthStoreError(
                "legacy bcrypt verification needs the 'bcrypt' package "
                "(pip install 'sofiavault[legacy-bcrypt]')"
            ) from exc
        digest = hashlib.sha256((password + self._pepper).encode('utf-8')).digest()
        try:
            return bcrypt.checkpw(base64.b64encode(digest), payload.encode('ascii'))
        except (ValueError, UnicodeEncodeError):
            return False


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
                 fields_key: Optional[bytes] = None,
                 legacy_verifiers: Optional[dict] = None):
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
        self._legacy: dict = {}
        for scheme, verifier in (legacy_verifiers or {}).items():
            if not isinstance(scheme, str) or not scheme or '$' in scheme:
                raise AuthStoreError(f"invalid legacy scheme name: {scheme!r}")
            if not callable(verifier):
                raise AuthStoreError(f"legacy verifier for {scheme!r} is not callable")
            self._legacy[scheme] = verifier
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
        v2_defs = ",\n".join(f"                {n} {d}" for n, d in _V2_COLUMNS)
        self._conn.execute(f"""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                verify_hash BLOB NOT NULL,
                time_cost INTEGER NOT NULL,
                memory_cost INTEGER NOT NULL,
                parallelism INTEGER NOT NULL,
                fields TEXT NOT NULL DEFAULT '{{}}',
                fields_enc BLOB,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
{v2_defs}
            )
        """)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        # Migrate before anything else writes: a failed migration must leave
        # a v1 file byte-identical, and a read-only v1 file must surface as
        # the typed "needs write access to migrate" error, not a raw sqlite
        # error from an unrelated CREATE TABLE.
        self._migrate_v1_to_v2()
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                username TEXT PRIMARY KEY,
                tag BLOB NOT NULL,
                expires_at REAL NOT NULL,
                issued_at REAL NOT NULL
            )
        """)
        self._conn.execute(
            "INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('schema_version', ?)",
            (str(AUTH_SCHEMA_VERSION),)
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

    def _schema_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM auth_meta WHERE key = 'schema_version'").fetchone()
        try:
            return int(row[0]) if row else 1
        except (TypeError, ValueError) as exc:
            raise AuthStoreError(f"auth_meta.schema_version is malformed: {row[0]!r}") from exc

    def _migrate_v1_to_v2(self):
        """Add the v2 columns to a 0.3.0 store, atomically.

        Every ALTER, the timestamp backfill and the version stamp run in one
        explicit transaction (Python's sqlite3 does not open one for DDL on
        its own), so a failure part-way leaves a v1 store that still opens.
        """
        if not self._conn.execute(
                "SELECT COUNT(*) FROM auth_meta WHERE key = 'schema_version'").fetchone()[0]:
            return  # brand-new store: created at v2 above, stamped below
        if self._schema_version() >= AUTH_SCHEMA_VERSION:
            return
        have = {r[1] for r in self._conn.execute("PRAGMA table_info(users)")}
        try:
            if self._conn.in_transaction:
                self._conn.commit()
            self._conn.execute("BEGIN")
            for name, definition in _V2_COLUMNS:
                if name not in have:
                    self._conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
            self._conn.execute(
                "UPDATE users SET password_changed_at = updated_at "
                "WHERE password_changed_at = ''")
            self._conn.execute(
                "INSERT OR REPLACE INTO auth_meta (key, value) VALUES ('schema_version', ?)",
                (str(AUTH_SCHEMA_VERSION),))
            self._conn.commit()
        except sqlite3.OperationalError as exc:
            with contextlib.suppress(sqlite3.Error):
                self._conn.rollback()
            if 'readonly' in str(exc).lower() or 'read-only' in str(exc).lower():
                raise AuthStoreError(
                    f"{self.path} is a schema v1 user store on a read-only file; "
                    "it needs write access once to migrate to v2"
                ) from exc
            raise AuthStoreError(f"schema v1→v2 migration failed: {exc}") from exc
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                self._conn.rollback()
            raise

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

    @staticmethod
    def _mfa_aad(username: str, label: bytes) -> bytes:
        """AAD for TOTP seeds / recovery tags: a distinct label per slot so a
        seed blob cannot be transplanted into the fields slot or vice versa."""
        return AUTH_CONTEXT + b"|" + username.encode('utf-8') + b"|" + label

    def _require_fields_key(self) -> bytes:
        if self._fields_key is None:
            raise AuthStoreError(_MFA_KEY_REQUIRED)
        return self._fields_key

    def _seal(self, payload: bytes, username: str, label: bytes) -> bytes:
        key = self._require_fields_key()
        nonce = secrets.token_bytes(NONCE_SIZE)
        return nonce + AESGCM(key).encrypt(nonce, payload, self._mfa_aad(username, label))

    def _unseal(self, blob, username: str, label: bytes) -> bytes:
        key = self._require_fields_key()
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < _MIN_FIELDS_ENC:
            raise AuthStoreError(
                f"{label.decode()} material for {username!r} is truncated")
        blob = bytes(blob)
        try:
            return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:],
                                       self._mfa_aad(username, label))
        except InvalidTag as exc:
            raise FieldsTampered(
                f"{label.decode()} material for {username!r} failed authentication"
            ) from exc

    def _tag(self, value: str) -> bytes:
        """Keyed tag for recovery codes and reset tokens: useless without the key."""
        return hmac.new(self._require_fields_key(), value.encode('utf-8'),
                        hashlib.sha256).digest()

    def _encode_fields(self, fields: dict, username: str) -> tuple[str, Optional[bytes]]:
        if self._fields_encrypted and self._fields_key is None:
            raise AuthStoreError(
                "this store encrypts profile fields; construct UserStore with fields_key"
            )
        try:
            payload = json.dumps(fields, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            # A caller handing add_user/update_fields a set, bytes, or other
            # non-JSON value should get the store's typed error, not a raw
            # TypeError from deep inside the encoder.
            raise AuthStoreError(
                f"profile fields are not JSON-serializable: {exc}"
            ) from exc
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

    def _create_user(self, username: str, password: Optional[str], fields: dict, *,
                     role: str = '', is_admin: bool = False, is_active: bool = True,
                     legacy_hash: Optional[str] = None) -> bool:
        username = normalize_username(username)
        if legacy_hash is None:
            _require_password(password)
        if not isinstance(role, str):
            raise AuthStoreError("role must be a string")
        with self._lock:
            if self._row(username) is not None:
                return False
            salt = secrets.token_bytes(SALT_SIZE)
            if legacy_hash is None:
                verify_hash = self._hash(password, salt)
            else:
                # Placeholder that can never match: the legacy verifier is the
                # only way in until the first successful login rewrites it.
                verify_hash = secrets.token_bytes(KEY_SIZE)
            fields_text, fields_enc = self._encode_fields(fields, username)
            now = _utcnow()
            try:
                self._conn.execute(
                    "INSERT INTO users (username, salt, verify_hash, time_cost, memory_cost,"
                    " parallelism, fields, fields_enc, is_active, created_at, updated_at,"
                    " role, is_admin, legacy_hash, password_changed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (username, salt, verify_hash, ARGON2_TIME_COST, ARGON2_MEMORY_COST,
                     ARGON2_PARALLELISM, fields_text, fields_enc, 1 if is_active else 0,
                     now, now, role, 1 if is_admin else 0, legacy_hash, now)
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
                                                      ARGON2_PARALLELISM),
                                 changed=True)
            return True

    def _write_password(self, username: str, password: str,
                        costs: tuple[int, int, int], *, changed: bool = False,
                        commit: bool = True):
        """Re-salt and re-hash an existing row at the given cost parameters.

        `changed=True` means the *password* is new (set_password, reset):
        it stamps password_changed_at. A rehash-on-verify or a legacy
        upgrade keeps the old stamp — the user did not change anything.
        Both paths clear legacy_hash: once an Argon2 row exists the legacy
        verifier must never be consulted again.
        """
        time_cost, memory_cost, parallelism = costs
        salt = secrets.token_bytes(SALT_SIZE)
        verify_hash = self._hash(password, salt, time_cost, memory_cost, parallelism)
        now = _utcnow()
        self._conn.execute(
            "UPDATE users SET salt = ?, verify_hash = ?, time_cost = ?,"
            " memory_cost = ?, parallelism = ?, updated_at = ?, legacy_hash = NULL"
            + (", password_changed_at = ?" if changed else "")
            + " WHERE username = ?",
            (salt, verify_hash, time_cost, memory_cost, parallelism, now)
            + ((now,) if changed else ()) + (username,)
        )
        if commit:
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

    def set_role(self, username: str, role: str) -> bool:
        """Set the plaintext role label (queryable; not a secret)."""
        if not isinstance(role, str):
            raise AuthStoreError("role must be a string")
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET role = ?, updated_at = ? WHERE username = ?",
                (role, _utcnow(), username))
            self._conn.commit()
            return cur.rowcount > 0

    def set_admin(self, username: str, is_admin: bool) -> bool:
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET is_admin = ?, updated_at = ? WHERE username = ?",
                (1 if is_admin else 0, _utcnow(), username))
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
                'role': row['role'] if isinstance(row['role'], str) else '',
                'is_admin': _is_truthy_active(row['is_admin']),
                'totp': _totp_status(row),
                'legacy': row['legacy_hash'] is not None,
                'password_changed_at': row['password_changed_at'],
            }

    def list_users(self, include_inactive: bool = True, *, role: Optional[str] = None,
                   admin_only: bool = False) -> list[str]:
        """Usernames, optionally filtered by typed flags (no field decryption)."""
        sql = "SELECT username FROM users"
        where, params = [], []
        if not include_inactive:
            where.append("is_active = 1")
        if role is not None:
            where.append("role = ?")
            params.append(role)
        if admin_only:
            where.append("is_admin = 1")
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._lock:
            return [r[0] for r in self._conn.execute(sql + " ORDER BY username", params)]

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

            if row['legacy_hash'] is not None:
                return self._verify_legacy(row, password)

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

            return self._result(row)

    def _result(self, row: dict) -> AuthResult:
        return AuthResult(
            username=row['username'],
            fields=self._decode_fields(row['fields'], row['fields_enc'],
                                       row['username']),
            role=row['role'] if isinstance(row['role'], str) else '',
            is_admin=_is_truthy_active(row['is_admin']),
            is_active=_is_truthy_active(row['is_active']),
            totp=_totp_status(row),
            password_changed_at=row['password_changed_at'] or '',
        )

    def _verify_legacy(self, row: dict, password: str) -> Optional[AuthResult]:
        """A row imported with its old hash: run the pluggable verifier once.

        On success the password is re-stored as Argon2id and legacy_hash is
        cleared, so the legacy scheme is consulted at most once per user.
        The Argon2 decoy is burned as well so the path pays at least the
        ceiling; the legacy scheme's own cost comes on top, which is why
        SECURITY.md documents legacy rows as timing-distinguishable until
        their first successful login.
        """
        scheme, sep, payload = str(row['legacy_hash']).partition('$')
        verifier = self._legacy.get(scheme) if sep else None
        if verifier is None:
            # Never a silent None: the operator configured an import for a
            # scheme this process cannot verify, and every login for that
            # user would otherwise look like a wrong password.
            self._burn_dummy_hash(password)
            raise AuthStoreError(
                f"no legacy verifier registered for scheme {scheme!r} "
                f"(user {row['username']!r}); pass legacy_verifiers= to UserStore"
            )
        self._burn_dummy_hash(password)
        if not verifier(password, payload):
            return None
        self._write_password(row['username'], password,
                             (ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM))
        return self._result(self._row(row['username']))

    # ── TOTP ─────────────────────────────────────────────────────────────

    def totp_enroll(self, username: str) -> str:
        """Issue a new TOTP secret, stored *pending* until totp_confirm().

        Returns the base32 secret for the user to save (build the QR with
        sofiavault.totp.provisioning_uri). Replaces any earlier enrolment.
        """
        username = normalize_username(username)
        self._require_fields_key()
        secret = _totp.generate_secret()
        with self._lock:
            if self._row(username) is None:
                raise AuthStoreError(f"unknown user {username!r}")
            self._conn.execute(
                "UPDATE users SET totp_enc = ?, totp_counter = -1, totp_confirmed = 0,"
                " recovery_enc = NULL, updated_at = ? WHERE username = ?",
                (self._seal(secret.encode('ascii'), username, b"totp"), _utcnow(),
                 username))
            self._conn.commit()
        return secret

    def totp_confirm(self, username: str, code: str, *, now: Optional[float] = None) -> bool:
        """Activate a pending enrolment with its first valid code."""
        return self._totp_check(username, code, now, confirm=True)

    def totp_verify(self, username: str, code: str, *, now: Optional[float] = None) -> bool:
        """Check a code against an *active* enrolment, atomically bumping the
        replay counter: a time-step is accepted once, ever, per user."""
        return self._totp_check(username, code, now, confirm=False)

    def _totp_check(self, username: str, code: str, now: Optional[float],
                    confirm: bool) -> bool:
        try:
            username = normalize_username(username)
        except InvalidUsername:
            return False
        self._require_fields_key()
        t = time.time() if now is None else now
        with self._lock:
            # BEGIN IMMEDIATE takes the write lock before the counter is read,
            # so two processes submitting the same code serialize here and
            # the second sees the bumped counter.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(username)
                if row is None or row['totp_enc'] is None:
                    return False
                confirmed = _is_truthy_active(row['totp_confirmed'])
                if confirm == confirmed:
                    return False   # confirm needs pending; verify needs active
                secret = self._unseal(row['totp_enc'], username, b"totp").decode('ascii')
                try:
                    last = int(row['totp_counter'])
                except (TypeError, ValueError) as exc:
                    raise AuthStoreError("stored totp_counter is not an integer") from exc
                accepted = _totp.verify(secret, code, t, last_counter=last)
                if accepted is None:
                    return False
                self._conn.execute(
                    "UPDATE users SET totp_counter = ?, totp_confirmed = 1, updated_at = ?"
                    " WHERE username = ? AND totp_counter = ?",
                    (accepted, _utcnow(), username, last))
                return True
            finally:
                # commit on success, rollback otherwise — a refused code must
                # not leave the write lock held
                self._conn.commit()

    def totp_disable(self, username: str) -> bool:
        """Remove the seed, the replay counter and any recovery codes."""
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET totp_enc = NULL, totp_counter = -1, totp_confirmed = 0,"
                " recovery_enc = NULL, updated_at = ? WHERE username = ?",
                (_utcnow(), username))
            self._conn.commit()
            return cur.rowcount > 0

    def totp_status(self, username: str) -> str:
        """"off", "pending" or "active"."""
        username = normalize_username(username)
        with self._lock:
            row = self._row(username)
        if row is None:
            raise AuthStoreError(f"unknown user {username!r}")
        return _totp_status(row)

    # ── Recovery codes ───────────────────────────────────────────────────

    def recovery_generate(self, username: str, count: int = 8) -> list:
        """Mint `count` single-use codes (xxxxx-xxxxx); replaces any old set.

        Only keyed HMAC tags are stored, so the codes are shown once, here.
        """
        username = normalize_username(username)
        if not 1 <= int(count) <= 64:
            raise AuthStoreError("count must be between 1 and 64")
        self._require_fields_key()
        codes = []
        for _ in range(int(count)):
            raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH))
            codes.append(raw[:5] + "-" + raw[5:])
        tags = [self._tag(_normalize_recovery_code(c)).hex() for c in codes]
        with self._lock:
            if self._row(username) is None:
                raise AuthStoreError(f"unknown user {username!r}")
            self._conn.execute(
                "UPDATE users SET recovery_enc = ?, updated_at = ? WHERE username = ?",
                (self._seal(json.dumps(tags).encode('ascii'), username, b"recovery"),
                 _utcnow(), username))
            self._conn.commit()
        return codes

    def _recovery_tags(self, row: dict, username: str) -> list:
        if row['recovery_enc'] is None:
            return []
        try:
            tags = json.loads(self._unseal(row['recovery_enc'], username, b"recovery"))
        except ValueError as exc:
            raise AuthStoreError(f"recovery codes for {username!r} are malformed") from exc
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise AuthStoreError(f"recovery codes for {username!r} are malformed")
        return tags

    def recovery_use(self, username: str, code: str) -> bool:
        """Consume a recovery code. True exactly once per code."""
        try:
            username = normalize_username(username)
        except InvalidUsername:
            return False
        if not isinstance(code, str):
            return False
        self._require_fields_key()
        tag = self._tag(_normalize_recovery_code(code)).hex()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(username)
                if row is None:
                    return False
                tags = self._recovery_tags(row, username)
                # Compare against every tag so timing does not leak the index.
                matched = [i for i, t in enumerate(tags)
                           if hmac.compare_digest(t.encode(), tag.encode())]
                if not matched:
                    return False
                del tags[matched[0]]
                self._conn.execute(
                    "UPDATE users SET recovery_enc = ?, updated_at = ? WHERE username = ?",
                    (self._seal(json.dumps(tags).encode('ascii'), username, b"recovery"),
                     _utcnow(), username))
                return True
            finally:
                self._conn.commit()

    def recovery_remaining(self, username: str) -> int:
        username = normalize_username(username)
        with self._lock:
            row = self._row(username)
            if row is None:
                raise AuthStoreError(f"unknown user {username!r}")
            if row['recovery_enc'] is None:
                return 0
            return len(self._recovery_tags(row, username))

    # ── Password-reset tokens ────────────────────────────────────────────

    def reset_token_issue(self, username: str, ttl_seconds: int = 3600) -> str:
        """A one-time, URL-safe 256-bit token; only its keyed tag is stored.

        Issuing does not change the password. One live token per user: a
        new one replaces the old.
        """
        username = normalize_username(username)
        if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise AuthStoreError("ttl_seconds must be positive")
        self._require_fields_key()
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            if self._row(username) is None:
                raise AuthStoreError(f"unknown user {username!r}")
            self._conn.execute(
                "INSERT OR REPLACE INTO reset_tokens (username, tag, expires_at, issued_at)"
                " VALUES (?, ?, ?, ?)",
                (username, self._tag(token), now + float(ttl_seconds), now))
            self._conn.commit()
        return token

    def reset_token_redeem(self, token: str, new_password: str) -> Optional[str]:
        """Set a new password if `token` is live. Returns the username, else None.

        The token is consumed either way once found; an expired one is
        removed. Clears legacy_hash and stamps password_changed_at. The app
        decides what to do with the user's sessions.
        """
        if not isinstance(token, str) or not token:
            return None
        _require_password(new_password)
        self._require_fields_key()
        tag = self._tag(token)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT username, tag, expires_at FROM reset_tokens").fetchall()
                hit = None
                for username, stored, expires_at in row:
                    if isinstance(stored, (bytes, bytearray)) and \
                            hmac.compare_digest(bytes(stored), tag):
                        hit = (username, expires_at)
                if hit is None:
                    return None
                username, expires_at = hit
                self._conn.execute("DELETE FROM reset_tokens WHERE username = ?", (username,))
                if not isinstance(expires_at, (int, float)) or time.time() > expires_at:
                    return None
                if self._row(username) is None:
                    return None
                self._write_password(username, new_password,
                                     (ARGON2_TIME_COST, ARGON2_MEMORY_COST,
                                      ARGON2_PARALLELISM), changed=True, commit=False)
                return username
            finally:
                self._conn.commit()

    def reset_token_revoke(self, username: str) -> bool:
        username = normalize_username(username)
        with self._lock:
            cur = self._conn.execute("DELETE FROM reset_tokens WHERE username = ?", (username,))
            self._conn.commit()
            return cur.rowcount > 0

    # ── Legacy-store import ──────────────────────────────────────────────

    def import_sqlite(self, path: Union[str, Path], table: str, *, scheme: str,
                      columns: Optional[dict] = None) -> tuple[list[str], list[str]]:
        """Copy users and their *existing* hashes from another SQLite table.

        `columns` maps our names to the source's: username, password_hash,
        and optionally role, is_admin, is_active (defaults: the same names;
        missing optional columns are ignored). Each user is stored with
        `legacy_hash = "<scheme>$<hash>"` and a placeholder Argon2 row; the
        first successful verify() through the matching legacy verifier
        rewrites them as Argon2id. Existing users are skipped. Returns
        (created, skipped).
        """
        if not isinstance(scheme, str) or not scheme or '$' in scheme:
            raise AuthStoreError(f"invalid legacy scheme name: {scheme!r}")
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', table):
            raise AuthStoreError(f"invalid table name: {table!r}")
        cols = {"username": "username", "password_hash": "password_hash",
                "role": "role", "is_admin": "is_admin", "is_active": "is_active"}
        cols.update(columns or {})
        for ours, theirs in cols.items():
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', str(theirs)):
                raise AuthStoreError(f"invalid column name for {ours}: {theirs!r}")
        src = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
        try:
            have = {r[1] for r in src.execute(f"PRAGMA table_info({table})")}
            if not have:
                raise AuthStoreError(f"no table {table!r} in {path}")
            for required in ("username", "password_hash"):
                if cols[required] not in have:
                    raise AuthStoreError(
                        f"{table} has no column {cols[required]!r} (for {required})")
            optional = [k for k in ("role", "is_admin", "is_active") if cols[k] in have]
            select = ", ".join([cols["username"], cols["password_hash"]]
                               + [cols[k] for k in optional])
            rows = src.execute(f"SELECT {select} FROM {table}").fetchall()
        finally:
            src.close()
        created, skipped = [], []
        for row in rows:
            raw_name, raw_hash = row[0], row[1]
            extra = dict(zip(optional, row[2:]))
            label = raw_name if isinstance(raw_name, str) else repr(raw_name)
            if not isinstance(raw_name, str) or not isinstance(raw_hash, str) or not raw_hash:
                skipped.append(f"{label} (missing username or hash)")
                continue
            try:
                username = normalize_username(raw_name)
            except InvalidUsername as exc:
                skipped.append(f"{label} ({exc})")
                continue
            role = extra.get("role")
            ok = self._create_user(
                username, None, {},
                role=role if isinstance(role, str) else '',
                is_admin=_truthy(extra.get("is_admin", 0)),
                is_active=_truthy(extra.get("is_active", 1)),
                legacy_hash=f"{scheme}${raw_hash}")
            if ok:
                created.append(username)
            else:
                skipped.append(f"{username} (already exists)")
        return created, skipped

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
            "SELECT " + ", ".join(_ROW_COLUMNS) + " FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip(_ROW_COLUMNS, row))


def _totp_status(row: dict) -> str:
    if row['totp_enc'] is None:
        return "off"
    return "active" if _is_truthy_active(row['totp_confirmed']) else "pending"


def _normalize_recovery_code(code: str) -> str:
    return code.strip().replace("-", "").replace(" ", "").upper()


def _truthy(value) -> bool:
    """Lenient reading of a *source* store's flag column during import."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "t")
    return bool(value)


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
