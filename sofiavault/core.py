"""SofiaVault crypto core.

Pure functions only: key derivation, encryption, master-record handling.
This module performs no I/O — no prints, no prompts, no filesystem access.
"""

import base64
import hmac
import secrets
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits for AES-256

# Domain-separation constant: HKDF info and GCM associated data for v2 entries
ENTRY_CONTEXT = b"sofiavault-entry-v2"


def derive_key(master_password: str, salt: bytes, *,
               time_cost: Optional[int] = None,
               memory_cost: Optional[int] = None,
               parallelism: Optional[int] = None) -> bytes:
    """Derive a 256-bit key from a password using Argon2id.

    The keyword parameters exist for stores that persist their cost
    settings per record (UserStore); default callers use the constants.
    """
    return hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost if time_cost is not None else ARGON2_TIME_COST,
        memory_cost=memory_cost if memory_cost is not None else ARGON2_MEMORY_COST,
        parallelism=parallelism if parallelism is not None else ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID
    )


def derive_entry_key(master_key: bytes, salt: bytes) -> bytes:
    """Derive a per-entry key from the master key using HKDF-SHA256.

    The master key already has full entropy (Argon2 output), so a fast
    KDF is the correct tool here — no need for a memory-hard pass per entry.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=ENTRY_CONTEXT,
    ).derive(master_key)


def encrypt(plaintext: str, key: bytes, aad: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)"""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: Optional[bytes] = None) -> str:
    """Decrypt ciphertext with AES-256-GCM"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode('utf-8')


# ── Master record helpers ────────────────────────────────────────────────────
#
# The master row stores `combined_salt` (= kdf_salt + verify_salt) and a
# verification hash of the derived key (never the key itself).

def create_master_record(password: str,
                         costs: Optional[tuple[int, int, int]] = None,
                         ) -> tuple[bytes, bytes, bytes]:
    """Build a new master record. Returns (combined_salt, verify_hash, key).

    `costs` = (time_cost, memory_cost, parallelism); None uses the constants.
    Callers persist whichever was used (storage.save_master) so the record
    keeps verifying after the constants change.
    """
    t, m, p = costs if costs is not None else (None, None, None)
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt, time_cost=t, memory_cost=m, parallelism=p)
    verify_salt = secrets.token_bytes(SALT_SIZE)
    verify_hash = _verify_hash(key, verify_salt, t, m, p)
    return salt + verify_salt, verify_hash, key


def create_master_record_for_key(key: bytes,
                                 costs: Optional[tuple[int, int, int]] = None,
                                 ) -> tuple[bytes, bytes]:
    """Master record for a raw key (no password). Returns (combined_salt, verify_hash).

    The KDF salt half is random and unused: any password derivation against
    it yields a key that fails verification, which is the intended answer.
    """
    t, m, p = costs if costs is not None else (None, None, None)
    salt = secrets.token_bytes(SALT_SIZE)
    verify_salt = secrets.token_bytes(SALT_SIZE)
    return salt + verify_salt, _verify_hash(key, verify_salt, t, m, p)


def _verify_hash(key: bytes, verify_salt: bytes, t, m, p) -> bytes:
    return derive_key(base64.b64encode(key).decode(), verify_salt,
                      time_cost=t, memory_cost=m, parallelism=p)


def verify_master_password(password: str, combined_salt: bytes,
                           stored_hash: bytes,
                           costs: Optional[tuple[int, int, int]] = None,
                           ) -> Optional[bytes]:
    """Derive and verify the master key. Returns None on wrong password."""
    t, m, p = costs if costs is not None else (None, None, None)
    salt = combined_salt[:SALT_SIZE]
    verify_salt = combined_salt[SALT_SIZE:]

    key = derive_key(password, salt, time_cost=t, memory_cost=m, parallelism=p)
    verify_hash = _verify_hash(key, verify_salt, t, m, p)

    if not hmac.compare_digest(verify_hash, stored_hash):
        return None
    return key


def verify_master_key(key: bytes, combined_salt: bytes, stored_hash: bytes,
                      costs: Optional[tuple[int, int, int]] = None) -> bool:
    """Check a raw master key against the stored verification hash."""
    t, m, p = costs if costs is not None else (None, None, None)
    verify_salt = combined_salt[SALT_SIZE:]
    return hmac.compare_digest(_verify_hash(key, verify_salt, t, m, p), stored_hash)
