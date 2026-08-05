"""Password generation. Pure functions — no I/O.

Interactive entropy collection (keyboard mashing) lives in the CLI layer;
this module only turns entropy into passwords.
"""

import hashlib
import secrets
import string

GEN_DEFAULT_LENGTH = 20
GEN_CHARSET = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
GEN_TARGET_USER_BITS = 128  # claimed user entropy target for --mix


def generate_password(length: int = GEN_DEFAULT_LENGTH) -> str:
    """Generate a password from the OS CSPRNG (secrets)."""
    return ''.join(secrets.choice(GEN_CHARSET) for _ in range(length))


def _password_from_pool(pool: bytes, length: int) -> str:
    """Derive a password from an entropy pool via rejection sampling.

    Expands the pool with SHA-512 counters and rejects bytes >= the largest
    multiple of the charset size, so every symbol is exactly equally likely
    (no modulo bias).
    """
    limit = 256 - (256 % len(GEN_CHARSET))
    out: list[str] = []
    counter = 0
    while len(out) < length:
        block = hashlib.sha512(pool + counter.to_bytes(4, 'big')).digest()
        counter += 1
        for b in block:
            if len(out) == length:
                break
            if b < limit:
                out.append(GEN_CHARSET[b % len(GEN_CHARSET)])
    return ''.join(out)


def mix_pool(user_entropy: bytes) -> bytes:
    """Build a mixed entropy pool: OS CSPRNG material + user-supplied bytes.

    User input AUGMENTS the OS entropy, never replaces it — the output is
    unpredictable if either source is good.
    """
    return hashlib.sha512(secrets.token_bytes(64) + user_entropy).digest()
