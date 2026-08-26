"""RFC 6238 time-based one-time passwords — pure functions, no I/O.

The store (UserStore) owns persistence and the replay counter; this module
only computes and compares codes so it can be tested against the RFC's
reference vectors independently of SQLite.

    secret = generate_secret()                      # base32, 160 bits
    uri = provisioning_uri(secret, "alice", "MyApp")   # for a QR code
    code_at(secret, time.time())                    # "492039"
    verify(secret, "492039", time.time(), last_counter=-1)  # -> accepted step or None
"""

import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse
from typing import Optional

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"
SECRET_BYTES = 20  # 160 bits, RFC 4226 §4 recommendation

_ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TOTPError(ValueError):
    """Malformed secret or parameters."""


def generate_secret(nbytes: int = SECRET_BYTES) -> str:
    """A fresh random base32 secret (no padding), as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise TOTPError("secret must be a non-empty base32 string")
    cleaned = secret.strip().replace(" ", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(cleaned, casefold=True)
    except (ValueError, TypeError) as exc:
        raise TOTPError("secret is not valid base32") from exc
    if not raw:
        raise TOTPError("secret decodes to nothing")
    return raw


def provisioning_uri(secret: str, account: str, issuer: str, *,
                     digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
                     algorithm: str = DEFAULT_ALGORITHM) -> str:
    """An `otpauth://totp/...` URI for enrolment (render it as a QR code)."""
    _decode_secret(secret)
    if algorithm.upper() not in _ALGORITHMS:
        raise TOTPError(f"unsupported algorithm: {algorithm}")
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    query = urllib.parse.urlencode({
        "secret": secret.strip().replace(" ", "").upper().rstrip("="),
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": period,
    })
    return f"otpauth://totp/{label}?{query}"


def hotp(secret: str, counter: int, *, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """RFC 4226 HOTP value for one counter."""
    if not isinstance(counter, int) or counter < 0:
        raise TOTPError("counter must be a non-negative integer")
    if not 6 <= digits <= 10:
        raise TOTPError("digits must be between 6 and 10")
    try:
        digestmod = _ALGORITHMS[algorithm.upper()]
    except KeyError as exc:
        raise TOTPError(f"unsupported algorithm: {algorithm}") from exc
    mac = hmac.new(_decode_secret(secret), struct.pack(">Q", counter), digestmod).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def time_step(t: float, period: int = DEFAULT_PERIOD) -> int:
    """The counter for Unix time `t`."""
    if period <= 0:
        raise TOTPError("period must be positive")
    return int(t) // period


def code_at(secret: str, t: float, *, digits: int = DEFAULT_DIGITS,
            period: int = DEFAULT_PERIOD, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """The TOTP code valid at Unix time `t`."""
    return hotp(secret, time_step(t, period), digits=digits, algorithm=algorithm)


def verify(secret: str, code: str, t: float, *, window: int = 1,
           last_counter: int = -1, digits: int = DEFAULT_DIGITS,
           period: int = DEFAULT_PERIOD,
           algorithm: str = DEFAULT_ALGORITHM) -> Optional[int]:
    """Check `code` against steps within ±`window` of `t`.

    Returns the accepted time-step, or None. A step that is not strictly
    greater than `last_counter` is never accepted — that is the replay
    guard; the caller must persist the returned step atomically with the
    decision. Every candidate is compared in constant time and every
    candidate is always evaluated, so timing does not reveal which step
    (if any) matched.
    """
    if not isinstance(code, str):
        return None
    candidate = code.strip().replace(" ", "")
    if len(candidate) != digits or not candidate.isdigit():
        return None
    if window < 0:
        raise TOTPError("window must be non-negative")
    current = time_step(t, period)
    accepted: Optional[int] = None
    for step in range(current - window, current + window + 1):
        if step < 0:
            continue
        expected = hotp(secret, step, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(expected, candidate) and step > last_counter \
                and accepted is None:
            accepted = step
    return accepted
