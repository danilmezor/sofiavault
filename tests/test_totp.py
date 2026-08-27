"""D-8 (pure part): RFC 6238 vectors and verify() semantics for sofiavault.totp."""

import base64
import hmac
from unittest import mock

import pytest

from sofiavault import totp

# RFC 6238 Appendix B. The reference secret is the ASCII string
# "12345678901234567890" (repeated to 32/64 bytes for SHA256/SHA512).
_SEED = b"12345678901234567890"
_SECRETS = {
    "SHA1": base64.b32encode(_SEED).decode(),
    "SHA256": base64.b32encode((_SEED * 2)[:32]).decode(),
    "SHA512": base64.b32encode((_SEED * 4)[:64]).decode(),
}
_VECTORS = [  # (time, SHA1, SHA256, SHA512) — 8-digit codes
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("t,sha1,sha256,sha512", _VECTORS)
def test_T_8_1_rfc6238_appendix_b_vectors(t, sha1, sha256, sha512):
    for algo, expected in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
        assert totp.code_at(_SECRETS[algo], t, digits=8, algorithm=algo) == expected
        # the default 6-digit path is the same value mod 10^6
        assert totp.code_at(_SECRETS[algo], t, algorithm=algo) == expected[-6:]


def test_T_8_2_verify_window_and_replay_counter():
    secret = totp.generate_secret()
    t = 1_700_000_000
    step = totp.time_step(t)
    for delta in (-1, 0, 1):
        code = totp.code_at(secret, t + delta * 30)
        assert totp.verify(secret, code, t, last_counter=-1) == step + delta
    for delta in (-2, 2):
        code = totp.code_at(secret, t + delta * 30)
        assert totp.verify(secret, code, t, last_counter=-1) is None
    code = totp.code_at(secret, t)
    assert totp.verify(secret, code, t, last_counter=step) is None
    assert totp.verify(secret, code, t, last_counter=step + 5) is None
    assert totp.verify(secret, code, t, last_counter=step - 1) == step
    # window=0 accepts only the current step
    assert totp.verify(secret, totp.code_at(secret, t - 30), t, window=0) is None
    # malformed codes never match and never raise
    for bad in ("", "12345", "1234567", "12345a", None, 123456, " 123 456 "):
        assert totp.verify(secret, bad, t) in (None, step)  # spaces are stripped


def test_T_8_6_verify_compares_every_candidate_in_constant_time():
    secret = totp.generate_secret()
    t = 1_700_000_000
    code = totp.code_at(secret, t)
    with mock.patch.object(totp.hmac, "compare_digest", wraps=hmac.compare_digest) as cd:
        assert totp.verify(secret, code, t, window=1) == totp.time_step(t)
        assert cd.call_count == 3          # all 2*window+1 candidates, no early exit
        cd.reset_mock()
        assert totp.verify(secret, "000000", t, window=2) is None
        assert cd.call_count == 5


def test_secret_and_uri_helpers():
    s = totp.generate_secret()
    assert len(base64.b32decode(s + "=" * (-len(s) % 8))) == 20
    uri = totp.provisioning_uri(s, "alice@example.com", "My App")
    assert uri.startswith("otpauth://totp/My%20App%3Aalice%40example.com?")
    assert f"secret={s}" in uri and "issuer=My+App" in uri and "digits=6" in uri
    assert totp.code_at(s.lower(), 59) == totp.code_at(s, 59)   # case-insensitive
    with pytest.raises(totp.TOTPError):
        totp.code_at("not base32!", 59)
    with pytest.raises(totp.TOTPError):
        totp.code_at(s, 59, algorithm="MD5")


@pytest.mark.slow
def test_totp_verify_timing_does_not_track_the_first_differing_digit():
    """Advisory statistical companion to T-8-6 (the structural test is the
    gate). Codes that differ from the right one in the first digit and in
    the last digit must take the same time to reject, within a generous
    bound: with compare_digest and no early exit there is no reason for
    any correlation at all."""
    import statistics
    import time as _time
    secret = totp.generate_secret()
    t = 1_700_000_000
    right = totp.code_at(secret, t)

    def flip(i):
        d = str((int(right[i]) + 1) % 10)
        return right[:i] + d + right[i + 1:]

    first, last = flip(0), flip(5)

    def median_ns(code, n=400):
        samples = []
        for _ in range(n):
            t0 = _time.perf_counter_ns()
            totp.verify(secret, code, t)
            samples.append(_time.perf_counter_ns() - t0)
        return statistics.median(samples)

    # interleave to share any drift
    a = b = 0
    for _ in range(5):
        a += median_ns(first)
        b += median_ns(last)
    assert abs(a - b) < 0.5 * max(a, b), (a, b)
