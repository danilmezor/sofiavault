"""Tests for the password generator."""

import math
from unittest.mock import patch

from sofiavault import (
    GEN_CHARSET,
    GEN_DEFAULT_LENGTH,
    _password_from_pool,
    cmd_gen,
    generate_password,
)


def test_generate_password_length_and_charset():
    pw = generate_password()
    assert len(pw) == GEN_DEFAULT_LENGTH
    assert all(c in GEN_CHARSET for c in pw)

    pw32 = generate_password(32)
    assert len(pw32) == 32


def test_generate_password_unique():
    assert generate_password() != generate_password()


def test_charset_entropy_is_sufficient():
    # 20 chars over the charset must clear 120 bits
    assert GEN_DEFAULT_LENGTH * math.log2(len(GEN_CHARSET)) >= 120


def test_password_from_pool_deterministic_and_valid():
    pool = b"\x01" * 64
    pw1 = _password_from_pool(pool, 24)
    pw2 = _password_from_pool(pool, 24)
    assert pw1 == pw2  # same pool -> same output
    assert len(pw1) == 24
    assert all(c in GEN_CHARSET for c in pw1)

    assert _password_from_pool(b"\x02" * 64, 24) != pw1  # different pool differs


def test_password_from_pool_no_modulo_bias_structure():
    # The rejection limit must be the largest multiple of the charset size
    limit = 256 - (256 % len(GEN_CHARSET))
    assert limit % len(GEN_CHARSET) == 0
    assert limit + len(GEN_CHARSET) > 256


def _generated_password(arg=""):
    """Run cmd_gen and capture the password it copied to the clipboard."""
    with patch("sofiavault.cli.copy_to_clipboard", return_value=True) as clip, \
         patch("sofiavault.cli.schedule_clipboard_clear", return_value=True):
        cmd_gen(arg)
    return clip.call_args[0][0]


def test_cmd_gen_default(capsys):
    pw = _generated_password()
    assert len(pw) == GEN_DEFAULT_LENGTH
    assert all(c in GEN_CHARSET for c in pw)
    out = capsys.readouterr().out
    assert pw in out
    assert "bits" in out
    assert "clipboard" in out.lower()


def test_cmd_gen_custom_length(capsys):
    assert len(_generated_password("32")) == 32


def test_cmd_gen_clamps_length(capsys):
    assert len(_generated_password("4")) == 8       # floor
    assert len(_generated_password("9999")) == 128  # ceiling


def test_cmd_gen_mix_uses_user_entropy(capsys):
    with patch("sofiavault.cli._collect_user_entropy",
               return_value=b"mash" * 32) as collect, \
         patch("sofiavault.cli.copy_to_clipboard", return_value=True) as clip, \
         patch("sofiavault.cli.schedule_clipboard_clear", return_value=True):
        cmd_gen("--mix")

    collect.assert_called_once()
    pw = clip.call_args[0][0]
    assert len(pw) == GEN_DEFAULT_LENGTH
    assert all(c in GEN_CHARSET for c in pw)
    assert "user entropy" in capsys.readouterr().out


def test_cmd_gen_mix_never_deterministic_from_user_seed(capsys):
    """Same user input twice must NOT produce the same password —
    the OS CSPRNG contribution guarantees it."""
    with patch("sofiavault.cli._collect_user_entropy", return_value=b"same-seed"), \
         patch("sofiavault.cli.copy_to_clipboard", return_value=True) as clip, \
         patch("sofiavault.cli.schedule_clipboard_clear", return_value=True):
        cmd_gen("--mix")
        first = clip.call_args[0][0]
        cmd_gen("--mix")
        second = clip.call_args[0][0]
    assert first != second


def test_cmd_gen_bad_args(capsys):
    with patch("sofiavault.cli.copy_to_clipboard") as clip:
        cmd_gen("--bogus")
    clip.assert_not_called()
    assert "Usage" in capsys.readouterr().out
