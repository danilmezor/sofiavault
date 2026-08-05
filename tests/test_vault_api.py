"""Tests for the Vault library API (sofiavault.vault)."""

import base64
import secrets
import tempfile
from pathlib import Path

import pytest

from sofiavault import KEY_SIZE
from sofiavault.vault import (
    EntryNotFound,
    Vault,
    VaultAlreadyInitialized,
    VaultLocked,
    VaultNotInitialized,
    WrongPassword,
)

PW = "library-test-pw"


def _tmp_vault_path() -> Path:
    return Path(tempfile.mkdtemp()) / "secrets.db"


def _make_vault() -> tuple[Vault, Path]:
    path = _tmp_vault_path()
    v = Vault.create(path, PW)
    return v, path


def test_create_set_get_roundtrip():
    v, path = _make_vault()
    v.set("telegram-bot", "tok-123", username="bot", url="https://t.me")
    assert v.get("telegram-bot") == "tok-123"

    entry = v.get_entry("telegram-bot")
    assert entry.service == "telegram-bot"
    assert entry.username == "bot"
    assert entry.url == "https://t.me"
    assert entry.password == "tok-123"
    assert entry.created_at
    v.close()
    path.unlink()


def test_open_with_password_and_wrong_password():
    v, path = _make_vault()
    v.set("api", "secret")
    v.close()

    with Vault.open(path, password=PW) as v2:
        assert v2.get("api") == "secret"

    with pytest.raises(WrongPassword):
        Vault.open(path, password="nope")
    path.unlink()


def test_export_key_and_open_with_key():
    v, path = _make_vault()
    v.set("api", "secret")
    key_b64 = v.export_key()
    v.close()

    key = base64.b64decode(key_b64)
    assert len(key) == KEY_SIZE
    with Vault.open(path, key=key) as v2:
        assert v2.get("api") == "secret"

    with pytest.raises(WrongPassword):
        Vault.open(path, key=secrets.token_bytes(KEY_SIZE))
    path.unlink()


def test_open_argument_validation():
    v, path = _make_vault()
    v.close()
    with pytest.raises(ValueError):
        Vault.open(path)  # neither
    with pytest.raises(ValueError):
        Vault.open(path, password=PW, key=b"x" * KEY_SIZE)  # both
    path.unlink()


def test_set_updates_existing_preserving_created_at():
    v, path = _make_vault()
    v.set("db", "one", username="u1")
    created = v.get_entry("db").created_at
    row_id = v.get_entry("db").id

    v.set("db", "two", username="u2")
    entry = v.get_entry("db")
    assert entry.password == "two"
    assert entry.username == "u2"
    assert entry.id == row_id            # updated in place
    assert entry.created_at == created   # preserved
    assert len(v.list_entries()) == 1
    v.close()
    path.unlink()


def test_delete_and_entry_not_found():
    v, path = _make_vault()
    v.set("gone", "x")
    v.delete("gone")
    with pytest.raises(EntryNotFound):
        v.get("gone")
    with pytest.raises(EntryNotFound):
        v.delete("gone")
    v.close()
    path.unlink()


def test_search_fuzzy():
    v, path = _make_vault()
    v.set("amazon", "a")
    v.set("google", "g")
    results = v.search("amazn")
    assert results and results[0][0].service == "amazon"
    v.close()
    path.unlink()


def test_closed_vault_raises_locked():
    v, path = _make_vault()
    v.close()
    with pytest.raises(VaultLocked):
        v.get("anything")
    with pytest.raises(VaultLocked):
        v.export_key()
    path.unlink()


def test_create_twice_and_open_missing():
    v, path = _make_vault()
    v.close()
    with pytest.raises(VaultAlreadyInitialized):
        Vault.create(path, PW)
    with pytest.raises(VaultNotInitialized):
        Vault.open(Path(tempfile.mkdtemp()) / "absent.db", password=PW)
    path.unlink()


# ── open_auto chain ──────────────────────────────────────────────────────────

def test_open_auto_key_env():
    v, path = _make_vault()
    v.set("s", "v")
    key_b64 = v.export_key()
    v.close()

    v2 = Vault.open_auto(path, environ={"SOFIAVAULT_KEY": key_b64})
    assert v2.get("s") == "v"
    v2.close()
    path.unlink()


def test_open_auto_password_env():
    v, path = _make_vault()
    v.close()
    v2 = Vault.open_auto(path, environ={"SOFIAVAULT_PASSWORD": PW})
    v2.close()
    path.unlink()


def test_open_auto_key_file():
    v, path = _make_vault()
    key_b64 = v.export_key()
    v.close()

    key_file = path.with_name("sv.key")
    key_file.write_text(key_b64 + "\n")
    import os
    os.chmod(key_file, 0o600)   # a group/world-readable key file is refused
    v2 = Vault.open_auto(path, environ={"SOFIAVAULT_KEY_FILE": str(key_file)})
    v2.close()
    key_file.unlink()
    path.unlink()


def test_open_auto_precedence_key_beats_password():
    v, path = _make_vault()
    key_b64 = v.export_key()
    v.close()
    # A wrong password later in the chain must not matter
    v2 = Vault.open_auto(path, environ={
        "SOFIAVAULT_KEY": key_b64,
        "SOFIAVAULT_PASSWORD": "wrong",
    })
    v2.close()
    path.unlink()


def test_open_auto_exhausted_raises_locked_never_prompts():
    v, path = _make_vault()
    v.close()
    with pytest.raises(VaultLocked):
        Vault.open_auto(path, environ={})
    path.unlink()


def test_open_auto_bad_key_material():
    v, path = _make_vault()
    v.close()
    with pytest.raises(VaultLocked):
        Vault.open_auto(path, environ={"SOFIAVAULT_KEY": "not-base64!!"})
    with pytest.raises(VaultLocked):
        Vault.open_auto(path, environ={"SOFIAVAULT_KEY": base64.b64encode(b"short").decode()})
    with pytest.raises(VaultLocked):
        Vault.open_auto(path, environ={"SOFIAVAULT_KEY_FILE": "/nonexistent/key"})
    path.unlink()


# ── Library silence guarantee ────────────────────────────────────────────────

def test_library_operations_are_silent(capsys):
    """Core/storage/vault must never print — the CLI owns all output."""
    v, path = _make_vault()
    v.set("quiet", "shh", username="nobody")
    v.get("quiet")
    v.get_entry("quiet")
    v.list_entries()
    v.search("quiet")
    v.delete("quiet")
    v.export_key()
    v.close()
    with pytest.raises(VaultLocked):
        Vault.open_auto(path, environ={})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    path.unlink()
