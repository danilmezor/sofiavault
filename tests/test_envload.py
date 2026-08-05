"""Tests for environment injection (sofiavault.envload)."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sofiavault import envload
from sofiavault.vault import Vault, VaultLocked

PW = "envload-test-pw"


def _make_vault() -> tuple[Vault, Path]:
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    return Vault.create(path, PW), path


def test_import_env_file_parsing():
    v, path = _make_vault()
    env_file = path.with_name("app.env")
    env_file.write_text(
        "# comment line\n"
        "\n"
        "API_KEY=abc123\n"
        "QUOTED='single quoted'\n"
        "DQUOTED=\"double quoted\"\n"
        "export EXPORTED=fromexport\n"
        "EMPTY=\n"
        "NOT A VALID LINE\n"
        "MIXED_case=kept\n"
    )

    imported, skipped, rejected = envload.import_env_file(v, env_file)

    assert set(imported) == {"API_KEY", "QUOTED", "DQUOTED", "EXPORTED", "MIXED_case"}
    assert rejected == []
    assert "EMPTY" in skipped
    assert v.get("env:api_key") == "abc123"
    assert v.get("env:quoted") == "single quoted"
    assert v.get("env:dquoted") == "double quoted"
    assert v.get("env:exported") == "fromexport"
    v.close()
    path.unlink()


def test_import_env_file_skips_existing_unless_overwrite():
    v, path = _make_vault()
    env_file = path.with_name("app.env")
    env_file.write_text("TOKEN=first\n")
    envload.import_env_file(v, env_file)

    env_file.write_text("TOKEN=second\n")
    imported, skipped, _rejected = envload.import_env_file(v, env_file)
    assert imported == [] and skipped == ["TOKEN"]
    assert v.get("env:token") == "first"

    imported, _s, _r = envload.import_env_file(v, env_file, overwrite=True)
    assert imported == ["TOKEN"]
    assert v.get("env:token") == "second"
    v.close()
    path.unlink()


def test_load_injects_uppercase_and_respects_existing():
    v, path = _make_vault()
    v.set("env:api_key", "secret-1")
    v.set("env:db_pass", "secret-2")
    v.set("not-an-env-entry", "ignored")

    env = {"API_KEY": "deployment-override"}
    injected, skipped = envload.load(vault=v, environ=env)

    assert injected == ["DB_PASS"]           # API_KEY was already set — kept
    assert skipped == ["API_KEY"]            # ...and the caller is told
    assert env["API_KEY"] == "deployment-override"
    assert env["DB_PASS"] == "secret-2"
    assert "NOT-AN-ENV-ENTRY" not in env

    injected, skipped = envload.load(vault=v, environ=env, overwrite=True)
    assert injected == ["API_KEY", "DB_PASS"] and skipped == []
    assert env["API_KEY"] == "secret-1"
    v.close()
    path.unlink()


def test_load_by_path_uses_open_auto():
    v, path = _make_vault()
    v.set("env:token", "tok")
    key_b64 = v.export_key()
    v.close()

    env: dict = {}
    with patch.dict("os.environ", {"SOFIAVAULT_KEY": key_b64}):
        injected, _skipped = envload.load(path, environ=env)
    assert injected == ["TOKEN"]
    assert env["TOKEN"] == "tok"

    with patch.dict("os.environ", {}, clear=True), pytest.raises(VaultLocked):
        envload.load(path, environ={})
    path.unlink()


def test_load_requires_path_or_vault():
    with pytest.raises(ValueError):
        envload.load()


def test_list_env_entries():
    v, path = _make_vault()
    v.set("env:beta", "2")
    v.set("env:alpha", "1")
    v.set("plain", "x")
    assert envload.list_env_entries(v) == ["ALPHA", "BETA"]
    v.close()
    path.unlink()


def test_exec_with_env_injects_then_execs():
    v, path = _make_vault()
    v.set("env:injected_var", "present")

    called = {}

    def fake_execv(prog, argv):
        import os
        called["prog"] = prog
        called["argv"] = argv
        called["env_value"] = os.environ.get("INJECTED_VAR")

    # argv[0] is resolved against the pre-injection PATH, so the command has
    # to be a real one — "myapp" would now fail closed with FileNotFoundError.
    import shutil
    with patch("sofiavault.envload.os.execv", side_effect=fake_execv):
        envload.exec_with_env(v, ["env", "--flag"])

    assert called["prog"] == shutil.which("env")
    assert called["argv"] == ["env", "--flag"]
    assert called["env_value"] == "present"
    import os
    os.environ.pop("INJECTED_VAR", None)  # clean up real environ
    path.unlink()


def test_exec_with_env_requires_command():
    v, path = _make_vault()
    with pytest.raises(ValueError):
        envload.exec_with_env(v, [])
    v.close()
    path.unlink()
