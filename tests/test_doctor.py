"""D-6: sofiavault doctor."""

import os
import tempfile
from pathlib import Path

import pytest

from sofiavault import cli_server, paths
from sofiavault.vault import Vault

PW = "doctor-pw-12345"


@pytest.fixture
def deployment(monkeypatch):
    d = Path(tempfile.mkdtemp())
    monkeypatch.setattr(paths, "DB_PATH", d / "unused-default.db")
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", False)
    monkeypatch.setattr(paths, "ALLOW_FILE", None)
    for var in ("SOFIAVAULT_KEY", "SOFIAVAULT_PASSWORD", "SOFIAVAULT_KEY_FILE",
                "SOFIAVAULT_ALLOW_FILE"):
        monkeypatch.delenv(var, raising=False)
    vault = d / "secrets.db"
    v = Vault.create(vault, PW)
    v.set("env:database_url", "postgres://x")
    v.set("env:api_key", "sk")
    key_file = d / "vault.key"
    cli_server.write_key_file(key_file, v.export_key())
    v.close()
    allow = d / "secrets.allow"
    allow.write_text("DATABASE_URL\nAPI_KEY\n")
    monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(key_file))
    return d, vault, key_file, allow


def test_T_6_1_correct_deployment_reports_zero_problems(deployment, capsys):
    d, vault, key_file, allow = deployment
    assert cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)]) == 0
    out = capsys.readouterr().out
    assert "0 problem(s)" in out and "PROBLEM" not in out
    assert "MAC verifies" in out and "every allowlisted name is present" in out


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_T_6_2_key_file_mode_0640_is_named_with_the_fix(deployment, capsys):
    d, vault, key_file, allow = deployment
    os.chmod(key_file, 0o640)
    assert cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)]) == 1
    out = capsys.readouterr().out
    assert str(key_file) in out and "0o640" in out and f"chmod 600 {key_file}" in out


def test_T_6_3_allowlisted_name_missing_from_vault(deployment, capsys):
    d, vault, key_file, allow = deployment
    allow.write_text("DATABASE_URL\nAPI_KEY\nSTRIPE_KEY\n")
    assert cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)]) == 1
    out = capsys.readouterr().out
    assert "missing from the vault: STRIPE_KEY" in out and "1 problem(s)" in out


def test_doctor_other_failure_modes(deployment, capsys, monkeypatch):
    d, vault, key_file, allow = deployment
    # read-only vault is advertised, not a problem
    os.chmod(vault, 0o400)
    try:
        code = cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)])
    finally:
        os.chmod(vault, 0o600)
    assert code == 0 and "read-only" in capsys.readouterr().out
    # tampered MAC
    import sqlite3
    c = sqlite3.connect(str(vault))
    c.execute("UPDATE vault_meta SET value='00' WHERE key='entries_mac'")
    c.commit()
    c.close()
    assert cli_server.main(["doctor", "--vault", str(vault), "--allow", str(allow)]) == 1
    assert "tampered" in capsys.readouterr().out
    # no key source at all
    monkeypatch.delenv("SOFIAVAULT_KEY_FILE")
    assert cli_server.main(["doctor", "--vault", str(vault)]) == 1
    out = capsys.readouterr().out
    assert "no key source" in out and "no allowlist configured" in out
