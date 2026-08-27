"""D-12: the auth CLI."""

import base64
import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from sofiavault import cli_server, paths
from sofiavault.auth import UserStore

KEY = bytes(range(32))


@pytest.fixture
def sandbox(monkeypatch):
    d = Path(tempfile.mkdtemp())
    home = d / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(paths, "USERS_DB_PATH", home / ".sofiavault" / "users.db")
    monkeypatch.setattr(paths, "USERS_DB_PATH_FROM_ENV", False)
    monkeypatch.setattr(paths, "DB_PATH", home / ".sofiavault" / "vault.db")
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", False)
    for var in ("SOFIAVAULT_FIELDS_KEY", "SOFIAVAULT_FIELDS_KEY_FILE", "SOFIAVAULT_PEPPER",
                "SOFIAVAULT_KEY", "SOFIAVAULT_KEY_FILE", "SOFIAVAULT_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SOFIAVAULT_FIELDS_KEY", base64.b64encode(KEY).decode())
    db = d / "users.db"
    with UserStore(db, fields_key=KEY) as s:
        s.add_user("alice", "alice-pw-1")
        s.add_user("bob", "bob-pw-1")
    return d, db


def test_T_12_1_every_subcommand_works_against_db_and_home_is_untouched(sandbox, capsys):
    d, db = sandbox
    users = d / "users.json"
    users.write_text(json.dumps([{"username": "carol", "password": "carol-pw-1", "team": "x"},
                                 {"username": "alice", "password": "dup"}]))
    assert cli_server.main(["auth", "import-json", str(users), "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "created carol" in out and "skipped alice" in out
    assert cli_server.main(["auth", "import", str(users), "--db", str(db)]) == 0
    assert "deprecated" in capsys.readouterr().err

    src = d / "legacy.db"
    c = sqlite3.connect(str(src))
    c.execute("CREATE TABLE managers (login TEXT, pw_hash TEXT, is_admin INTEGER, role TEXT)")
    c.execute("INSERT INTO managers VALUES ('dave', 'h', 1, 'senior')")
    c.commit()
    c.close()
    assert cli_server.main(["auth", "import-sqlite", str(src), "--table", "managers",
                            "--scheme", "fake", "--map", "username=login",
                            "--map", "password_hash=pw_hash", "--db", str(db)]) == 0
    assert "created dave" in capsys.readouterr().out
    assert cli_server.main(["auth", "import-sqlite", str(src), "--table", "managers",
                            "--scheme", "fake", "--map", "bad", "--db", str(db)]) == 2

    assert cli_server.main(["auth", "list", "--db", str(db)]) == 0
    assert capsys.readouterr().out.split() == ["alice", "bob", "carol", "dave"]
    assert cli_server.main(["auth", "list", "--admins", "--db", str(db)]) == 0
    assert capsys.readouterr().out.split() == ["dave"]
    assert cli_server.main(["auth", "list", "--role", "senior", "-v", "--db", str(db)]) == 0
    assert "dave  admin role=senior legacy-hash" in capsys.readouterr().out

    assert cli_server.main(["auth", "set-flag", "alice", "--admin", "--role", "ops",
                            "--db", str(db)]) == 0
    assert cli_server.main(["auth", "set-flag", "bob", "--inactive", "--db", str(db)]) == 0
    assert cli_server.main(["auth", "set-flag", "nobody", "--admin", "--db", str(db)]) == 3
    assert cli_server.main(["auth", "set-flag", "alice", "--db", str(db)]) == 2
    capsys.readouterr()
    assert cli_server.main(["auth", "list", "--active-only", "--db", str(db)]) == 0
    assert "bob" not in capsys.readouterr().out.split()
    with UserStore(db, fields_key=KEY) as s:
        r = s.verify("alice", "alice-pw-1")
        assert r.is_admin and r.role == "ops"
        s.totp_enroll("alice")
    assert cli_server.main(["auth", "totp", "status", "alice", "--db", str(db)]) == 0
    assert capsys.readouterr().out.strip() == "pending"
    assert cli_server.main(["auth", "totp", "disable", "alice", "--db", str(db)]) == 0
    assert cli_server.main(["auth", "totp", "status", "alice", "--db", str(db)]) == 0
    assert capsys.readouterr().out.strip() == "off"
    assert cli_server.main(["auth", "totp", "disable", "nobody", "--db", str(db)]) == 3
    assert cli_server.main(["auth", "totp", "status", "nobody", "--db", str(db)]) == 1
    assert not (d / "home" / ".sofiavault").exists()


def test_T_12_2_reset_token_from_cli_redeems_through_the_library(sandbox, capsys):
    d, db = sandbox
    assert cli_server.main(["auth", "reset", "alice", "--ttl", "120", "--db", str(db)]) == 0
    out, err = capsys.readouterr()
    token = out.strip()
    assert len(token) >= 43 and "shown once" in err
    assert token not in db.read_bytes().decode("latin-1")
    with UserStore(db, fields_key=KEY) as s:
        assert s.reset_token_redeem(token, "fresh-pw-2") == "alice"
        assert s.verify("alice", "fresh-pw-2") is not None
        assert s.reset_token_redeem(token, "again-pw-3") is None
    assert cli_server.main(["auth", "reset", "nobody", "--db", str(db)]) == 1
    # without a fields key the command fails with the documented remedy
    os.environ.pop("SOFIAVAULT_FIELDS_KEY")
    assert cli_server.main(["auth", "reset", "alice", "--db", str(db)]) == 1
    err = capsys.readouterr().err
    assert "fields_key required" in err and "import-sqlite" in err


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_T_12_3_fields_key_file_mode_is_enforced_like_the_vault_key(sandbox, monkeypatch, capsys):
    d, db = sandbox
    monkeypatch.delenv("SOFIAVAULT_FIELDS_KEY")
    key_file = d / "fields.key"
    key_file.write_text(base64.b64encode(KEY).decode() + "\n")
    os.chmod(key_file, 0o640)
    monkeypatch.setenv("SOFIAVAULT_FIELDS_KEY_FILE", str(key_file))
    assert cli_server.main(["auth", "list", "--db", str(db)]) == 2
    err = capsys.readouterr().err
    assert "SOFIAVAULT_FIELDS_KEY_FILE" in err and "accessible to other users" in err
    assert f"chmod 600 {key_file}" in err
    os.chmod(key_file, 0o600)
    assert cli_server.main(["auth", "list", "--db", str(db)]) == 0
    assert capsys.readouterr().out.split() == ["alice", "bob"]
    # and doctor reports on the user store
    monkeypatch.setenv("SOFIAVAULT_PASSWORD", "x")
    assert cli_server.main(["doctor", "--vault", str(d / "none.db"),
                            "--users-db", str(db)]) == 1
    out = capsys.readouterr().out
    assert "fields key configured" in out and "schema v2, 2 users" in out
