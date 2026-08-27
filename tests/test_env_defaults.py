"""S4: the three SOFIAVAULT_* location defaults are honoured (read at import,
so each case is a subprocess)."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from sofiavault.auth import UserStore
from sofiavault.vault import Vault

REPO = Path(__file__).resolve().parent.parent
PW = "defaults-pw-12345"


def _run(args, extra_env):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOFIAVAULT_")}
    env.update(extra_env)
    return subprocess.run([sys.executable, "-m", "sofiavault.cli", *args],
                          capture_output=True, text=True, env=env, cwd=REPO, timeout=60)


def test_S_4_sofiavault_db_default_is_used_and_echoed():
    d = Path(tempfile.mkdtemp())
    v = Vault.create(d / "v.db", PW)
    v.set("env:from_env_default", "1")
    v.close()
    proc = _run(["env", "list"], {"SOFIAVAULT_DB": str(d / "v.db"), "SOFIAVAULT_PASSWORD": PW,
                                 "HOME": str(d)})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["FROM_ENV_DEFAULT"]
    assert "SOFIAVAULT_DB" in proc.stderr and str(d / "v.db") in proc.stderr
    assert not (d / ".sofiavault").exists()


def test_S_4_sofiavault_users_db_default_is_used_and_echoed():
    d = Path(tempfile.mkdtemp())
    with UserStore(d / "u.db") as s:
        s.add_user("alice", "alice-pw-1")
    proc = _run(["auth", "list"], {"SOFIAVAULT_USERS_DB": str(d / "u.db"), "HOME": str(d)})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["alice"]
    assert "SOFIAVAULT_USERS_DB" in proc.stderr
    assert not (d / ".sofiavault").exists()


def test_S_4_sofiavault_allow_file_default_narrows_run():
    d = Path(tempfile.mkdtemp())
    v = Vault.create(d / "v.db", PW)
    v.set("env:wanted", "1")
    v.set("env:unwanted", "2")
    v.close()
    (d / "allow").write_text("WANTED\n")
    dump = "import os, json; print(json.dumps(dict(os.environ)))"
    proc = _run(["run", "--vault", str(d / "v.db"), "--", sys.executable, "-c", dump],
                {"SOFIAVAULT_ALLOW_FILE": str(d / "allow"), "SOFIAVAULT_PASSWORD": PW,
                 "HOME": str(d)})
    assert proc.returncode == 0, proc.stderr
    child = json.loads(proc.stdout)
    assert child["WANTED"] == "1" and "UNWANTED" not in child
    assert "falling back" not in proc.stderr
    # a configured-but-missing default fails closed
    proc = _run(["run", "--vault", str(d / "v.db"), "--", "true"],
                {"SOFIAVAULT_ALLOW_FILE": str(d / "missing"), "SOFIAVAULT_PASSWORD": PW,
                 "HOME": str(d)})
    assert proc.returncode == 1 and "allowlist" in proc.stderr
