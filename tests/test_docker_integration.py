"""T-6-4: the README's Docker recipe, run for real when Docker is available.

Builds a minimal image from the working tree, bind-mounts a vault and a 0600
key file owned by uid 1000, runs `sofiavault run --allow … -- env` as that
uid, and checks that the child sees the secrets while `docker inspect` (the
container's own environment) does not.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from sofiavault import cli_server
from sofiavault.vault import Vault

REPO = Path(__file__).resolve().parent.parent
PW = "docker-pw-12345"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")

DOCKERFILE = f"""
FROM python:{sys.version_info.major}.{sys.version_info.minor}-slim
RUN useradd --uid 1000 --create-home app
COPY sofiavault /src/sofiavault
COPY pyproject.toml README.md /src/
RUN pip install --no-cache-dir /src
USER app
"""


@pytest.mark.slow
def test_T_6_4_container_child_sees_secrets_but_inspect_does_not():
    d = Path(tempfile.mkdtemp())
    ctx = d / "ctx"
    shutil.copytree(REPO / "sofiavault", ctx / "sofiavault",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(REPO / "pyproject.toml", ctx)
    shutil.copy(REPO / "README.md", ctx)
    (ctx / "Dockerfile").write_text(DOCKERFILE)
    tag = f"sofiavault-test-{uuid.uuid4().hex[:8]}"
    build = subprocess.run(["docker", "build", "-q", "-t", tag, str(ctx)],
                           capture_output=True, text=True, timeout=600)
    assert build.returncode == 0, build.stderr

    mount = d / "mount"
    mount.mkdir()
    vault = mount / "secrets.db"
    v = Vault.create(vault, PW)
    v.set("env:database_url", "postgres://from-vault")
    v.set("env:unlisted", "must-not-appear")
    key_file = mount / "vault.key"
    cli_server.write_key_file(key_file, v.export_key())
    v.close()
    (mount / "secrets.allow").write_text("DATABASE_URL\n")
    os.chmod(vault, 0o400)
    # The container runs as uid 1000; the key file must be 0600 and owned by it.
    fix_owner = "chown 1000 /m/vault.key /m/secrets.db && chmod 600 /m/vault.key"
    subprocess.run(["docker", "run", "--rm", "-v", f"{mount}:/m", "--user", "0",
                    tag, "sh", "-c", fix_owner],
                   check=True, capture_output=True, timeout=120)
    name = f"{tag}-run"
    try:
        run = subprocess.run(
            ["docker", "run", "--name", name, "-v", f"{mount}:/m:ro",
             "-e", "SOFIAVAULT_KEY_FILE=/m/vault.key",
             tag, "sofiavault", "run", "--vault", "/m/secrets.db",
             "--allow", "/m/secrets.allow", "--", "env"],
            capture_output=True, text=True, timeout=120)
        assert run.returncode == 0, run.stderr
        assert "DATABASE_URL=postgres://from-vault" in run.stdout
        assert "must-not-appear" not in run.stdout
        assert "SOFIAVAULT_KEY_FILE" not in run.stdout
        inspect = subprocess.run(["docker", "inspect", name], capture_output=True,
                                 text=True, timeout=60)
        assert "from-vault" not in inspect.stdout
        assert "must-not-appear" not in inspect.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, timeout=60)
        os.chmod(vault, 0o600)
