"""D-4: Vault.reload(), automatic cross-process refresh, typed read-only error."""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sofiavault.vault import Vault, VaultCorrupted, VaultReadOnly

PW = "reload-test-pw"
FIXTURE = Path(__file__).parent / "fixtures" / "0.3.0" / "vault.db"


def _vault() -> tuple[Vault, Path]:
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    return Vault.create(path, PW), path


def _set_in_subprocess(path: Path, service: str, value: str):
    code = (
        "import sys; from sofiavault.vault import Vault\n"
        f"v = Vault.open({str(path)!r}, password={PW!r}); "
        f"v.set({service!r}, {value!r}); v.close()"
    )
    subprocess.run([sys.executable, "-c", code], check=True,
                   cwd=Path(__file__).parent.parent)


def test_T_4_1_other_process_write_is_visible_without_reopen():
    a, path = _vault()
    a.set("existing", "1")
    _set_in_subprocess(path, "env:FROM_B", "written-by-b")
    assert a.get("env:FROM_B") == "written-by-b"
    assert {e.service for e in a.list_entries()} == {"existing", "env:from_b"}
    a.close()


def test_T_4_2_stale_index_does_not_create_duplicate_row():
    a, path = _vault()
    a.set("shared", "from-a")
    _set_in_subprocess(path, "shared", "from-b")
    a.set("shared", "from-a-again")
    rows = sqlite3.connect(str(path)).execute(
        "SELECT COUNT(*) FROM entries_v2").fetchone()[0]
    assert rows == 1
    assert Vault.open(path, password=PW).get("shared") == "from-a-again"
    a.close()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                    reason="file modes are advisory for root / non-POSIX")
def test_T_4_3_read_only_file_is_a_typed_error_and_readonly_open_works():
    v, path = _vault()
    v.set("api", "secret")
    v.close()
    os.chmod(path, 0o400)
    try:
        with pytest.raises(VaultReadOnly):
            Vault.open(path, password=PW)
        ro = Vault.open(path, password=PW, readonly=True)
        assert ro.readonly is True
        assert ro.get("api") == "secret"
        with pytest.raises(VaultReadOnly):
            ro.set("api", "changed")
        with pytest.raises(VaultReadOnly):
            ro.delete("api")
        with pytest.raises(VaultReadOnly):
            ro.rekey(new_password="x")
        ro.close()
        # A v3 fixture opens read-only without being migrated.
        fixture = path.parent / "v3.db"
        shutil.copy(FIXTURE, fixture)
        os.chmod(fixture, 0o400)
        with Vault.open(fixture, password="fixture-master-password-0.3.0",
                        readonly=True) as v3:
            assert v3.get("env:API_KEY") == "sk-fixture-0123456789"
        assert sqlite3.connect(f"file:{fixture}?mode=ro", uri=True).execute(
            "SELECT value FROM vault_meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
    finally:
        os.chmod(path, 0o600)


def test_T_4_4_mac_changed_on_disk_latches_tampered_on_reload():
    v, path = _vault()
    v.set("api", "secret")
    other = sqlite3.connect(str(path))
    other.execute("UPDATE vault_meta SET value = 'ff' WHERE key = 'entries_mac'")
    other.commit()
    other.close()
    assert v.tampered is False
    v.reload()
    assert v.tampered is True
    # 0.3.0 contract kept: a tampered vault serves nothing (fail closed), and
    # writes refuse rather than launder the edit into a fresh MAC.
    with pytest.raises(VaultCorrupted):
        v.get("api")
    with pytest.raises(VaultCorrupted):
        v.set("api", "new")
    v.close()


def test_readonly_open_of_uninitialized_or_missing_file():
    from sofiavault.vault import VaultNotInitialized
    with pytest.raises(VaultNotInitialized):
        Vault.open(Path(tempfile.mkdtemp()) / "nope.db", password=PW, readonly=True)
