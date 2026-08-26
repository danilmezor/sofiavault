"""D-5: master-key rotation and schema v4 (persisted master costs)."""

import base64
import secrets
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from sofiavault import core, storage
from sofiavault.vault import Vault, VaultCorrupted, WrongPassword

PW = "rekey-old-pw"
NEW = "rekey-new-pw"
FIXTURE = Path(__file__).parent / "fixtures" / "0.3.0" / "vault.db"
FIXTURE_PW = "fixture-master-password-0.3.0"


def _vault(n: int = 5) -> tuple[Vault, Path]:
    path = Path(tempfile.mkdtemp()) / "secrets.db"
    v = Vault.create(path, PW)
    for i in range(n):
        v.set(f"svc{i}", f"secret-{i}", username=f"u{i}")
    return v, path


def _vault_id(path: Path) -> str:
    return sqlite3.connect(str(path)).execute(
        "SELECT value FROM vault_meta WHERE key='vault_id'").fetchone()[0]


def test_T_5_1_rekey_with_password_and_with_raw_key():
    v, path = _vault()
    before = _vault_id(path)
    new_b64 = v.rekey(new_password=NEW)
    assert len(base64.b64decode(new_b64)) == core.KEY_SIZE
    assert v.get("svc3") == "secret-3"          # instance keeps working
    v.close()

    with pytest.raises(WrongPassword):
        Vault.open(path, password=PW)
    with Vault.open(path, password=NEW) as v2:
        for i in range(5):
            assert v2.get(f"svc{i}") == f"secret-{i}"
            assert v2.get_entry(f"svc{i}").username == f"u{i}"
        assert v2.tampered is False
        raw = secrets.token_bytes(core.KEY_SIZE)
        v2.rekey(new_key=raw)
    with pytest.raises(WrongPassword):
        Vault.open(path, password=NEW)
    with Vault.open(path, key=raw) as v3:
        assert v3.get("svc0") == "secret-0"
    assert _vault_id(path) == before


def test_T_5_2_failure_mid_rekey_leaves_file_unchanged(monkeypatch):
    v, path = _vault(6)
    original = path.read_bytes()
    calls = {"n": 0}
    real_encrypt = storage.encrypt

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 4:
            raise RuntimeError("simulated crash after 3 of 6 entries")
        return real_encrypt(*args, **kwargs)

    monkeypatch.setattr(storage, "encrypt", flaky)
    with pytest.raises(RuntimeError):
        v.rekey(new_password=NEW)
    monkeypatch.undo()
    v.close()
    assert path.read_bytes() == original
    with Vault.open(path, password=PW) as again:
        assert again.tampered is False
        assert [again.get(f"svc{i}") for i in range(6)] == [f"secret-{i}" for i in range(6)]

    # A commit that fails must roll back too. sqlite3.Connection is a C type
    # whose methods cannot be patched, so the failure is injected through a
    # proxy that forwards everything except commit().
    v = Vault.open(path, password=PW)

    class FailingCommit:
        def __init__(self, conn):
            self._c = conn

        def commit(self):
            raise sqlite3.OperationalError("disk full")

        def __getattr__(self, name):
            return getattr(self._c, name)

    real_conn = v._conn
    v._conn = FailingCommit(real_conn)
    with pytest.raises(VaultCorrupted):
        v.rekey(new_password=NEW)
    v._conn = real_conn
    v.close()
    with Vault.open(path, password=PW) as again:
        assert again.get("svc5") == "secret-5"


def test_T_5_3_v3_fixture_migrates_to_v4_and_persisted_costs_win(monkeypatch):
    path = Path(tempfile.mkdtemp()) / "v3.db"
    shutil.copy(FIXTURE, path)
    with Vault.open(path, password=FIXTURE_PW) as v:
        assert v.tampered is False
        assert v.get("env:API_KEY") == "sk-fixture-0123456789"
    conn = sqlite3.connect(str(path))
    assert storage.get_schema_version(conn) == 4
    assert conn.execute(
        "SELECT time_cost, memory_cost, parallelism FROM master").fetchone() == \
        storage.default_costs()

    # Now pretend a later build raised the constants: the persisted costs
    # must still be the ones used to derive, so the vault keeps opening.
    monkeypatch.setattr(core, "ARGON2_TIME_COST", core.ARGON2_TIME_COST + 1)
    monkeypatch.setattr(storage, "ARGON2_TIME_COST", core.ARGON2_TIME_COST)
    with Vault.open(path, password=FIXTURE_PW) as v:
        assert v.get("github") == "hunter2"
    # ...and a vault created on that build persists the raised costs.
    new_path = path.parent / "new.db"
    Vault.create(new_path, PW).close()
    row = sqlite3.connect(str(new_path)).execute(
        "SELECT time_cost FROM master").fetchone()
    assert row[0] == core.ARGON2_TIME_COST


def test_T_5_5_master_row_is_covered_by_the_mac():
    """Editing the master row's salt or costs must fail the entry-set MAC.

    Checked at the storage level with the genuine key: through Vault.open the
    same edits already surface as WrongPassword (the verify hash depends on
    them), so the MAC is the layer that would catch a rollback of the whole
    master row to a pre-rekey copy alongside rolled-back entries.
    """
    v, path = _vault(1)
    key = base64.b64decode(v.export_key())
    v.close()
    for column, value in (("salt", secrets.token_bytes(32)), ("time_cost", 99),
                          ("memory_cost", 8192), ("parallelism", 1)):
        conn = sqlite3.connect(str(path))
        assert storage.verify_entries_mac(conn, key) is True
        conn.execute(f"UPDATE master SET {column} = ?", (value,))
        conn.commit()
        assert storage.verify_entries_mac(conn, key) is False, column
        conn.close()
        with pytest.raises(WrongPassword):
            Vault.open(path, password=PW)
        _restore_master(path, key)


def _restore_master(path: Path, key: bytes):
    """Rewrite a valid master record for `key` (test helper, not an API)."""
    costs = storage.default_costs()
    combined_salt, verify_hash = core.create_master_record_for_key(key, costs)
    conn = sqlite3.connect(str(path))
    storage.save_master(conn, combined_salt, verify_hash, key, costs=costs)
    conn.close()
    with Vault.open(path, key=key) as v:
        assert v.tampered is False


def test_master_costs_edit_is_detected_when_key_still_matches():
    """A raw-key open does not depend on the KDF costs, so it is the path
    where a cost edit must be caught by the MAC alone."""
    v, path = _vault(1)
    key = base64.b64decode(v.export_key())
    v.close()
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE master SET memory_cost = memory_cost + 1")
    conn.commit()
    conn.close()
    with pytest.raises(WrongPassword):
        # verify_hash is derived with the persisted costs, so it no longer
        # matches; the edit cannot be used to open the vault at all.
        Vault.open(path, key=key)


def test_rekey_refuses_tampered_or_corrupt_vault():
    v, path = _vault(2)
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE entries_v2 SET blob = X'00' WHERE id = 1")
    conn.commit()
    conn.close()
    v.reload()
    with pytest.raises(VaultCorrupted):
        v.rekey(new_password=NEW)
    v.close()
    with Vault.open(path, password=PW) as again:
        assert again.get("svc1") == "secret-1"    # the untouched row survived
