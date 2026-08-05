"""Tests for the post-unlock update check."""

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sofiavault import check_for_updates

REPO = Path("/fake/repo")


def _git_result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _fake_git(responses):
    """Build a _git replacement dispatching on the git subcommand.

    `responses` maps subcommand -> result (or None to simulate timeout).
    Records calls in the returned function's `.calls` list.
    """
    def fake(repo, *args, timeout=5):
        fake.calls.append(args[0])
        return responses.get(args[0], _git_result())
    fake.calls = []
    return fake


def test_disabled_via_env_var():
    git = _fake_git({})
    with patch.dict(os.environ, {"SOFIAVAULT_SKIP_UPDATE_CHECK": "1"}), \
         patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO):
        check_for_updates()
    assert git.calls == []


def test_silent_when_not_a_git_install():
    git = _fake_git({})
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=None):
        check_for_updates()
    assert git.calls == []


def test_silent_when_offline(capsys):
    git = _fake_git({"fetch": None})  # timeout / no network
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO):
        check_for_updates()
    assert capsys.readouterr().out == ""


def test_silent_when_up_to_date(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="0\n"),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO):
        check_for_updates()
    assert capsys.readouterr().out == ""
    assert "log" not in git.calls


def test_behind_warns_and_user_declines(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="3\n"),
        "log": _git_result(0, stdout="Fix clipboard leak\nHarden perms\nDocs\n"),
        "rev-parse": _git_result(0, stdout="main\n"),
        "status": _git_result(0, stdout=""),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=True), \
         patch("builtins.input", return_value="n"):
        check_for_updates()

    out = capsys.readouterr().out
    assert "SECURITY UPDATE AVAILABLE" in out
    assert "3 new commits" in out
    assert "Fix clipboard leak" in out
    assert "at risk" in out
    assert "outdated" in out  # decline warning
    assert "pull" not in git.calls


def test_behind_user_accepts_pull_and_exit(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="1\n"),
        "log": _git_result(0, stdout="Security fix\n"),
        "rev-parse": _git_result(0, stdout="main\n"),
        "status": _git_result(0, stdout=""),
        "pull": _git_result(0, stdout="Fast-forward\n"),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=True), \
         patch("builtins.input", return_value=""), \
         pytest.raises(SystemExit) as exc:  # Enter = default Yes
        check_for_updates()

    assert exc.value.code == 0
    assert "pull" in git.calls
    out = capsys.readouterr().out
    assert "restart" in out.lower()


def test_failed_pull_gives_manual_instructions(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="1\n"),
        "log": _git_result(0, stdout="Security fix\n"),
        "rev-parse": _git_result(0, stdout="main\n"),
        "status": _git_result(0, stdout=""),
        "pull": _git_result(1, stderr="fatal: not possible to fast-forward\n"),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=True), \
         patch("builtins.input", return_value="y"):
        check_for_updates()  # must NOT raise SystemExit

    out = capsys.readouterr().out
    assert "Update failed" in out
    assert "pull --ff-only origin main" in out


def test_dirty_tree_never_auto_pulls(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="2\n"),
        "log": _git_result(0, stdout="Security fix\n"),
        "rev-parse": _git_result(0, stdout="main\n"),
        "status": _git_result(0, stdout=" M sofiavault.py\n"),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=AssertionError("must not prompt")):
        check_for_updates()

    out = capsys.readouterr().out
    assert "local changes present" in out
    assert "pull" not in git.calls


def test_non_main_branch_never_auto_pulls(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="2\n"),
        "log": _git_result(0, stdout="Security fix\n"),
        "rev-parse": _git_result(0, stdout="feature-branch\n"),
        "status": _git_result(0, stdout=""),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=AssertionError("must not prompt")):
        check_for_updates()

    out = capsys.readouterr().out
    assert "not on the main branch" in out
    assert "pull" not in git.calls


def test_non_interactive_warns_without_prompting(capsys):
    git = _fake_git({
        "fetch": _git_result(0),
        "rev-list": _git_result(0, stdout="1\n"),
        "log": _git_result(0, stdout="Security fix\n"),
    })
    with patch("sofiavault.cli._git", git), \
         patch("sofiavault.cli._repo_dir", return_value=REPO), \
         patch("sofiavault.cli._stdin_is_interactive", return_value=False), \
         patch("builtins.input", side_effect=AssertionError("must not prompt")):
        check_for_updates()

    out = capsys.readouterr().out
    assert "SECURITY UPDATE AVAILABLE" in out
    assert "Non-interactive" in out
    assert "pull" not in git.calls
