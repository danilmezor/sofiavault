"""SofiaVault CLI — everything interactive lives here.

The library modules (core, storage, vault, auth, envload, generator) are
silent; this module owns prompts, colors, the REPL, clipboard, the update
check, and command dispatch.
"""

import base64
import cmd
import contextlib
import csv
import getpass
import math
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import __version__, cli_server, envload, paths
from .auth import AuthStoreError, UserStore
from .core import create_master_record, verify_master_password
from .generator import (
    GEN_CHARSET,
    GEN_DEFAULT_LENGTH,
    GEN_TARGET_USER_BITS,
    _password_from_pool,
    generate_password,
    mix_pool,
)
from .storage import (
    VaultEntry,
    _is_vault_file,
    _load_entry_payload,
    _shred_file,
    delete_entry,
    entry_row_exists,
    fuzzy_find_service,
    get_entry_by_service,
    get_master_costs,
    get_master_data,
    get_password,
    init_db,
    is_vault_initialized,
    load_entries,
    migrate_legacy_vault,
    migrate_v2_to_v3,
    migrate_v3_to_v4,
    save_entry,
    save_master,
    update_entry,
    verify_entries_mac,
)
from .vault import (
    Vault,
    VaultCorrupted,
    VaultLocked,
    VaultNotInitialized,
    WrongPassword,
)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

AUTO_LOCK_SECONDS = 300  # 5 minutes
CLIPBOARD_CLEAR_SECONDS = 45
UPDATE_FETCH_TIMEOUT = 5   # seconds; keeps unlock fast when offline
UPDATE_PULL_TIMEOUT = 60

# Box drawing and symbol characters (extracted for Python 3.9 f-string compat)
SYM_BOX_TOP = "┌"
SYM_BOX_SIDE = "│"
SYM_BOX_BOT = "└"
SYM_BOX_H = "─"
SYM_CHECK = "✓"
SYM_CROSS = "✗"
SYM_BULLET = "•"
SYM_SKIP = "⊘"
SYM_HEART = "♥"
SYM_ARROWS = "↑↓"
SYM_DOT = "·"
SYM_DASH = "—"


# ─────────────────────────────────────────────────────────────────────────────
# Terminal Colors (ANSI - works on both light and dark themes)
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI color codes. Disabled automatically if output is not a TTY."""
    # sys.stdout is None under pythonw/detached daemons, and this runs at
    # import time — `import sofiavault` must survive it.
    _enabled = sys.stdout is not None and sys.stdout.isatty()

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRED = "\033[91m"
    BGREEN = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE = "\033[94m"
    BMAGENTA = "\033[95m"
    BCYAN = "\033[96m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and isinstance(getattr(cls, attr), str) and attr != '_enabled':
                setattr(cls, attr, "")
        cls._enabled = False


# Disable colors if not a TTY or NO_COLOR is set
if not C._enabled or os.environ.get("NO_COLOR"):
    C.disable()


def style(text: str, *codes: str) -> str:
    """Apply ANSI style codes to text."""
    if not C._enabled:
        return text
    prefix = "".join(codes)
    return f"{prefix}{text}{C.RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Clipboard
# ─────────────────────────────────────────────────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard. Returns True on success."""
    try:
        if sys.platform == 'darwin':
            subprocess.run(['pbcopy'], input=text.encode(), check=True,
                           capture_output=True)
        elif sys.platform.startswith('linux'):
            subprocess.run(['xclip', '-selection', 'clipboard'],
                           input=text.encode(), check=True, capture_output=True)
        elif sys.platform == 'win32':
            subprocess.run(['clip'], input=text.encode(), check=True,
                           capture_output=True)
        else:
            return False
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# Runs in a detached child process: waits, then clears the clipboard only if
# it still holds the copied password (never clobbers newer clipboard content).
_CLIP_CLEAR_SOURCE = (
    "import subprocess, sys, time\n"
    "secret = sys.stdin.buffer.read().decode('utf-8', 'replace')\n"
    "time.sleep(float(sys.argv[1]))\n"
    "if sys.platform == 'darwin':\n"
    "    read_cmd, write_cmd = ['pbpaste'], ['pbcopy']\n"
    "elif sys.platform.startswith('linux'):\n"
    "    read_cmd = ['xclip', '-selection', 'clipboard', '-o']\n"
    "    write_cmd = ['xclip', '-selection', 'clipboard']\n"
    "elif sys.platform == 'win32':\n"
    "    read_cmd = ['powershell', '-NoProfile', '-Command', 'Get-Clipboard']\n"
    "    write_cmd = ['clip']\n"
    "else:\n"
    "    sys.exit(0)\n"
    "try:\n"
    "    out = subprocess.run(read_cmd, capture_output=True, timeout=10).stdout\n"
    "except Exception:\n"
    "    sys.exit(0)\n"
    "current = out.decode('utf-8', 'replace')\n"
    "if current.rstrip('\\r\\n') != secret.rstrip('\\r\\n'):\n"
    "    sys.exit(0)\n"
    "try:\n"
    "    subprocess.run(write_cmd, input=b'', capture_output=True, timeout=10)\n"
    "except Exception:\n"
    "    pass\n"
)


def schedule_clipboard_clear(secret: str, delay: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
    """Spawn a detached process that clears the clipboard after `delay` seconds.

    Detached so it survives one-shot mode exiting immediately. The secret is
    passed via stdin, never argv, so it is not visible in the process list.
    """
    try:
        kwargs = {}
        if sys.platform == 'win32':
            detached = getattr(subprocess, 'DETACHED_PROCESS', 0x8)
            new_group = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200)
            kwargs['creationflags'] = detached | new_group
        else:
            kwargs['start_new_session'] = True
        proc = subprocess.Popen(
            [sys.executable, '-c', _CLIP_CLEAR_SOURCE, str(delay)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, **kwargs
        )
        proc.stdin.write(secret.encode('utf-8'))
        proc.stdin.close()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Update Check
# ─────────────────────────────────────────────────────────────────────────────

def _repo_dir() -> Optional[Path]:
    """Return the git clone this package runs from, or None (pip installs etc.).

    Only the exact repo layout counts: <root>/sofiavault/cli.py with
    <root>/.git and <root>/pyproject.toml naming this project. Scanning
    further up would match whatever unrelated repo happens to enclose an
    extracted tarball — and the update check runs `git pull` in its result.
    """
    try:
        here = Path(__file__).resolve()
    except OSError:
        return None
    if len(here.parents) < 2:
        return None
    repo = here.parents[1]
    if not (repo / '.git').exists():
        return None
    try:
        pyproject = (repo / 'pyproject.toml').read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return None
    if 'name = "sofiavault"' not in pyproject:
        return None
    return repo


def _git(repo: Path, *args: str, timeout: int = UPDATE_FETCH_TIMEOUT):
    """Run a git command in the repo. Returns None on timeout/missing git."""
    try:
        return subprocess.run(
            ['git', '-C', str(repo), *args],
            capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


def _stdin_is_interactive() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def check_for_updates():
    """Offer to update when this install is behind origin/main.

    Runs right after the vault is unlocked. Stays silent and fast when
    offline, when not installed from a git clone, or when disabled with
    SOFIAVAULT_SKIP_UPDATE_CHECK=1. Never auto-pulls over local changes
    or a non-main checkout — those get manual instructions instead.
    """
    if os.environ.get('SOFIAVAULT_SKIP_UPDATE_CHECK'):
        return
    repo = _repo_dir()
    if repo is None:
        return

    fetch = _git(repo, 'fetch', '--quiet', 'origin', 'main')
    if fetch is None or fetch.returncode != 0:
        return  # offline, no remote, or no git — skip silently

    count = _git(repo, 'rev-list', '--count', 'HEAD..origin/main')
    if count is None or count.returncode != 0:
        return
    try:
        behind = int(count.stdout.strip() or 0)
    except ValueError:
        return
    if behind == 0:
        return

    log = _git(repo, 'log', '--pretty=%s', '-8', 'HEAD..origin/main')
    subjects = log.stdout.splitlines() if log is not None and log.returncode == 0 else []

    plural = 's' if behind != 1 else ''
    print()
    print(f"  {style(_hr(), C.YELLOW)}")
    print(f"  {style('!  SECURITY UPDATE AVAILABLE', C.BOLD, C.BYELLOW)}  "
          f"{style(f'({behind} new commit{plural} on main)', C.DIM)}")
    print(f"  {style(_hr(), C.YELLOW)}")
    print(f"  {style('Your password manager is out of date.', C.BOLD)}")
    print("  Updates often contain security fixes — staying on an old")
    print("  version may leave known vulnerabilities unpatched and put")
    print("  your stored credentials at risk.")
    if subjects:
        print()
        print(f"  {style('What changed:', C.DIM)}")
        for subject in subjects:
            print(f"    {style(SYM_BULLET, C.CYAN)} {subject}")
        if behind > len(subjects):
            print(f"    {style(f'... and {behind - len(subjects)} more', C.DIM)}")
    print()

    manual_cmd = f"git -C {repo} pull --ff-only origin main"

    if not _stdin_is_interactive():
        print_warn("Non-interactive session — continuing with the outdated version.")
        print_info(f"Update with: {manual_cmd}")
        print()
        return

    branch = _git(repo, 'rev-parse', '--abbrev-ref', 'HEAD')
    on_main = branch is not None and branch.returncode == 0 and branch.stdout.strip() == 'main'
    status = _git(repo, 'status', '--porcelain', '--untracked-files=no')
    dirty = status is None or status.returncode != 0 or bool(status.stdout.strip())

    if not on_main or dirty:
        reason = "local changes present" if dirty else "not on the main branch"
        print_warn(f"Can't update automatically ({reason}).")
        print_info(f"Update manually: {manual_cmd}")
        print()
        return

    try:
        answer = input(
            f"  {style('Update now?', C.BOLD)} {style('[Y/n]', C.DIM)}: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = 'n'

    if answer in ('', 'y', 'yes'):
        pull = _git(repo, 'pull', '--ff-only', 'origin', 'main',
                    timeout=UPDATE_PULL_TIMEOUT)
        if pull is not None and pull.returncode == 0:
            print()
            print_success("Updated to the latest version.")
            print_info("Please restart SofiaVault to finish the update.")
            print()
            sys.exit(0)
        print_error("Update failed.")
        detail = ((pull.stderr or pull.stdout).strip().splitlines() if pull else [])
        if detail:
            print_info(detail[0])
        print_info(f"Update manually: {manual_cmd}")
    else:
        print_warn("Skipping update — you remain on an outdated, "
                   "potentially vulnerable version.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Display Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _terminal_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _hr(char: str = "─") -> str:
    return char * min(_terminal_width(), 60)


def print_banner():
    """Print the SofiaVault banner"""
    art = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣦⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠈⠙⠿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠋⠀⠈⠙⢿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣤⣤⣶⣿⠏⠀⠀⠀⠀⠀⠈⠻⣦⣤⣶⡶⢶⣶⣶⣶⣶⣿⣏⡀⠀⣰⡄⠀⠀⠻⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣌⠉⠁⠀⠀⢀⣠⡿⠀⠀⠀⠈⠳⡀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⣿⣿⣦⣄⡀⠈⠻⠿⢶⣶⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠿⣿⣿⣷⣶⣾⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⣿⣿⡿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠟⣽⠟⠉⣿⠀⠀⣠⣶⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⢀⣾⠃⠀⠀⠏⠀⡴⠛⠉⠀⠀⠉⢻⣿⣿⣿⣦⡀⠀⠀⠀⠀⢠⠀⠀⠈⢦⡀⠀⠀⠙⢿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⠻⣿⣟⠿⠿⠿⠿⠿⣿⡇⢀⣾⠁⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⢸⣿⠉⣿⡿⠿⣶⣄⡀⠀⣼⡆⠀⠀⠀⠙⢶⣤⣤⣾⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠙⢷⣤⡀⠀⢀⣿⠁⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣆⡙⠿⠦⠄⢈⣽⣿⡿⠀⠀⣀⣤⣤⣤⣭⣛⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣶⣾⠏⣸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣬⠟⠛⠓⠶⣾⣿⣿⠟⠁⢠⡾⠟⠋⠉⣀⣠⣬⣭⣿⠿⣶⣦⡀⠀⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠉⠁⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⢿⣿⡿⠃⢀⣴⣶⣦⡀⠉⠀⠀⠀⢁⣀⡀⠒⠛⠛⠿⢿⣿⣿⠀⠀⠹⣿⣀⣿⢻⡆⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⡏⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⢀⣾⢿⣿⠇⣼⣿⠃⠀⣼⣿⣿⡿⢿⣆⠀⠀⠀⠀⣿⠻⣷⡀⠀⠀⠀⠙⠃⠀⠀⠀⣿⣿⡏⢈⡇⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣼⣿⣷⣆⠀⢸⣿⠀⠀⠀⠀⠀⠀⣰⠟⠁⢸⡿⠀⣿⡏⠀⢠⣿⣿⣿⣧⠀⠹⣆⠀⠀⣸⡿⠀⢹⣷⠀⠀⠀⣠⡀⠀⠀⣰⡿⠋⢀⣼⣷⣦⡀⠀
⢀⣤⣴⣶⠿⠟⠛⠋⠉⠘⣿⠀⢸⣿⡀⠀⠀⠀⠀⣰⠏⠀⠀⣿⡇⠀⣿⠃⠀⢸⣿⣿⣿⣿⠀⢠⣿⣿⣿⣿⠃⣀⣠⣿⣷⣤⣴⣿⣷⣶⣿⣿⣶⣾⡿⠟⠃⠹⣿⡆
⠀⠀⠉⠙⠻⠷⣶⣤⣄⣠⣿⠀⢸⣿⡇⠀⠀⠀⢰⡏⠀⠀⠀⢻⡇⠀⣿⠀⠀⢸⣿⣿⠙⣿⢠⣾⠇⢹⣿⣷⠿⠛⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠋⠀⠈⣿⣧⠀⠀⠀⣿⠀⠀⠀⠀⢸⡇⠀⢿⡄⠀⢸⣿⡿⠀⢹⣿⡟⣠⡿⠋⣀⣠⣤⣤⣄⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣾⡿⠁
⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⡄⠀⠀⢻⣿⡄⠀⢸⡇⠀⠀⠀⠀⠈⠃⠀⠸⡇⠀⢸⣏⠀⠀⠘⣿⣾⡏⠠⠚⠉⠁⠀⠀⠉⠉⠙⠛⠻⠿⠿⣿⣿⣿⡿⢿⣿⠉⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣠⣄⠘⣿⣧⠀⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⢿⣦⣠⣼⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⣿⡿⠻⣷⡹⣿⣆⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⠈⢿⡏⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⠏⣰⠇⠀⠀⣀⣤⣾⡿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠉⠀⠀⢹⣧⠹⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⢁⣴⠿⠶⠾⠿⠿⠟⠋⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⣿⣥⣴⣶⡶⣶⣿⣿⠀⠹⣿⣆⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⣤⣀⡀⠒⠚⢉⣠⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠈⠻⣿⣷⣄⠘⢿⣷⡈⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⡿⠿⠿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣷⣦⣙⢿⣦⣌⠛⠶⣤⣤⣤⣤⣤⣤⡴⠀⣰⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣷⣿⣿⣿⣶⣤⣉⡉⠉⠉⢉⣀⣴⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⢿⣿⣿⣿⣿⠿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
    try:
        print(style(art, C.MAGENTA))
    except UnicodeEncodeError:
        print()  # terminal encoding can't render the art — skip it
    print(style("                       ♥ SofiaVault ♥", C.BOLD, C.MAGENTA))
    print(style("                  Secure Password Manager", C.DIM))
    print()


def print_entry(service: str, username: str, url: str, password: str,
                match_score: int = 0, show_password: bool = False):
    """Print a password entry with nice formatting.

    By default the password is copied to the clipboard (auto-cleared after
    CLIPBOARD_CLEAR_SECONDS) and hidden on screen. It is only printed when
    show_password is True, or as a fallback when no clipboard is available.
    """
    print()
    print(f"  {style(SYM_BOX_TOP + SYM_BOX_H * 44, C.DIM)}")

    if match_score and match_score < 100:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Service ', C.DIM)} "
              f"{style(service, C.BOLD, C.CYAN)}"
              f"  {style(f'({match_score}% match)', C.DIM)}")
    else:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Service ', C.DIM)} "
              f"{style(service, C.BOLD, C.CYAN)}")

    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('User    ', C.DIM)} {username}")

    if url:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('URL     ', C.DIM)} "
              f"{style(url, C.UNDERLINE)}")

    copied = copy_to_clipboard(password)
    clearing = copied and schedule_clipboard_clear(password)

    if show_password or not copied:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Pass    ', C.DIM)} "
              f"{style(password, C.BOLD, C.GREEN)}")
    else:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Pass    ', C.DIM)} "
              f"{style(SYM_BULLET * 12, C.DIM)}")

    print(f"  {style(SYM_BOX_SIDE, C.DIM)}")
    if copied:
        note = "Copied to clipboard"
        if clearing:
            note += f" {SYM_DOT} clears in {CLIPBOARD_CLEAR_SECONDS}s"
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(note, C.DIM, C.GREEN)}")
        if not show_password:
            hint = f"'show {service}' to display it"
            print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(hint, C.DIM)}")
    else:
        warn = "Clipboard unavailable — password shown above"
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(warn, C.DIM, C.YELLOW)}")

    print(f"  {style(SYM_BOX_BOT + SYM_BOX_H * 44, C.DIM)}")
    print()


def print_success(msg: str):
    print(f"  {style(SYM_CHECK, C.GREEN)} {msg}")


def print_error(msg: str):
    print(f"  {style(SYM_CROSS, C.RED)} {msg}")


def print_warn(msg: str):
    print(f"  {style('!', C.YELLOW)} {msg}")


def print_info(msg: str):
    print(f"  {style(SYM_DOT, C.CYAN)} {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Password generation (interactive parts)
# ─────────────────────────────────────────────────────────────────────────────

def _collect_user_entropy(target_bits: int = GEN_TARGET_USER_BITS) -> bytes:
    """Collect keyboard-mash entropy: key bytes + nanosecond timings.

    Credited conservatively at ~2 bits per keystroke (1 for the character,
    1 for the inter-keystroke timing). The result is only ever MIXED with
    the OS CSPRNG, never used alone, so a weak mash cannot hurt.
    """
    needed = max(1, target_bits // 2)
    collected = bytearray()
    count = 0

    print()
    print_info("Mash random keys — content and timing both feed the pool.")
    print_info("Press Enter to finish early.")
    print()

    def note(ch: bytes):
        nonlocal count
        collected.extend(ch)
        collected.extend(time.perf_counter_ns().to_bytes(8, 'big'))
        count += 1
        if sys.stdout.isatty():
            pct = min(100, int(100 * count / needed))
            filled = pct * 24 // 100
            bar = "#" * filled + "-" * (24 - filled)
            sys.stdout.write(f"\r  [{bar}] {pct}%")
            sys.stdout.flush()

    try:
        if sys.platform == 'win32':
            import msvcrt
            while count < needed:
                ch = msvcrt.getch()
                if ch in (b'\r', b'\n'):
                    break
                note(ch)
        elif sys.stdin.isatty():
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                while count < needed:
                    ch = os.read(fd, 1)
                    if ch in (b'\r', b'\n'):
                        break
                    note(ch)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        else:
            raise OSError("no tty")
    except (ImportError, OSError):
        # Non-interactive fallback: a typed line still contributes content
        typed = getpass.getpass(style("  Type a long random string: ", C.DIM))
        collected.extend(typed.encode('utf-8'))
        collected.extend(time.perf_counter_ns().to_bytes(8, 'big'))
        count = len(typed)

    if sys.stdout.isatty():
        print()
    if count < needed:
        print_warn(f"Stopped early — ~{count * 2} bits of claimed user entropy "
                   "(still mixed with the OS CSPRNG, so this is safe).")
    return bytes(collected)


def _print_generated(password: str, mixed: bool = False):
    """Show a generated password and copy it to the clipboard."""
    bits = int(len(password) * math.log2(len(GEN_CHARSET)))
    copied = copy_to_clipboard(password)
    clearing = copied and schedule_clipboard_clear(password)

    print()
    print(f"  {style(SYM_BOX_TOP + SYM_BOX_H * 44, C.DIM)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Password', C.DIM)} "
          f"{style(password, C.BOLD, C.GREEN)}")
    source = "OS CSPRNG + user entropy" if mixed else "OS CSPRNG"
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(f'~{bits} bits {SYM_DOT} {source}', C.DIM)}")
    if copied:
        note = "Copied to clipboard"
        if clearing:
            note += f" {SYM_DOT} clears in {CLIPBOARD_CLEAR_SECONDS}s"
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(note, C.DIM, C.GREEN)}")
    print(f"  {style(SYM_BOX_BOT + SYM_BOX_H * 44, C.DIM)}")
    print()


def cmd_gen(arg: str = ''):
    """Generate a strong password: gen [length] [--mix]"""
    length = GEN_DEFAULT_LENGTH
    mix = False
    for token in arg.split():
        if token in ('--mix', 'mix'):
            mix = True
        elif token.isdigit():
            length = int(token)
        else:
            print_info("Usage: gen [length] [--mix]")
            return
    length = max(8, min(128, length))

    if mix:
        user_entropy = _collect_user_entropy()
        password = _password_from_pool(mix_pool(user_entropy), length)
    else:
        password = generate_password(length)

    _print_generated(password, mixed=mix)


# ─────────────────────────────────────────────────────────────────────────────
# Vault Transfer (export / import) & Wipe
# ─────────────────────────────────────────────────────────────────────────────

def _clickable_path(path: Path) -> str:
    """Render a filesystem path as an OSC 8 terminal hyperlink when possible."""
    text = str(path)
    if not C._enabled:
        return text
    return f"\033]8;;{path.as_uri()}\033\\{text}\033]8;;\033\\"


def cmd_export():
    """Show where the encrypted vault file lives so the user can copy it."""
    if not paths.DB_PATH.exists():
        print()
        print_error("No vault file found — nothing to export.")
        print()
        return

    size_kb = paths.DB_PATH.stat().st_size / 1024
    print()
    print(f"  {style(SYM_BOX_TOP + SYM_BOX_H * 44, C.DIM)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Vault file', C.BOLD)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} "
          f"{style(_clickable_path(paths.DB_PATH), C.CYAN, C.UNDERLINE)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(paths.DB_PATH.as_uri(), C.DIM)}")
    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style(f'{size_kb:.1f} KB', C.DIM)}")
    print(f"  {style(SYM_BOX_BOT + SYM_BOX_H * 44, C.DIM)}")
    print()
    print_info("The file is fully encrypted — safe to copy to a USB drive or cloud.")
    print_info("On the other device run: sofiavault import <path/to/vault.db>")
    print_info("You'll need your master password to open it there.")
    print()


def _copy_private(src: Path, dst: Path):
    """Copy `src` to `dst` as a fresh 0600 regular file, never through a link.

    shutil.copy2 follows a symlink at `dst`, so a link planted at the backup
    path by another local user would have the vault written over — and
    chmod-ed — wherever it pointed (review finding F9). The destination is
    unlinked without following and re-created O_EXCL|O_NOFOLLOW at 0600.
    """
    if dst.is_symlink() or dst.exists():
        dst.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(dst), flags, 0o600)
    with os.fdopen(fd, 'wb') as out, open(src, 'rb') as inp:
        shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())
    with contextlib.suppress(OSError):
        os.chmod(dst, 0o600)


def cmd_import_vault(src: str) -> bool:
    """Replace the local vault with a vault file from another device.

    Verifies the file is a real SofiaVault database AND that the user knows
    its master password before anything is touched. An existing local vault
    is backed up first. Returns True if the vault was replaced.
    """
    path = Path(src).expanduser().resolve()

    if not path.exists():
        print()
        print_error(f"File not found: {path}")
        print()
        return False
    if not _is_vault_file(path):
        print()
        print_error("That file is not a SofiaVault vault.")
        print()
        return False
    if paths.DB_PATH.exists() and path.samefile(paths.DB_PATH):
        print()
        print_error("That is already the active vault.")
        print()
        return False

    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Import Vault', C.BOLD)}  {style(str(path), C.CYAN)}")
    print(f"  {style(_hr(), C.DIM)}")
    print()

    # Prove ownership of the imported vault before touching anything
    password = get_master_password("Master password of the imported vault: ")
    ro = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        combined_salt, stored_hash = get_master_data(ro)
        key = verify_master_password(password, combined_salt, stored_hash,
                                     costs=get_master_costs(ro))
    finally:
        ro.close()
    if key is None:
        print_error("Wrong password for that vault. Nothing was changed.")
        print()
        return False

    if paths.DB_PATH.exists():
        confirm = input(
            f"  {style('!', C.YELLOW)} This will replace your current vault "
            f"(a backup is kept). Continue? {style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm != 'y':
            print_info("Cancelled. Nothing was changed.")
            print()
            return False
        backup = paths.DB_PATH.with_name(paths.DB_PATH.name + ".replaced-backup")
        _copy_private(paths.DB_PATH, backup)
        print_info(f"Previous vault backed up to {backup}")

    paths.DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _copy_private(path, paths.DB_PATH)

    print()
    print_success("Vault imported.")
    print_info("Unlock it with the imported vault's master password.")
    print()
    return True


def _wipe_targets() -> list[Path]:
    """The explicit allowlist of files a wipe may touch — nothing else.

    Derived from paths.DB_PATH (not hardcoded) so tests that patch it stay
    sandboxed. Includes the auth store `auth import` creates next to the
    vault: wipe promises every stored credential artifact is destroyed,
    and its Argon2 verifiers are exactly that.
    """
    users_db = paths.DB_PATH.parent / 'users.db'
    targets = [
        paths.DB_PATH,
        paths.DB_PATH.with_name(paths.DB_PATH.name + ".v1-backup"),
        paths.DB_PATH.with_name(paths.DB_PATH.name + ".replaced-backup"),
        users_db,
        paths.HISTORY_PATH,
    ]
    for db in (paths.DB_PATH, users_db):
        targets += [Path(str(db) + suffix) for suffix in ("-wal", "-shm", "-journal")]
    return targets


def cmd_wipe(session: "VaultSession"):
    """Permanently destroy the vault. Exits the program on success."""
    print()
    print(f"  {style(_hr(), C.RED)}")
    print(f"  {style('!  WIPE VAULT — THIS CANNOT BE UNDONE', C.BOLD, C.BRED)}")
    print(f"  {style(_hr(), C.RED)}")
    print("  Every stored password, all backups, and the command history")
    print("  will be overwritten with random data and deleted.")
    print()

    password = get_master_password()
    if _key_from_password(session.conn, password) is None:
        print_error("Wrong password. Wipe cancelled — nothing was changed.")
        print()
        return

    phrase = input(
        f"  Type {style('wipe my vault', C.BOLD, C.RED)} to confirm: "
    ).strip().lower()
    if phrase != "wipe my vault":
        print_info("Wipe cancelled — nothing was changed.")
        print()
        return

    session.lock()
    session.conn.close()

    for target in _wipe_targets():
        _shred_file(target)
    with contextlib.suppress(OSError):
        if paths.DB_PATH.parent.name == '.sofiavault':
            paths.DB_PATH.parent.rmdir()

    print()
    print_success("Vault wiped. All entries are gone.")
    print_info("Note: on SSDs and copy-on-write filesystems (e.g. APFS), software")
    print_info("overwriting cannot guarantee physical erasure — full-disk")
    print_info("encryption (FileVault/BitLocker/LUKS) is the reliable protection.")
    print()
    sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Vault Session
# ─────────────────────────────────────────────────────────────────────────────

class VaultSession:
    """Holds the active vault connection, derived key, and decrypted index."""

    def __init__(self, conn: sqlite3.Connection, key: Optional[bytes]):
        self.conn = conn
        self.key = key
        self.entries: list[VaultEntry] = []
        self.corrupt_count = 0
        self.tampered = False
        self.last_activity = time.time()
        if key is not None:
            self.reload()

    def reload(self):
        """Rebuild the decrypted metadata index from the database."""
        self.entries, self.corrupt_count = load_entries(self.conn, self.key)
        # Same entry-set check the library enforces: detects whole-blob
        # rollback, row insertion, and row deletion, which per-entry
        # authentication cannot see. Latched — see _verify_before_write.
        if not verify_entries_mac(self.conn, self.key):
            self.tampered = True

    def lock(self):
        """Drop the key and all decrypted data from memory."""
        self.key = None
        self.entries = []

    def unlock_with(self, key: bytes):
        self.key = key
        self.reload()
        self.touch()

    def touch(self):
        self.last_activity = time.time()

    def is_expired(self) -> bool:
        return time.time() - self.last_activity > AUTO_LOCK_SECONDS


# ─────────────────────────────────────────────────────────────────────────────
# CLI Commands
# ─────────────────────────────────────────────────────────────────────────────

def get_master_password(prompt: str = "Master password: ") -> str:
    """Securely get master password"""
    return getpass.getpass(style(f"  {prompt}", C.DIM))


def setup_master(conn: sqlite3.Connection) -> bytes:
    """Set up master password for first time"""
    print()
    print(f"  {style('Welcome to SofiaVault!', C.BOLD)} ♥")
    msg_setup = "Let's set up your master password."
    msg_warn = "This password unlocks everything — don't forget it!"
    print(f"  {style(msg_setup, C.DIM)}")
    print(f"  {style(msg_warn, C.DIM)}")
    print()

    while True:
        password = get_master_password("Create master password: ")
        if len(password) < 8:
            print_warn("Password must be at least 8 characters.")
            continue

        confirm = get_master_password("Confirm master password: ")
        if password != confirm:
            print_error("Passwords don't match. Try again.")
            print()
            continue
        break

    combined_salt, verify_hash, key = create_master_record(password)
    save_master(conn, combined_salt, verify_hash, key)
    print()
    print_success("You're all set! Your vault is ready. ♥")
    print()
    return key


def _key_from_password(conn: sqlite3.Connection, password: str) -> Optional[bytes]:
    """Derive and verify the master key. Returns None on wrong password."""
    combined_salt, stored_hash = get_master_data(conn)
    return verify_master_password(password, combined_salt, stored_hash,
                                  costs=get_master_costs(conn))


def unlock_vault(conn: sqlite3.Connection) -> Optional[bytes]:
    """Unlock vault with master password"""
    password = get_master_password()
    key = _key_from_password(conn, password)
    if key is None:
        print_error("Wrong password.")
    return key


def _reveal_entry(session: VaultSession, entry: VaultEntry,
                  match_score: int = 0, show: bool = False):
    """Decrypt and display one entry, handling corruption gracefully."""
    password = get_password(session.conn, session.key, entry.id)
    if password is None:
        print_error(f"Decryption failed for '{entry.service}'. "
                    "The entry may be corrupted or tampered with.")
        return
    print_entry(entry.service, entry.username, entry.url, password,
                match_score=match_score, show_password=show)


def cmd_add(session: VaultSession):
    """Add a new password entry"""
    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Add New Entry', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print()

    service = input(f"  {style('Service', C.DIM)} (e.g., amazon, gmail): ").strip()
    if not service:
        print_error("Service name required.")
        return

    existing = get_entry_by_service(session.entries, service)
    if existing:
        confirm = input(
            f"  {style('!', C.YELLOW)} '{service}' already exists. "
            f"Overwrite? {style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm != 'y':
            print_info("Cancelled.")
            return

    username = input(f"  {style('Username/Email', C.DIM)}: ").strip()
    if not username:
        print_error("Username required.")
        return

    password = getpass.getpass(f"  {style('Password', C.DIM)} (hidden): ")
    if not password:
        print_error("Password required.")
        return

    # Only replace the existing entry once the replacement is fully
    # collected — an abort above must leave the old entry untouched.
    _verify_before_write(session)
    if existing and not entry_row_exists(session.conn, existing.id):
        # The row went away after the index was built; UPDATE would match
        # nothing and report success for a password that was never stored.
        existing = None
    if existing:
        payload = _load_entry_payload(session.conn, session.key, existing.id)
        if payload is None:
            # Became unreadable since the index was built. The overwrite was
            # confirmed for an entry the user believed intact, so destroying
            # the ciphertext here is not what they consented to — refuse, as
            # Vault.set does. The row is still in the index this session is
            # working from, so `delete` can name it if that is the intent.
            print()
            print_error(f"'{service}' could not be decrypted. It may be "
                        "corrupted or tampered with; it was not overwritten.")
            print_info(f"Inspect a backup first, or remove it with: "
                       f"delete {service}")
            print()
            return
        update_entry(session.conn, session.key, existing.id, service,
                     username, payload.get('url', ''), password,
                     payload.get('created_at', ''))
    else:
        save_entry(session.conn, session.key, service, username, password)
    session.reload()
    print()
    print_success(f"Saved {style(service, C.CYAN)} for {username}")
    print()


def cmd_get(session: VaultSession, query: str, show: bool = False):
    """Get password for a service (fuzzy matched)"""
    exact = get_entry_by_service(session.entries, query)
    if exact:
        _reveal_entry(session, exact, show=show)
        return

    matches = fuzzy_find_service(session.entries, query)

    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print_info("Type 'list' to see all entries.")
        print()
        return

    if len(matches) == 1 and matches[0][1] >= 80:
        entry, score = matches[0]
        _reveal_entry(session, entry, match_score=score, show=show)
        return

    print()
    print(f"  {style('Found', C.DIM)} {style(str(len(matches)), C.BOLD)} "
          f"{style('possible matches for', C.DIM)} "
          f"'{style(query, C.CYAN)}':")
    print()
    for i, (entry, score) in enumerate(matches, 1):
        score_color = C.GREEN if score >= 80 else C.YELLOW if score >= 60 else C.RED
        print(f"  {style(f'[{i}]', C.BOLD)} {entry.service} "
              f"{style(f'({entry.username})', C.DIM)}  "
              f"{style(f'{score}%', score_color)}")

    print(f"  {style('[0]', C.DIM)} Cancel")
    print()

    try:
        choice = input(f"  {style('Select:', C.DIM)} ").strip()
        if not choice or choice == '0':
            return

        idx = int(choice) - 1
        if 0 <= idx < len(matches):
            entry, _ = matches[idx]
            _reveal_entry(session, entry, show=show)
    except (ValueError, IndexError):
        print_error("Invalid selection.")


def _select_entry(session: VaultSession, query: str) -> Optional[VaultEntry]:
    """Resolve a query to one entry: exact match, then fuzzy with a menu."""
    exact = get_entry_by_service(session.entries, query)
    if exact:
        return exact

    matches = fuzzy_find_service(session.entries, query, threshold=70)
    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print()
        return None
    if len(matches) == 1:
        return matches[0][0]

    print()
    print(f"  {style('Multiple matches for', C.DIM)} '{style(query, C.CYAN)}':")
    print()
    for i, (entry, _score) in enumerate(matches, 1):
        print(f"  {style(f'[{i}]', C.BOLD)} {entry.service} "
              f"{style(f'({entry.username})', C.DIM)}")
    print(f"  {style('[0]', C.DIM)} Cancel")
    print()
    try:
        choice = input(f"  {style('Select:', C.DIM)} ").strip()
        if not choice or choice == '0':
            return None
        idx = int(choice) - 1
        if 0 <= idx < len(matches):
            return matches[idx][0]
    except (ValueError, IndexError):
        pass
    print_error("Invalid selection.")
    return None


def cmd_edit(session: VaultSession, query: str):
    """Edit an existing entry; Enter keeps each current value."""
    entry = _select_entry(session, query)
    if entry is None:
        return

    data = _load_entry_payload(session.conn, session.key, entry.id)
    if data is None:
        print_error(f"Decryption failed for '{entry.service}'. "
                    "The entry may be corrupted or tampered with.")
        return

    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Edit Entry', C.BOLD)}  {style(entry.service, C.CYAN)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Enter keeps the current value.', C.DIM)}")
    print()

    new_service = input(
        f"  {style('Service ', C.DIM)} [{entry.service}]: "
    ).strip().lower() or entry.service
    if new_service != entry.service and any(
        e.service == new_service and e.id != entry.id for e in session.entries
    ):
        print_error(f"'{new_service}' already exists. Nothing was changed.")
        print()
        return

    cur_username = data.get('username', '')
    new_username = input(
        f"  {style('Username', C.DIM)} [{cur_username}]: "
    ).strip() or cur_username

    cur_url = data.get('url', '')
    clear_hint = style("('-' clears)", C.DIM)
    url_raw = input(
        f"  {style('URL     ', C.DIM)} [{cur_url or 'none'}] {clear_hint}: "
    ).strip()
    new_url = '' if url_raw == '-' else (url_raw or cur_url)

    cur_password = data.get('password', '')
    gen_answer = input(
        f"  {style('Generate a strong password?', C.DIM)} {style('[y/N]', C.DIM)}: "
    ).strip().lower()
    if gen_answer in ('y', 'yes'):
        new_password = generate_password()
        _print_generated(new_password)
    else:
        typed = getpass.getpass(
            f"  {style('Password', C.DIM)} (hidden, Enter to keep): "
        )
        new_password = typed if typed else cur_password

    if (new_service == entry.service and new_username == cur_username
            and new_url == cur_url and new_password == cur_password):
        print_info("No changes.")
        print()
        return

    _verify_before_write(session)
    if not entry_row_exists(session.conn, entry.id):
        # Deleted by another writer while these prompts were open. UPDATE
        # would match no row and still report success, losing the password.
        print()
        print_error(f"'{entry.service}' was removed from the vault while you "
                    "were editing it. Nothing was changed.")
        print_info(f"Store it as a new entry with: add  (service: {new_service})")
        print()
        session.reload()
        return

    update_entry(session.conn, session.key, entry.id, new_service, new_username,
                 new_url, new_password, data.get('created_at', ''))
    session.reload()
    print()
    print_success(f"Updated {style(new_service, C.CYAN)}")
    print()


def cmd_list(session: VaultSession):
    """List all stored services"""
    entries = session.entries

    if not entries:
        print()
        print_info("No passwords saved yet.")
        print_info("Use 'add' to store your first one. ♥")
        print()
        return

    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Your Passwords', C.BOLD)}  "
          f"{style(f'({len(entries)})', C.DIM)}")
    print(f"  {style(_hr(), C.DIM)}")
    print()
    for entry in entries:
        print(f"  {style(SYM_BULLET, C.CYAN)} {style(entry.service, C.BOLD)}"
              f"  {style(entry.username, C.DIM)}")
    print()
    if session.corrupt_count:
        print_warn(f"{session.corrupt_count} entries could not be decrypted "
                   "and are not shown.")
        print()


def cmd_delete(session: VaultSession, query: str):
    """Delete an entry"""
    matches = fuzzy_find_service(session.entries, query, threshold=70)

    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print()
        return

    if len(matches) == 1:
        entry, _score = matches[0]
        confirm = input(
            f"  {style('!', C.YELLOW)} Delete "
            f"'{style(entry.service, C.BOLD)}' ({entry.username})? "
            f"{style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm == 'y':
            _verify_before_write(session)
            delete_entry(session.conn, entry.id, session.key)
            session.reload()
            print_success(f"Deleted '{entry.service}'")
        print()
        return

    print()
    print(f"  {style('Multiple matches for', C.DIM)} '{style(query, C.CYAN)}':")
    print()
    for i, (entry, _score) in enumerate(matches, 1):
        print(f"  {style(f'[{i}]', C.BOLD)} {entry.service} "
              f"{style(f'({entry.username})', C.DIM)}")
    print(f"  {style('[0]', C.DIM)} Cancel")
    print()

    try:
        choice = input(f"  {style('Select to delete:', C.DIM)} ").strip()
        if not choice or choice == '0':
            return

        idx = int(choice) - 1
        if 0 <= idx < len(matches):
            entry, _ = matches[idx]
            confirm = input(
                f"  {style('!', C.YELLOW)} Delete "
                f"'{style(entry.service, C.BOLD)}'? "
                f"{style('[y/N]', C.DIM)}: "
            ).strip().lower()
            if confirm == 'y':
                _verify_before_write(session)
                delete_entry(session.conn, entry.id, session.key)
                session.reload()
                print_success(f"Deleted '{entry.service}'")
            print()
    except (ValueError, IndexError):
        print_error("Invalid selection.")


def cmd_import(session: VaultSession, csv_path: str):
    """Import passwords from a CSV file"""
    path = Path(csv_path).expanduser().resolve()

    if not path.exists():
        print()
        print_error(f"File not found: {path}")
        print()
        return

    if path.suffix.lower() != '.csv':
        print_warn("File doesn't have .csv extension")

    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Import', C.BOLD)}  {style(path.name, C.CYAN)}")
    print(f"  {style(_hr(), C.DIM)}")
    print()

    required = {'TITLE', 'PASSWORD', 'USERNAME'}

    imported = 0
    skipped = 0
    errors = 0

    _verify_before_write(session)
    existing_services = {e.service for e in session.entries}

    try:
        with open(path, encoding='utf-8-sig') as f:  # utf-8-sig handles BOM
            sample = f.read(4096)
            f.seek(0)

            sniffer = csv.Sniffer()
            try:
                dialect = sniffer.sniff(sample, delimiters=',;\t|')
            except csv.Error:
                dialect = csv.excel  # Default to comma

            reader = csv.DictReader(f, dialect=dialect)

            if reader.fieldnames is None:
                print_error("CSV file appears to be empty")
                print()
                return

            col_map = {col.upper().strip(): col for col in reader.fieldnames}

            missing = required - set(col_map.keys())
            if missing:
                print_error(f"Missing required columns: {', '.join(missing)}")
                print_info(f"Found: {', '.join(reader.fieldnames)}")
                print_info("Required: TITLE, PASSWORD, USERNAME")
                print_info("Optional: URL")
                print()
                return

            for row_num, row in enumerate(reader, start=2):
                try:
                    title = row.get(col_map.get('TITLE', ''), '').strip()
                    password = row.get(col_map.get('PASSWORD', ''), '').strip()
                    username = row.get(col_map.get('USERNAME', ''), '').strip()
                    url = (row.get(col_map.get('URL', ''), '').strip()
                           if 'URL' in col_map else '')

                    if not title:
                        print(f"  {style(SYM_SKIP, C.DIM)} Row {row_num}: "
                              f"{style('empty TITLE', C.DIM)}")
                        skipped += 1
                        continue

                    if not password:
                        print(f"  {style(SYM_SKIP, C.DIM)} Row {row_num}: "
                              f"'{title}' {style('empty PASSWORD', C.DIM)}")
                        skipped += 1
                        continue

                    if not username:
                        print(f"  {style(SYM_SKIP, C.DIM)} Row {row_num}: "
                              f"'{title}' {style('empty USERNAME', C.DIM)}")
                        skipped += 1
                        continue

                    title_key = title.lower().strip()
                    if title_key in existing_services:
                        print(f"  {style(SYM_SKIP, C.DIM)} Row {row_num}: "
                              f"'{title}' {style('already exists', C.DIM)}")
                        skipped += 1
                        continue

                    save_entry(session.conn, session.key, title, username,
                               password, url)
                    existing_services.add(title_key)
                    print_success(f"{title} ({username})")
                    imported += 1

                except Exception as e:
                    print_error(f"Row {row_num}: {e}")
                    errors += 1

        session.reload()
        print()
        print(f"  {style(_hr(), C.DIM)}")
        print_success(f"Imported: {imported}")
        if skipped:
            print_info(f"Skipped:  {skipped}")
        if errors:
            print_error(f"Errors:   {errors}")
        print()

    except UnicodeDecodeError:
        print_error("File encoding error. Please ensure the CSV is UTF-8 encoded.")
        print()
    except csv.Error as e:
        print_error(f"CSV parsing error: {e}")
        print()
    except Exception as e:
        print_error(f"Error reading file: {e}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# Server commands: env / run / auth / key
# ─────────────────────────────────────────────────────────────────────────────

def _vault_from_session(session: VaultSession) -> Vault:
    """Wrap an unlocked CLI session in a library Vault (shares the conn).

    Built fresh each call: the CLI writes through storage directly, so a
    cached wrapper would keep serving the entry index it decrypted at
    construction — and `import_env_file` decides what to skip from exactly
    that index. The session's latched tamper flag is carried over, since a
    new Vault starts out believing the vault is clean.
    """
    vault = Vault(session.conn, session.key, paths.DB_PATH)
    if session.tampered:
        vault.tampered = True
    return vault


def cmd_env(session: VaultSession, args: list[str]):
    """Manage env:* entries: env import <.env file> | env list"""
    if args and args[0] == 'import' and len(args) > 1:
        src = Path(args[1]).expanduser()
        if not src.exists():
            print()
            print_error(f"File not found: {src}")
            print()
            return
        vault = _vault_from_session(session)
        try:
            imported, skipped, rejected = envload.import_env_file(vault, src)
        except OSError as exc:
            print_error(f"Could not read {src}: {exc}")
            return
        except envload.MalformedEnvFile as exc:
            print()
            print_error(str(exc))
            print_warn("Nothing was imported.")
            print()
            return
        except VaultCorrupted as exc:
            # Vault.set re-verifies the entry-set MAC before every write, and
            # each set commits as it goes — so this can land partway through.
            print()
            print_error(str(exc))
            print_warn("The import stopped partway. Entries written before this "
                       "point are already in the vault.")
            print_info("Check with: sofiavault env list")
            print()
            return
        session.reload()
        print()
        print(f"  {style(_hr(), C.DIM)}")
        print_success(f"Imported {len(imported)} secrets as env:* entries")
        for name in imported:
            print(f"  {style(SYM_BULLET, C.CYAN)} {name}")
        if skipped:
            print_info(f"Skipped (already present or empty): {', '.join(skipped)}")
        if rejected:
            print()
            print_error(f"Rejected {len(rejected)} unsafe variable name(s): "
                        f"{', '.join(rejected)}")
            print_warn("These control how programs load code (LD_PRELOAD, BASH_ENV,")
            print_warn("PYTHONPATH, PATH, ...). Injecting them from a vault would let")
            print_warn("anyone who can write one entry run code in your app.")
        print()
        print_warn("The source file still holds these secrets in plaintext.")
        print_warn("Remove them from it and rotate anything that was exposed.")
        print_info("Inject at boot with: sofiavault run -- <your command>")
        print()
    elif args and args[0] == 'list':
        names = envload.list_env_entries(_vault_from_session(session))
        print()
        if not names:
            print_info("No env:* entries yet. Add with: sofiavault env import <.env>")
        else:
            print(f"  {style('Environment entries', C.BOLD)}  "
                  f"{style(f'({len(names)})', C.DIM)}")
            print()
            for name in names:
                print(f"  {style(SYM_BULLET, C.CYAN)} {name}")
        print()
    else:
        print_info("Usage: sofiavault env import <path/to/.env>")
        print_info("       sofiavault env list")


def cmd_run(args: list[str]):
    """Inject env:* entries and exec a command: run [--vault PATH] -- cmd..."""
    vault_path = paths.DB_PATH
    rest = list(args)
    if rest and rest[0] == '--vault':
        if len(rest) < 2:
            print_info("Usage: sofiavault run [--vault PATH] -- <command...>")
            return
        vault_path = Path(rest[1]).expanduser()
        rest = rest[2:]
    if rest and rest[0] == '--':
        rest = rest[1:]
    if not rest:
        print_info("Usage: sofiavault run [--vault PATH] -- <command...>")
        return

    try:
        vault = Vault.open_auto(vault_path)
    except VaultLocked:
        # We ARE the interactive layer — fall back to a prompt
        if not vault_path.exists():
            print_error(f"No vault at {vault_path}")
            sys.exit(1)
        password = get_master_password()
        try:
            vault = Vault.open(vault_path, password=password)
        except WrongPassword:
            print_error("Wrong password.")
            sys.exit(1)
    except (WrongPassword, VaultNotInitialized) as exc:
        print_error(str(exc))
        sys.exit(1)

    try:
        envload.exec_with_env(vault, rest)  # never returns on success
    except FileNotFoundError:
        print_error(f"Command not found: {rest[0]}")
        sys.exit(127)
    except envload.UnsafeVariableName as exc:
        print_error(str(exc))
        print_warn("Remove the entry with: sofiavault delete env:<name>")
        sys.exit(1)
    except VaultCorrupted as exc:
        print_error(str(exc))
        sys.exit(1)


def cmd_auth(args: list[str]):
    """User-store operations: auth import <users.json> [--db PATH]"""
    if len(args) >= 2 and args[0] == 'import':
        src = Path(args[1]).expanduser()
        db = paths.DB_PATH.parent / 'users.db'
        if '--db' in args:
            idx = args.index('--db')
            if idx + 1 >= len(args):
                print_info("Usage: sofiavault auth import <users.json> [--db PATH]")
                return
            db = Path(args[idx + 1]).expanduser()
        if not src.exists():
            print()
            print_error(f"File not found: {src}")
            print()
            return
        try:
            with UserStore(db) as store:
                created, skipped = store.import_json(src)
        except (AuthStoreError, ValueError) as exc:
            print_error(f"Import failed: {exc}")
            return
        print()
        print(f"  {style(_hr(), C.DIM)}")
        print_success(f"Created {len(created)} users in {db}")
        if skipped:
            print_info(f"Skipped: {', '.join(skipped)}")
        print()
        print_warn("The source file held PLAINTEXT passwords. Now:")
        print_warn("  1. Delete it (and purge it from version control history).")
        print_warn("  2. Rotate every imported password — they were exposed.")
        print()
    else:
        print_info("Usage: sofiavault auth import <users.json> [--db PATH]")


def cmd_key(key: bytes):
    """Print the base64 master key once, for provisioning SOFIAVAULT_KEY."""
    print()
    print_warn("This key unlocks your entire vault. Treat it exactly like")
    print_warn("your master password. It is shown ONCE and not stored.")
    print()
    print(f"  {style(base64.b64encode(key).decode('ascii'), C.BOLD)}")
    print()
    print_info("Server use: export SOFIAVAULT_KEY='<value>'  (or put it in a")
    print_info("0600 key file and set SOFIAVAULT_KEY_FILE=/path/to/file)")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Interactive REPL
# ─────────────────────────────────────────────────────────────────────────────

def _build_prompt() -> str:
    """Build the interactive prompt string."""
    if C._enabled:
        return f"{C.BOLD}{C.MAGENTA}sv{C.RESET}{C.DIM}>{C.RESET} "
    return "sv> "


def print_repl_help():
    """Print help for interactive mode."""
    print()
    print(f"  {style('Commands', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('<service>', C.CYAN)}              "
          f"Copy password {style('(fuzzy match)', C.DIM)}")
    print(f"  {style('show', C.CYAN)} {style('<service>', C.DIM)}         "
          f"Copy and display password")
    print(f"  {style('add', C.CYAN)}                    "
          f"Add new entry")
    print(f"  {style('edit', C.CYAN)} {style('<service>', C.DIM)}         "
          f"Edit an entry (Enter keeps values)")
    print(f"  {style('gen', C.CYAN)} {style('[len] [--mix]', C.DIM)}      "
          f"Generate a strong password")
    print(f"  {style('list', C.CYAN)} / {style('ls', C.CYAN)}              "
          f"List all services")
    print(f"  {style('delete', C.CYAN)} / {style('rm', C.CYAN)} "
          f"{style('<service>', C.DIM)}  Delete an entry")
    print(f"  {style('import', C.CYAN)} {style('<file>', C.DIM)}          "
          f"Import a CSV or a vault file")
    print(f"  {style('export', C.CYAN)}                 "
          f"Show vault file location to copy")
    print(f"  {style('wipe', C.CYAN)}                   "
          f"Destroy the vault permanently")
    print(f"  {style('help', C.CYAN)}                   "
          f"Show this help")
    print(f"  {style('exit', C.CYAN)} / {style('quit', C.CYAN)}            "
          f"Lock and exit")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Tab', C.DIM)} to complete  "
          f"{style(SYM_ARROWS, C.DIM)} for history  "
          f"{style('Ctrl+D', C.DIM)} to exit")
    print()


def print_oneshot_help():
    """Print help for one-shot CLI mode."""
    print(f"  {style('Usage', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  sofiavault                        "
          f"{style('Interactive mode', C.DIM)}")
    print(f"  sofiavault {style('<service>', C.CYAN)}            "
          f"{style('Copy password (fuzzy match)', C.DIM)}")
    print(f"  sofiavault {style('show', C.CYAN)} {style('<service>', C.DIM)}       "
          f"{style('Copy and display password', C.DIM)}")
    print(f"  sofiavault {style('add', C.CYAN)}                  "
          f"{style('Add new entry', C.DIM)}")
    print(f"  sofiavault {style('edit', C.CYAN)} {style('<service>', C.DIM)}       "
          f"{style('Edit an entry', C.DIM)}")
    print(f"  sofiavault {style('gen', C.CYAN)} {style('[len] [--mix]', C.DIM)}    "
          f"{style('Generate a strong password', C.DIM)}")
    print(f"  sofiavault {style('list', C.CYAN)}                 "
          f"{style('List all services', C.DIM)}")
    print(f"  sofiavault {style('delete', C.CYAN)} {style('<service>', C.DIM)}     "
          f"{style('Delete an entry', C.DIM)}")
    print(f"  sofiavault {style('import', C.CYAN)} {style('<file>', C.DIM)}        "
          f"{style('Import a CSV or a vault file', C.DIM)}")
    print(f"  sofiavault {style('export', C.CYAN)}               "
          f"{style('Show vault file location', C.DIM)}")
    print(f"  sofiavault {style('wipe', C.CYAN)}                 "
          f"{style('Destroy the vault permanently', C.DIM)}")
    print()
    print(f"  {style('Server / library', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  sofiavault {style('env set', C.CYAN)} {style('NAME < value', C.DIM)}  "
          f"{style('Store a secret (stdin, --from-file, --value)', C.DIM)}")
    print(f"  sofiavault {style('env get|del', C.CYAN)} {style('NAME', C.DIM)}     "
          f"{style('Read / remove one secret', C.DIM)}")
    print(f"  sofiavault {style('env import', C.CYAN)} {style('<.env>', C.DIM)}    "
          f"{style('Store dotenv secrets as env:* entries', C.DIM)}")
    print(f"  sofiavault {style('env export', C.CYAN)} {style('--allow F', C.DIM)} "
          f"{style('Dump allowlisted secrets (dotenv/json)', C.DIM)}")
    print(f"  sofiavault {style('env list', C.CYAN)}             "
          f"{style('List injectable env vars', C.DIM)}")
    print(f"  sofiavault {style('run', C.CYAN)} {style('--allow F -- <cmd>', C.DIM)} "
          f"{style('Exec a command with env:* injected', C.DIM)}")
    print(f"  sofiavault {style('rekey', C.CYAN)} {style('[--key-file P]', C.DIM)} "
          f"{style('Rotate the master key', C.DIM)}")
    print(f"  sofiavault {style('doctor', C.CYAN)}               "
          f"{style('Check a deployment would boot', C.DIM)}")
    print(f"  sofiavault {style('auth import-json', C.CYAN)} {style('<json>', C.DIM)} "
          f"{style('Build a user credential store', C.DIM)}")
    print(f"  sofiavault {style('auth', C.CYAN)} {style('list|reset|totp|set-flag', C.DIM)} "
          f"{style('Operate the user store', C.DIM)}")
    print(f"  sofiavault {style('key', C.CYAN)}                  "
          f"{style('Print master key for SOFIAVAULT_KEY', C.DIM)}")
    print()
    print(f"  {style('Examples', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  sofiavault amazon           "
          f"{style('Copy Amazon password', C.DIM)}")
    fuzzy_desc = "Fuzzy matches 'amazon'"
    print(f"  sofiavault amazn            "
          f"{style(fuzzy_desc, C.DIM)}")
    print("  sofiavault import ~/passwords.csv")
    print("  sofiavault run --allow secrets.allow -- uvicorn app:main")
    print("  echo \"$TOKEN\" | sofiavault env set API_TOKEN --vault /srv/app/secrets.db")
    print(f"  {style('All env/run/rekey/doctor commands take --vault PATH', C.DIM)}")
    print(f"  {style('(default: $SOFIAVAULT_DB) and add --help for details.', C.DIM)}")
    print()


class VaultREPL(cmd.Cmd):
    """Interactive SofiaVault shell."""

    intro = ""
    prompt = _build_prompt()

    def __init__(self, session: VaultSession):
        super().__init__()
        self.session = session

    def _check_lock(self) -> bool:
        """Re-authenticate if session expired. Returns False if auth fails.

        On expiry the key and decrypted index are dropped from memory
        immediately, before the user is prompted to re-authenticate.
        """
        if self.session.key is not None and not self.session.is_expired():
            return True
        self.session.lock()
        print()
        print_warn("Session locked. Please re-authenticate.")
        key = unlock_vault(self.session.conn)
        if key is None:
            return False
        self.session.unlock_with(key)
        # The vault file may have been modified while the session sat locked.
        _refuse_if_tampered(self.session)
        return True

    def precmd(self, line: str) -> str:
        if line.strip() in ('exit', 'quit', 'EOF', ''):
            return line
        if not self._check_lock():
            print_error("Authentication failed.")
            return ''
        self.session.touch()
        return line

    def emptyline(self):
        pass

    # ── Commands ──────────────────────────────────────────────────────────

    def do_add(self, _arg: str):
        """Add a new password entry"""
        cmd_add(self.session)

    def do_list(self, _arg: str):
        """List all stored services"""
        cmd_list(self.session)

    do_ls = do_list

    def do_get(self, arg: str):
        """Copy password for a service: get <service>"""
        if not arg.strip():
            print_info("Usage: get <service>  (or just type the service name)")
            return
        cmd_get(self.session, arg.strip())

    def do_show(self, arg: str):
        """Copy and display password on screen: show <service>"""
        if not arg.strip():
            print_info("Usage: show <service>")
            return
        cmd_get(self.session, arg.strip(), show=True)

    def do_edit(self, arg: str):
        """Edit an entry (Enter keeps current values): edit <service>"""
        if not arg.strip():
            print_info("Usage: edit <service>")
            return
        cmd_edit(self.session, arg.strip())

    def do_gen(self, arg: str):
        """Generate a strong password: gen [length] [--mix]"""
        cmd_gen(arg.strip())

    def do_delete(self, arg: str):
        """Delete an entry: delete <service>"""
        if not arg.strip():
            print_info("Usage: delete <service>")
            return
        cmd_delete(self.session, arg.strip())

    do_del = do_delete
    do_rm = do_delete

    def do_import(self, arg: str):
        """Import a CSV or a vault file from another device: import <file>"""
        target = arg.strip()
        if not target:
            print_info("Usage: import <path/to/file.csv>  (or a vault.db file)")
            return
        if _is_vault_file(Path(target).expanduser()):
            if cmd_import_vault(target):
                print(f"  {style('Restart SofiaVault to unlock the imported vault.', C.DIM)}")
                print()
                return True  # exit the REPL — the old session is stale
            return
        cmd_import(self.session, target)

    def do_export(self, _arg: str):
        """Show the vault file location for copying to another device"""
        cmd_export()

    def do_wipe(self, _arg: str):
        """Permanently destroy the vault (asks for password + confirmation)"""
        cmd_wipe(self.session)

    def do_help(self, arg: str):
        """Show help"""
        if arg:
            super().do_help(arg)
        else:
            print_repl_help()

    def do_exit(self, _arg: str):
        """Lock vault and exit"""
        self.session.lock()
        print()
        print(f"  {style('Vault locked. Goodbye!', C.DIM)} ♥")
        print()
        return True

    do_quit = do_exit

    def do_EOF(self, _arg: str):
        """Handle Ctrl+D"""
        print()
        return self.do_exit(_arg)

    def default(self, line: str):
        """Treat any unknown command as a service name lookup."""
        query = line.strip()
        if query:
            cmd_get(self.session, query)

    # ── Tab Completion ────────────────────────────────────────────────────

    def _complete_service(self, text: str) -> list[str]:
        names = [e.service for e in self.session.entries]
        if text:
            return [n for n in names if n.startswith(text.lower())]
        return names

    def complete_get(self, text, _line, _begidx, _endidx):
        return self._complete_service(text)

    def complete_show(self, text, _line, _begidx, _endidx):
        return self._complete_service(text)

    def complete_delete(self, text, _line, _begidx, _endidx):
        return self._complete_service(text)

    complete_del = complete_delete
    complete_rm = complete_delete
    complete_edit = complete_delete

    def completedefault(self, text, _line, _begidx, _endidx):
        return self._complete_service(text)


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def _migration_progress(done: int, total: int):
    if done == 0:
        print()
        print_info(f"Upgrading vault to encrypted-metadata format ({total} entries)...")
        print_info("This is a one-time step and may take a moment.")
    else:
        print_info(f"  {done}/{total}...")


def _open_vault(show_banner_on_setup: bool) -> tuple[sqlite3.Connection, bytes]:
    """Init DB, unlock (or set up) the vault, and run any pending migration."""
    conn = init_db()

    if not is_vault_initialized(conn):
        if show_banner_on_setup:
            print_banner()
        key = setup_master(conn)
    else:
        key = unlock_vault(conn)
        if key is None:
            sys.exit(1)

    # Update check runs before migration on purpose: if the user updates
    # and restarts, the new version handles any pending migration itself.
    check_for_updates()
    result = migrate_legacy_vault(conn, key, on_progress=_migration_progress)
    # Re-authenticate v2 blobs against their row/vault id. Without this a
    # 0.2.x vault would decrypt to nothing and look empty.
    upgraded = migrate_v2_to_v3(conn, key)
    if upgraded:
        print_info(f"Upgraded {upgraded} entries to the tamper-evident format.")
    # v4: persist the master record's Argon2 costs and cover it with the MAC.
    migrate_v3_to_v4(conn, key)
    if result.total:
        if result.failed:
            print_warn(f"Migrated {result.migrated}/{result.total} entries. "
                       f"{len(result.failed)} could not be decrypted and were "
                       f"left untouched: {', '.join(result.failed)}")
            print_warn(f"Original vault backup: {result.backup}")
        else:
            print_success(f"Vault upgraded {SYM_DASH} {result.migrated} "
                          "entries re-encrypted.")
            print_info(f"Backup of the original vault: {result.backup}")
        print()
    return conn, key


def _warn_corrupt(session: VaultSession):
    if session.corrupt_count:
        print_warn(f"{session.corrupt_count} entries could not be decrypted.")


def _refuse_if_tampered(session: VaultSession):
    """Fail closed when the entry-set MAC does not verify.

    The CLI must neither hand out nor re-sign secrets from a vault whose
    row set no longer matches its authentication tag — that mismatch is
    exactly the rollback/insertion/deletion evidence the MAC exists to
    surface, and the library (Vault, envload) already refuses it.
    """
    if not session.tampered:
        return
    print()
    print_error("TAMPERING DETECTED: this vault's entries do not match their")
    print_error("authentication tag. A secret may have been rolled back, added,")
    print_error("or removed by someone with write access to the vault file.")
    print()
    print_info("No secrets were revealed or written. If you have a trusted")
    print_info(f"backup, restore it over {paths.DB_PATH} and try again.")
    print_info("To destroy the vault securely instead, run: sofiavault wipe")
    print()
    session.lock()
    sys.exit(1)


def _verify_before_write(session: VaultSession):
    """Re-check the entry-set MAC against the file right before a write.

    The flag from the last reload is not enough: every write re-signs the
    current row set, so a vault file rewritten while the session sat idle
    would otherwise be laundered into a fresh valid MAC.

    Latched, never cleared: any writer holding the master key re-signs on
    every write, so a MAC that verifies again later says nothing about the
    edit this session already saw.
    """
    if not verify_entries_mac(session.conn, session.key):
        session.tampered = True
    _refuse_if_tampered(session)


def _run_oneshot(args: list[str]):
    """Run a single command and exit (backward-compatible mode)."""
    command = args[0].lower()

    # Commands that must not (or need not) unlock the local vault first
    if command in cli_server.SERVER_COMMANDS:
        # Non-interactive server commands: explicit --vault, open_auto
        # unlock chain, exit codes. `env import`/`env list` keep their 0.3.0
        # meaning; they simply no longer prompt when stdin is not a TTY.
        sys.exit(cli_server.main(args))
    if command == 'import' and len(args) > 1 \
            and _is_vault_file(Path(args[1]).expanduser()):
        # Importing a vault file must work on a fresh device with no local vault
        cmd_import_vault(args[1])
        return
    if command == 'gen':
        # Generating a password doesn't touch the vault
        cmd_gen(' '.join(args[1:]))
        return

    conn, key = _open_vault(show_banner_on_setup=True)
    session = VaultSession(conn, key)
    if command != 'wipe':
        # Wiping must stay reachable on a tampered vault — it is the
        # documented remediation, and it launders nothing.
        _refuse_if_tampered(session)
    _warn_corrupt(session)

    if command == 'add':
        cmd_add(session)
    elif command in ('list', 'ls'):
        cmd_list(session)
    elif command == 'show':
        if len(args) > 1:
            cmd_get(session, args[1], show=True)
        else:
            print_info("Usage: sofiavault show <service>")
    elif command == 'edit':
        if len(args) > 1:
            cmd_edit(session, args[1])
        else:
            print_info("Usage: sofiavault edit <service>")
    elif command == 'import':
        if len(args) > 1:
            cmd_import(session, args[1])
        else:
            print_info("Usage: sofiavault import <path/to/file.csv>")
    elif command == 'export':
        cmd_export()
    elif command == 'env':
        cmd_env(session, args[1:])
    elif command == 'key':
        cmd_key(key)
    elif command == 'wipe':
        cmd_wipe(session)
    elif command in ('delete', 'del', 'rm'):
        if len(args) > 1:
            cmd_delete(session, args[1])
        else:
            print_info("Usage: sofiavault delete <service>")
    else:
        query = command.split(':', 1)[1] if ':' in command else command
        cmd_get(session, query)

    session.lock()
    conn.close()


def _run_repl():
    """Launch the interactive REPL."""
    print_banner()
    conn, key = _open_vault(show_banner_on_setup=False)
    session = VaultSession(conn, key)
    _refuse_if_tampered(session)

    print_success(f"Vault unlocked  "
                  f"{style(f'({len(session.entries)} entries)', C.DIM)}")
    _warn_corrupt(session)
    print()
    print(f"  {style('Type a service name to search, or', C.DIM)} "
          f"{style('help', C.CYAN)} {style('for commands.', C.DIM)}")
    print()

    repl = VaultREPL(session)

    # Readline history
    try:
        import readline
        paths.HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if paths.HISTORY_PATH.exists():
            readline.read_history_file(str(paths.HISTORY_PATH))
        readline.set_history_length(500)
    except (ImportError, OSError):
        readline = None  # type: ignore[assignment]

    try:
        repl.cmdloop()
    except KeyboardInterrupt:
        print()
        print(f"\n  {style('Vault locked. Goodbye!', C.DIM)} ♥\n")
    finally:
        try:
            if readline:
                readline.write_history_file(str(paths.HISTORY_PATH))
                os.chmod(paths.HISTORY_PATH, 0o600)
        except (OSError, NameError):
            pass
        session.lock()
        conn.close()


def main():
    args = sys.argv[1:]

    if not args:
        _run_repl()
        return

    if args[0] in ('help', '-h', '--help'):
        print_banner()
        print_oneshot_help()
        return

    if args[0] in ('version', '--version', '-V'):
        print(f"SofiaVault {__version__}")
        return

    _run_oneshot(args)


if __name__ == '__main__':
    main()
