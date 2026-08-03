#!/usr/bin/env python3
"""
SofiaVault - A secure terminal password manager
Uses Argon2 for master key derivation, HKDF-SHA256 for per-entry keys,
and AES-256-GCM for encryption. All entry data (service, username, URL,
password) is stored inside a single authenticated ciphertext per entry.
"""

import base64
import cmd
import contextlib
import csv
import getpass
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from rapidfuzz import fuzz, process
except ImportError:
    print("Missing dependencies. Run:")
    print("  pip install argon2-cffi cryptography rapidfuzz")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

__version__ = "0.2.1"

DB_PATH = Path.home() / ".sofiavault" / "vault.db"
HISTORY_PATH = Path.home() / ".sofiavault" / ".history"
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits for AES-256
AUTO_LOCK_SECONDS = 300  # 5 minutes
CLIPBOARD_CLEAR_SECONDS = 45
UPDATE_FETCH_TIMEOUT = 5   # seconds; keeps unlock fast when offline
UPDATE_PULL_TIMEOUT = 60

# Domain-separation constant: HKDF info and GCM associated data for v2 entries
ENTRY_CONTEXT = b"sofiavault-entry-v2"

# Box drawing and symbol characters (extracted for Python 3.9 f-string compat)
SYM_BOX_TOP = "┌"      # ┌
SYM_BOX_SIDE = "│"     # │
SYM_BOX_BOT = "└"      # └
SYM_BOX_H = "─"        # ─
SYM_CHECK = "✓"        # ✓
SYM_CROSS = "✗"        # ✗
SYM_BULLET = "•"       # •
SYM_SKIP = "⊘"         # ⊘
SYM_HEART = "♥"        # ♥
SYM_ARROWS = "↑↓" # ↑↓
SYM_DOT = "·"          # ·
SYM_DASH = "—"         # —


# ─────────────────────────────────────────────────────────────────────────────
# Terminal Colors (ANSI - works on both light and dark themes)
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI color codes. Disabled automatically if output is not a TTY."""
    _enabled = sys.stdout.isatty()

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Standard colors (visible on both light and dark backgrounds)
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright variants
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
# Crypto Functions
# ─────────────────────────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from master password using Argon2id"""
    return hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID
    )


def derive_entry_key(master_key: bytes, salt: bytes) -> bytes:
    """Derive a per-entry key from the master key using HKDF-SHA256.

    The master key already has full entropy (Argon2 output), so a fast
    KDF is the correct tool here — no need for a memory-hard pass per entry.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=ENTRY_CONTEXT,
    ).derive(master_key)


def encrypt(plaintext: str, key: bytes, aad: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)"""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: Optional[bytes] = None) -> str:
    """Decrypt ciphertext with AES-256-GCM"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode('utf-8')


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
    """Return the git clone this script runs from, or None (pip installs etc.)."""
    try:
        here = Path(__file__).resolve().parent
    except OSError:
        return None
    if (here / '.git').exists():
        return here
    return None


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
# Database Functions
# ─────────────────────────────────────────────────────────────────────────────

def _harden_storage_perms():
    """Restrict vault directory/files to the owning user (POSIX).

    Also repairs permissions of vaults created by older versions.
    The directory is only touched when it is the real ~/.sofiavault dir,
    so tests pointing DB_PATH at a temp dir never chmod shared locations.
    """
    with contextlib.suppress(OSError):
        if DB_PATH.parent.name == '.sofiavault':
            os.chmod(DB_PATH.parent, 0o700)
    with contextlib.suppress(OSError):
        if DB_PATH.exists():
            os.chmod(DB_PATH, 0o600)
    with contextlib.suppress(OSError):
        if HISTORY_PATH.exists():
            os.chmod(HISTORY_PATH, 0o600)


def init_db() -> sqlite3.Connection:
    """Initialize database and return connection"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _harden_storage_perms()
    conn = sqlite3.connect(str(DB_PATH))
    # Overwrite deleted content with zeros so removed entries (and migrated
    # legacy plaintext) don't linger in the database file's free pages.
    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verify_hash BLOB NOT NULL
        )
    """)
    # v2 entries: all fields (service, username, url, password, created_at)
    # live inside one authenticated AES-GCM blob. No plaintext metadata,
    # and nothing an attacker can relabel or swap between rows.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            blob BLOB NOT NULL
        )
    """)
    conn.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', '2')")
    conn.commit()
    _harden_storage_perms()
    return conn


def is_vault_initialized(conn: sqlite3.Connection) -> bool:
    """Check if master password has been set"""
    cur = conn.execute("SELECT COUNT(*) FROM master")
    return cur.fetchone()[0] > 0


def save_master(conn: sqlite3.Connection, salt: bytes, verify_hash: bytes):
    """Save master password verification data"""
    conn.execute(
        "INSERT OR REPLACE INTO master (id, salt, verify_hash) VALUES (1, ?, ?)",
        (salt, verify_hash)
    )
    conn.commit()


def get_master_data(conn: sqlite3.Connection) -> tuple[bytes, bytes]:
    """Get master salt and verify hash"""
    cur = conn.execute("SELECT salt, verify_hash FROM master WHERE id = 1")
    row = cur.fetchone()
    return row[0], row[1]


@dataclass
class VaultEntry:
    """Decrypted entry metadata held in memory while the vault is unlocked."""
    id: int
    service: str
    username: str
    url: str


def save_entry(conn: sqlite3.Connection, key: bytes, service: str, username: str,
               password: str, url: str = '', created_at: Optional[str] = None,
               commit: bool = True) -> int:
    """Encrypt and save a password entry. Returns the new row id."""
    if created_at is None:
        created_at = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    payload = json.dumps({
        'service': service.lower().strip(),
        'username': username,
        'url': url,
        'password': password,
        'created_at': created_at,
    }, ensure_ascii=False)

    entry_salt = secrets.token_bytes(SALT_SIZE)
    entry_key = derive_entry_key(key, entry_salt)
    nonce, blob = encrypt(payload, entry_key, aad=ENTRY_CONTEXT)

    cur = conn.execute(
        "INSERT INTO entries_v2 (salt, nonce, blob) VALUES (?, ?, ?)",
        (entry_salt, nonce, blob)
    )
    if commit:
        conn.commit()
    return cur.lastrowid


def _decrypt_entry_row(key: bytes, salt: bytes, nonce: bytes, blob: bytes) -> dict:
    """Decrypt one entry blob to its dict payload. Raises on tampering/corruption."""
    entry_key = derive_entry_key(key, salt)
    return json.loads(decrypt(nonce, blob, entry_key, aad=ENTRY_CONTEXT))


def load_entries(conn: sqlite3.Connection, key: bytes) -> tuple[list[VaultEntry], int]:
    """Decrypt metadata for all entries. Returns (entries, corrupt_count)."""
    entries = []
    corrupt = 0
    cur = conn.execute("SELECT id, salt, nonce, blob FROM entries_v2")
    for row_id, salt, nonce, blob in cur.fetchall():
        try:
            data = _decrypt_entry_row(key, salt, nonce, blob)
            entries.append(VaultEntry(
                id=row_id,
                service=data.get('service', ''),
                username=data.get('username', ''),
                url=data.get('url', ''),
            ))
        except Exception:
            corrupt += 1
    entries.sort(key=lambda e: e.service)
    return entries, corrupt


def get_password(conn: sqlite3.Connection, key: bytes, entry_id: int) -> Optional[str]:
    """Decrypt and return the password for one entry, or None on failure."""
    cur = conn.execute("SELECT salt, nonce, blob FROM entries_v2 WHERE id = ?", (entry_id,))
    row = cur.fetchone()
    if row is None:
        return None
    try:
        return _decrypt_entry_row(key, row[0], row[1], row[2])['password']
    except Exception:
        return None


def get_entry_by_service(entries: list[VaultEntry], service: str) -> Optional[VaultEntry]:
    """Find an entry by exact service name in the decrypted index."""
    target = service.lower().strip()
    for entry in entries:
        if entry.service == target:
            return entry
    return None


def delete_entry(conn: sqlite3.Connection, entry_id: int):
    """Delete entry by ID"""
    conn.execute("DELETE FROM entries_v2 WHERE id = ?", (entry_id,))
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Legacy (v1) Migration
# ─────────────────────────────────────────────────────────────────────────────

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    )
    return cur.fetchone()[0] > 0


def migrate_legacy_vault(conn: sqlite3.Connection, key: bytes) -> None:
    """Upgrade a v1 vault (plaintext metadata, Argon2 entry keys) to v2.

    Runs automatically after unlock. Safety properties:
      - The original database file is backed up (once) before anything changes.
      - All re-encryption happens in a single transaction; a crash or error
        rolls back and leaves the vault exactly as it was.
      - Entries that fail to decrypt (already corrupt in v1) are left in the
        legacy table untouched and reported — never silently dropped.
    """
    if not _table_exists(conn, 'entries'):
        return

    # Very old v1 databases may lack the url column
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute("ALTER TABLE entries ADD COLUMN url TEXT DEFAULT ''")

    rows = conn.execute(
        "SELECT id, service, username, url, salt, nonce, encrypted_password, created_at "
        "FROM entries"
    ).fetchall()

    if not rows:
        conn.execute("DROP TABLE entries")
        conn.commit()
        return

    backup = DB_PATH.with_name(DB_PATH.name + ".v1-backup")
    if DB_PATH.exists() and not backup.exists():
        shutil.copy2(DB_PATH, backup)
        with contextlib.suppress(OSError):
            os.chmod(backup, 0o600)

    print()
    print_info(f"Upgrading vault to encrypted-metadata format ({len(rows)} entries)...")
    print_info("This is a one-time step and may take a moment.")

    failed = []
    try:
        for i, (row_id, service, username, url, salt, nonce, enc, created_at) in enumerate(
            rows, 1
        ):
            legacy_key = derive_key(base64.b64encode(key).decode(), salt)
            try:
                password = decrypt(nonce, enc, legacy_key)
            except Exception:
                failed.append(service)
                continue
            save_entry(conn, key, service, username, password, url or '',
                       created_at=str(created_at or ''), commit=False)
            conn.execute("DELETE FROM entries WHERE id = ?", (row_id,))
            if i % 20 == 0:
                print_info(f"  {i}/{len(rows)}...")
        if not failed:
            conn.execute("DROP TABLE entries")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    # Rewrite the database file so freed pages holding v1 plaintext metadata
    # are physically removed, not just marked unused.
    conn.execute("VACUUM")

    migrated = len(rows) - len(failed)
    if failed:
        print_warn(f"Migrated {migrated}/{len(rows)} entries. "
                   f"{len(failed)} could not be decrypted and were left untouched: "
                   f"{', '.join(failed)}")
        print_warn(f"Original vault backup: {backup}")
    else:
        print_success(f"Vault upgraded {SYM_DASH} {migrated} entries re-encrypted.")
        print_info(f"Backup of the original vault: {backup}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzy Matching
# ─────────────────────────────────────────────────────────────────────────────

def fuzzy_find_service(
    entries: list[VaultEntry], query: str, threshold: int = 60
) -> list[tuple[VaultEntry, int]]:
    """Find entries matching query using fuzzy matching on the decrypted index."""
    if not entries:
        return []

    names = [e.service for e in entries]
    matches = process.extract(query.lower(), names, scorer=fuzz.ratio, limit=5)

    results = [
        (entries[idx], score)
        for _name, score, idx in matches
        if score >= threshold
    ]
    return sorted(results, key=lambda x: x[1], reverse=True)


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
                                ,;;
              !!!!!!!' ,!!!!;  ;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!>,
           !!!!' ,.'!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
          !!!!!!!!!!!'                                             <> '!!!!!!!
          !!!!!!!!!!                                                '!> '!!!!!
          !!!!!!!!'                                                  '!> '!!!!
          !!!!!!!                                          .,,.       '!>  !!!
          !!!!          d$$$$$$$$$$$$?????-           d$$P   ????$$$$$,  '! !!!!
          !!!           ???$$????      '?c, ,,cccc, '?           ?$    '!>'!!!
          !!> zc,._                    ,cc,$$$$$$$$$$bc                  !> !!!
          !! <$$L   '"c,   b,       ,c$$$$$$$$$$$$$$$$$$c ,,c,           '! '!!
          !! $$$$$$ccc$$?? 'M, ;;' c$$$$$$$   '"$$$b'?$$"'?             '!  !!!
          ! <$$$$$$$$P  , !!!!!!!!!!!!!!!!!
          ! $$$$L._   ;!!!''',,  $$$$$$$$$$F ,$PFz,  ?$F  ,cb             !! !!
          > $$$$$r'Mn,'!' ,d$$F d$$$$$$$$$$$c$$$ $$c.  ?,;' )             !! !!
           <$$$$P  ,, ,/ ,$$$$$F,$$$$$$$$$$$$$$$$ "   34$?,ccF ..::..      !! !!
           J$$$P :!!!! z$$$$$$bJ$$$$$$$$$$$$$?$$,'hcdFdF  .::::::    ;!! !!!!
           $b =e,_'!! <$$$$$$$$$$$$$$$$$$$$$$h?$$,'? .- .:::::::::::'    ;!> !!
           $$$c  M';f $$$$$$$$$$$$$$$$$$$$$$$$$L?$, ,z$$L':::::::'' .    !!> !!
          J$$$F >;;!  $$$$P)$$$$$$$$$$$$$$$$$$$$$$bd$$$$$ 4c,,,,cd$F?c   !!> !!
          J$$$F !!!!> $$$P,$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ J$$$$$P?$P'$$  !!' !!
          J$$$F ',,'>  ?$F,$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $?c$$ 3$  ?bcr !!  !!
          J$$c,' ' ,!; ? J$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'<$cP    ,$c$$F !! .!!
          $P   ?b,'!!!;  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$' c,,cdP  ,$$$$P :!! :!!
          L    d$$c '!!! $$$$$$$$$$$$$$$$$$$$$$$$$$$$$' d$$$F,zP $$$$F z,'' :!!
          $$$$$$$$$$c '' '$$$$$$$$$$$$$$$$$$$$$$$$$$$',$$$",d$" d$$P",d   ". '!
                ,$$$$$  ,c$$PF )$$$$$$$$bc,.  ?$P ,c$$PFF   ,,,   d$$$$$$ccc$$$
               ,$$$$F d$$P ,zd$$$PF ,J$$$$$$$be. ' .,ccd$$$$$$$$b,  $$$$$$$$$$$
            ,zd$$$$$L ?$ ,d$$$P ,cd$$$$$$$P  ,,cd$$$$$$$$$$$$$$$???-'?$$$$$$$$$
          ?$$$$$$$$$$b,. $$$$ ,d$$$$$$$P ,c$$$$$$$$$$$$$$$$$P  ,ccccccc,,.CC$$$
          ?$$$$$$$$$$$$$,  ?L $$$$$$$P ,$$$$$$$$$$$$$$$$$$$P ,d$$$$$$$$$$$$$$$$$
          <$$$$$$$$$$$$$$$$cc,.     ,c$$$$$$$$$$$$$$$$$$  z$$$$$$$$$$$$$$$$$$$P
          '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$P ,z$$$$$$$$$$$$$$$$$$$P"
            ?$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$P',d$$$$$$$$$$$$$$$$$PF
              "?$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$P"    '""""??????""""""
                 "?$$$$$$$$$$$$$$$$$$$$$$$$PF"
                     ""???$$$$$$$$$$PF""'
"""
    print(style(art, C.MAGENTA))
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
# Vault Session
# ─────────────────────────────────────────────────────────────────────────────

class VaultSession:
    """Holds the active vault connection, derived key, and decrypted index."""

    def __init__(self, conn: sqlite3.Connection, key: Optional[bytes]):
        self.conn = conn
        self.key = key
        self.entries: list[VaultEntry] = []
        self.corrupt_count = 0
        self.last_activity = time.time()
        if key is not None:
            self.reload()

    def reload(self):
        """Rebuild the decrypted metadata index from the database."""
        self.entries, self.corrupt_count = load_entries(self.conn, self.key)

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

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)

    # Store hash of the key for verification (not the key itself!)
    verify_salt = secrets.token_bytes(SALT_SIZE)
    verify_hash = derive_key(base64.b64encode(key).decode(), verify_salt)

    save_master(conn, salt + verify_salt, verify_hash)
    print()
    print_success("You're all set! Your vault is ready. ♥")
    print()
    return key


def unlock_vault(conn: sqlite3.Connection) -> Optional[bytes]:
    """Unlock vault with master password"""
    password = get_master_password()

    combined_salt, stored_hash = get_master_data(conn)
    salt = combined_salt[:SALT_SIZE]
    verify_salt = combined_salt[SALT_SIZE:]

    key = derive_key(password, salt)
    verify_hash = derive_key(base64.b64encode(key).decode(), verify_salt)

    if not hmac.compare_digest(verify_hash, stored_hash):
        print_error("Wrong password.")
        return None

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

    # Check if exists
    existing = get_entry_by_service(session.entries, service)
    if existing:
        confirm = input(
            f"  {style('!', C.YELLOW)} '{service}' already exists. "
            f"Overwrite? {style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm != 'y':
            print_info("Cancelled.")
            return
        delete_entry(session.conn, existing.id)

    username = input(f"  {style('Username/Email', C.DIM)}: ").strip()
    if not username:
        print_error("Username required.")
        return

    password = getpass.getpass(f"  {style('Password', C.DIM)} (hidden): ")
    if not password:
        print_error("Password required.")
        return

    save_entry(session.conn, session.key, service, username, password)
    session.reload()
    print()
    print_success(f"Saved {style(service, C.CYAN)} for {username}")
    print()


def cmd_get(session: VaultSession, query: str, show: bool = False):
    """Get password for a service (fuzzy matched)"""
    # Try exact match first
    exact = get_entry_by_service(session.entries, query)
    if exact:
        _reveal_entry(session, exact, show=show)
        return

    # Fuzzy match
    matches = fuzzy_find_service(session.entries, query)

    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print_info("Type 'list' to see all entries.")
        print()
        return

    if len(matches) == 1 and matches[0][1] >= 80:
        # High confidence single match
        entry, score = matches[0]
        _reveal_entry(session, entry, match_score=score, show=show)
        return

    # Multiple matches or low confidence - ask user
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
            delete_entry(session.conn, entry.id)
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
                delete_entry(session.conn, entry.id)
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

    # Required columns (case-insensitive matching)
    required = {'TITLE', 'PASSWORD', 'USERNAME'}

    imported = 0
    skipped = 0
    errors = 0

    existing_services = {e.service for e in session.entries}

    try:
        with open(path, encoding='utf-8-sig') as f:  # utf-8-sig handles BOM
            # Detect delimiter
            sample = f.read(4096)
            f.seek(0)

            # Try to detect delimiter
            sniffer = csv.Sniffer()
            try:
                dialect = sniffer.sniff(sample, delimiters=',;\t|')
            except csv.Error:
                dialect = csv.excel  # Default to comma

            reader = csv.DictReader(f, dialect=dialect)

            # Normalize column names to uppercase
            if reader.fieldnames is None:
                print_error("CSV file appears to be empty")
                print()
                return

            # Create mapping from actual column names to uppercase
            col_map = {col.upper().strip(): col for col in reader.fieldnames}

            # Check for required columns
            missing = required - set(col_map.keys())
            if missing:
                print_error(f"Missing required columns: {', '.join(missing)}")
                print_info(f"Found: {', '.join(reader.fieldnames)}")
                print_info("Required: TITLE, PASSWORD, USERNAME")
                print_info("Optional: URL")
                print()
                return

            # Process rows
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
    print(f"  {style('list', C.CYAN)} / {style('ls', C.CYAN)}              "
          f"List all services")
    print(f"  {style('delete', C.CYAN)} / {style('rm', C.CYAN)} "
          f"{style('<service>', C.DIM)}  Delete an entry")
    print(f"  {style('import', C.CYAN)} {style('<file>', C.DIM)}          "
          f"Import from CSV")
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
    print(f"  sofiavault {style('list', C.CYAN)}                 "
          f"{style('List all services', C.DIM)}")
    print(f"  sofiavault {style('delete', C.CYAN)} {style('<service>', C.DIM)}     "
          f"{style('Delete an entry', C.DIM)}")
    print(f"  sofiavault {style('import', C.CYAN)} {style('<file>', C.DIM)}        "
          f"{style('Import from CSV', C.DIM)}")
    print(f"  sofiavault {style('help', C.CYAN)}                 "
          f"{style('Show this help', C.DIM)}")
    print()
    print(f"  {style('Examples', C.BOLD)}")
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  sofiavault amazon           "
          f"{style('Copy Amazon password', C.DIM)}")
    fuzzy_desc = "Fuzzy matches 'amazon'"
    print(f"  sofiavault amazn            "
          f"{style(fuzzy_desc, C.DIM)}")
    print("  sofiavault import ~/passwords.csv")
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

    def do_delete(self, arg: str):
        """Delete an entry: delete <service>"""
        if not arg.strip():
            print_info("Usage: delete <service>")
            return
        cmd_delete(self.session, arg.strip())

    do_del = do_delete
    do_rm = do_delete

    def do_import(self, arg: str):
        """Import from CSV: import <file>"""
        if not arg.strip():
            print_info("Usage: import <path/to/file.csv>")
            return
        cmd_import(self.session, arg.strip())

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

    def completedefault(self, text, _line, _begidx, _endidx):
        return self._complete_service(text)


# ─────────────────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────

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
    migrate_legacy_vault(conn, key)
    return conn, key


def _warn_corrupt(session: VaultSession):
    if session.corrupt_count:
        print_warn(f"{session.corrupt_count} entries could not be decrypted.")


def _run_oneshot(args: list[str]):
    """Run a single command and exit (backward-compatible mode)."""
    conn, key = _open_vault(show_banner_on_setup=True)
    session = VaultSession(conn, key)
    _warn_corrupt(session)

    command = args[0].lower()

    if command == 'add':
        cmd_add(session)
    elif command in ('list', 'ls'):
        cmd_list(session)
    elif command == 'show':
        if len(args) > 1:
            cmd_get(session, args[1], show=True)
        else:
            print_info("Usage: sofiavault show <service>")
    elif command == 'import':
        if len(args) > 1:
            cmd_import(session, args[1])
        else:
            print_info("Usage: sofiavault import <path/to/file.csv>")
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
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if HISTORY_PATH.exists():
            readline.read_history_file(str(HISTORY_PATH))
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
                readline.write_history_file(str(HISTORY_PATH))
                os.chmod(HISTORY_PATH, 0o600)
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
