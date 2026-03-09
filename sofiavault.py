#!/usr/bin/env python3
"""
SofiaVault - A secure terminal password manager
Uses Argon2 for key derivation and AES-256-GCM for encryption
"""

import base64
import cmd
import contextlib
import csv
import getpass
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from rapidfuzz import fuzz, process
except ImportError:
    print("Missing dependencies. Run:")
    print("  pip install argon2-cffi cryptography rapidfuzz")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

DB_PATH = Path.home() / ".sofiavault" / "vault.db"
HISTORY_PATH = Path.home() / ".sofiavault" / ".history"
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits for AES-256
AUTO_LOCK_SECONDS = 300  # 5 minutes

# Box drawing and symbol characters (extracted for Python 3.9 f-string compat)
SYM_BOX_TOP = "\u250c"      # ┌
SYM_BOX_SIDE = "\u2502"     # │
SYM_BOX_BOT = "\u2514"      # └
SYM_BOX_H = "\u2500"        # ─
SYM_CHECK = "\u2713"        # ✓
SYM_CROSS = "\u2717"        # ✗
SYM_BULLET = "\u2022"       # •
SYM_SKIP = "\u2298"         # ⊘
SYM_HEART = "♥"        # ♥
SYM_ARROWS = "\u2191\u2193" # ↑↓
SYM_DOT = "\u00b7"          # ·
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


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)"""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """Decrypt ciphertext with AES-256-GCM"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
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


# ─────────────────────────────────────────────────────────────────────────────
# Database Functions
# ─────────────────────────────────────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    """Initialize database and return connection"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verify_hash BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            url TEXT DEFAULT '',
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL,
            encrypted_password BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service ON entries(service)")

    # Migration: add url column if missing (for existing databases)
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute("ALTER TABLE entries ADD COLUMN url TEXT DEFAULT ''")

    conn.commit()
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


def save_entry(conn: sqlite3.Connection, service: str, username: str,
               salt: bytes, nonce: bytes, encrypted_password: bytes, url: str = ''):
    """Save a password entry"""
    conn.execute(
        """INSERT INTO entries (service, username, url, salt, nonce, encrypted_password)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (service.lower(), username, url, salt, nonce, encrypted_password)
    )
    conn.commit()


def get_all_services(conn: sqlite3.Connection) -> list[tuple[int, str, str]]:
    """Get all services with their IDs and usernames"""
    cur = conn.execute("SELECT id, service, username FROM entries ORDER BY service")
    return cur.fetchall()


def get_entry_by_service(conn: sqlite3.Connection, service: str) -> Optional[tuple]:
    """Get entry by exact service name"""
    cur = conn.execute(
        "SELECT id, service, username, url, salt, nonce, encrypted_password "
        "FROM entries WHERE service = ?",
        (service.lower(),)
    )
    return cur.fetchone()


def delete_entry(conn: sqlite3.Connection, entry_id: int):
    """Delete entry by ID"""
    conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzy Matching
# ─────────────────────────────────────────────────────────────────────────────

def fuzzy_find_service(
    conn: sqlite3.Connection, query: str, threshold: int = 60
) -> list[tuple]:
    """Find services matching query using fuzzy matching"""
    services = get_all_services(conn)
    if not services:
        return []

    service_names = [s[1] for s in services]
    matches = process.extract(query.lower(), service_names, scorer=fuzz.ratio, limit=5)

    results = []
    for match_name, score, _ in matches:
        if score >= threshold:
            for s in services:
                if s[1] == match_name:
                    results.append((s, score))
                    break

    return sorted(results, key=lambda x: x[1], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Display Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _terminal_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _hr(char: str = "\u2500") -> str:
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
                match_score: int = 0):
    """Print a password entry with nice formatting."""
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

    print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Pass    ', C.DIM)} "
          f"{style(password, C.BOLD, C.GREEN)}")

    copied = copy_to_clipboard(password)
    if copied:
        print(f"  {style(SYM_BOX_SIDE, C.DIM)}")
        print(f"  {style(SYM_BOX_SIDE, C.DIM)} {style('Copied to clipboard', C.DIM, C.GREEN)}")

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

    if verify_hash != stored_hash:
        print_error("Wrong password.")
        return None

    return key


def cmd_add(conn: sqlite3.Connection, key: bytes):
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
    existing = get_entry_by_service(conn, service)
    if existing:
        confirm = input(
            f"  {style('!', C.YELLOW)} '{service}' already exists. "
            f"Overwrite? {style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm != 'y':
            print_info("Cancelled.")
            return
        delete_entry(conn, existing[0])

    username = input(f"  {style('Username/Email', C.DIM)}: ").strip()
    if not username:
        print_error("Username required.")
        return

    password = getpass.getpass(f"  {style('Password', C.DIM)} (hidden): ")
    if not password:
        print_error("Password required.")
        return

    # Encrypt with a unique salt for this entry
    entry_salt = secrets.token_bytes(SALT_SIZE)
    entry_key = derive_key(base64.b64encode(key).decode(), entry_salt)
    nonce, encrypted = encrypt(password, entry_key)

    save_entry(conn, service, username, entry_salt, nonce, encrypted)
    print()
    print_success(f"Saved {style(service, C.CYAN)} for {username}")
    print()


def cmd_get(conn: sqlite3.Connection, key: bytes, query: str):
    """Get password for a service (fuzzy matched)"""
    # Try exact match first
    exact = get_entry_by_service(conn, query)
    if exact:
        _entry_id, service, username, url, salt, nonce, encrypted = exact
        entry_key = derive_key(base64.b64encode(key).decode(), salt)
        try:
            password = decrypt(nonce, encrypted, entry_key)
            print_entry(service, username, url, password)
            return
        except Exception:
            print_error("Decryption failed. Database may be corrupted.")
            return

    # Fuzzy match
    matches = fuzzy_find_service(conn, query)

    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print_info("Type 'list' to see all entries.")
        print()
        return

    if len(matches) == 1 and matches[0][1] >= 80:
        # High confidence single match
        entry, score = matches[0]
        _entry_id, service, username = entry

        full_entry = get_entry_by_service(conn, service)
        if full_entry:
            _, _, _, url, salt, nonce, encrypted = full_entry
            entry_key = derive_key(base64.b64encode(key).decode(), salt)
            password = decrypt(nonce, encrypted, entry_key)
            print_entry(service, username, url, password, match_score=score)
            return

    # Multiple matches or low confidence - ask user
    print()
    print(f"  {style('Found', C.DIM)} {style(str(len(matches)), C.BOLD)} "
          f"{style('possible matches for', C.DIM)} "
          f"'{style(query, C.CYAN)}':")
    print()
    for i, (entry, score) in enumerate(matches, 1):
        score_color = C.GREEN if score >= 80 else C.YELLOW if score >= 60 else C.RED
        print(f"  {style(f'[{i}]', C.BOLD)} {entry[1]} "
              f"{style(f'({entry[2]})', C.DIM)}  "
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
            full_entry = get_entry_by_service(conn, entry[1])
            if full_entry:
                _, service, username, url, salt, nonce, encrypted = full_entry
                entry_key = derive_key(base64.b64encode(key).decode(), salt)
                password = decrypt(nonce, encrypted, entry_key)
                print_entry(service, username, url, password)
    except (ValueError, IndexError):
        print_error("Invalid selection.")


def cmd_list(conn: sqlite3.Connection):
    """List all stored services"""
    services = get_all_services(conn)

    if not services:
        print()
        print_info("No passwords saved yet.")
        print_info("Use 'add' to store your first one. ♥")
        print()
        return

    print()
    print(f"  {style(_hr(), C.DIM)}")
    print(f"  {style('Your Passwords', C.BOLD)}  "
          f"{style(f'({len(services)})', C.DIM)}")
    print(f"  {style(_hr(), C.DIM)}")
    print()
    for _, service, username in services:
        print(f"  {style(SYM_BULLET, C.CYAN)} {style(service, C.BOLD)}"
              f"  {style(username, C.DIM)}")
    print()


def cmd_delete(conn: sqlite3.Connection, query: str):
    """Delete an entry"""
    matches = fuzzy_find_service(conn, query, threshold=70)

    if not matches:
        print()
        print_error(f"No matches found for '{query}'")
        print()
        return

    if len(matches) == 1:
        entry, _score = matches[0]
        confirm = input(
            f"  {style('!', C.YELLOW)} Delete "
            f"'{style(entry[1], C.BOLD)}' ({entry[2]})? "
            f"{style('[y/N]', C.DIM)}: "
        ).strip().lower()
        if confirm == 'y':
            delete_entry(conn, entry[0])
            print_success(f"Deleted '{entry[1]}'")
        print()
        return

    print()
    print(f"  {style('Multiple matches for', C.DIM)} '{style(query, C.CYAN)}':")
    print()
    for i, (entry, _score) in enumerate(matches, 1):
        print(f"  {style(f'[{i}]', C.BOLD)} {entry[1]} "
              f"{style(f'({entry[2]})', C.DIM)}")
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
                f"'{style(entry[1], C.BOLD)}'? "
                f"{style('[y/N]', C.DIM)}: "
            ).strip().lower()
            if confirm == 'y':
                delete_entry(conn, entry[0])
                print_success(f"Deleted '{entry[1]}'")
            print()
    except (ValueError, IndexError):
        print_error("Invalid selection.")


def cmd_import(conn: sqlite3.Connection, key: bytes, csv_path: str):
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

                    existing = get_entry_by_service(conn, title)
                    if existing:
                        print(f"  {style(SYM_SKIP, C.DIM)} Row {row_num}: "
                              f"'{title}' {style('already exists', C.DIM)}")
                        skipped += 1
                        continue

                    entry_salt = secrets.token_bytes(SALT_SIZE)
                    entry_key = derive_key(
                        base64.b64encode(key).decode(), entry_salt
                    )
                    nonce, encrypted = encrypt(password, entry_key)

                    save_entry(conn, title, username, entry_salt, nonce,
                               encrypted, url)
                    print_success(f"{title} ({username})")
                    imported += 1

                except Exception as e:
                    print_error(f"Row {row_num}: {e}")
                    errors += 1

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
# Vault Session
# ─────────────────────────────────────────────────────────────────────────────

class VaultSession:
    """Holds the active vault connection and derived key."""
    def __init__(self, conn: sqlite3.Connection, key: bytes):
        self.conn = conn
        self.key = key
        self.last_activity = time.time()

    def touch(self):
        self.last_activity = time.time()

    def is_expired(self) -> bool:
        return time.time() - self.last_activity > AUTO_LOCK_SECONDS


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
          f"Get password {style('(fuzzy match)', C.DIM)}")
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
          f"{style('Get password (fuzzy match)', C.DIM)}")
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
          f"{style('Get Amazon password', C.DIM)}")
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
        """Re-authenticate if session expired. Returns False if auth fails."""
        if not self.session.is_expired():
            return True
        print()
        print_warn("Session timed out. Please re-authenticate.")
        key = unlock_vault(self.session.conn)
        if key is None:
            return False
        self.session.key = key
        self.session.touch()
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
        cmd_add(self.session.conn, self.session.key)

    def do_list(self, _arg: str):
        """List all stored services"""
        cmd_list(self.session.conn)

    do_ls = do_list

    def do_get(self, arg: str):
        """Get password for a service: get <service>"""
        if not arg.strip():
            print_info("Usage: get <service>  (or just type the service name)")
            return
        cmd_get(self.session.conn, self.session.key, arg.strip())

    def do_delete(self, arg: str):
        """Delete an entry: delete <service>"""
        if not arg.strip():
            print_info("Usage: delete <service>")
            return
        cmd_delete(self.session.conn, arg.strip())

    do_del = do_delete
    do_rm = do_delete

    def do_import(self, arg: str):
        """Import from CSV: import <file>"""
        if not arg.strip():
            print_info("Usage: import <path/to/file.csv>")
            return
        cmd_import(self.session.conn, self.session.key, arg.strip())

    def do_help(self, arg: str):
        """Show help"""
        if arg:
            super().do_help(arg)
        else:
            print_repl_help()

    def do_exit(self, _arg: str):
        """Lock vault and exit"""
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
            cmd_get(self.session.conn, self.session.key, query)

    # ── Tab Completion ────────────────────────────────────────────────────

    def _complete_service(self, text: str) -> list[str]:
        services = get_all_services(self.session.conn)
        names = [s[1] for s in services]
        if text:
            return [n for n in names if n.startswith(text.lower())]
        return names

    def complete_get(self, text, _line, _begidx, _endidx):
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

def _run_oneshot(args: list[str]):
    """Run a single command and exit (backward-compatible mode)."""
    conn = init_db()

    if not is_vault_initialized(conn):
        print_banner()
        key = setup_master(conn)
    else:
        key = unlock_vault(conn)
        if key is None:
            sys.exit(1)

    command = args[0].lower()

    if command == 'add':
        cmd_add(conn, key)
    elif command in ('list', 'ls'):
        cmd_list(conn)
    elif command == 'import':
        if len(args) > 1:
            cmd_import(conn, key, args[1])
        else:
            print_info("Usage: sofiavault import <path/to/file.csv>")
    elif command in ('delete', 'del', 'rm'):
        if len(args) > 1:
            cmd_delete(conn, args[1])
        else:
            print_info("Usage: sofiavault delete <service>")
    else:
        query = command.split(':', 1)[1] if ':' in command else command
        cmd_get(conn, key, query)

    conn.close()


def _run_repl():
    """Launch the interactive REPL."""
    print_banner()
    conn = init_db()

    if not is_vault_initialized(conn):
        key = setup_master(conn)
    else:
        key = unlock_vault(conn)
        if key is None:
            sys.exit(1)

    entry_count = len(get_all_services(conn))
    print_success(f"Vault unlocked  "
                  f"{style(f'({entry_count} entries)', C.DIM)}")
    print()
    print(f"  {style('Type a service name to search, or', C.DIM)} "
          f"{style('help', C.CYAN)} {style('for commands.', C.DIM)}")
    print()

    session = VaultSession(conn, key)
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
        except (OSError, NameError):
            pass
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

    _run_oneshot(args)


if __name__ == '__main__':
    main()
