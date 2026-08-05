# SofiaVault - Secure Terminal Password Manager

[![CI](https://github.com/danilmezor/sofiavault/actions/workflows/ci.yml/badge.svg)](https://github.com/danilmezor/sofiavault/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A simple but secure password manager that runs entirely in your terminal. Works on macOS, Linux, and Windows.

## Features

- **Interactive mode** - Launch `sofiavault` and stay in the shell, like a real app
- **Fuzzy matching** - Don't remember the exact name? Just type close enough
- **Clipboard copy with auto-clear** - Passwords are copied to your clipboard and
  automatically cleared after 45 seconds
- **Hidden by default** - Retrieved passwords are never printed unless you ask
  with `show`
- **Edit & generate** - Rotate a password in seconds with `edit`; `gen` makes
  strong random passwords (optionally mixing in your own keyboard-mash entropy
  on top of the OS CSPRNG)
- **Tab completion** - Press Tab to autocomplete service names
- **CSV import** - Migrate from other password managers in seconds
- **Auto-lock** - Session locks after 5 minutes of inactivity and wipes the key
  and decrypted data from memory
- **Cross-platform** - Works identically on macOS, Linux, and Windows
- **Zero plaintext storage** - Passwords *and* metadata (service names,
  usernames, URLs) are encrypted; the database contains only ciphertext
- **Update check** - After unlocking, SofiaVault tells you when security
  updates are available and can install them with one keystroke

## Security

| Component | Algorithm |
|-----------|-----------|
| Master Key Derivation | Argon2id (64 MB memory, 3 iterations, 4 parallelism) |
| Per-Entry Keys | HKDF-SHA256 with a unique 16-byte CSPRNG salt per entry |
| Encryption | AES-256-GCM authenticated encryption (metadata included in the ciphertext) |
| File permissions | Vault directory 0700, database 0600 (POSIX) |

See [SECURITY.md](SECURITY.md) for threat model and vulnerability reporting.

## Installation

### With pip

```bash
pip install .
sofiavault help
```

### macOS Quick Install

```bash
cd sofiavault
./setup.sh
```

This installs dependencies and makes `sofiavault` available globally in your terminal.

### Cross-platform Install

```bash
cd sofiavault
python install.py
```

### Manual Install

```bash
pip install argon2-cffi cryptography rapidfuzz

# macOS/Linux
chmod +x sofiavault.py
ln -s $(pwd)/sofiavault.py ~/.local/bin/sofiavault

# Windows (PowerShell as Admin)
# Add the folder to your PATH, or create an alias
```

## Usage

### Interactive Mode (recommended)

Just run `sofiavault` with no arguments to enter the interactive shell:

```
$ sofiavault

  ♥ SofiaVault ♥
  Master password: ********
  ✓ Vault unlocked (12 entries)

sv> gmail
  ┌────────────────────────────────────────────
  │ Service  gmail
  │ User     user@gmail.com
  │ Pass     ••••••••••••
  │
  │ Copied to clipboard · clears in 45s
  │ 'show gmail' to display it
  └────────────────────────────────────────────

sv> show gmail
sv> add
sv> list
sv> delete twitter
sv> exit
```

Tab-complete service names, use arrow keys for command history.

### One-shot Mode

Every command also works as a single CLI call:

```bash
sofiavault amazon           # copy password to clipboard (fuzzy match)
sofiavault show amazon      # copy and display the password
sofiavault add              # add new entry
sofiavault edit amazon      # edit an entry (Enter keeps current values)
sofiavault gen              # generate a strong password (gen 32, gen --mix)
sofiavault list             # list all services
sofiavault delete amazon    # delete an entry
sofiavault import file.csv  # import from CSV
sofiavault help             # show help
```

## Importing Existing Passwords

```bash
sofiavault import /path/to/passwords.csv
```

Your CSV must have these columns (names are case-insensitive):

| Column | Required | Description |
|--------|----------|-------------|
| TITLE | Yes | Service/website name |
| USERNAME | Yes | Username or email |
| PASSWORD | Yes | The password |
| URL | No | Website URL |

Example:

```csv
TITLE,USERNAME,PASSWORD,URL
Amazon,john@gmail.com,MyAmazonPass123,https://amazon.com
Google,john@gmail.com,GoogleSecure456,https://google.com
Netflix,johnny,NetflixPwd789,https://netflix.com
```

Import features:
- Auto-detects delimiters (comma, semicolon, tab, pipe)
- Skips duplicates
- Handles missing URL column
- Reports progress

## Fuzzy Matching

You don't need to remember exact service names:

| You type | Finds |
|----------|-------|
| `sofiavault amazn` | amazon |
| `sofiavault gogle` | google |
| `sofiavault nflx` | netflix |
| `sofiavault gh` | github |

If multiple services match, you'll be asked to choose.

## Where Is My Data?

Your encrypted database is stored at:
- **macOS/Linux**: `~/.sofiavault/vault.db`
- **Windows**: `C:\Users\<you>\.sofiavault\vault.db`

On POSIX systems the directory is created with mode 0700 and the database with
0600, so no other local user can read them.

## How It Works

```
Master Password
      |
      v
   Argon2id (64MB memory, 3 iterations)
      |
      v
   256-bit Master Key
      |
      +---> Verification hash (stored)
      |
      +---> HKDF-SHA256 (unique salt per entry)
              |
              v
           AES-256-GCM
              |
              v
           One authenticated blob per entry (stored):
           service + username + URL + password
```

## Using SofiaVault as a Library (servers & apps)

Since 0.3.0, SofiaVault is also a plug-and-play secrets library for
applications — aimed at replacing the plaintext-`.env` pattern.

### Encrypted app secrets

```python
from sofiavault import Vault

with Vault.open_auto("/srv/app/secrets.db") as v:
    token = v.get("telegram-bot")
```

`open_auto` resolves the key non-interactively (first hit wins):
`SOFIAVAULT_KEY` (base64, from `sofiavault key`) → `SOFIAVAULT_PASSWORD`
→ `SOFIAVAULT_KEY_FILE` (0600 key file) → OS keyring (`pip install
"sofiavault[keyring]"`). It raises `VaultLocked` rather than prompt.

### Drop-in dotenv replacement

```bash
sofiavault env import .env         # one-time: encrypt your secrets
sofiavault run -- uvicorn app:main # inject env:* entries, exec the app
```

Or with one code line at your entry point instead of `load_dotenv()`:

```python
import sofiavault.envload
sofiavault.envload.load("/srv/app/secrets.db")
```

Entries named `env:NAME` become environment variables; variables already
set in the environment always win (`load()` returns both what it injected
and what it skipped, so you can log or reject an ambient override).
Variable names are validated, and loader/interpreter variables
(`LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`, `PATH`, ...) are refused — a
`.env` file is untrusted input, and injecting one of those would turn a
single vault write into code execution. `sofiavault run` also strips the
`SOFIAVAULT_*` bootstrap credentials before exec, so the child gets its
secrets and not the key to the whole vault.

Honest security model: your server still needs one bootstrap secret — but
it's one secret to guard instead of sixty, everything is encrypted at rest
with enforced permissions, tampering with the vault file is detected, and
`git add .env` accidents become non-events.

### Verify-only user authentication

For apps that authenticate their own users, `UserStore` holds Argon2id
verifiers — it can never reveal a password and needs no master key:

```python
from sofiavault.auth import UserStore

store = UserStore("/srv/app/users.db")
store.add_user("alice", "hunter2", access_level=3)
result = store.verify("alice", submitted)   # AuthResult or None
```

Never store end-user credentials in the retrievable vault — a breached
server must yield slow hashes, not decryptable passwords. Migrate a
legacy plaintext credential file with `sofiavault auth import users.json`
(then delete the file, purge it from git history, and rotate everything).

## Using Multiple Devices

The vault is a single encrypted file, so moving it between machines is simple:

```bash
sofiavault export             # shows the vault file location (clickable link)
sofiavault import vault.db    # installs a vault file copied from another device
sofiavault wipe               # permanently destroys the vault on this machine
```

- **export** prints where `vault.db` lives. The file is fully encrypted —
  safe to copy via USB drive or cloud storage. You'll need your master
  password on the other device.
- **import** auto-detects whether the file is a vault or a CSV. For a vault
  file it verifies the file's master password *before* touching anything,
  backs up any existing local vault to `vault.db.replaced-backup`, then
  copies it into place. Works on a brand-new device with no vault yet.
- **wipe** asks for your master password plus a typed confirmation phrase,
  then overwrites the vault, its backups, and the command history with
  random data (3 passes) before deleting them. Only SofiaVault's own files
  are touched — nothing else on disk. Note: on SSDs and copy-on-write
  filesystems, software overwriting can't guarantee physical erasure;
  full-disk encryption (FileVault/BitLocker/LUKS) is the reliable backstop.

## Staying Up to Date

If you installed from a git clone (the `setup.sh` / `install.py` path), every
unlock quickly checks whether `origin/main` has new commits. If it does, you'll
see what changed and be offered a one-keystroke update — for a password
manager, staying current matters, since updates often carry security fixes.

- Offline or no remote? The check is skipped silently (capped at 5 seconds).
- Local changes or a different branch checked out? It never auto-pulls; you
  get the manual command instead.
- Prefer no network activity on unlock? Set `SOFIAVAULT_SKIP_UPDATE_CHECK=1`
  (the check contacts your git remote, e.g. GitHub, each time you unlock).

## Upgrading from 0.1.x

Nothing to do — the first time you unlock an existing vault with 0.2.0, it is
upgraded automatically. Your master password and all entries are preserved, and
a backup of the original file is written to `~/.sofiavault/vault.db.v1-backup`
before anything is changed. Once you've confirmed everything works, delete the
backup (it still contains the old format's plaintext service names).

## Important Notes

1. **Master password cannot be recovered** - If you forget it, your passwords are gone forever
2. **Back up your vault.db** - It's encrypted, safe to back up anywhere
3. **Use a strong master password** - At least 12+ characters recommended

## Development

```bash
pip install -e ".[dev]"
pytest -v
ruff check .
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
