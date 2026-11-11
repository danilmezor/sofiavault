# Password manager

SofiaVault runs entirely in your terminal on macOS, Linux and Windows.

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

## Install

## With pip

```bash
pip install .
sofiavault help
```

## macOS Quick Install

```bash
cd sofiavault
./setup.sh
```

This installs dependencies and makes `sofiavault` available globally in your terminal.

## Cross-platform Install

```bash
cd sofiavault
python install.py
```

## Manual Install

```bash
pip install argon2-cffi cryptography rapidfuzz

# macOS/Linux
chmod +x sofiavault.py
ln -s $(pwd)/sofiavault.py ~/.local/bin/sofiavault

# Windows (PowerShell as Admin)
# Add the folder to your PATH, or create an alias
```

## Use

## Interactive Mode (recommended)

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

## One-shot Mode

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

## Import existing passwords

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

## Fuzzy matching

You don't need to remember exact service names:

| You type | Finds |
|----------|-------|
| `sofiavault amazn` | amazon |
| `sofiavault gogle` | google |
| `sofiavault nflx` | netflix |
| `sofiavault gh` | github |

If multiple services match, you'll be asked to choose.

## Where your data lives

Your encrypted database is stored at:
- **macOS/Linux**: `~/.sofiavault/vault.db`
- **Windows**: `C:\Users\<you>\.sofiavault\vault.db`

On POSIX systems the directory is created with mode 0700 and the database with
0600, so no other local user can read them.

## Multiple devices

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
  then overwrites the vault, its backups, the local user auth store, and the
  command history with random data (3 passes) before deleting them. Only
  SofiaVault's own files are touched — nothing else on disk. It stays
  available on a vault that fails its tamper check, so a compromised vault
  can always be destroyed securely. Note: on SSDs and copy-on-write
  filesystems, software overwriting can't guarantee physical erasure;
  full-disk encryption (FileVault/BitLocker/LUKS) is the reliable backstop.

## Updates

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

## Before you rely on it

1. **Master password cannot be recovered** - If you forget it, your passwords are gone forever
2. **Back up your vault.db** - It's encrypted, safe to back up anywhere
3. **Use a strong master password** - At least 12+ characters recommended
