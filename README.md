# SofiaVault - Secure Terminal Password Manager

[![CI](https://github.com/danilmezor/sofiavault/actions/workflows/ci.yml/badge.svg)](https://github.com/danilmezor/sofiavault/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A simple but secure password manager that runs entirely in your terminal. Works on macOS, Linux, and Windows.

## Features

- **Interactive mode** - Launch `sofiavault` and stay in the shell, like a real app
- **Fuzzy matching** - Don't remember the exact name? Just type close enough
- **Clipboard copy** - Passwords are automatically copied to your clipboard
- **Tab completion** - Press Tab to autocomplete service names
- **CSV import** - Migrate from other password managers in seconds
- **Auto-lock** - Session locks after 5 minutes of inactivity
- **Cross-platform** - Works identically on macOS, Linux, and Windows
- **Zero plaintext storage** - Passwords are never stored unencrypted

## Security

| Component | Algorithm |
|-----------|-----------|
| Key Derivation | Argon2id (64 MB memory, 3 iterations, 4 parallelism) |
| Encryption | AES-256-GCM authenticated encryption |
| Salts | Unique 16-byte CSPRNG salt per entry |

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
  │ Pass     MySecurePass123
  │
  │ Copied to clipboard
  └────────────────────────────────────────────

sv> add
sv> list
sv> delete twitter
sv> exit
```

Tab-complete service names, use arrow keys for command history.

### One-shot Mode

Every command also works as a single CLI call:

```bash
sofiavault amazon           # get password (fuzzy match)
sofiavault add              # add new entry
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

## How It Works

```
Master Password
      |
      v
   Argon2id (64MB memory, 3 iterations)
      |
      v
   256-bit Key
      |
      +---> Verification hash (stored)
      |
      +---> Per-entry key derivation
              |
              v
           AES-256-GCM
              |
              v
           Encrypted password (stored)
```

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
