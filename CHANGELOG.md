# Changelog

All notable changes to SofiaVault will be documented in this file.

## [0.2.2] - 2026-08-02

### Added
- **Multi-device support**:
  - `export` — shows the vault file location as a clickable terminal link;
    the file is fully encrypted and safe to copy between machines.
  - `import <vault.db>` — the import command now auto-detects vault files
    (vs CSV) and installs them: verifies the imported vault's master password
    before touching anything, backs up any existing local vault to
    `vault.db.replaced-backup`, and works on fresh devices with no vault yet.
    Old-format (v1) vaults are upgraded automatically on first unlock.
  - `wipe` — permanently destroys the vault: requires the master password
    plus a typed confirmation phrase, then overwrites vault, backups, and
    history with 3 passes of random data before deleting. Only an explicit
    allowlist of SofiaVault's own files is touched; symlinks are never
    followed. See SECURITY.md for SSD/copy-on-write caveats.

### Changed
- New banner artwork: the guardian bulldog in its doghouse is now drawn in
  high-resolution Braille-block characters and is actually recognizable.
  Falls back to a plain banner on terminals that can't encode the glyphs.

## [0.2.1] - 2026-08-02

### Added
- **Update check on unlock**: when installed from a git clone and the machine
  is online, SofiaVault checks `origin/main` right after the master password
  is entered. If the install is behind, it shows what changed, explains why
  staying current matters for a password manager, and offers a one-keystroke
  update (`git pull --ff-only`), then asks you to restart.
  - Silent and fast when offline, when there is no remote, or for non-git
    installs; the fetch is capped at 5 seconds so unlock is never held up.
  - Never auto-pulls over local changes or a non-`main` checkout — prints
    manual instructions instead.
  - Runs before vault migration, so after an update the new version handles
    any pending storage upgrades.
  - Opt out with `SOFIAVAULT_SKIP_UPDATE_CHECK=1` (note: the check contacts
    your git remote, e.g. GitHub, each time you unlock).
- `sofiavault --version` / `version` command.

## [0.2.0] - 2026-08-02

Security-focused release. Existing vaults are upgraded automatically and
losslessly on first unlock; your master password is unchanged. A backup of the
original database is written to `~/.sofiavault/vault.db.v1-backup` first.

### Security
- **Encrypted metadata**: service names, usernames, and URLs are now encrypted
  along with the password in a single authenticated AES-256-GCM blob per entry.
  Previously they were stored in plaintext.
- **Tamper resistance**: entry data is bound together with authenticated
  associated data — an attacker with file access can no longer relabel entries
  or swap ciphertexts between services undetected.
- **File permissions**: `~/.sofiavault` is created with mode 0700 and
  `vault.db` / `.history` with 0600 (POSIX). Permissions of existing installs
  are repaired automatically on startup.
- **Real auto-lock**: on session timeout (and on exit) the derived key and all
  decrypted data are dropped from memory before re-authentication is prompted.
- **Clipboard auto-clear**: copied passwords are cleared from the clipboard
  after 45 seconds (only if the clipboard still holds them).
- **Hidden passwords**: retrieved passwords are masked on screen by default;
  the new `show <service>` command displays one explicitly.
- **Constant-time comparison** for master password verification
  (`hmac.compare_digest`).
- **Secure deletion**: `PRAGMA secure_delete` is enabled and the database is
  vacuumed after migration, so deleted entries and legacy plaintext do not
  linger in the file's free pages.

### Changed
- Per-entry keys are now derived with HKDF-SHA256 from the Argon2id master key
  (instead of a full Argon2 pass per entry), making unlock and lookup much
  faster with no loss of security.
- Corrupted entries are reported gracefully instead of crashing fuzzy lookups.

### Fixed
- `setup.sh` no longer aborts on a fresh install (a `set -e` interaction
  prevented the symlink from being created the first time).

## [0.1.0] - 2025-01-01

### Added
- Secure password storage with AES-256-GCM encryption
- Argon2id key derivation with per-entry salts
- Fuzzy matching for service name lookups
- CSV import with auto-delimiter detection
- Cross-platform support (macOS, Linux, Windows)
- Cross-platform installer script
