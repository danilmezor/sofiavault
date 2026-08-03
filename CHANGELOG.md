# Changelog

All notable changes to SofiaVault will be documented in this file.

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
