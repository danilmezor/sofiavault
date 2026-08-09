# Changelog

All notable changes to SofiaVault will be documented in this file.

## [0.3.0] - 2026-08-05

SofiaVault is now a plug-and-play library as well as a CLI. The design is
aimed at the countless production apps built on the dotenv pattern —
plaintext `.env` files full of secrets, injected wholesale into containers.

### Added
- **Library API** (`from sofiavault import Vault`): silent, importable,
  typed exceptions (`WrongPassword`, `VaultLocked`, `EntryNotFound`, ...).
  `Vault.create/open/open_auto`, `get/get_entry/set/delete/list_entries/
  search`, `export_key`, context-manager support. Importing the package
  never prompts, prints, or touches the network.
- **Non-interactive unlock** for servers via `Vault.open_auto()`:
  `SOFIAVAULT_KEY` (base64 raw key) → `SOFIAVAULT_PASSWORD` →
  `SOFIAVAULT_KEY_FILE` → OS keyring (optional `keyring` extra) →
  `VaultLocked`. The library never falls back to a prompt.
- **Environment injection** (`sofiavault.envload`): entries named
  `env:NAME` inject as environment variables. One line replaces
  `load_dotenv()`; existing variables are never overwritten by default.
  - `sofiavault env import <.env>` bulk-imports a dotenv file (with a
    warning to scrub and rotate the plaintext source).
  - `sofiavault env list` shows what would be injected.
  - `sofiavault run [--vault PATH] -- <cmd>` resolves the key, injects
    `env:*` entries, and execs the command — zero code changes required;
    secrets never touch disk unencrypted or appear in `env_file` dumps.
  - `sofiavault key` prints the base64 master key once, for provisioning.
- **Verify-only user store** (`from sofiavault.auth import UserStore`):
  Argon2id credential verification for apps that authenticate their own
  users. Can never produce a plaintext password and needs no master key.
  Per-user salts and cost parameters with transparent rehash-on-verify,
  anti-enumeration dummy hashing, optional pepper (no default value —
  ever), optional AES-GCM encryption of profile fields at rest, and
  `import_json` / `sofiavault auth import` for migrating legacy plaintext
  credential files (with an explicit rotate-everything warning).

### Security (hardening found in pre-release review of the new surface)
- **Environment injection is validated.** Variable names must be
  well-formed, and dangerous variables are refused at both import and
  inject time — otherwise a single vault write became code execution in
  every process the vault configured.
  - `envload.load(..., allow=[...])` restricts injection to the variables
    the application actually consumes. This is the recommended gate: it is
    the only one that does not have to anticipate the attacker's choice of
    variable. Names outside the allowlist are ignored, but a *dangerous*
    one still raises rather than passing unnoticed.
  - Without `allow=`, a denylist applies. It now covers git command hooks
    (`GIT_SSH_COMMAND`, `GIT_CONFIG_*`, ...), TLS trust and proxies
    (`SSL_CERT_FILE`, `NODE_TLS_REJECT_UNAUTHORIZED`, `*_PROXY`), home and
    config redirection (`HOME`, `XDG_*`, `TMPDIR`), cloud credential
    plugins (`AWS_CONFIG_FILE`, `KUBECONFIG`), package-manager registries,
    pager hooks (`LESSOPEN`) and the Windows set — alongside the original
    loader/interpreter names. Ordinary secrets (`AWS_SECRET_ACCESS_KEY`,
    `PGPASSWORD`, `DATABASE_URL`, ...) are unaffected.
  - `.env` parsing consumes multiline quoted values whole. Previously the
    continuation lines of a pasted PEM block were parsed as fresh
    `NAME=value` pairs, so a `GIT_SSH_COMMAND=` line hidden inside key
    material became a real variable. An unterminated quote is now a hard
    `MalformedEnvFile` error and imports nothing.
  - `sofiavault run` resolves the program against the pre-injection
    `PATH`, so a vault entry can never choose which binary is executed.
- **`sofiavault run` no longer leaks the master key to the child.** The
  `SOFIAVAULT_KEY` / `SOFIAVAULT_PASSWORD` / `SOFIAVAULT_KEY_FILE`
  variables are stripped before exec, so a compromised child holds only
  the secrets it was scoped to receive.
- **Tamper-evident storage (schema v3).** Entry blobs are now
  authenticated against their row id and a per-vault id, and the vault
  keeps a MAC over the whole entry set. Rolling back a rotated secret,
  inserting a shadow row, deleting a row, and transplanting blobs between
  vaults sharing a master key are all detected. Existing vaults upgrade
  automatically and losslessly on first open.
  - The MAC cannot be stripped. It is written when the master password is
    created, a v3 vault is *required* to carry one, and the MAC covers
    `schema_version` and `vault_id` as well as the rows. Previously an
    attacker with write access could delete one unauthenticated
    `vault_meta` row — or roll `schema_version` back to `2`, which made
    the v2→v3 migration re-sign whatever the rows then held — and every
    rollback defence above went quiet.
  - `storage.delete_entry()` now requires the master key; the keyless form
    used to clear the MAC outright.
- **Fail closed on tampering.** A corrupted entry used to surface as
  `EntryNotFound` (a `KeyError`), which an application's
  `except KeyError: use_default()` would read as "never configured" — a
  silent security downgrade. It now raises `VaultCorrupted`, and
  `envload.load()` refuses to inject a partial environment. `load()` also
  checks the entry-set MAC directly: a deleted `env:*` row leaves every
  survivor decryptable, so it shows up as tampering rather than
  corruption, and an application would otherwise have fallen back to its
  default for the missing variable.
- **UserStore anti-enumeration survives cost upgrades.** Verification
  spends the same work whether or not the user exists. The decoy is priced
  at the *ceiling* of the stored parameters and current defaults, and a row
  whose stored cost is below that ceiling pays the difference before the
  comparison branch. Pricing the decoy from the cheapest stored row, as an
  earlier build did, made a single probe distinguish real users from
  unknown ones at 7x; pricing it from the ceiling alone merely inverted the
  tell. Measured spread across unknown / inactive / wrong-password /
  legacy-row accounts is now ~1.1x.
  The ceiling is recomputed whenever another connection commits
  (`PRAGMA data_version`), not only on this instance's own writes — each
  worker process holds its own `UserStore`, so a cost raised by one worker
  would otherwise leave the others priced at a stale, lower ceiling.
  The level-up deficit is spent as `memory_cost` rather than whole Argon2
  passes, which lands on the ceiling instead of overshooting it and
  leaving legacy rows separable.
- **Stored Argon2 parameters and binary columns are validated on read**,
  so a tampered row cannot wedge or OOM verification with an absurd
  `memory_cost`, cannot raise `TypeError` past the store's own error type
  with a non-`bytes` `salt` or `verify_hash`, and a successful login never
  *lowers* cost parameters an operator raised.
- **Encrypted profile fields cannot be downgraded to plaintext.** The
  store records whether it encrypts fields; a row presenting plaintext in
  an encrypting store is refused. Previously, setting `fields_enc` to NULL
  and writing `{"role": "admin"}` into the plaintext column granted the
  fields without touching a password hash or knowing the field key.
- **Profile fields are bound to their user** (AES-GCM associated data),
  and `is_active` is read strictly, so a tampered row cannot graft an
  admin's fields onto another account or revive a revoked one.
- **Username identity policy**: NFKC-normalized and casefolded, with
  control/format characters rejected — no more `Admin`/`ADMIN`/`ａdmin`
  shadow accounts or log-forging usernames.
- Files are created 0600 before anything can open them (no
  world-readable window), key files with group/other access are refused,
  `envload.load()` reports what it skipped, `import_json` refuses to
  coerce non-string passwords, malformed master records raise a typed
  error, and destructive helpers are out of the public API.

### Changed
- The single-file module is now a package (`core`, `storage`, `vault`,
  `auth`, `envload`, `generator`, `cli`) with the historical flat import
  surface preserved (`from sofiavault import derive_key, ...`).
- **Breaking**: `delete_entry(conn, entry_id)` is now
  `delete_entry(conn, entry_id, key)`. The keyless form cleared the
  entry-set MAC — a one-line tamper-evidence strip — so it was removed
  deliberately rather than kept for compatibility.
- **Breaking**: the vault location moved to `sofiavault.paths.DB_PATH` /
  `sofiavault.paths.HISTORY_PATH`. Reading `sofiavault.DB_PATH` still
  works; *assigning* it now raises `AttributeError` naming the new home.
  Silently accepting the old assignment would have left scripts and tests
  operating on the real `~/.sofiavault` vault while believing they were
  sandboxed — with `wipe` among the commands that reads it.
- `Vault` and `UserStore` serialize access internally, so a single
  instance can be shared by a threaded server.
- `envload.load()` returns `(injected, skipped)` and
  `import_env_file()` returns `(imported, skipped, rejected)`.
- The entire CLI UX is unchanged; existing vaults and symlink installs
  keep working (a root launcher script preserves `setup.sh` /
  `install.py` installs).

## [0.2.3] - 2026-08-02

### Added
- **`edit <service>`** — update an entry in place. Every field shows its
  current value and Enter keeps it, so rotating one password takes seconds.
  Supports fuzzy matching, renaming with collision checks, `-` to clear the
  URL, and preserves the original creation date (an `updated_at` timestamp
  is stamped inside the encrypted blob). Entries are re-encrypted with a
  fresh salt and nonce on every edit.
- **`gen [length] [--mix]`** — strong password generator (default 20 chars,
  ~124 bits, OS CSPRNG via `secrets`, bias-free rejection sampling). The
  generated password is copied to the clipboard with the usual auto-clear.
  With `--mix`, keyboard-mash characters and nanosecond keystroke timings
  are hashed together with 64 bytes of OS entropy — user input augments the
  CSPRNG but never replaces it, so a weak mash cannot weaken the result.
  `edit` offers generation inline when changing a password; `gen` in
  one-shot mode works without unlocking the vault.

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
