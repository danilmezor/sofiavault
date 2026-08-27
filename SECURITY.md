# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SofiaVault, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **danil.zanozin@gmail.com**

You should receive a response within 48 hours. Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Threat Model

SofiaVault is designed to protect passwords at rest on a single machine. It protects against:

- Unauthorized access to the vault database file
- Brute-force attacks on the master password (via Argon2id memory-hard KDF)
- Metadata disclosure — service names, usernames, and URLs are encrypted, not just passwords
- Ciphertext tampering and entry relabeling — each entry is a single authenticated
  AES-256-GCM blob, so an attacker with file access cannot swap a password onto a
  different service name without detection
- Rollback, insertion, and deletion of whole entries — a MAC over the entry set
  is checked when the vault is opened *and* again immediately before every
  write, so a file edited while a session is unlocked cannot be laundered into
  a fresh valid tag. Both the CLI and the library refuse to read or write a
  vault that fails this check
- Other local users reading the vault — the vault directory and files are created
  with owner-only permissions (0700 / 0600 on POSIX systems)
- Clipboard scraping over time — copied passwords are automatically cleared from
  the clipboard after 45 seconds (only if the clipboard still holds them)
- Shoulder surfing — passwords are hidden by default when retrieved; displaying
  one on screen requires the explicit `show` command

When the interactive session auto-locks (5 minutes of inactivity) or exits, the
derived key and all decrypted data are dropped from process memory before the
re-authentication prompt.

It does **not** protect against:

- **A hostile `.env` file handed to `env import`.** Dotenv has no escape
  sequences, so quoting is ambiguous in two shapes that cannot be told
  apart from legitimate files by inspection: a line *inside* a multi-line
  quoted value that ends in the quote character closes it early (making
  the following lines ordinary entries), and a line whose quote closes
  mid-line with text after it (`FOO="bar" baz`) reads as the opening of a
  multi-line value and absorbs the lines below it, which are then not
  imported as their own entries. Anyone who can write the `.env` can use
  the first to smuggle in a variable name. `envload.load(allow=[...])`
  bounds what may ever be injected regardless of how a file parses, and
  is the control to rely on; the denylist is a development safety net.
  Review a `.env` you did not write before importing it, and check the
  result with `sofiavault env list`.
- Keyloggers or malware on the host machine
- A compromised master password
- Memory forensics while the vault is unlocked (Python cannot guarantee
  zeroization of secrets in memory)
- Clipboard managers that record history the instant a password is copied

## Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Master Key Derivation | Argon2id | 64 MB memory, 3 iterations, 4 parallelism |
| Per-Entry Key Derivation | HKDF-SHA256 | unique 16-byte salt per entry |
| Encryption | AES-256-GCM | 12-byte nonce, 256-bit key, authenticated AAD |
| Salt | CSPRNG | 16 bytes per entry |
| Random | `secrets` module | OS-level CSPRNG |
| Master verification | constant-time comparison | `hmac.compare_digest` |

Each entry's full record (service, username, URL, password, timestamp) is
serialized and encrypted as one AES-256-GCM blob with a domain-separation
string as associated data. The database stores only random salts, nonces, and
ciphertext. `PRAGMA secure_delete` is enabled so deleted entries are
overwritten with zeros rather than left in free pages.

## Storage Format & Migration

Vaults created before v0.2.0 stored service names, usernames, and URLs in
plaintext and derived per-entry keys with Argon2. On first unlock with v0.2.0+,
the vault is upgraded automatically:

1. The original database file is backed up to `~/.sofiavault/vault.db.v1-backup`
   (permissions 0600) before anything is modified.

   **Keep this in mind:** that backup is a v1 file, so it still contains
   plaintext service names, usernames, and URLs, plus the pre-migration
   ciphertext of every password under your master password. Deleting or
   rotating a secret afterwards does not remove it from the backup, and
   the backup rides along into Time Machine / rsync / cloud-sync copies.
   Delete it once you have confirmed the upgrade worked.
2. Every entry is decrypted with the legacy scheme and re-encrypted into the
   new format inside a single transaction — an interruption rolls back cleanly.
3. Entries that fail to decrypt are left untouched and reported, never dropped.
4. The database file is vacuumed so no legacy plaintext remains in free pages.

The master password and its verification data are unchanged; your existing
master password continues to work. After verifying the upgrade you may delete
the `.v1-backup` file — it still contains the old plaintext metadata.

## Server / Library Mode (0.3.0)

- **Bootstrap secret**: a server unlocking the vault non-interactively
  needs one credential (`SOFIAVAULT_KEY`, `SOFIAVAULT_PASSWORD`, a 0600
  key file, or the OS keyring). SofiaVault reduces N plaintext secrets to
  one well-guarded secret; it does not eliminate the last secret. Root on
  the running host can still win — full-disk encryption and OS access
  control remain the backstop.
- **The library never prompts, prints, or touches the network.** All
  interactivity (including the update check) lives in the CLI.
- **UserStore is verify-only**: per-user Argon2id verifiers with salts
  and stored cost parameters, constant-time comparison, transparent
  rehash-on-verify, and dummy hashing for unknown/inactive usernames.
  There is no code path that returns a user's password. Rate limiting,
  lockout and sessions are deliberately the calling application's
  responsibility; since 0.4.0 TOTP, recovery codes and reset tokens are
  the store's (see below).
- **Anti-enumeration, stated precisely:** the decoy hash for an unknown
  user is priced at the *most expensive cost parameters any real row
  uses* (floored at the current defaults), and a cheaper legacy row is
  padded up to that same ceiling on every verify, so neither "unknown" nor
  "exists on an old row" is faster than the other. `add_user()` is
  deliberately not constant-time (it returns False for an existing name)
  — it is an administrative call and must not back a self-service signup
  route without the caller adding its own timing/response equalization.
- **Tamper evidence:** each entry blob is authenticated against its row
  id and a per-vault id, and the vault stores a MAC over the whole entry
  set. Restoring an old blob into its own row (rolling back a rotated
  secret), inserting a shadow row, deleting a row, or transplanting a
  blob between vaults that share a master key are all detected, and the
  vault then fails closed rather than serving a stale or missing secret.
- **Environment injection is not a trusted channel:** variable names are
  validated, and loader/interpreter variables (`LD_PRELOAD`, `BASH_ENV`,
  `PYTHONPATH`, `PATH`, ...) are refused, so a single vault write cannot
  become code execution in every process the vault configures.
  `sofiavault run` also strips the `SOFIAVAULT_*` bootstrap credentials
  before exec, so a compromised child gets only the secrets it was
  scoped to receive — not the key to the whole vault.
- **Never store end-user credentials in the retrievable vault.** The
  vault exists for secrets the app must read back (API keys, tokens);
  user passwords must only ever be stored as hashes.

## Threat Model (0.4.0)

| | |
|---|---|
| **Protects** | secrets at rest (vault); secrets absent from images / `.env` / `docker inspect` (for the consuming app's own containers); credential material at rest (Argon2id, encrypted seeds, keyed tags); replay of TOTP codes and recovery codes; offline brute force of recovery codes and reset tokens; transplant of ciphertext between rows/stores; stale-index duplicate writes; silent boot without secrets (doctor + allowlist fail-closed) |
| **Does not protect** | a host root that can read the key file; secrets that must be passed to third-party images via their own env (they are out of `.env`, not out of their container's `inspect`); build-time constants in a shipped JS bundle (delivery-model problem, stays deferred); the app's session layer |

## Credentials Layer (0.4.0)

- **MFA material never leaves `fields_key`.** TOTP seeds are AES-256-GCM
  blobs whose associated data binds them to one user *and* to the `totp`
  slot (a seed cannot be transplanted into the profile-fields slot of the
  same user, or vice versa). Recovery codes and password-reset tokens are
  stored only as `HMAC-SHA256(fields_key, value)` tags — a copy of the
  database without the key cannot brute-force a 50-bit recovery code
  offline, nor mint a reset. A store created without `fields_key` cannot
  hold any of this; the policy is one-way, and `sofiavault doctor` warns.
- **Every credential row is authenticated, per store.** On a store that
  has `fields_key`, each row carries `HMAC-SHA256(fields_key, store_id |
  username | salt | verify_hash | costs | fields | is_active | role |
  is_admin | totp_enc | totp_counter | totp_confirmed | recovery_enc |
  legacy_hash | password_changed_at)`, checked *before* the password is
  looked at in `verify()` and in every MFA, recovery, reset and flag
  operation. Setting `is_admin = 1` with a SQL client, switching MFA off
  by nulling the seed or un-confirming it, rolling the replay counter
  back, swapping another user's password material onto the admin, or
  poisoning `legacy_hash` all surface as `FieldsTampered`. The random
  `store_id` (in `auth_meta`) is part of the tag and of the TOTP/recovery
  AAD, so a row copied from another store that shares the key is
  rejected; reset-token tags cover their expiry, so a DB write cannot
  extend one. **Limit:** a per-row tag authenticates *state*, not
  *history* — restoring a whole row together with its earlier tag is a
  valid earlier state (a used recovery code or TOTP step comes back). The
  file's own protections (0600, the host) are the control there. A store
  created *without* `fields_key` carries no tags: its rows are as
  unauthenticated as its file, which is one more reason to create stores
  with a key.
- **TOTP replay is closed atomically.** The last accepted time-step is
  read, the code checked, and the step written inside one
  `BEGIN IMMEDIATE` transaction, so two submissions of the same code —
  from two threads or two processes — cannot both succeed. A pending
  enrolment (seed issued, never confirmed) is never accepted by
  `totp_verify`. Every candidate step is compared with
  `hmac.compare_digest` and every candidate is always evaluated.
- **Recovery codes are single-use by construction**: the matching tag is
  removed in the same transaction that accepts it.
- **Legacy hashes are a bridge, not a home.** Users imported with
  `import_sqlite` keep their old (e.g. bcrypt) hash as `legacy_hash` and a
  placeholder Argon2 row that can never match; their first successful
  login through the registered legacy verifier rewrites the row as
  Argon2id and clears `legacy_hash`, as does redeeming a reset token. An
  unknown scheme raises rather than silently denying. **Timing:** a
  legacy row pays the Argon2 decoy ceiling *plus* the legacy scheme's own
  cost, so until its first successful login it is distinguishable from an
  unknown user by timing. Unknown users and ordinary Argon2 rows remain
  indistinguishable from each other.
- **Master-key rotation (`rekey`)** re-encrypts every entry and replaces
  the master record and MAC in one transaction; a failure leaves the old
  key valid. The master row's salt and Argon2 costs are covered by the
  entry-set MAC (schema v4), so they cannot be swapped or rolled back
  unnoticed, and the persisted costs mean a future change to the defaults
  cannot lock an existing vault out.
- **Read-only deployments.** `Vault.open(readonly=True)` (and every
  read-only CLI command) opens the file with sqlite's `mode=ro`, never
  creates, migrates or re-signs anything, and a vault that cannot be
  written surfaces as the typed `VaultReadOnly` rather than a raw sqlite
  error.

## Vault Wipe

`sofiavault wipe` requires the master password plus a typed confirmation
phrase. It then overwrites an explicit allowlist of SofiaVault's own files
(`vault.db`, its WAL/journal sidecars, migration and import backups, the
user auth store `users.db` created by `sofiavault auth import-json`, and the
command history) with 3 passes of CSPRNG data, fsyncing between passes, before
deleting them. Symlinks are removed without following, and no directory is
swept — files outside the allowlist are never touched.

**Honest limitation:** on SSDs (wear leveling) and copy-on-write filesystems
(APFS, Btrfs, ZFS), overwriting a file in place does not guarantee the
original physical blocks are erased. Software-level shredding is best-effort
there. The reliable protection against forensic recovery is full-disk
encryption (FileVault, BitLocker, LUKS) — with it, a wiped vault is
unrecoverable regardless of filesystem behavior.
