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
  lockout, sessions, and 2FA are deliberately the calling application's
  responsibility.
- **Anti-enumeration, stated precisely:** the decoy hash for an unknown
  user is priced using the *cheapest cost parameters actually stored in
  that database*, so it stays indistinguishable from a real verification
  even after a cost upgrade leaves older rows behind. `add_user()` is
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

## Vault Wipe

`sofiavault wipe` requires the master password plus a typed confirmation
phrase. It then overwrites an explicit allowlist of SofiaVault's own files
(`vault.db`, its WAL/journal sidecars, migration and import backups, the
user auth store `users.db` created by `sofiavault auth import`, and the
command history) with 3 passes of CSPRNG data, fsyncing between passes, before
deleting them. Symlinks are removed without following, and no directory is
swept — files outside the allowlist are never touched.

**Honest limitation:** on SSDs (wear leveling) and copy-on-write filesystems
(APFS, Btrfs, ZFS), overwriting a file in place does not guarantee the
original physical blocks are erased. Software-level shredding is best-effort
there. The reliable protection against forensic recovery is full-disk
encryption (FileVault, BitLocker, LUKS) — with it, a wiped vault is
unrecoverable regardless of filesystem behavior.
