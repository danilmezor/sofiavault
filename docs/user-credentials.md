# User credentials

Passwords, TOTP, recovery codes and reset tokens for apps that sign in their own users.

For apps that authenticate their own users, `UserStore` is a complete
credential store — it can never reveal a password and needs no master
key. The app keeps sessions and policy; the store keeps the facts:

```python
from sofiavault.auth import UserStore
from sofiavault import totp

store = UserStore("/srv/app/users.db", fields_key=key)   # 32 bytes, e.g. from the vault
store.add_user("alice", "hunter2", team="ops")
store.set_role("alice", "senior"); store.set_admin("alice", True)

r = store.verify("alice", submitted)          # AuthResult or None
if r and r.totp == "active":                   # typed flags: r.role, r.is_admin, r.totp
    ok = store.totp_verify("alice", code) or store.recovery_use("alice", code)

secret = store.totp_enroll("alice")            # pending until the first valid code
uri = totp.provisioning_uri(secret, "alice", "MyApp")   # render as a QR code
store.totp_confirm("alice", first_code)
codes = store.recovery_generate("alice")       # shown once; only keyed tags are stored

token = store.reset_token_issue("alice")       # one-time, 1 h; only its tag is stored
store.reset_token_redeem(token, new_password)  # -> "alice"

store.list_users(role="senior", admin_only=True)   # typed columns, no decryption
```

TOTP replay protection is atomic (the accepted time-step is written in the
same transaction that checks the code), recovery codes are single-use, and
everything MFA-related requires `fields_key` — a store created without one
holds password-only users. Never store end-user credentials in the
retrievable vault: a breached server must yield slow hashes, not
decryptable passwords.

## Migrating without a mass reset

 Users on an existing bcrypt-style
store keep their passwords:

```bash
sofiavault auth import-sqlite runtime/auth.db --table managers \
    --scheme bcrypt-sha256-pepper --db /srv/app/users.db
```

```python
from sofiavault.auth import UserStore, LegacyBcryptSha256Pepper
store = UserStore(path, fields_key=key,
                  legacy_verifiers={"bcrypt-sha256-pepper": LegacyBcryptSha256Pepper(pepper)})
```

Each user's first successful login re-stores the password as Argon2id and
drops the legacy hash (`pip install "sofiavault[legacy-bcrypt]"` for the
built-in verifier; any `(password, payload) -> bool` callable works).
Users whose passwords leaked get `sofiavault auth reset USER` — a one-time
token, never an admin-chosen password. A plaintext JSON file imports with
`sofiavault auth import-json users.json` (then delete it, purge it from git
history, and reset everyone). `sofiavault auth list|totp|set-flag` cover
the rest of day-two operations; `--db` defaults to `$SOFIAVAULT_USERS_DB`,
and the fields key comes from `SOFIAVAULT_FIELDS_KEY[_FILE]` with the same
0600 rule as the vault key.
