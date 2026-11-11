# App secrets

SofiaVault is also a secrets library for applications: it replaces plaintext `.env` files with one encrypted vault file.

## Read secrets from code

```python
from sofiavault import Vault

with Vault.open_auto("/srv/app/secrets.db") as v:
    token = v.get("telegram-bot")
```

`open_auto` resolves the key non-interactively (first hit wins):
`SOFIAVAULT_KEY` (base64, from `sofiavault key`) → `SOFIAVAULT_PASSWORD`
→ `SOFIAVAULT_KEY_FILE` (0600 key file) → OS keyring (`pip install
"sofiavault[keyring]"`). It raises `VaultLocked` rather than prompt.

## Replace dotenv

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
set in the environment always win. `load()` returns a `LoadReport`
(`injected`, `skipped`, `denied`, `vault_path`) that also unpacks as an
`(injected, skipped)` pair, so you can log an ambient override or see
that the vault *has* a name the allowlist blocked.

**Use an allowlist.** One plain-text file, one variable name per line,
shared by the CLI and the library, reviewable in git:

```bash
# config/secrets.allow
DATABASE_URL
STRIPE_API_KEY
```

```bash
sofiavault run --allow config/secrets.allow -- uvicorn app:main
```

```python
sofiavault.envload.load("/srv/app/secrets.db", allow_file="config/secrets.allow")
```

or set `SOFIAVAULT_ALLOW_FILE` once and omit both. A configured allowlist
that is missing, empty or malformed fails closed (`AllowListError`) — the
app must not boot silently without its secrets. The allowlist only ever
narrows: a loader variable that is also allowlisted still raises.
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

## Provision, rotate and check from a shell

Every server-side command takes `--vault PATH` (default `$SOFIAVAULT_DB`,
then `~/.sofiavault/vault.db`), unlocks through the same non-interactive
chain as `open_auto`, only prompts when stdin is a TTY, and speaks in
exit codes (`0` ok · `1` error · `2` usage / no key source · `3` not
found · `127` command not found):

```bash
echo "$STRIPE_KEY" | sofiavault env set STRIPE_API_KEY --vault /srv/app/secrets.db
sofiavault env get STRIPE_API_KEY --vault /srv/app/secrets.db      # exit 3 if absent
sofiavault env del OLD_TOKEN      --vault /srv/app/secrets.db
sofiavault env list               --vault /srv/app/secrets.db
sofiavault env import .env        --vault /srv/app/secrets.db --allow config/secrets.allow
sofiavault env export --allow config/secrets.allow [--format json]   # allowlist REQUIRED
sofiavault rekey --key-file /srv/app/vault.key                      # rotate the master key
sofiavault doctor --allow config/secrets.allow                       # would this boot?
```

`env set` reads the value from stdin (or `--from-file`) so it never sits
in shell history. `rekey` re-encrypts every entry under a new key in one
transaction and, with `--key-file`, writes the new key at 0600 via
temp-file + rename. `doctor` checks the key file (exists, 0600, owned by
you), the vault (readable, writable or read-only, schema, MAC), the
allowlist, and which allowlisted names are *missing* from the vault —
exit 0 only if the deployment would boot, so it belongs in a healthcheck.

A `Vault` held open for hours sees other processes' writes automatically
(one `PRAGMA data_version` per call; `vault.reload()` forces it), never
inserts a duplicate row from a stale index, and `Vault.open(...,
readonly=True)` works on a read-only file.

## Docker

The vault is a file and the key is a file — mount both, don't bake them:

```yaml
services:
  app:
    image: your/app
    user: "1000:1000"
    command: ["sofiavault", "run", "--vault", "/run/sv/secrets.db",
              "--allow", "/app/config/secrets.allow", "--", "uvicorn", "app:main"]
    environment:
      SOFIAVAULT_KEY_FILE: /run/sv/vault.key
    volumes:
      - /srv/app/secrets.db:/run/sv/secrets.db:ro   # or rw if the app writes
      - /srv/app/vault.key:/run/sv/vault.key:ro     # chmod 600, chown 1000
```

- The key file must be mode `0600` and owned by the uid the container
  runs as (`chown 1000 vault.key && chmod 600 vault.key`); `sofiavault
  doctor` tells you if it isn't.
- Bind-mount, don't use compose `secrets:` — its file mode is not
  controllable and the 0600 check will refuse it.
- A read-only mount is fine: `run`, `env get`, `env list` and `doctor`
  open the vault read-only.
- Don't put `SOFIAVAULT_PASSWORD` in a long-running service's
  environment: it appears in `docker inspect` and pays an Argon2
  derivation on every open. A key file does neither — the child process
  sees its allowlisted secrets and nothing else.
