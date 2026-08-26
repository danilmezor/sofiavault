"""Generate the 0.3.0 on-disk fixtures (vault.db schema v3, users.db schema v1).

Run ONLY against the 0.3.0 code (tag v0.3.0). The outputs are checked in and
must never be regenerated on a later schema; they exist so that migration and
compatibility tests (T-5-3, T-7-1, T-7-2, T-14-2) exercise real 0.3.0 files.

    git checkout v0.3.0 -- sofiavault && python tests/fixtures/0.3.0/make_fixtures.py

Credentials (test-only, deliberately public):
    vault master password : PASSWORD
    vault entries         : see ENTRIES
    users.db pepper       : none;  fields_key: none (plaintext fields)
    users                 : see USERS
"""
from pathlib import Path

from sofiavault.auth import UserStore
from sofiavault.vault import Vault

HERE = Path(__file__).parent
PASSWORD = "fixture-master-password-0.3.0"
ENTRIES = [
    ("github", "octocat", "hunter2", "https://github.com"),
    ("env:DATABASE_URL", "", "postgres://u:p@db/app", ""),
    ("env:API_KEY", "", "sk-fixture-0123456789", ""),
    ("env:MULTI", "", "line1\nline2 = with # chars ", ""),
]
USERS = [
    ("alice", "alice-password", {"role": "senior", "is_admin": True}),
    ("bob", "bob-password", {"role": "junior"}),
]


def main():
    for name in ("vault.db", "users.db"):
        (HERE / name).unlink(missing_ok=True)
    with Vault.create(HERE / "vault.db", PASSWORD) as v:
        for service, user, secret, url in ENTRIES:
            v.set(service, secret, user, url)
    with UserStore(HERE / "users.db") as s:
        for user, pw, fields in USERS:
            s.add_user(user, pw, **fields)
    print("wrote", HERE / "vault.db", HERE / "users.db")


if __name__ == "__main__":
    main()
