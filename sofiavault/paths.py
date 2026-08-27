"""Default on-disk locations for the SofiaVault CLI.

These are CLI conveniences only. Library consumers (Vault, UserStore,
envload) always receive explicit paths and never read this module, with one
exception: envload.load() consults ALLOW_FILE when neither allow= nor
allow_file= is given (D-1).

Environment overrides, read once at import:

    SOFIAVAULT_DB          vault database   (default ~/.sofiavault/vault.db)
    SOFIAVAULT_USERS_DB    user store       (default ~/.sofiavault/users.db)
    SOFIAVAULT_ALLOW_FILE  allowlist file   (default: none — denylist mode)

Access these as `paths.DB_PATH` (attribute style) so tests can patch
`sofiavault.paths.DB_PATH` in one place.
"""

import os
from pathlib import Path
from typing import Optional

_HOME = Path.home() / ".sofiavault"


def _env_path(var: str, default: Optional[Path]) -> Optional[Path]:
    raw = os.environ.get(var)
    if raw is None or not raw.strip():
        return default
    return Path(raw).expanduser()


DB_PATH: Path = _env_path("SOFIAVAULT_DB", _HOME / "vault.db")
USERS_DB_PATH: Path = _env_path("SOFIAVAULT_USERS_DB", _HOME / "users.db")
ALLOW_FILE: Optional[Path] = _env_path("SOFIAVAULT_ALLOW_FILE", None)
HISTORY_PATH = _HOME / ".history"

#: True when the vault location came from SOFIAVAULT_DB rather than the
#: default. The CLI echoes the path on unlock in that case so an operator
#: never edits the wrong vault silently.
DB_PATH_FROM_ENV: bool = bool((os.environ.get("SOFIAVAULT_DB") or "").strip())
USERS_DB_PATH_FROM_ENV: bool = bool((os.environ.get("SOFIAVAULT_USERS_DB") or "").strip())
