"""SofiaVault — encrypted secrets vault, CLI password manager, and
verify-only user auth store.

Library entry points:

    from sofiavault import Vault, UserStore
    import sofiavault.envload

Importing this package is silent: no prompts, no prints, no network.
The flat re-exports below keep the historical single-module surface
(`from sofiavault import derive_key, init_db, ...`) working, with one
deliberate exception: delete_entry now requires the master key so the
entry-set MAC is re-signed instead of stripped (see CHANGELOG, 0.3.0).
"""

__version__ = "0.3.0"

#: The supported public surface. Private helpers (notably the destructive
#: _shred_file) are reachable via their modules but are deliberately not
#: part of `from sofiavault import *` or the documented API.
__all__ = [
    "__version__",
    # vault
    "Vault", "Entry", "VaultEntry",
    "VaultError", "VaultLocked", "VaultCorrupted", "WrongPassword",
    "EntryNotFound", "VaultNotInitialized", "VaultAlreadyInitialized",
    # auth
    "UserStore", "AuthResult", "AuthStoreError", "InvalidUsername",
    "normalize_username",
    # env
    "envload", "paths",
    # 0.2.x compatibility aliases for the CLI's default locations
    "DB_PATH", "HISTORY_PATH",
    # generator
    "generate_password", "GEN_CHARSET", "GEN_DEFAULT_LENGTH",
    # crypto primitives
    "derive_key", "derive_entry_key", "encrypt", "decrypt",
    "KEY_SIZE", "SALT_SIZE", "NONCE_SIZE",
    # cli entry point
    "main",
]

# ── 0.2.x compatibility: sofiavault.DB_PATH / sofiavault.HISTORY_PATH ────────
# The historical single-module surface exposed these as assignable globals
# ("sofiavault.DB_PATH = tmp" pointed every command at a sandbox vault).
# They now live in sofiavault.paths, and all vault-location code reads
# paths.* — a plain re-export here would make that assignment a dead
# attribute nothing reads, silently retargeting commands at the real
# ~/.sofiavault vault. These forwarding properties keep both reads and
# writes hitting paths.*, so the old pattern keeps working.
import sys as _sys
import types as _types
from pathlib import Path as _Path

from . import envload, paths  # noqa: F401  (isort: after siblings to avoid cycle)
from .auth import (  # noqa: F401
    AuthResult,
    AuthStoreError,
    InvalidUsername,
    UserStore,
    normalize_username,
)
from .cli import (  # noqa: F401
    AUTO_LOCK_SECONDS,
    CLIPBOARD_CLEAR_SECONDS,
    C,
    VaultREPL,
    VaultSession,
    check_for_updates,
    cmd_add,
    cmd_auth,
    cmd_delete,
    cmd_edit,
    cmd_env,
    cmd_export,
    cmd_gen,
    cmd_get,
    cmd_import,
    cmd_import_vault,
    cmd_key,
    cmd_list,
    cmd_run,
    cmd_wipe,
    copy_to_clipboard,
    main,
    schedule_clipboard_clear,
    setup_master,
    style,
    unlock_vault,
)
from .core import (  # noqa: F401
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    ENTRY_CONTEXT,
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    create_master_record,
    decrypt,
    derive_entry_key,
    derive_key,
    encrypt,
    verify_master_key,
    verify_master_password,
)
from .generator import (  # noqa: F401
    GEN_CHARSET,
    GEN_DEFAULT_LENGTH,
    GEN_TARGET_USER_BITS,
    _password_from_pool,
    generate_password,
    mix_pool,
)
from .storage import (  # noqa: F401
    MigrationResult,
    VaultEntry,
    _is_vault_file,
    _load_entry_payload,
    _shred_file,
    _table_exists,
    delete_entry,
    fuzzy_find_service,
    get_entry_by_service,
    get_master_data,
    get_password,
    init_db,
    is_vault_initialized,
    load_entries,
    migrate_legacy_vault,
    save_entry,
    save_master,
    update_entry,
)
from .vault import (  # noqa: F401
    Entry,
    EntryNotFound,
    Vault,
    VaultAlreadyInitialized,
    VaultCorrupted,
    VaultError,
    VaultLocked,
    VaultNotInitialized,
    WrongPassword,
)


class _CompatModule(_types.ModuleType):
    # Every accessor also refreshes the inert __dict__ seed (see below):
    # mock.patch reads the seed as the "original" to restore on exit, so a
    # stale seed would resurrect the import-time real ~/.sofiavault path
    # over a sandbox a test had installed.

    @property
    def DB_PATH(self) -> _Path:
        self.__dict__["DB_PATH"] = paths.DB_PATH
        return paths.DB_PATH

    @DB_PATH.setter
    def DB_PATH(self, value):
        paths.DB_PATH = _Path(value)
        self.__dict__["DB_PATH"] = paths.DB_PATH

    @property
    def HISTORY_PATH(self) -> _Path:
        self.__dict__["HISTORY_PATH"] = paths.HISTORY_PATH
        return paths.HISTORY_PATH

    @HISTORY_PATH.setter
    def HISTORY_PATH(self, value):
        paths.HISTORY_PATH = _Path(value)
        self.__dict__["HISTORY_PATH"] = paths.HISTORY_PATH


_sys.modules[__name__].__class__ = _CompatModule

# Seed inert module-__dict__ entries so unittest.mock.patch("sofiavault.DB_PATH")
# sees the attribute as local and restores the original on exit. Reads and
# writes never touch these: the properties above are data descriptors, which
# take precedence over the instance __dict__.
_sys.modules[__name__].__dict__["DB_PATH"] = paths.DB_PATH
_sys.modules[__name__].__dict__["HISTORY_PATH"] = paths.HISTORY_PATH
