"""SofiaVault — encrypted secrets vault, CLI password manager, and
verify-only user auth store.

Library entry points:

    from sofiavault import Vault, UserStore
    import sofiavault.envload

Importing this package is silent: no prompts, no prints, no network.
The flat re-exports below keep the historical single-module surface
(`from sofiavault import derive_key, init_db, ...`) working.
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
    # generator
    "generate_password", "GEN_CHARSET", "GEN_DEFAULT_LENGTH",
    # crypto primitives
    "derive_key", "derive_entry_key", "encrypt", "decrypt",
    "KEY_SIZE", "SALT_SIZE", "NONCE_SIZE",
    # cli entry point
    "main",
]

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
