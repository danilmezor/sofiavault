"""Default on-disk locations for the SofiaVault CLI.

These are CLI conveniences only. Library consumers (Vault, UserStore,
envload) always receive explicit paths and never read this module.
Access these as `paths.DB_PATH` (attribute style) so tests can patch
`sofiavault.paths.DB_PATH` in one place.
"""

from pathlib import Path

DB_PATH = Path.home() / ".sofiavault" / "vault.db"
HISTORY_PATH = Path.home() / ".sofiavault" / ".history"
