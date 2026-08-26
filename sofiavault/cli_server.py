"""Non-interactive server-side commands: env, run, rekey, doctor (and auth).

These are the commands a provisioning script, Dockerfile, CI job or
healthcheck runs. They differ from the personal-vault REPL in three ways:

* the vault path is explicit (`--vault`, else SOFIAVAULT_DB, else the
  default) and echoed when it came from the environment;
* unlocking goes through Vault.open_auto (SOFIAVAULT_KEY / _PASSWORD /
  _KEY_FILE / keyring); a password prompt appears only when stdin is a TTY;
* results are exit codes, not prose:

      0  ok            2  usage error, or no key source (VaultLocked)
      1  error         3  not found (env get)         127  exec target missing
"""

import argparse
import base64
import contextlib
import getpass
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Optional

from . import envload, paths
from .core import KEY_SIZE
from .storage import get_schema_version, verify_entries_mac
from .vault import (
    Vault,
    VaultCorrupted,
    VaultError,
    VaultLocked,
    VaultNotInitialized,
    VaultReadOnly,
    WrongPassword,
)

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_NOT_FOUND, EXIT_EXEC = 0, 1, 2, 3, 127


class _Usage(Exception):
    """A usage error the caller turns into exit 2 (argparse's convention)."""


class _Exit(Exception):
    def __init__(self, code: int, message: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message


def _err(msg: str):
    print(f"error: {msg}", file=sys.stderr)


def _warn(msg: str):
    print(f"warning: {msg}", file=sys.stderr)


def _stdin_is_tty() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


# ── vault resolution / unlock ───────────────────────────────────────────────

def _vault_path(arg: Optional[str]) -> Path:
    if arg:
        return Path(arg).expanduser()
    if paths.DB_PATH_FROM_ENV:
        print(f"using vault from SOFIAVAULT_DB: {paths.DB_PATH}", file=sys.stderr)
    return paths.DB_PATH


def _open(path: Path, *, readonly: bool = False, create: bool = False) -> Vault:
    """Unlock `path` via the open_auto chain; prompt only on a TTY.

    `create=True` lets set/import initialise a missing vault — from
    SOFIAVAULT_PASSWORD non-interactively, or by prompting on a TTY.
    """
    if not path.exists():
        if not create:
            raise _Exit(EXIT_ERROR, f"no vault at {path}")
        return _create(path)
    try:
        return Vault.open_auto(path) if not readonly else _open_auto_readonly(path)
    except VaultLocked as exc:
        if not _stdin_is_tty():
            raise _Exit(EXIT_USAGE, f"{exc}") from exc
        password = getpass.getpass("Master password: ")
        try:
            return Vault.open(path, password=password, readonly=readonly)
        except WrongPassword as exc2:
            raise _Exit(EXIT_ERROR, "wrong password") from exc2
    except WrongPassword as exc:
        raise _Exit(EXIT_ERROR, str(exc)) from exc
    except VaultReadOnly as exc:
        if readonly:
            raise
        raise _Exit(EXIT_ERROR, f"{exc} (read-only commands: env get, env list, "
                                "run, doctor)") from exc
    except VaultNotInitialized as exc:
        raise _Exit(EXIT_ERROR, str(exc)) from exc


def _open_auto_readonly(path: Path) -> Vault:
    """open_auto's key chain, but a read-only open (so a 0400 file works)."""
    # Resolve the key exactly as open_auto would, then open read-only.
    key = _resolve_key_from_env(path)
    if key is None:
        raise VaultLocked("no key source available: set SOFIAVAULT_KEY, "
                          "SOFIAVAULT_PASSWORD, or SOFIAVAULT_KEY_FILE")
    kind, value = key
    if kind == "key":
        return Vault.open(path, key=value, readonly=True)
    return Vault.open(path, password=value, readonly=True)


def _resolve_key_from_env(path: Path):
    """(kind, value) from the SOFIAVAULT_* chain, or None. Mirrors open_auto."""
    env = os.environ
    if env.get("SOFIAVAULT_KEY"):
        from .vault import _decode_key
        return "key", _decode_key(env["SOFIAVAULT_KEY"], "SOFIAVAULT_KEY")
    if env.get("SOFIAVAULT_PASSWORD"):
        return "password", env["SOFIAVAULT_PASSWORD"]
    if env.get("SOFIAVAULT_KEY_FILE"):
        from .vault import _decode_key
        key_path = Path(env["SOFIAVAULT_KEY_FILE"])
        check_private_file(key_path, "SOFIAVAULT_KEY_FILE")
        return "key", _decode_key(key_path.read_text(encoding="utf-8").strip(),
                                  "SOFIAVAULT_KEY_FILE")
    with contextlib.suppress(Exception):
        import keyring
        secret = keyring.get_password("sofiavault", str(path))
        if secret:
            return "password", secret
    return None


def check_private_file(path: Path, label: str):
    """Refuse a key/secret file that other users can read (POSIX)."""
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise VaultLocked(f"cannot read {label}: {exc}") from exc
    if os.name == "posix" and mode & 0o077:
        raise VaultLocked(
            f"{label} {path} is accessible to other users (mode "
            f"{oct(mode & 0o777)}); run 'chmod 600 {path}'"
        )


def _create(path: Path) -> Vault:
    password = os.environ.get("SOFIAVAULT_PASSWORD")
    if not password:
        if not _stdin_is_tty():
            raise _Exit(EXIT_USAGE, f"no vault at {path}; set SOFIAVAULT_PASSWORD "
                                    "to create it non-interactively")
        while True:
            password = getpass.getpass(f"Create master password for {path}: ")
            if len(password) < 8:
                print("Password must be at least 8 characters.", file=sys.stderr)
                continue
            if getpass.getpass("Confirm master password: ") == password:
                break
            print("Passwords don't match.", file=sys.stderr)
    print(f"created new vault at {path}", file=sys.stderr)
    return Vault.create(path, password)


# ── env ─────────────────────────────────────────────────────────────────────

def _read_value(args) -> str:
    if args.value is not None:
        _warn("--value leaves the secret in shell history; prefer stdin or --from-file")
        return args.value
    if args.from_file is not None:
        try:
            return Path(args.from_file).expanduser().read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise _Exit(EXIT_ERROR, f"cannot read {args.from_file}: {exc}") from exc
    data = sys.stdin.read()
    if data.endswith("\n"):
        data = data[:-1]   # `echo value |` and heredocs add one; keep anything else
    if not data:
        raise _Exit(EXIT_USAGE, "empty value on stdin (pass --from-file for an "
                                "intentionally empty or whitespace-only value)")
    return data


def _service(name: str) -> str:
    if not envload.VALID_NAME.match(name):
        raise _Exit(EXIT_USAGE, f"not a valid environment variable name: {name!r}")
    return envload.ENV_PREFIX + name.lower()


def cmd_env_set(args) -> int:
    service = _service(args.name)
    value = _read_value(args)
    if "\0" in value:
        raise _Exit(EXIT_USAGE, "value contains a NUL byte")
    if not envload.is_safe_name(args.name) and not args.allow_unsafe_names:
        raise _Exit(EXIT_USAGE, f"{args.name.upper()} controls how programs load code; "
                                "refusing (pass --allow-unsafe-names to override)")
    with _open(_vault_path(args.vault), create=True) as v:
        v.set(service, value)
    return EXIT_OK


def cmd_env_get(args) -> int:
    service = _service(args.name)
    with _open(_vault_path(args.vault), readonly=True) as v:
        try:
            value = v.get(service)
        except KeyError:
            return EXIT_NOT_FOUND
    sys.stdout.write(value if args.no_newline else value + "\n")
    sys.stdout.flush()
    return EXIT_OK


def cmd_env_del(args) -> int:
    service = _service(args.name)
    with _open(_vault_path(args.vault)) as v:
        try:
            v.delete(service)
        except KeyError:
            return EXIT_NOT_FOUND
    return EXIT_OK


def cmd_env_list(args) -> int:
    with _open(_vault_path(args.vault), readonly=True) as v:
        for name in envload.list_env_entries(v):
            print(name)
    return EXIT_OK


def cmd_env_import(args) -> int:
    src = Path(args.file).expanduser()
    if not src.exists():
        raise _Exit(EXIT_ERROR, f"file not found: {src}")
    allow = envload.load_allowlist(args.allow) if args.allow else None
    with _open(_vault_path(args.vault), create=True) as v:
        try:
            imported, skipped, rejected = envload.import_env_file(
                v, src, overwrite=args.overwrite, allow=allow)
        except envload.MalformedEnvFile as exc:
            raise _Exit(EXIT_ERROR, f"{exc}\nnothing was imported") from exc
    for name in imported:
        print(f"imported {name}")
    for name in skipped:
        print(f"skipped {name} (already present or empty)")
    for name in rejected:
        print(f"rejected {name} (unsafe or not allowlisted)")
    _warn(f"{src} still holds these secrets in plaintext: remove them and rotate")
    return EXIT_OK


def cmd_env_export(args) -> int:
    with _open(_vault_path(args.vault), readonly=True) as v:
        try:
            text = envload.export_env(v, allow_file=args.allow, fmt=args.format)
        except envload.ExportError as exc:
            raise _Exit(EXIT_ERROR, str(exc)) from exc
    sys.stdout.write(text)
    sys.stdout.flush()
    return EXIT_OK


# ── run ─────────────────────────────────────────────────────────────────────

def cmd_run(args) -> int:
    argv = list(args.command)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise _Usage("no command given")
    allow_file = args.allow
    if allow_file is None and paths.ALLOW_FILE is None:
        _warn("no allowlist (--allow FILE or SOFIAVAULT_ALLOW_FILE); "
              "falling back to the denylist")
    v = _open(_vault_path(args.vault), readonly=True)
    try:
        envload.exec_with_env(v, argv, allow_file=allow_file)  # never returns
    except FileNotFoundError:
        raise _Exit(EXIT_EXEC, f"command not found: {argv[0]}") from None
    except envload.UnsafeVariableName as exc:
        raise _Exit(EXIT_ERROR, f"{exc}\nremove it with: sofiavault env del <name>") from exc
    return EXIT_OK  # pragma: no cover — execv replaced the process


# ── rekey ───────────────────────────────────────────────────────────────────

def _read_new_password() -> str:
    if _stdin_is_tty():
        while True:
            pw = getpass.getpass("New master password: ")
            if len(pw) < 8:
                print("Password must be at least 8 characters.", file=sys.stderr)
                continue
            if getpass.getpass("Confirm new master password: ") == pw:
                return pw
            print("Passwords don't match.", file=sys.stderr)
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        raise _Exit(EXIT_USAGE, "new password expected on stdin (or --key-file PATH "
                                "to rotate to a fresh random key)")
    return pw


def write_key_file(path: Path, key_b64: str):
    """Write `key_b64` to `path` at 0600 via temp-file + atomic rename.

    At every instant either the old file or the new one is complete on
    disk — never neither, never a half-written key.
    """
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key_b64 + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    os.chmod(path, 0o600)


def cmd_rekey(args) -> int:
    path = _vault_path(args.vault)
    v = _open(path)
    try:
        if args.key_file:
            key_path = Path(args.key_file).expanduser()
            new_key = secrets.token_bytes(KEY_SIZE)
            new_b64 = v.rekey(new_key=new_key)
            write_key_file(key_path, new_b64)
            print(f"rotated; new key written to {key_path}", file=sys.stderr)
        else:
            new_b64 = v.rekey(new_password=_read_new_password())
            print("rotated", file=sys.stderr)
    except VaultCorrupted as exc:
        raise _Exit(EXIT_ERROR, f"rekey refused: {exc}") from exc
    finally:
        v.close()
    if args.print_key:
        print(new_b64)
    return EXIT_OK


# ── doctor ──────────────────────────────────────────────────────────────────

class _Report:
    def __init__(self):
        self.problems: list = []
        self.lines: list = []

    def ok(self, msg: str):
        self.lines.append(f"ok       {msg}")

    def warn(self, msg: str):
        self.lines.append(f"warning  {msg}")

    def problem(self, msg: str, fix: str = ""):
        self.problems.append(msg)
        self.lines.append(f"PROBLEM  {msg}" + (f"\n         fix: {fix}" if fix else ""))


def _check_key_file(rep: _Report, key_file: Path):
    if not key_file.exists():
        rep.problem(f"key file {key_file} does not exist",
                    "sofiavault key > FILE; chmod 600 FILE")
        return
    st = key_file.stat()
    if os.name == "posix":
        if st.st_mode & 0o077:
            rep.problem(f"key file {key_file} has mode {oct(stat.S_IMODE(st.st_mode))}",
                        f"chmod 600 {key_file}")
        else:
            rep.ok(f"key file {key_file} mode 0600")
        if st.st_uid != os.geteuid():
            rep.problem(f"key file {key_file} is owned by uid {st.st_uid}, "
                        f"not the current uid {os.geteuid()}",
                        f"chown {os.geteuid()} {key_file}")
        else:
            rep.ok(f"key file {key_file} owned by current uid")
    try:
        raw = base64.b64decode(key_file.read_text(encoding="utf-8").strip(), validate=True)
        if len(raw) != KEY_SIZE:
            rep.problem(f"key file {key_file} does not decode to {KEY_SIZE} bytes")
        else:
            rep.ok("key file decodes to a 32-byte key")
    except Exception as exc:
        rep.problem(f"key file {key_file} is not valid base64: {exc}")


def cmd_doctor(args) -> int:
    rep = _Report()
    path = _vault_path(args.vault)
    key_file = Path(args.key_file).expanduser() if args.key_file else (
        Path(os.environ["SOFIAVAULT_KEY_FILE"]).expanduser()
        if os.environ.get("SOFIAVAULT_KEY_FILE") else None)
    if key_file is not None:
        _check_key_file(rep, key_file)
    elif os.environ.get("SOFIAVAULT_KEY"):
        rep.ok("key source: SOFIAVAULT_KEY")
    elif os.environ.get("SOFIAVAULT_PASSWORD"):
        rep.warn("key source: SOFIAVAULT_PASSWORD (Argon2 derivation on every open; "
                 "prefer a key file for long-running services)")
    else:
        rep.problem("no key source: set SOFIAVAULT_KEY_FILE (recommended), "
                    "SOFIAVAULT_KEY or SOFIAVAULT_PASSWORD")

    if not path.exists():
        rep.problem(f"vault {path} does not exist")
    else:
        readable = os.access(path, os.R_OK)
        writable = os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
        if not readable:
            rep.problem(f"vault {path} is not readable")
        else:
            rep.ok(f"vault {path} readable" + (", writable" if writable else
                                                ", read-only (open with readonly=True)"))
        v = None
        if readable and not rep.problems:
            try:
                v = _open(path, readonly=True)
            except _Exit as exc:
                rep.problem(f"cannot unlock vault: {exc.message}")
            except VaultError as exc:
                rep.problem(f"cannot open vault: {exc}")
        if v is not None:
            try:
                rep.ok(f"schema version {get_schema_version(v._conn)}")
                if v.tampered or not verify_entries_mac(v._conn, v._key):
                    rep.problem("entry-set MAC does not verify: the vault was tampered "
                                "with or rolled back")
                else:
                    rep.ok("entry-set MAC verifies")
                if v.corrupt_count:
                    rep.problem(f"{v.corrupt_count} entries fail authenticated decryption")
                names = envload.list_env_entries(v)
                rep.ok(f"{len(v.list_entries())} entries, {len(names)} env:* entries")
                _check_allow(rep, args.allow, names)
            finally:
                v.close()
        else:
            _check_allow(rep, args.allow, None)

    for line in rep.lines:
        print(line)
    print(f"{len(rep.problems)} problem(s)")
    return EXIT_OK if not rep.problems else EXIT_ERROR


def _check_allow(rep: _Report, allow_arg: Optional[str], names: Optional[list]):
    allow_path = Path(allow_arg).expanduser() if allow_arg else paths.ALLOW_FILE
    if allow_path is None:
        rep.warn("no allowlist configured (denylist mode); set SOFIAVAULT_ALLOW_FILE")
        return
    try:
        allowed = envload.load_allowlist(allow_path)
    except envload.AllowListError as exc:
        rep.problem(str(exc))
        return
    rep.ok(f"allowlist {allow_path}: {len(allowed)} names")
    if names is None:
        return
    missing = sorted(set(allowed) - {n.upper() for n in names})
    if missing:
        rep.problem("allowlisted names missing from the vault: " + ", ".join(missing),
                    "sofiavault env set NAME < value")
    else:
        rep.ok("every allowlisted name is present in the vault")


# ── parser ──────────────────────────────────────────────────────────────────

class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _Usage(message)


def build_parser() -> argparse.ArgumentParser:
    root = _Parser(prog="sofiavault", add_help=True)
    sub = root.add_subparsers(dest="command", required=True)

    env = sub.add_parser("env", help="manage env:* entries")
    env_sub = env.add_subparsers(dest="env_command", required=True)

    def vault_opt(p):
        p.add_argument("--vault", metavar="PATH",
                       help="vault file (default: $SOFIAVAULT_DB or ~/.sofiavault/vault.db)")

    p = env_sub.add_parser("set", help="store a value (from stdin by default)")
    p.add_argument("name")
    vault_opt(p)
    src = p.add_mutually_exclusive_group()
    src.add_argument("--stdin", action="store_true", help="read the value from stdin (default)")
    src.add_argument("--value", metavar="V", help="value on the command line (warns)")
    src.add_argument("--from-file", metavar="F", help="read the value verbatim from a file")
    p.add_argument("--allow-unsafe-names", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_env_set)

    p = env_sub.add_parser("get", help="print a value (exit 3 if absent)")
    p.add_argument("name")
    p.add_argument("-n", "--no-newline", action="store_true")
    vault_opt(p)
    p.set_defaults(func=cmd_env_get)

    p = env_sub.add_parser("del", aliases=["delete", "rm"], help="delete an entry")
    p.add_argument("name")
    vault_opt(p)
    p.set_defaults(func=cmd_env_del)

    p = env_sub.add_parser("list", aliases=["ls"], help="list injectable names")
    vault_opt(p)
    p.set_defaults(func=cmd_env_list)

    p = env_sub.add_parser("import", help="import a dotenv file")
    p.add_argument("file")
    vault_opt(p)
    p.add_argument("--allow", metavar="FILE", help="only import allowlisted names")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_env_import)

    p = env_sub.add_parser("export", help="dump allowlisted values (allowlist required)")
    vault_opt(p)
    p.add_argument("--allow", metavar="FILE", required=True)
    p.add_argument("--format", choices=("dotenv", "json"), default="dotenv")
    p.set_defaults(func=cmd_env_export)

    p = sub.add_parser("run", help="exec a command with env:* injected")
    vault_opt(p)
    p.add_argument("--allow", metavar="FILE",
                   help="allowlist file (default: $SOFIAVAULT_ALLOW_FILE)")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("rekey", help="rotate the master key")
    vault_opt(p)
    p.add_argument("--key-file", metavar="PATH",
                   help="rotate to a fresh random key and write it here (0600)")
    p.add_argument("--print-key", action="store_true", help="print the new base64 key")
    p.set_defaults(func=cmd_rekey)

    p = sub.add_parser("doctor", help="check a deployment would boot")
    vault_opt(p)
    p.add_argument("--key-file", metavar="FILE", help="default: $SOFIAVAULT_KEY_FILE")
    p.add_argument("--allow", metavar="FILE", help="default: $SOFIAVAULT_ALLOW_FILE")
    p.set_defaults(func=cmd_doctor)
    return root


SERVER_COMMANDS = ("env", "run", "rekey", "doctor")


def main(argv: list) -> int:
    """Entry point for the server-side subcommands. Returns the exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _Usage as exc:
        _err(str(exc))
        return EXIT_USAGE
    except SystemExit as exc:      # --help
        return int(exc.code or 0)
    try:
        return args.func(args)
    except _Usage as exc:
        _err(str(exc))
        return EXIT_USAGE
    except _Exit as exc:
        if exc.message:
            _err(exc.message)
        return exc.code
    except envload.AllowListError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except VaultLocked as exc:
        _err(str(exc))
        return EXIT_USAGE
    except VaultError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
