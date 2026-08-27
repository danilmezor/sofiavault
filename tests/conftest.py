"""Suite-wide audit: every design test id must *pass*, not merely exist.

tests/test_docs.py checks that each T-id is implemented exactly once; that
check is satisfied by a test that is skipped (no bcrypt, no Docker, no
v0.3.0 tag). Here the outcome of every id-carrying test is recorded and,
after a full run, ids that never passed are listed. With `CI` or
`SOFIAVAULT_STRICT_IDS` set in the environment that list fails the session
(review finding S2); otherwise it is reported as a warning line.
"""

import os
import re
from pathlib import Path

_ID_RE = re.compile(r"(?:^|_)T_(\d+)_(\d+)(?:_|$)")
_ID_FILE = Path(__file__).parent / "fixtures" / "test-ids-0.4.0.txt"
_outcomes: dict = {}


def pytest_runtest_logreport(report):
    m = _ID_RE.search(report.nodeid.rsplit("::", 1)[-1])
    if not m:
        return
    tid = f"T-{m.group(1)}-{m.group(2)}"
    bucket = _outcomes.setdefault(tid, set())
    if report.when == "call" and report.passed:
        bucket.add("passed")
    elif report.skipped:
        bucket.add("skipped")
    elif report.failed:
        bucket.add("failed")


def _is_full_run(session) -> bool:
    opt = session.config.option
    if getattr(opt, "keyword", "") or getattr(opt, "markexpr", ""):
        return False
    args = [str(Path(a).resolve()) for a in session.config.args]
    return all(a == str(Path(__file__).parent.resolve())
               or a == str(Path(__file__).parent.parent.resolve()) for a in args)


def pytest_sessionfinish(session, exitstatus):
    if not _is_full_run(session) or not _ID_FILE.exists():
        return
    expected = _ID_FILE.read_text().split()
    not_passed = [i for i in expected if "passed" not in _outcomes.get(i, ())]
    if not not_passed:
        return
    detail = ", ".join(f"{i}({'/'.join(sorted(_outcomes.get(i, {'missing'})))})"
                       for i in not_passed)
    strict = bool(os.environ.get("CI") or os.environ.get("SOFIAVAULT_STRICT_IDS"))
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    line = (f"design test ids that did not pass: {detail}"
            + ("" if strict else "  [set SOFIAVAULT_STRICT_IDS=1 to fail on this]"))
    if reporter is not None:
        reporter.write_line(("ERROR " if strict else "WARNING ") + line,
                            red=strict, yellow=not strict)
    if strict:
        session.exitstatus = 1
