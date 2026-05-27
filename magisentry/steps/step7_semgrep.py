"""Step 7 — Semgrep static analysis.

Optional: if the `semgrep` binary is not on PATH, returns FAILURE with
`can_retry=False` so fail-secure offers Skip rather than infinite Retry.
Yara is step 8, its own module (`step8_yara.py`) with its own config
toggle — that's why this file no longer mentions Yara.
"""
import json
import shutil
import subprocess
from pathlib import Path

from ..models import StepResult
from ._common import split_pkg

STEP = "step7_semgrep"


def _find_semgrep() -> str | None:
    """Locate the semgrep executable.

    Search order:
      1. uv tool isolation — semgrep.exe lives in the same Scripts/
         (Windows) or bin/ (POSIX) directory as the isolated Python.
         Derived from the same logic as _get_uv_python_path() in
         wizard.py so both helpers stay in sync.
      2. PATH fallback — covers manual / system-wide installs.

    Returns the full path string or None when not found anywhere.
    """
    import os
    from pathlib import Path as _Path
    from .._platform import IS_WINDOWS

    # --- 1. uv tool isolation ---
    if IS_WINDOWS:
        candidates = []
        for env_var in ("APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(env_var, "")
            if base:
                candidates.append(
                    _Path(base) / "uv" / "tools" / "magisentry"
                    / "Scripts" / "semgrep.exe"
                )
    else:
        candidates = [
            _Path.home() / ".local" / "share" / "uv" / "tools"
            / "magisentry" / "bin" / "semgrep"
        ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    # --- 2. PATH fallback ---
    return shutil.which("semgrep")


def run(ecosystem, package, config, t, ctx):
    extracted = ctx.get("extracted")
    if not extracted:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause="no extracted directory from step 4",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    semgrep_bin = _find_semgrep()
    if semgrep_bin is None:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_not_installed"),
            possible_cause=t.t("step7_cause_not_installed"),
            recommendation=t.t("step7_recommend_not_installed"),
            can_retry=False,
        )
    try:
        proc = subprocess.run(
            # `p/supply-chain` is purpose-built for supply-chain audits:
            # post-install hooks calling out, base64-encoded payloads, etc.
            # `p/secrets` catches hardcoded credentials in third-party code.
            # NOTE: semgrep 1.163.0 had an RPC bug breaking both rulesets on
            # Windows. Fixed by pinning semgrep==1.162.0 in setup.py.
            # `p/security-audit` was tried but produced false positives on
            # legitimate library code (subprocess/eval/SSL patterns).
            # `p/malicious-code` returns HTTP 404 on the Semgrep registry.
            [semgrep_bin,
             "--config", "p/supply-chain",
             "--config", "p/secrets",
             "--json", "--quiet", "--no-git-ignore", str(extracted)],
            capture_output=True, text=True, timeout=300,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash") + f" ({e})",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )

    if proc.returncode not in (0, 1):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash") + " " + (proc.stderr or "")[:200],
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash"),
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    findings = report.get("results") or []
    # Test fixtures legitimately include "hardcoded credentials" like
    # `API_KEY = "fake-key-for-testing"`. Any well-tested package
    # will trip p/secrets in its `tests/`, `fixtures/`, `docs/`,
    # `examples/` trees. Split findings by path: if every hit is in
    # one of those buckets, downgrade to a warning instead of
    # blocking the install — a real attacker won't carefully hide
    # their payload inside `tests/`.
    real_findings: list = []
    test_findings: list = []
    for f in findings:
        path = (f.get("path") or "").replace("\\", "/").lower()
        if _is_test_path(path):
            test_findings.append(f)
        else:
            real_findings.append(f)

    name, _ = split_pkg(ecosystem, package)

    if real_findings:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_pattern",
                        count=len(real_findings), package=name)
                    + "\n    " + _format_findings(real_findings),
            warnings=([_summarise_test_findings(test_findings, t)]
                      if test_findings else []),
            can_retry=False,
        )
    if test_findings:
        return StepResult(
            status="OK", step=STEP,
            warnings=[_summarise_test_findings(test_findings, t)],
        )
    return StepResult(status="OK", step=STEP)


_TEST_PATH_MARKERS = ("/tests/", "/test/", "/fixtures/",
                      "/docs/", "/examples/")


def _is_test_path(path_lower: str) -> bool:
    """Return True when the path lives under a directory that
    legitimately ships fake secrets / test patterns."""
    if not path_lower:
        return False
    # Prefix-anchored check too: "tests/foo" without a leading slash.
    if any(path_lower.startswith(m.lstrip("/")) for m in _TEST_PATH_MARKERS):
        return True
    return any(m in path_lower for m in _TEST_PATH_MARKERS)


def _format_findings(items: list) -> str:
    """Render up to 3 findings as `rule @ path:line`, summarising
    the rest with `... and N more`."""
    details = []
    for f in items[:3]:
        rule = f.get("check_id", "unknown-rule")
        path = f.get("path", "?")
        line = (f.get("start") or {}).get("line", "?")
        try:
            rel = "/".join(Path(path).parts[-2:])
        except Exception:
            rel = path
        details.append(f"{rule} @ {rel}:{line}")
    if len(items) > 3:
        details.append(f"... and {len(items) - 3} more")
    return "\n    ".join(details)


def _summarise_test_findings(items: list, t) -> str:
    """One-line warning summarising findings that all sit in test
    fixtures / docs / examples. The full list (first 5) is appended
    inline so the user still sees what was matched."""
    head = t.t("step7_warning_test_only", count=len(items))
    return head + "\n    " + _format_findings(items[:5])
