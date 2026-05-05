"""Self-audit of MagiSentry's own dependencies.

Runs on every scan startup. Non-blocking — only informs the user. Checks:
  - magika, pip-audit, semgrep
  - For each installed dep: query OSV for CVEs against the installed version
  - For each installed dep: query PyPI for the latest version

Uses `urllib` (stdlib) only, mirroring the rest of the project. Reuses the
same OSV endpoint contract that `step2_osv.py` already proved out.
"""
import json
import shutil
import subprocess
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from .i18n import Translator

# Deps we audit. `pkg_name` is the importable / PyPI package name.
DEPS = ("magika", "pip-audit", "semgrep")


def _installed_version(pkg_name: str) -> Optional[str]:
    """Return installed version, or None. Tries importlib.metadata first,
    falls back to `<binary> --version` for CLI-only deps like semgrep."""
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:  # pragma: no cover (Python <3.8 not supported anyway)
        return None
    try:
        return version(pkg_name)
    except PackageNotFoundError:
        pass
    # Fallback: ask the binary. Some users install semgrep system-wide.
    bin_name = pkg_name
    if shutil.which(bin_name) is None:
        return None
    try:
        proc = subprocess.run([bin_name, "--version"],
                              capture_output=True, text=True, timeout=10)
        out = (proc.stdout or proc.stderr or "").strip().split("\n", 1)[0]
        # e.g. "1.2.3" or "semgrep 1.2.3"
        for tok in out.split():
            if tok and tok[0].isdigit():
                return tok
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _osv_cves(pkg_name: str, version: str) -> Optional[List[str]]:
    """Return list of CVE/GHSA ids for this exact version, or None on error."""
    body = json.dumps({
        "package": {"name": pkg_name, "ecosystem": "PyPI"},
        "version": version,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query", data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, ValueError):
        return None
    return sorted({v.get("id", "?") for v in (data.get("vulns") or [])})


def _pypi_latest(pkg_name: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{pkg_name}/json", timeout=5,
        ) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, ValueError):
        return None
    return (data.get("info") or {}).get("version")


def _newer(a: str, b: str) -> bool:
    """True if a is strictly newer than b. Best-effort dotted comparison."""
    def key(s: str):
        out = []
        for part in s.split("."):
            num = ""
            for ch in part:
                if ch.isdigit():
                    num += ch
                else:
                    break
            out.append(int(num) if num else 0)
        return tuple(out)
    try:
        return key(a) > key(b)
    except (ValueError, TypeError):
        return False


def audit() -> Tuple[List[str], List[str]]:
    """Return (cve_warnings, update_suggestions). Each is a list of strings
    already formatted for printing — caller decides how to surface them."""
    cve_warnings: List[str] = []
    updates: List[str] = []
    for dep in DEPS:
        installed = _installed_version(dep)
        if not installed:
            continue  # not installed; not our concern here
        cves = _osv_cves(dep, installed)
        if cves:
            cve_warnings.append(
                f"{dep} {installed} has known CVE(s): {', '.join(cves)}"
            )
        latest = _pypi_latest(dep)
        if latest and _newer(latest, installed):
            updates.append(f"{dep}: {installed} -> {latest}")
    return cve_warnings, updates


def print_audit(t: Translator, config=None) -> None:
    """Run the audit and print findings via Translator. Silent if all clean."""
    cves, updates = audit()
    if cves:
        print()
        print(t.t("self_audit_cve_header"))
        for line in cves:
            print("  ! " + line)
        print("  " + t.t("self_audit_cve_recommend"))
        try:
            from .notifier import notify_dep_cve
            notify_dep_cve(t, cves, config)
        except Exception:
            pass
    if updates:
        print(t.t("self_audit_updates_header"))
        for line in updates:
            print("    " + line)
        print("  " + t.t("self_audit_updates_recommend"))
