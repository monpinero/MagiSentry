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


def audit() -> Tuple[List[str], List[Tuple[str, str, str]]]:
    """Return (cve_warnings, updates).

    `cve_warnings` is a list of pre-formatted strings ready to print.
    `updates` is a list of (pkg, installed, latest) tuples — structured
    so the caller (scanner.py) can drive an interactive menu instead of
    a flat printout. The split exists because CVE warnings are pure
    information while updates are an action point."""
    cve_warnings: List[str] = []
    updates: List[Tuple[str, str, str]] = []
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
            updates.append((dep, installed, latest))
    return cve_warnings, updates


def should_show_update(pkg: str, latest: str, config=None) -> bool:
    """Filter for `dep_skip` / `dep_remind` config state.

    `dep_skip[pkg] == latest`: user said "Skip this version" — silence
    the menu for THIS exact version (a newer one re-triggers the prompt).

    `dep_remind[pkg]` is an ISO timestamp; suppress until `now >= that`.
    A malformed timestamp is treated as expired so a corrupt config
    can't permanently silence the menu."""
    if config is None:
        return True
    skip = getattr(config, "dep_skip", {})
    if skip.get(pkg) == latest:
        return False
    remind = getattr(config, "dep_remind", {})
    if pkg in remind:
        import datetime
        try:
            remind_after = datetime.datetime.fromisoformat(remind[pkg])
            if datetime.datetime.now() < remind_after:
                return False
        except (ValueError, TypeError):
            pass
    return True


def print_audit(t: Translator, config=None
                ) -> List[Tuple[str, str, str]]:
    """Run the audit, surface CVE warnings, return pending updates.

    CVE warnings are printed inline (informational, no user action).
    Updates are RETURNED, not printed — the caller (scanner.main) hands
    them to the [1]-[4] interactive menu. Updates suppressed by
    `dep_skip` / `dep_remind` are filtered out here so the scanner
    never sees them. Silent if everything is clean."""
    cves, all_updates = audit()
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
    return [
        (pkg, installed, latest)
        for pkg, installed, latest in all_updates
        if should_show_update(pkg, latest, config)
    ]
