"""Trusted-dependency allow-list for MagiSentry's own runtime deps.

When MagiSentry scans the new version of one of its own dependencies
(semgrep, magika, yara-python, pip-audit, winotify) before upgrading,
those packages legitimately contain the patterns MagiSentry is designed
to catch:

  * semgrep ships .dll / .so binaries under `semgrep/bin/` and reads
    SEMGREP_APP_TOKEN from the environment with `requests.post(...)` —
    a textbook credential-theft signature in user code.
  * magika ships `magika.exe` in its wheel's .data/scripts/ directory.
  * yara-python ships .pyd (Windows) / .so (Linux) extension modules.
  * pip-audit reads env vars and calls `requests.get` against PyPI's
    advisory DB.

The allow-list scopes file-level exemptions to ONE package each. The
exemption fires only when ALL three conditions hold:

  1. The package currently being scanned is in TRUSTED_DEPS.
  2. The candidate file's path inside the extracted archive matches
     one of the package's allowed glob patterns.
  3. The package is actually installed in the current Python
     environment (importlib.metadata can locate it).

Without (3) an attacker could publish `evilpkg` whose wheel layout
mimics `semgrep/bin/x.dll` and inherit semgrep's exemption. The
installed-check makes the allow-list a property of the user's runtime,
not of the wheel's contents.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# (pkg_name) -> dict with:
#   magika_patterns:  globs of files to skip inside step 6 (Magika)
#   yara_patterns:    globs of paths to skip inside step 8 (Yara)
# Patterns are matched against POSIX-normalised relative paths inside
# the extracted archive. Case-insensitive (Windows-friendly).
TRUSTED_DEPS: Dict[str, Dict[str, List[str]]] = {
    "semgrep": {
        # Native binaries live under semgrep/bin/ and semgrep.libs/.
        # Wheels split: pure-python + native parts may sit DIRECTLY at
        # the wheel root (post-install layout) OR under the
        # `<wheel>.data/purelib/` directory (build layout). Both must
        # be covered because step 4 extracts the wheel as-is.
        # Note: fnmatch `*` is not path-aware, so `semgrep/bin/*` already
        # matches arbitrary depth — no separate `**/*` needed.
        "magika_patterns": [
            "semgrep/bin/*",
            "semgrep.libs/*",
            "semgrep-*.data/purelib/semgrep/bin/*",
            "semgrep-*.data/purelib/semgrep.libs/*",
            # CLI entry point dropped by setuptools for `console_scripts`.
            "semgrep-*.data/scripts/semgrep*",
        ],
        # Auth + telemetry code reads SEMGREP_APP_TOKEN and posts to
        # semgrep.dev; test fixtures contain .env / dotenv markers that
        # trip env_exfiltration. Restrict to the package tree itself
        # — covering both layouts as above.
        "yara_patterns": [
            "semgrep/*",
            "semgrep.libs/*",
            "semgrep-*.data/purelib/semgrep/*",
            "semgrep-*.data/purelib/semgrep.libs/*",
            "semgrep-*.dist-info/*",
        ],
    },
    "magika": {
        "magika_patterns": [
            # Standard console_scripts wheel layout.
            "magika-*.data/scripts/magika*",
            # ONNX runtime DLLs bundled inside the package.
            "magika/onnxruntime/*",
            "magika/*.dll",
            "magika/*.pyd",
            "magika/*.so",
        ],
        # Magika's own code is pure-Python ML inference — low YARA risk,
        # but include the tree for symmetry / future-proofing.
        "yara_patterns": [
            "magika/*",
            "magika-*.dist-info/*",
        ],
    },
    "yara-python": {
        "magika_patterns": [
            # The C extension on Windows ships as .pyd; on Linux as .so.
            "yara/*.pyd",
            "yara/*.so",
            "yara/*",  # ships compiled rules + native shim
        ],
        "yara_patterns": [
            "yara/*",
            "yara_python-*.dist-info/*",
        ],
    },
    "pip-audit": {
        # pip-audit is pure Python — no native binaries.
        "magika_patterns": [],
        # But it reads PIP_INDEX_URL / env vars and calls requests.get,
        # which trips credential_theft on auth-related modules.
        "yara_patterns": [
            "pip_audit/*",
            "pip_audit-*.dist-info/*",
        ],
    },
    "winotify": {
        # Pure-Python Windows toast wrapper, no binaries.
        "magika_patterns": [],
        # No known YARA FP today but reserve the slot so future versions
        # don't surprise us.
        "yara_patterns": [
            "winotify/*",
            "winotify-*.dist-info/*",
        ],
    },
}


# Aliases — pip name vs. import name vs. wheel-archive top-level dir.
# importlib.metadata uses the PyPI name; the wheel directory inside
# extracted archives may differ (e.g. "pip-audit" → "pip_audit").
_ALIASES: Dict[str, str] = {
    "pip-audit": "pip_audit",
    "yara-python": "yara_python",
}


def _normalise_pkg(name: str) -> str:
    """Strip version pin / extras / case for matching against TRUSTED_DEPS."""
    n = name.split("==", 1)[0].split("[", 1)[0].split(";", 1)[0].strip().lower()
    # `_` ↔ `-` are interchangeable on PyPI; canonicalise to dash.
    return n.replace("_", "-")


def _is_installed(pkg_name: str) -> bool:
    """True if `pkg_name` is importable / has metadata in this env.

    This is the third condition for any exemption. Without it a wheel
    that *looks* like semgrep's layout would inherit semgrep's
    exemption — but the user never installed semgrep, so a malicious
    `semgrep/bin/x.dll` in some other package's archive should still
    be flagged."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover (Py<3.8 not supported)
        return False
    try:
        version(pkg_name)
        return True
    except PackageNotFoundError:
        return False


def _relative_posix(file_path: Path, archive_root: Optional[Path]) -> str:
    """Return a POSIX-style path relative to archive_root, lowercased."""
    if archive_root is None:
        rel = file_path.name
    else:
        try:
            rel = str(file_path.relative_to(archive_root))
        except ValueError:
            rel = file_path.name
    return rel.replace(os.sep, "/").lower()


def _match_any(rel: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(rel, pat.lower()) for pat in patterns)


def _resolve_pkg(scanned_package: str) -> Optional[str]:
    """Return the TRUSTED_DEPS key matching the package being scanned,
    or None if this scan is not for one of our trusted deps."""
    norm = _normalise_pkg(scanned_package)
    if norm in TRUSTED_DEPS:
        return norm
    # Try reverse alias (import name → pypi name).
    for pypi, alias in _ALIASES.items():
        if norm == alias.replace("_", "-"):
            return pypi
    return None


def is_trusted_dep_file(file_path: Path,
                        scanned_package: str,
                        archive_root: Optional[Path] = None
                        ) -> Tuple[bool, str]:
    """Return (True, pkg_name) if `file_path` is a legitimate native
    binary belonging to one of MagiSentry's own dependencies AND that
    dependency is actually installed in the current environment.

    `scanned_package` is the package being scanned (e.g. "semgrep" or
    "semgrep==1.165.0"). The exemption is scoped to that package — a
    file matching semgrep's pattern only counts when semgrep itself
    is being scanned. This blocks the "layout-spoofing" attack where
    a malicious package mimics semgrep's directory tree.

    `archive_root` is the extracted archive root from step 4
    (`ctx["extracted"]`); patterns are matched against POSIX-style
    paths relative to that root."""
    pkg = _resolve_pkg(scanned_package)
    if pkg is None:
        return (False, "")
    patterns = TRUSTED_DEPS[pkg].get("magika_patterns", [])
    if not patterns:
        return (False, "")
    rel = _relative_posix(file_path, archive_root)
    if not _match_any(rel, patterns):
        return (False, "")
    # Final gate: package must actually be installed locally.
    if not _is_installed(pkg):
        return (False, "")
    return (True, pkg)


def is_trusted_dep_path(file_path: Path,
                        scanned_package: str,
                        archive_root: Optional[Path] = None
                        ) -> Tuple[bool, str]:
    """Same contract as `is_trusted_dep_file` but for YARA-scope
    patterns (the whole package tree, not just native binaries)."""
    pkg = _resolve_pkg(scanned_package)
    if pkg is None:
        return (False, "")
    patterns = TRUSTED_DEPS[pkg].get("yara_patterns", [])
    if not patterns:
        return (False, "")
    rel = _relative_posix(file_path, archive_root)
    if not _match_any(rel, patterns):
        return (False, "")
    if not _is_installed(pkg):
        return (False, "")
    return (True, pkg)
