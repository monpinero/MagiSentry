"""Universal shim runner for shell wrappers (`pip.bat`, `npm.bat`, ...).

Usage:
    python -m magisentry.shim <ecosystem> <args...>

Behavior:
    1. If <args> looks like an `install` command, route through the magisentry
       scanner. Scanner exit 0 -> fall through and exec the REAL ecosystem
       binary with the same args. Scanner exit 2 -> block (exit 2). Scanner
       exit 1 (fail-secure) -> block.
    2. Otherwise (e.g. `pip list`, `npm test`) -> exec the REAL binary
       transparently with no scanning.

The shim avoids infinite loops by skipping any binary whose directory
contains this very shim wrapper (PATH ordering trick).
"""
import os
import shutil
import subprocess
import sys
from typing import List, Optional

from .hooks._shared import (
    parse_install_command, run_for_packages,
    normalise_uv_args, normalise_uvx_args,
)

REAL_BIN_NAMES = {
    "pip": ["pip", "pip3"],
    "npm": ["npm"],
    "yarn": ["yarn"],
    "pnpm": ["pnpm"],
    "uv": ["uv"],
    "uvx": ["uvx"],
}


def _find_real(name: str) -> Optional[str]:
    """Return path to the real executable, skipping our own shim directory."""
    shim_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else ""
    path_env = os.environ.get("PATH", "")
    for entry in path_env.split(os.pathsep):
        if not entry or os.path.normcase(os.path.abspath(entry)) == os.path.normcase(shim_dir):
            continue
        candidate = shutil.which(name, path=entry)
        if candidate:
            return candidate
    # Fallback: maybe it's only on PATH alongside us — last resort.
    return shutil.which(name)


def _exec_real(ecosystem: str, args: List[str]) -> int:
    for name in REAL_BIN_NAMES.get(ecosystem, [ecosystem]):
        real = _find_real(name)
        if real:
            return subprocess.call([real] + args)
    sys.stderr.write(f"magisentry shim: real `{ecosystem}` binary not found on PATH\n")
    return 127


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return 0
    ecosystem = argv[0]
    rest = argv[1:]
    if ecosystem not in ("pip", "npm", "yarn", "pnpm", "uv", "uvx"):
        sys.stderr.write(f"magisentry shim: unknown ecosystem `{ecosystem}`\n")
        return 1

    # uv/uvx: only a few sub-commands install packages. Everything else
    # (uv sync, uv run, uv build, uv venv, ...) passes through untouched.
    if ecosystem in ("uv", "uvx"):
        normaliser = normalise_uv_args if ecosystem == "uv" else normalise_uvx_args
        packages = normaliser(rest)
        if packages is None:
            return _exec_real(ecosystem, rest)
        rc = run_for_packages("pip", packages)
        if rc == 2:
            sys.stderr.write("MagiSentry blocked this install.\n")
            return 2
        if rc == 1:
            sys.stderr.write("MagiSentry scanner failed in fail-secure mode — install blocked.\n")
            return 2
        return _exec_real(ecosystem, rest)

    # Reconstruct command for parser.
    full = ecosystem + " " + " ".join(rest)
    parsed = parse_install_command(full)
    if parsed is None:
        # Not an install — passthrough.
        return _exec_real(ecosystem, rest)

    eco, packages = parsed
    rc = run_for_packages(eco, packages)
    if rc == 2:
        sys.stderr.write("MagiSentry blocked this install.\n")
        return 2
    if rc == 1:
        sys.stderr.write("MagiSentry scanner failed in fail-secure mode — install blocked.\n")
        return 2
    # Allow original install to proceed.
    return _exec_real(ecosystem, rest)


if __name__ == "__main__":
    sys.exit(main())
