"""Single source of truth for OS detection.

Use sys.platform — more precise than os.name (which collapses macOS and
Linux into "posix"). WSL is treated as Linux: sys.platform on WSL is
"linux" and the integration story uses Linux setup.
"""
import os
import sys

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def is_wsl() -> bool:
    """Heuristic for "running inside WSL". Used only to print a friendly
    note in the wizard — behaviour stays the same as native Linux."""
    if not IS_LINUX:
        return False
    if "microsoft" in os.uname().release.lower():
        return True
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    return False
