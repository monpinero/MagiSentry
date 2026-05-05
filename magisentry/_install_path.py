r"""Ensure the Python user-scripts directory (where pip --user puts
`magisentry.exe`) and `~/.magisentry/bin` are on the user-scope PATH.
Runs once at the end of `setup_windows.bat`. No-op on Linux/macOS.

Why winreg directly, not setx:
  setx silently truncates at 1024 characters. On a typical developer
  machine the user PATH already passes 1024 chars, so any setx-based
  approach randomly drops the tail — including the Scripts entry we
  just added. Writing via winreg.SetValueEx has no length cap.

Why not os.environ['PATH']:
  That's the merged system+user view. Echoing it back into the user
  scope would promote system entries into user scope and cause PATH
  to grow unboundedly across runs. We read user PATH straight from
  HKCU\Environment instead.

Bonus: deduplicates existing user-PATH entries (case-insensitive),
which silently fixes any past bloat from buggy installers.
"""
import os
import site
import sys
from pathlib import Path
from typing import List


def _user_scripts_dir() -> str:
    """`pip install --user` script-wrapper directory.

    Derived from `site.getusersitepackages()` so it adapts automatically
    to whichever Python version is in use. On Windows that returns e.g.
    `...\\AppData\\Roaming\\Python\\Python314\\site-packages`; the
    sibling `Scripts` directory holds the .exe wrappers.
    """
    return str(Path(site.getusersitepackages()).parent / "Scripts")


def _add_to_registry_path(new_dir: str) -> bool:
    """Idempotently append `new_dir` to user-scope PATH and dedupe.

    Returns True if the registry was actually written (entry added or
    duplicates removed), False if no change was needed.
    """
    import winreg  # type: ignore
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment",
                        0, winreg.KEY_ALL_ACCESS) as key:
        try:
            current, kind = winreg.QueryValueEx(key, "PATH")
        except FileNotFoundError:
            current, kind = "", winreg.REG_EXPAND_SZ

        entries = [e for e in current.split(";") if e.strip()]

        # Dedupe (case-insensitive) preserving first-seen order.
        seen: List[str] = []
        for e in entries:
            if e.lower() not in (x.lower() for x in seen):
                seen.append(e)

        # Append new_dir if not already present.
        added = False
        if new_dir.lower() not in (x.lower() for x in seen):
            seen.append(new_dir)
            added = True

        rebuilt = ";".join(seen)
        if rebuilt == current:
            return False  # No change

        winreg.SetValueEx(key, "PATH", 0, kind, rebuilt)
        return True or added  # truthy — registry was rewritten


def main() -> int:
    if os.name != "nt":
        return 0

    targets = [
        _user_scripts_dir(),
        str(Path.home() / ".magisentry" / "bin"),
    ]

    any_change = False
    for d in targets:
        try:
            if _add_to_registry_path(d):
                any_change = True
                print(f"Registered on user PATH: {d}")
            else:
                print(f"Already on user PATH: {d}")
        except OSError as e:
            print(f"WARN: could not update user PATH ({e})", file=sys.stderr)

    if any_change:
        print("Open a NEW terminal for changes to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
