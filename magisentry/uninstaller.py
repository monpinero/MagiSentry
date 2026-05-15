"""Interactive uninstall flow for MagiSentry.

Three-step removal:
  1. Confirm with the user (single [y/N] prompt).
  2. Delete `~/.magisentry/` (config + scan counter + shell shim dir).
  3. Strip the magisentry shim entry from the Windows user PATH (best
     effort — never crashes if registry access fails).
  4. `pip uninstall magisentry -y`.

`t` is the translation callable returned by Translator (i.e. `t.t`) or any
function `key -> str`. The caller wires the locale, so this module is
agnostic about which language is active.
"""
import shutil
import subprocess
import sys
from pathlib import Path

from ._platform import IS_WINDOWS, IS_LINUX, IS_MAC


def _remove_unix_path_hook() -> None:
    """Strip every line mentioning `magisentry` from the user's shell rc
    files. Best-effort: any I/O failure is swallowed so a partial
    uninstall is never worse than no uninstall."""
    for rc in ("~/.bashrc", "~/.zshrc", "~/.profile"):
        rc_path = Path(rc).expanduser()
        if not rc_path.exists():
            continue
        try:
            lines = rc_path.read_text(encoding="utf-8").splitlines(keepends=True)
            cleaned = [line for line in lines if "magisentry" not in line.lower()]
            if len(cleaned) != len(lines):
                rc_path.write_text("".join(cleaned), encoding="utf-8")
        except OSError:
            continue


def _remove_windows_path_hook() -> None:
    """Remove every PATH entry mentioning `magisentry` from the user
    environment via the registry. Best-effort: any failure is swallowed
    so a partial uninstall is never worse than no uninstall."""
    try:
        import winreg  # type: ignore
    except ImportError:
        return
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Environment",
            0, winreg.KEY_ALL_ACCESS,
        )
        try:
            path_val, _ = winreg.QueryValueEx(key, "PATH")
        except FileNotFoundError:
            winreg.CloseKey(key)
            return
        entries = [
            e for e in path_val.split(";")
            if e.strip() and "magisentry" not in e.lower()
        ]
        winreg.SetValueEx(
            key, "PATH", 0, winreg.REG_EXPAND_SZ, ";".join(entries),
        )
        winreg.CloseKey(key)
    except Exception:
        # Registry access can fail for many reasons (permissions, locked
        # hive, etc.). PATH cleanup is a best-effort housekeeping step,
        # not a correctness gate.
        return


def uninstall(t) -> None:
    """Interactive uninstall.

    `t` is a translation callable (e.g. `Translator(...).t`). Pass any
    function `key -> str` if you want to invoke this without the i18n
    layer (tests, headless runs, etc.).
    """
    print()
    print(t("uninstall_confirm"))
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer != "y":
        print(t("uninstall_cancelled"))
        return

    # 1. Remove ~/.magisentry/ (config, scan counter, shim dir).
    config_dir = Path.home() / ".magisentry"
    if config_dir.exists():
        shutil.rmtree(config_dir, ignore_errors=True)
        print(t("uninstall_config_removed"))

    # 2. Remove the magisentry entry from the user's shell environment.
    if IS_WINDOWS:
        _remove_windows_path_hook()
    elif IS_LINUX or IS_MAC:
        _remove_unix_path_hook()

    # 3. pip uninstall — non-fatal if the package is already gone.
    subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "magisentry", "-y"],
        check=False,
    )
    print()
    print(t("uninstall_done"))
