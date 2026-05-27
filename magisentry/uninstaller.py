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


def _uv_available() -> bool:
    """Return True iff `uv` is on PATH and responds to --version.

    `shutil.which` alone would be enough on POSIX, but a broken /
    half-removed uv on Windows can leave a phantom entry in PATH that
    matches `which` yet fails to execute. The `--version` round-trip
    is the only reliable probe."""
    if shutil.which("uv") is None:
        return False
    try:
        return subprocess.run(
            ["uv", "--version"], capture_output=True, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _kill_running_magisentry() -> None:
    """Best-effort: stop any running `magisentry.exe` on Windows.

    `uv tool uninstall` and `pip uninstall` both fail with
    "[WinError 32] file in use" if a `magisentry pip install …` is
    still running in another terminal — taskkill removes that
    contention. Silent no-op when no process is running or on
    non-Windows."""
    if not IS_WINDOWS:
        return
    try:
        subprocess.run(
            ["taskkill", "/f", "/im", "magisentry.exe"],
            capture_output=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return


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

    # 0. Clean up AI-tool hook entries BEFORE we delete anything else.
    #    install_hooks knows how to surgically remove just MagiSentry's
    #    contributions to ~/.claude/settings.json, ~/.continue/config.json,
    #    .cursor/rules, .windsurf/rules, .vscode/tasks.json. Best-effort:
    #    never block uninstall if hooks cleanup fails (the user can run
    #    `magisentry-install-hooks --uninstall --all` manually).
    try:
        from .install_hooks import main as _hooks_main
        _hooks_main(["--uninstall", "--all"])
    except Exception:
        pass

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

    # 3. Stop any running MagiSentry process so the uninstall step
    #    isn't blocked by a locked binary (Windows only).
    _kill_running_magisentry()

    # 4. Uninstall via uv tool if available, falling back to pip for
    #    legacy `pip install --user` deployments. Both are run with
    #    `check=False` — "not installed" is a perfectly fine outcome.
    if _uv_available():
        subprocess.run(
            ["uv", "tool", "uninstall", "magisentry"],
            check=False, capture_output=True,
        )
    # pip uninstall covers the pre-uv-migration case where MagiSentry
    # was installed via `pip install --user`. Harmless when the uv
    # branch already cleared everything.
    subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "magisentry", "-y"],
        check=False,
    )
    print()
    print(t("uninstall_done"))
