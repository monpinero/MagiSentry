"""Cross-platform desktop notifications.

Single public entry point: `send_notification(title, body, config)`. The
function is fire-and-forget — never raises, never blocks the scan, never
affects scan exit codes.

Backend per OS:
  Windows  -> winotify (always installed via setup.py platform marker)
  macOS    -> osascript "display notification"
  Linux    -> notify-send (libnotify); silently skipped on headless boxes

Thin convenience wrappers `notify_threat`, `notify_update`, `notify_dep_cve`
are kept for the existing call sites in scanner.py / self_audit.py.
"""
import shutil
import subprocess
from typing import List, Optional

from ._platform import IS_WINDOWS, IS_MAC, IS_LINUX
from .i18n import Translator
from .models import StepResult

_APP_ID = "MagiSentry"


def _can_notify_linux() -> bool:
    return shutil.which("notify-send") is not None


def _escape_applescript(s: str) -> str:
    """Escape `"` and `\\` for embedding inside an osascript string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def send_notification(title: str, body: str,
                      config: Optional[object] = None) -> None:
    """Fire-and-forget toast.

    `config` may be None (always notify), a dict with `"notifications"`
    key, or a `Config` instance with a `notifications` attribute.
    """
    if config is not None:
        if isinstance(config, dict):
            enabled = bool(config.get("notifications", True))
        else:
            enabled = bool(getattr(config, "notifications", True))
        if not enabled:
            return

    try:
        if IS_WINDOWS:
            from winotify import Notification, audio  # type: ignore
            toast = Notification(
                app_id=_APP_ID, title=title, msg=body, duration="short",
            )
            toast.set_audio(audio.Default, loop=False)
            toast.show()

        elif IS_MAC:
            script = (
                f'display notification "{_escape_applescript(body)}" '
                f'with title "{_escape_applescript(title)}"'
            )
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

        elif IS_LINUX and _can_notify_linux():
            subprocess.Popen(
                ["notify-send", title, body, f"--app-name={_APP_ID}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        # Headless Linux / unsupported OS: silent — stderr block still works.
    except Exception:
        # Notification failure must NEVER affect scan result.
        return


# ---------- thin wrappers used elsewhere in the project ----------

def notify_threat(t: Translator, package: str,
                  threats: List[StepResult],
                  config: Optional[object] = None) -> None:
    if not threats:
        return
    first = threats[0]
    step_key = first.step.split("_", 1)[0] + "_name" if "_" in first.step else first.step
    body_lines = [package, first.message or "", t.t(step_key)]
    body = "\n".join(filter(None, body_lines))[:200]
    send_notification(t.t("toast_threat_title"), body, config)


def notify_update(t: Translator, current: str, latest: str,
                  config: Optional[object] = None) -> None:
    body = f"magisentry {current} -> {latest}"
    send_notification(t.t("toast_update_title"), body, config)


def notify_dep_cve(t: Translator, dep_warnings: List[str],
                   config: Optional[object] = None) -> None:
    if not dep_warnings:
        return
    body = "\n".join(dep_warnings[:3])[:200]
    send_notification(t.t("toast_dep_cve_title"), body, config)
