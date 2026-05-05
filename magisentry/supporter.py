"""Donation / supporter prompts. Three trigger points:

  1. Every Nth successful scan (counter persisted in config dir)
  2. After a threat is successfully blocked
  3. After setup completes (called from `setup_windows.bat` chain via wizard)

Output is written to BOTH stdout and stderr so Claude Code surfaces it
in the chat window. Real URLs / addresses live in `donation.json` and
are author-filled placeholders by default — never hardcoded.
"""
import json
import sys
from pathlib import Path
from typing import Optional

from .i18n import Translator

PKG_DIR = Path(__file__).resolve().parent
DONATION_FILE = PKG_DIR / "donation.json"
COUNTER_FILE = Path.home() / ".magisentry" / "scan_counter.json"


def _load_donation() -> dict:
    try:
        return json.loads(DONATION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_counter() -> int:
    try:
        return int(json.loads(COUNTER_FILE.read_text(encoding="utf-8")).get("count", 0))
    except (OSError, json.JSONDecodeError, ValueError):
        return 0


def _save_counter(value: int) -> None:
    try:
        COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
        COUNTER_FILE.write_text(json.dumps({"count": value}), encoding="utf-8")
    except OSError:
        pass


def _print_prompt(t: Translator, donation: dict) -> None:
    kofi = donation.get("kofi_url") or "KOFI_PLACEHOLDER"
    xmr = donation.get("xmr_address") or "XMR_PLACEHOLDER"
    lines = [
        "─" * 60,
        t.t("supporter_header"),
        "",
        t.t("supporter_kofi", url=kofi),
        t.t("supporter_xmr", address=xmr),
        "",
        t.t("supporter_xmr_hint"),
        "─" * 60,
    ]
    block = "\n".join(lines) + "\n"
    # Write to stderr ONLY. Claude Code surfaces stderr in chat, and any
    # interactive terminal still shows stderr alongside stdout — so writing
    # to both rendered the block twice in the wizard.
    sys.stderr.write(block)
    sys.stderr.flush()


def record_scan(threat_blocked: bool, t: Optional[Translator] = None) -> None:
    """Bump the per-user scan counter and emit the prompt when due.

    threat_blocked=True is also a hard trigger if `show_on_threat_blocked`
    is enabled in donation.json.
    """
    donation = _load_donation()
    if not donation:
        return
    t = t or Translator("en")

    every = int(donation.get("prompt_every_n_scans") or 50)
    count = _load_counter() + 1
    _save_counter(count)

    triggered = False
    if threat_blocked and donation.get("show_on_threat_blocked", True):
        triggered = True
    elif every > 0 and count % every == 0:
        triggered = True

    if triggered:
        _print_prompt(t, donation)


def show_after_install(t: Optional[Translator] = None) -> None:
    """Called once after `setup_windows.bat` finishes. Always shows the
    prompt regardless of the per-scan cadence."""
    donation = _load_donation()
    if not donation:
        return
    _print_prompt(t or Translator("en"), donation)


def show_after_install_complete(t: Optional[Translator] = None) -> None:
    """Called after a normal install passes the scan, IF
    `show_on_install_complete` is true in donation.json."""
    donation = _load_donation()
    if not donation or not donation.get("show_on_install_complete", False):
        return
    _print_prompt(t or Translator("en"), donation)
