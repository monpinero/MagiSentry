"""Configuration & whitelist on disk under ~/.magisentry/."""
import json
import os
from pathlib import Path
from typing import Optional, List

from .models import Config

CONFIG_DIR = Path.home() / ".magisentry"
CONFIG_PATH = CONFIG_DIR / "config.json"
WHITELIST_PATH = CONFIG_DIR / "whitelist.txt"
AUDIT_LOG_PATH = CONFIG_DIR / "config_audit.log"


def exists() -> bool:
    return CONFIG_PATH.exists()


def load() -> Optional[Config]:
    if not CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return Config.from_dict(data)
    except (OSError, json.JSONDecodeError):
        return None


def save(config: Config) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp, CONFIG_PATH)
    return CONFIG_PATH


def _write_audit(entry: str) -> None:
    """Append one timestamped line to config_audit.log. Never raises —
    audit failure must never block a legitimate config save."""
    try:
        import datetime
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {entry}\n")
    except Exception:
        pass


def save_protected(config: Config, change_desc: str,
                   force: bool = False) -> bool:
    """Save config behind a [y/N] confirmation + audit-log gate.

    Defends against AI agents (or anything else) silently mutating
    ~/.magisentry/config.json. Returns True if the change was written,
    False if the user declined or stdin was closed (EOFError).

    `force=True` skips the prompt — intended for CI/CD pipelines that
    cannot answer interactive prompts. Forced writes are still recorded
    in the audit log, prefixed with [WARN] so the absence of a human
    confirmation is visible after the fact.
    """
    if not force:
        try:
            answer = input(f"Apply change ({change_desc})? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "y":
            return False
        _write_audit(change_desc)
    else:
        _write_audit(f"[WARN] --force flag used (non-interactive) | {change_desc}")
    save(config)
    return True


def whitelist_entries() -> List[str]:
    if not WHITELIST_PATH.exists():
        return []
    return [
        line.strip()
        for line in WHITELIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def is_whitelisted(ecosystem: str, package: str) -> bool:
    name = package.split("==")[0].split("@")[0].lower()
    entry = f"{ecosystem}:{name}"
    return entry in (e.lower() for e in whitelist_entries())


def _normalise(ecosystem: str, package: str) -> str:
    """Canonicalise a whitelist entry. Strips version pin / npm scope tag,
    lowercases the package name, and prefixes the ecosystem."""
    name = package.split("==")[0].split("@")[0].lower()
    return f"{ecosystem}:{name}"


def whitelist_add(ecosystem: str, package: str,
                  force: bool = False) -> str:
    """Add `<ecosystem>:<package>` to the whitelist behind a [y/N] gate.

    Whitelisting silently bypasses the scanner for that package, so a
    confirmation prompt is required by default. Stdin closed → cancel
    (an AI agent without interactive input cannot whitelist anything).
    `force=True` skips the prompt for CI/CD; the audit log records
    the [--force] tag so the absence of human confirmation is visible.

    Returns one of: "added", "already_exists", "cancelled".
    """
    entry = _normalise(ecosystem, package)
    if entry.lower() in (e.lower() for e in whitelist_entries()):
        return "already_exists"
    if not force:
        try:
            answer = input(
                f"Add {entry} to whitelist (scan will be skipped)? [y/N] "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "y":
            return "cancelled"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(WHITELIST_PATH, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    _write_audit(f"whitelist add: {entry}" + (" [--force]" if force else ""))
    return "added"


def whitelist_remove(ecosystem: str, package: str,
                     force: bool = False) -> str:
    """Remove `<ecosystem>:<package>` from the whitelist behind a [y/N]
    gate. Returns "removed", "not_found", or "cancelled".

    Removal restores scanning for that package, so it's strictly safer
    than `add`. We still gate it to keep the audit log honest — every
    whitelist mutation is timestamped and attributable."""
    entry = _normalise(ecosystem, package)
    entries = whitelist_entries()
    if not any(e.lower() == entry.lower() for e in entries):
        return "not_found"
    if not force:
        try:
            answer = input(
                f"Remove {entry} from whitelist? [y/N] "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "y":
            return "cancelled"
    remaining = [e for e in entries if e.lower() != entry.lower()]
    WHITELIST_PATH.write_text(
        "\n".join(remaining) + ("\n" if remaining else ""),
        encoding="utf-8",
    )
    _write_audit(f"whitelist remove: {entry}" + (" [--force]" if force else ""))
    return "removed"
