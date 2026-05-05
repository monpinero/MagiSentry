"""Configuration & whitelist on disk under ~/.magisentry/."""
import json
import os
from pathlib import Path
from typing import Optional, List

from .models import Config

CONFIG_DIR = Path.home() / ".magisentry"
CONFIG_PATH = CONFIG_DIR / "config.json"
WHITELIST_PATH = CONFIG_DIR / "whitelist.txt"


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
