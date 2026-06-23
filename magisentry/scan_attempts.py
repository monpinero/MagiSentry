"""Per-package failure memory for fail-secure mode.

Tracks how many times the SAME install spec has failed verification so the
fail-secure action plan can escalate across separate MagiSentry invocations
(the process exits after each scan, so state must persist on disk).

Only failing packages are stored; a successful scan clears the entry. Entries
older than the TTL are pruned on load. Cross-platform: Path.home() + atomic
os.replace + epoch timestamps; no OS-specific locking (last-write-wins).
"""
import json
import os
import time
from pathlib import Path
from typing import Dict

ATTEMPTS_FILE = Path.home() / ".magisentry" / "scan_attempts.json"
TTL_SECONDS = 24 * 60 * 60     # entries older than this are dropped on load
MAX_ENTRIES = 200              # safety cap; oldest evicted beyond this


def _key(ecosystem: str, package: str) -> str:
    """Stable, case-insensitive key. The spec is kept verbatim (minus case),
    so `pip:requests==2.0` and `pip:requests` are distinct keys."""
    return f"{ecosystem.strip().lower()}:{package.strip().lower()}"


def _load() -> Dict[str, dict]:
    """Read the attempt map, dropping expired entries. Missing or corrupt
    file -> empty map (never raises)."""
    try:
        raw = json.loads(ATTEMPTS_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {}
    except (OSError, json.JSONDecodeError):
        return {}
    now = time.time()
    pruned = {
        k: v for k, v in raw.items()
        if isinstance(v, dict)
        and (now - float(v.get("last_seen", 0))) <= TTL_SECONDS
    }
    if len(pruned) > MAX_ENTRIES:
        newest = sorted(pruned.items(),
                        key=lambda kv: float(kv[1].get("last_seen", 0)),
                        reverse=True)[:MAX_ENTRIES]
        pruned = dict(newest)
    return pruned


def _save(data: Dict[str, dict]) -> None:
    """Atomically write the map. Best-effort: never raises (a memory failure
    must never block a scan)."""
    try:
        ATTEMPTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ATTEMPTS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, ATTEMPTS_FILE)
    except OSError:
        pass


def record_failure(ecosystem: str, package: str, step: str) -> int:
    """Record one fail-secure verification failure for this spec and return
    the running failure count (1 = first failure → tier 1). Best-effort;
    returns at least 1 even if persistence fails."""
    data = _load()
    k = _key(ecosystem, package)
    now = time.time()
    entry = data.get(k)
    if isinstance(entry, dict):
        count = int(entry.get("count", 0)) + 1
        first_seen = float(entry.get("first_seen", now))
    else:
        count = 1
        first_seen = now
    data[k] = {
        "first_seen": first_seen,
        "last_seen": now,
        "count": count,
        "last_step": step,
    }
    _save(data)
    return count


def clear(ecosystem: str, package: str) -> None:
    """Forget this spec (called after a successful scan). Best-effort."""
    data = _load()
    k = _key(ecosystem, package)
    if k in data:
        del data[k]
        _save(data)
