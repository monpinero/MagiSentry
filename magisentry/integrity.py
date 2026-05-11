"""Integrity verification for MagiSentry's own source files.

Manifest lives at ~/.magisentry/integrity_manifest.json. Hashes every
.py file under the magisentry package directory plus every shim file
under ~/.magisentry/bin/ (the universal pip/python wrappers).

Design rationale: non-blocking. Tampering warnings go to stderr; the
scan continues. The only operation that mutates the manifest is
`magisentry integrity update`, which gates the rewrite behind a
[y/N] prompt — an AI agent with closed stdin cannot silently re-bless
a tampered tree.
"""
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List

MANIFEST_PATH = Path.home() / ".magisentry" / "integrity_manifest.json"
PACKAGE_DIR = Path(__file__).parent          # magisentry/ package root
SHIM_DIR = Path.home() / ".magisentry" / "bin"


def _hash_file(path: Path) -> str:
    """SHA-256 hex digest of file contents. Empty string on read error
    so a missing/locked file doesn't crash the comparison."""
    h = hashlib.sha256()
    try:
        h.update(path.read_bytes())
    except OSError:
        return ""
    return h.hexdigest()


def _collect_files() -> Dict[str, Path]:
    """Return {portable_label: absolute_path} for every file we hash.

    Labels use POSIX separators on every platform so a manifest built
    on Windows is verifiable on Linux (and vice versa). __pycache__
    is excluded — bytecode is regenerated on every import and would
    invalidate the manifest immediately."""
    files: Dict[str, Path] = {}
    for p in sorted(PACKAGE_DIR.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        label = "magisentry/" + p.relative_to(PACKAGE_DIR).as_posix()
        files[label] = p
    if SHIM_DIR.exists():
        for p in sorted(SHIM_DIR.iterdir()):
            if p.is_file():
                files["bin/" + p.name] = p
    return files


def build_manifest() -> Dict[str, str]:
    """Compute current SHA-256 for every collected file."""
    return {
        label: _hash_file(path)
        for label, path in _collect_files().items()
    }


def load_manifest() -> Dict[str, str]:
    """Load saved manifest. Returns {} if missing or corrupt — the
    caller distinguishes "no manifest" from "manifest mismatch"."""
    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        files = data.get("files", {})
        return files if isinstance(files, dict) else {}
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}


def save_manifest(hashes: Dict[str, str]) -> None:
    """Atomically save manifest to disk. Never raises — write failure
    must not crash the install or the scan."""
    import datetime
    try:
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = MANIFEST_PATH.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({
                "version": "1",
                "updated": datetime.datetime.now().isoformat(timespec="seconds"),
                "files": hashes,
            }, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, MANIFEST_PATH)
    except Exception:
        pass


def check() -> List[str]:
    """Compare current hashes against saved manifest.

    Returns the list of changed (or newly-appeared) file labels.
    Empty list means "all OK" OR "no manifest" — the caller separates
    those via has_manifest()."""
    saved = load_manifest()
    if not saved:
        return []
    current = build_manifest()
    changed: List[str] = []
    for label, old_hash in saved.items():
        new_hash = current.get(label, "")
        if new_hash != old_hash:
            changed.append(label)
    for label in current:
        if label not in saved:
            changed.append(label)
    return changed


def has_manifest() -> bool:
    return MANIFEST_PATH.exists()
