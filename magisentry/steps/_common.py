"""Shared helpers for the scan steps."""
import json
import urllib.request
import urllib.error
from typing import Optional, Tuple


def split_pkg(ecosystem: str, package: str) -> Tuple[str, Optional[str]]:
    """Return (name, version_or_None)."""
    if ecosystem == "pip":
        if "==" in package:
            n, v = package.split("==", 1)
            return n.strip(), v.strip()
        return package.strip(), None
    # npm: name@version, but scoped names start with @ -> handle.
    pkg = package.strip()
    if pkg.startswith("@"):
        # @scope/name[@ver]
        if pkg.count("@") >= 2:
            head, ver = pkg.rsplit("@", 1)
            return head, ver
        return pkg, None
    if "@" in pkg:
        n, v = pkg.split("@", 1)
        return n, v
    return pkg, None


def http_json(url: str, *, data: Optional[bytes] = None,
              headers: Optional[dict] = None, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if data is not None and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_bytes(url: str, *, headers: Optional[dict] = None,
                   timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()
