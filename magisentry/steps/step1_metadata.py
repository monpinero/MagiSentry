"""Step 1 — PyPI / npm metadata check."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import urllib.error

from ..models import StepResult
from ._common import split_pkg, http_json

STEP = "step1_metadata"
NEW_DAYS = 30
MIN_RELEASES = 3


def _pypi(name: str):
    info = http_json(f"https://pypi.org/pypi/{name}/json", timeout=15)
    releases = info.get("releases") or {}
    summary = (info.get("info") or {}).get("summary") or ""
    earliest = None
    for files in releases.values():
        for f in files:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not t:
                continue
            try:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                if earliest is None or dt < earliest:
                    earliest = dt
            except ValueError:
                pass
    return len(releases), summary, earliest


def _npm(name: str):
    info = http_json(f"https://registry.npmjs.org/{name}", timeout=15)
    versions = info.get("versions") or {}
    summary = info.get("description") or ""
    times = info.get("time") or {}
    earliest = None
    for k, v in times.items():
        if k in ("created", "modified"):
            continue
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if earliest is None or dt < earliest:
                earliest = dt
        except (ValueError, AttributeError):
            pass
    if earliest is None and "created" in times:
        try:
            earliest = datetime.fromisoformat(times["created"].replace("Z", "+00:00"))
        except ValueError:
            pass
    return len(versions), summary, earliest


def _check_project_pin(ecosystem: str, name: str, raw_spec: str) -> Optional[dict]:
    """If CWD's pyproject.toml / package.json pins this package to a
    different version than what's being installed, return a dict suitable
    for `step1_warning_conflict_pinned`. Returns None on no conflict."""
    requested = raw_spec
    cwd = Path.cwd()
    if ecosystem == "pip":
        py = cwd / "pyproject.toml"
        if not py.exists():
            return None
        try:
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib  # type: ignore
            data = tomllib.loads(py.read_text(encoding="utf-8"))
        except Exception:
            return None
        for spec in (data.get("project") or {}).get("dependencies") or []:
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$", spec)
            if m and m.group(1).lower() == name.lower() and m.group(2):
                pinned = (m.group(1) + (m.group(2) or "")).strip()
                if pinned.lower() != requested.lower():
                    return {"file": "pyproject.toml",
                            "pinned": pinned, "requested": requested}
        return None
    # npm
    pj = cwd / "package.json"
    if not pj.exists():
        return None
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for key in ("dependencies", "devDependencies"):
        for nm, ver in (data.get(key) or {}).items():
            if nm.lower() == name.lower():
                pinned = f"{nm}@{ver}"
                if pinned.lower() != requested.lower():
                    return {"file": "package.json",
                            "pinned": pinned, "requested": requested}
    return None


def run(ecosystem, package, config, t, ctx):
    name, _ = split_pkg(ecosystem, package)
    try:
        if ecosystem == "pip":
            count, summary, earliest = _pypi(name)
        else:
            count, summary, earliest = _npm(name)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return StepResult(
                status="THREAT", step=STEP,
                message=t.t("step1_threat_not_found", package=name),
                possible_cause="", recommendation="", can_retry=False,
            )
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step1_failure_network"),
            possible_cause=t.t("step1_cause_network"),
            recommendation=t.t("step1_recommend_network"),
            can_retry=True,
        )
    except (urllib.error.URLError, TimeoutError, OSError):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step1_failure_network"),
            possible_cause=t.t("step1_cause_network"),
            recommendation=t.t("step1_recommend_network"),
            can_retry=True,
        )

    warnings = []
    pin_warn = _check_project_pin(ecosystem, name, package)
    if pin_warn:
        warnings.append(t.t("step1_warning_conflict_pinned", **pin_warn))
    if count < MIN_RELEASES:
        warnings.append(t.t("step1_warning_few_releases", count=count))
    if earliest is not None:
        age_days = (datetime.now(timezone.utc) - earliest).days
        if age_days < NEW_DAYS:
            warnings.append(t.t("step1_warning_too_new", days=age_days))
    if not summary.strip():
        warnings.append(t.t("step1_warning_no_description"))

    return StepResult(status="OK", step=STEP, warnings=warnings)
