"""Step 8 — VS Code extension scanning.

Runs when the user (or an AI agent) issues `code --install-extension <id>`.
Different from steps 1-7 because the "package" identifier is
`<publisher>.<name>` and the registries are Open VSX + VS Code Marketplace.

Checks:
  1. Open VSX (https://open-vsx.org/api/<publisher>/<name>) — install count,
     last modified.
  2. VS Code Marketplace gallery (POST query) — install count, publisher
     extension count, flags.
  3. VirusTotal hash on the .vsix if a download URL is available.

Heuristics for SUSPICIOUS:
  - <1000 installs AND first published <90 days ago
  - publisher has only 1 extension ever published
  - last updated >3 years ago (abandoned)

Step 8's `package` argument is the extension id (`publisher.name`), not a
pip/npm spec. Ecosystem string used by the orchestrator is `"vscode"`.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from ..models import StepResult

STEP = "step9_vscode"

NEW_DAYS = 90
LOW_INSTALLS = 1000
ABANDONED_DAYS = 365 * 3


def _split_id(extension_id: str) -> Tuple[Optional[str], Optional[str]]:
    if "." not in extension_id:
        return None, None
    publisher, name = extension_id.split(".", 1)
    return publisher.strip(), name.strip()


def _http_json(url: str, *, data: Optional[bytes] = None,
               headers: Optional[dict] = None,
               timeout: int = 15) -> Optional[dict]:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json;api-version=7.1-preview.1;excludeUrls=true")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, ValueError):
        return None


def _open_vsx(publisher: str, name: str) -> Optional[dict]:
    return _http_json(f"https://open-vsx.org/api/{publisher}/{name}")


def _marketplace(publisher: str, name: str) -> Optional[dict]:
    body = json.dumps({
        "filters": [{
            "criteria": [
                {"filterType": 7, "value": f"{publisher}.{name}"},
            ],
            "pageNumber": 1, "pageSize": 1, "sortBy": 0, "sortOrder": 0,
        }],
        # 0x100 = include statistics, 0x200 = include latest version files
        "flags": 914,
    }).encode("utf-8")
    data = _http_json(
        "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
        data=body, timeout=15,
    )
    if not data:
        return None
    extensions = (data.get("results") or [{}])[0].get("extensions") or []
    return extensions[0] if extensions else None


def _publisher_ext_count(publisher: str) -> Optional[int]:
    body = json.dumps({
        "filters": [{
            "criteria": [{"filterType": 8, "value": publisher}],
            "pageNumber": 1, "pageSize": 50, "sortBy": 0, "sortOrder": 0,
        }],
        "flags": 0,
    }).encode("utf-8")
    data = _http_json(
        "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
        data=body, timeout=15,
    )
    if not data:
        return None
    exts = (data.get("results") or [{}])[0].get("extensions") or []
    return len(exts)


def _is_publisher_verified(market: Optional[dict]) -> bool:
    """Heuristic: VS Code marketplace marks domain-verified publishers
    in two places. `publisher.flags` is a comma-separated string that
    contains "verified" once the publisher proved control of a domain;
    `publisher.domain` is non-null on verified publishers. Either
    signal is enough to consider them reputable for the purposes of
    Step 8's low-install heuristic."""
    if not market:
        return False
    pub = market.get("publisher") or {}
    flags = (pub.get("flags") or "").lower()
    if "verified" in flags:
        return True
    domain = pub.get("domain")
    if domain:
        return True
    is_verified = pub.get("isDomainVerified")
    if isinstance(is_verified, bool) and is_verified:
        return True
    return False


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _vt_hash_check(file_url: str, api_key: str, t) -> Optional[StepResult]:
    """Best-effort VT lookup of the .vsix. None on any failure."""
    try:
        with urllib.request.urlopen(file_url, timeout=120) as resp:
            data = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError):
        return None
    digest = hashlib.sha256(data).hexdigest()
    time.sleep(15)  # respect VT free-tier rate limit (4/min)
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{digest}",
        headers={"x-apikey": api_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            vt = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # unknown to VT
        return None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    stats = (((vt.get("data") or {}).get("attributes") or {})
             .get("last_analysis_stats") or {})
    bad = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
    if bad > 0:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step8_threat_vt", malicious=bad),
            can_retry=False,
        )
    return None


def run(ecosystem, package, config, t, ctx):
    publisher, name = _split_id(package)
    if not publisher or not name:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step8_failure_bad_id", package=package),
            possible_cause=t.t("step8_cause_bad_id"),
            recommendation=t.t("step8_recommend_bad_id"),
            can_retry=False,
        )

    ovsx = _open_vsx(publisher, name)
    market = _marketplace(publisher, name)
    if ovsx is None and market is None:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step8_failure_network"),
            possible_cause=t.t("step8_cause_network"),
            recommendation=t.t("step8_recommend_network"),
            can_retry=True,
        )

    # Primary metadata source: marketplace (more accurate install counts).
    installs: Optional[int] = None
    last_updated: Optional[datetime] = None
    download_url: Optional[str] = None

    if market:
        for stat in (market.get("statistics") or []):
            if stat.get("statisticName") == "install":
                installs = int(stat.get("value") or 0)
                break
        versions = market.get("versions") or [{}]
        last_updated = _parse_ts(versions[0].get("lastUpdated"))
        for f in versions[0].get("files") or []:
            if f.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage":
                download_url = f.get("source")
                break

    if installs is None and ovsx:
        installs = ovsx.get("downloadCount")
    if last_updated is None and ovsx:
        last_updated = _parse_ts(ovsx.get("timestamp"))
    if download_url is None and ovsx:
        # Open VSX file URL pattern.
        download_url = (ovsx.get("files") or {}).get("download")

    pub_ext_count = _publisher_ext_count(publisher) if market is not None else None
    publisher_verified = _is_publisher_verified(market)

    # ---- threat / warning evaluation ----
    warnings: List[str] = []
    threats: List[str] = []
    now = datetime.now(timezone.utc)

    if last_updated is not None and (now - last_updated).days > ABANDONED_DAYS:
        warnings.append(t.t("step8_warning_abandoned",
                            days=(now - last_updated).days))

    # pub_ext_count == 1 is the common case for new indie developers
    # — calling it out as a "warning" creates a confusing prompt
    # for every fresh extension. Surface it as an informational
    # note instead. We still keep it in `warnings` so the message
    # reaches the user, but the i18n text is intentionally neutral.
    if pub_ext_count == 1:
        warnings.append(t.t("step8_note_single_ext_publisher",
                            publisher=publisher))

    # Low-install + new-publisher is genuinely suspicious — BUT only
    # when paired with an unverified publisher. Microsoft / domain-
    # verified publishers occasionally push a new extension with low
    # initial install counts (private previews, dogfooding tools);
    # treating those as THREATs forces unnecessary [y/N] prompts.
    # Three-way AND: low installs AND new AND not verified.
    if (installs is not None and installs < LOW_INSTALLS
            and last_updated is not None
            and (now - last_updated).days < NEW_DAYS):
        if publisher_verified:
            warnings.append(t.t("step8_warning_new_verified_publisher",
                                installs=installs, publisher=publisher))
        else:
            threats.append(t.t("step8_threat_new_low_install",
                               installs=installs))

    # ---- VirusTotal sub-check ----
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if download_url and api_key:
        vt = _vt_hash_check(download_url, api_key, t)
        if vt is not None:
            return vt

    if threats:
        return StepResult(
            status="THREAT", step=STEP,
            message="; ".join(threats),
            warnings=warnings,
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP, warnings=warnings)
