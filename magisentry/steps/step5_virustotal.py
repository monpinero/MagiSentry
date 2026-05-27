"""Step 5 — VirusTotal hash check. Sends only the SHA256, never the file."""
import hashlib
import os
import time
import urllib.error
import urllib.request

from ..models import StepResult

STEP = "step5_virustotal"
RATE_SLEEP = 15  # seconds between calls (4/min free tier)


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def run(ecosystem, package, config, t, ctx):
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step5_failure_no_key"),
            possible_cause=t.t("step5_cause_no_key"),
            recommendation=t.t("step5_recommend_no_key"),
            can_retry=False,
        )
    archive = ctx.get("archive")
    if not archive:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step5_failure_network"),
            possible_cause="step 4 (download) did not produce an artifact",
            recommendation=t.t("step5_recommend_network"),
            can_retry=False,
        )
    digest = _sha256(archive)
    time.sleep(RATE_SLEEP)
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{digest}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            import json
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # File unknown to VT — not malicious by absence.
            return StepResult(status="OK", step=STEP)
        if e.code == 429:
            return StepResult(
                status="FAILURE", step=STEP,
                message=t.t("step5_failure_rate_limit"),
                possible_cause=t.t("step5_cause_rate_limit"),
                recommendation=t.t("step5_recommend_rate_limit"),
                can_retry=True,
            )
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step5_failure_network"),
            possible_cause=t.t("step5_cause_network") + f" (HTTP {e.code})",
            recommendation=t.t("step5_recommend_network"),
            can_retry=True,
        )
    except (urllib.error.URLError, TimeoutError, OSError):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step5_failure_network"),
            possible_cause=t.t("step5_cause_network"),
            recommendation=t.t("step5_recommend_network"),
            can_retry=True,
        )

    stats = (((data.get("data") or {}).get("attributes") or {})
             .get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0
    # Single-engine FPs are common on VirusTotal — every AV vendor has
    # its own quirks (one engine flagging a popular wheel because of a
    # one-byte string match is not credible signal). Require corroborating
    # signal: >=2 "malicious" or >=3 "suspicious" engines. A single hit
    # bubbles up as a warning so the user still sees it, but doesn't
    # block install on its own.
    if malicious >= 2 or suspicious >= 3:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step5_threat_av",
                        malicious=malicious, suspicious=suspicious,
                        total=total),
            can_retry=False,
        )
    warnings = []
    if malicious or suspicious:
        warnings.append(t.t("step5_warning_single_engine",
                            malicious=malicious, suspicious=suspicious,
                            total=total))
    return StepResult(status="OK", step=STEP, warnings=warnings)
