"""Step 2 — OSV CVE check (Google's open-source vulnerability database)."""
import json
import urllib.error

from ..models import StepResult
from ._common import split_pkg, http_json

STEP = "step2_osv"

ECOSYSTEM = {"pip": "PyPI", "npm": "npm"}


def _resolve_latest(ecosystem: str, name: str):
    try:
        if ecosystem == "pip":
            data = http_json(f"https://pypi.org/pypi/{name}/json", timeout=15)
            return (data.get("info") or {}).get("version")
        data = http_json(f"https://registry.npmjs.org/{name}", timeout=15)
        return (data.get("dist-tags") or {}).get("latest")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def run(ecosystem, package, config, t, ctx):
    name, version = split_pkg(ecosystem, package)
    if not version:
        version = _resolve_latest(ecosystem, name)
    # CRITICAL: refuse to query OSV without a concrete version. OSV
    # interprets a version-less query as "return ALL historical CVEs
    # for this package" — which is correct for the package itself but
    # WRONG for "this exact install". When _resolve_latest() returned
    # None (PyPI/npm unreachable), forwarding the query without a
    # version would surface decade-old fixed CVEs as fresh THREATs.
    # Better to return a retryable FAILURE so the user knows the scan
    # is incomplete than to silently fabricate threats from old CVEs.
    if not version:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step2_failure_no_version", package=name),
            possible_cause=t.t("step2_cause_no_version"),
            recommendation=t.t("step2_recommend_no_version"),
            can_retry=True,
        )
    body = {"package": {"name": name, "ecosystem": ECOSYSTEM[ecosystem]},
            "version": version}
    try:
        data = http_json("https://api.osv.dev/v1/query",
                         data=json.dumps(body).encode("utf-8"),
                         timeout=20)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step2_failure_osv"),
            possible_cause=t.t("step2_cause_osv"),
            recommendation=t.t("step2_recommend_osv"),
            can_retry=True,
        )
    vulns = data.get("vulns") or []
    if vulns:
        ids = ", ".join(sorted({v.get("id", "?") for v in vulns}))
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step2_threat_cve",
                        count=len(vulns), package=name,
                        version=version or "*", ids=ids),
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
