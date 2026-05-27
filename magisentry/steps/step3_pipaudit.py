"""Step 3 — pip-audit recursive dependency CVE scan (pip ecosystem only)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ..models import StepResult
from ._common import split_pkg

STEP = "step3_pipaudit"


def run(ecosystem, package, config, t, ctx):
    if ecosystem != "pip":
        return StepResult(status="OK", step=STEP,
                          warnings=[t.t("step3_skipped_npm")])
    # Local-archive scan path: when the orchestrator has handed us a
    # pre-existing .whl/.tar.gz/.zip on disk, point pip-audit straight
    # at it instead of fabricating a `name==version` line. pip's
    # requirements parser accepts absolute archive paths and will pull
    # the metadata from the archive itself.
    local_archive = ctx.get("local_archive")
    if local_archive is not None:
        spec = str(Path(local_archive).resolve())
        name = Path(local_archive).name
    else:
        name, version = split_pkg(ecosystem, package)
        spec = f"{name}=={version}" if version else name
    with tempfile.TemporaryDirectory() as tmp:
        req = Path(tmp).resolve() / "req.txt"
        req.write_text(spec + "\n", encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip_audit", "-r", str(req),
                 "--format", "json", "--progress-spinner", "off"],
                capture_output=True, text=True, timeout=180,
            )
        except FileNotFoundError:
            return StepResult(
                status="FAILURE", step=STEP,
                message=t.t("step3_failure_pipaudit"),
                possible_cause=t.t("step3_cause_pipaudit"),
                recommendation=t.t("step3_recommend_pipaudit"),
                can_retry=True,
            )
        except subprocess.TimeoutExpired:
            return StepResult(
                status="FAILURE", step=STEP,
                message=t.t("step3_failure_pipaudit"),
                possible_cause=t.t("step3_cause_pipaudit"),
                recommendation=t.t("step3_recommend_pipaudit"),
                can_retry=True,
            )

    if proc.returncode not in (0, 1):
        # 1 = vulns found, 0 = clean. Anything else is a tool failure.
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step3_failure_pipaudit"),
            possible_cause=t.t("step3_cause_pipaudit") + " " + (proc.stderr or "").strip()[:200],
            recommendation=t.t("step3_recommend_pipaudit"),
            can_retry=True,
        )

    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step3_failure_pipaudit"),
            possible_cause=t.t("step3_cause_pipaudit"),
            recommendation=t.t("step3_recommend_pipaudit"),
            can_retry=True,
        )

    # Bucket each vuln by severity. pip-audit's JSON does NOT include
    # CVSS scores directly, but when the OSV upstream attaches a
    # `severity` block with a CVSS_V3 vector or a numeric `score`, we
    # surface it. Anything we can prove is below 4.0 (CVSS "low") is
    # demoted to a warning so a single low-severity transitive CVE
    # doesn't block an install with the same weight as a 9.8 RCE.
    # Vulns with no parseable severity stay as THREAT — unknown means
    # opaque, and opaque means we err on the safe side.
    deps = report.get("dependencies") or report.get("vulnerabilities") or []
    threat_count = 0
    low_warnings: list = []
    if isinstance(deps, list):
        for d in deps:
            for v in (d.get("vulns") or d.get("vulnerabilities") or []):
                score = _parse_cvss(v)
                vid = v.get("id") or "?"
                if score is not None and score < 4.0:
                    low_warnings.append(
                        t.t("step3_warning_low_cvss",
                            id=vid, score=f"{score:.1f}")
                    )
                else:
                    threat_count += 1
    if threat_count:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step3_threat_dep_cve",
                        count=threat_count, package=name),
            warnings=low_warnings,
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP, warnings=low_warnings)


def _parse_cvss(vuln: dict):
    """Best-effort numeric CVSS extraction from a pip-audit vuln dict.

    pip-audit forwards OSV's `severity` list when present. Each entry
    is `{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}` or a plain
    numeric `score`. We pull the first parseable number. Returns
    None when no severity info is attached — caller treats that as
    THREAT (unknown = unsafe default)."""
    for sev in (vuln.get("severity") or []):
        if not isinstance(sev, dict):
            continue
        raw = sev.get("score")
        if raw is None:
            continue
        # Numeric: {"type":"NUMERIC","score":7.5} or just 7.5 stringified.
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
        # CVSS vector: extract the AV-prefixed component if present.
        if isinstance(raw, str) and "CVSS:" in raw:
            for part in raw.split("/"):
                if part.replace(".", "", 1).isdigit():
                    try:
                        return float(part)
                    except ValueError:
                        pass
    return None
