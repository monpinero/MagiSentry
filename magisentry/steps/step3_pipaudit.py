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
        req = Path(tmp) / "req.txt"
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

    deps = report.get("dependencies") or report.get("vulnerabilities") or []
    total_vulns = 0
    if isinstance(deps, list):
        for d in deps:
            total_vulns += len(d.get("vulns") or d.get("vulnerabilities") or [])
    if total_vulns:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step3_threat_dep_cve", count=total_vulns, package=name),
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
