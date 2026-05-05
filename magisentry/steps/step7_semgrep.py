"""Step 7 sub-step A — Semgrep static analysis.

Optional: if the `semgrep` binary is not on PATH, returns FAILURE with
`can_retry=False` so fail-secure offers Skip rather than infinite Retry.
The Yara sub-step is now its own module (`step7_yara.py`) with its own
config toggle — that's why this file no longer mentions Yara.
"""
import json
import shutil
import subprocess

from ..models import StepResult
from ._common import split_pkg

STEP = "step7_semgrep"


def run(ecosystem, package, config, t, ctx):
    extracted = ctx.get("extracted")
    if not extracted:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause="no extracted directory from step 4",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    if shutil.which("semgrep") is None:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_not_installed"),
            possible_cause=t.t("step7_cause_not_installed"),
            recommendation=t.t("step7_recommend_not_installed"),
            can_retry=False,
        )
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "p/security-audit",
             "--config", "p/secrets",
             "--json", "--quiet", "--no-git-ignore", str(extracted)],
            capture_output=True, text=True, timeout=300,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash") + f" ({e})",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )

    if proc.returncode not in (0, 1):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash") + " " + (proc.stderr or "")[:200],
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash"),
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    findings = report.get("results") or []
    if findings:
        name, _ = split_pkg(ecosystem, package)
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_pattern",
                        count=len(findings), package=name),
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
