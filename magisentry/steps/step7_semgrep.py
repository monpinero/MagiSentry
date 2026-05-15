"""Step 7 — Semgrep static analysis.

Optional: if the `semgrep` binary is not on PATH, returns FAILURE with
`can_retry=False` so fail-secure offers Skip rather than infinite Retry.
Yara is step 8, its own module (`step8_yara.py`) with its own config
toggle — that's why this file no longer mentions Yara.
"""
import json
import shutil
import subprocess
from pathlib import Path

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
            # `p/security-audit` is meant for auditing FIRST-PARTY code
            # — it flags subprocess/eval/SSL patterns that legitimately
            # appear in third-party libraries (requests, numpy, etc.)
            # and produced a wall of false positives.
            # `p/malicious-code` was tried as a replacement but returns
            # HTTP 404 — the ruleset doesn't exist on the Semgrep
            # registry. `p/supply-chain` is the published equivalent:
            # purpose-built for supply-chain audits (post-install hooks
            # calling out, base64-encoded payloads, etc.) rather than
            # coding-style smells. `p/secrets` stays — hardcoded creds
            # in a third-party package are always relevant.
            ["semgrep", "--config", "p/supply-chain",
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
        # Surface the first three findings inline so the user sees
        # WHICH rule fired in WHICH file at WHICH line — without that
        # context "Semgrep flagged 2 patterns" is uninformative and
        # most users dismiss it. Long absolute paths are truncated to
        # the last two segments so the message stays readable.
        details = []
        for f in findings[:3]:
            rule = f.get("check_id", "unknown-rule")
            path = f.get("path", "?")
            line = (f.get("start") or {}).get("line", "?")
            try:
                rel = "/".join(Path(path).parts[-2:])
            except Exception:
                rel = path
            details.append(f"{rule} @ {rel}:{line}")
        if len(findings) > 3:
            details.append(f"... and {len(findings) - 3} more")
        detail_str = "\n    ".join(details)

        name, _ = split_pkg(ecosystem, package)
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_pattern",
                        count=len(findings), package=name)
                    + "\n    " + detail_str,
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
