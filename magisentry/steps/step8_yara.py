"""Step 8 — Yara pattern scan.

Optional: if `yara-python` is not installed, returns FAILURE with
`can_retry=False` — fail-secure offers Skip / Abort.
"""
from pathlib import Path
from typing import List

from ..models import StepResult

STEP = "step8_yara"
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "magisentry.yar"

_TEXT_SUFFIXES = {
    ".py", ".pyx", ".pyw", ".pyi",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs",
    ".cfg", ".ini", ".env",
}


def run(ecosystem, package, config, t, ctx):
    extracted = ctx.get("extracted")
    if not extracted:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_yara_crash"),
            possible_cause="no extracted directory from step 4",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    try:
        import yara  # type: ignore
    except ImportError:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step8_yara_skipped"),
            possible_cause=t.t("step7_cause_not_installed"),
            recommendation="pip install yara-python  # or disable yara in config",
            can_retry=False,
        )
    if not RULES_FILE.exists():
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_yara_crash"),
            possible_cause=f"missing rules file: {RULES_FILE}",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )
    try:
        # Use `source=` (read the file in Python) instead of
        # `filepath=` because yara-python on Windows passes the path
        # to the C library as a byte string in the system codepage —
        # any non-ASCII character (e.g. "ň" in "Koreň") makes the
        # underlying open() fail with ENOENT. Reading via pathlib +
        # utf-8 sidesteps the issue entirely; YARA itself compiles
        # from the in-memory source string.
        rules = yara.compile(source=RULES_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_yara_crash"),
            possible_cause=f"yara.compile: {e}",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )

    matched: List[str] = []
    extracted_path = Path(extracted)
    for path in extracted_path.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            ms = rules.match(str(path), timeout=30)
        except Exception:
            continue
        for m in ms:
            matched.append(f"{m.rule}:{path.name}")
            if len(matched) >= 10:
                break
        if len(matched) >= 10:
            break

    if matched:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_yara", rules=", ".join(matched[:5])),
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
