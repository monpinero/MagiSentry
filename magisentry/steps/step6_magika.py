"""Step 6 — Magika file-type scan (offline, ~3MB ML model)."""
from pathlib import Path

from ..models import StepResult

STEP = "step6_magika"

SUSPICIOUS = {
    "pebin", "pe", "exe", "dll", "msi",
    "elf", "macho", "dex", "apk",
    "bat", "cmd", "ps1",
    "jar", "class",
    "vba", "ole",
}


def run(ecosystem, package, config, t, ctx):
    extracted = ctx.get("extracted")
    if not extracted:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step6_failure_magika"),
            possible_cause="no extracted directory from step 4",
            recommendation=t.t("step6_recommend_magika"),
            can_retry=False,
        )
    try:
        from magika import Magika
    except ImportError:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step6_failure_magika"),
            possible_cause="magika package not installed (`pip install magika`)",
            recommendation=t.t("step6_recommend_magika"),
            can_retry=False,
        )
    try:
        m = Magika()
    except Exception as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step6_failure_magika"),
            possible_cause=t.t("step6_cause_magika") + f" ({e})",
            recommendation=t.t("step6_recommend_magika"),
            can_retry=True,
        )

    threats = []
    extracted_path = Path(extracted)
    for path in extracted_path.rglob("*"):
        if not path.is_file():
            continue
        try:
            res = m.identify_path(path)
        except Exception:
            continue
        # Compatible with magika 0.5+ (.output.ct_label) and 0.6+ (.output.label).
        label = ""
        out = getattr(res, "output", None)
        if out is not None:
            label = (getattr(out, "ct_label", None)
                     or getattr(out, "label", None) or "")
        label = str(label).lower()
        # Legitimate wheel CLI executables live at
        #   {pkg}-{ver}.data/scripts/{name}.exe
        # which is the standard `console_scripts` install path. Allow
        # ONLY when the executable's stem matches the package's own
        # name — `magika.exe` inside `magika-1.0.3.data/scripts/` is
        # fine; `svchost.exe` in the same directory is still a threat.
        # Compromised packages are caught earlier by OSV / pip-audit /
        # VirusTotal — step 6 is about file *contents*, not reputation.
        parts = path.parts
        if "scripts" in parts:
            idx = parts.index("scripts")
            if idx > 0 and parts[idx - 1].endswith(".data"):
                data_dir = parts[idx - 1]              # "magika-1.0.3.data"
                pkg_base = data_dir.split("-")[0].lower()
                exe_stem = path.stem.lower()
                if exe_stem == pkg_base:
                    continue  # legitimate CLI tool — skip
                # Name mismatch in scripts/ → fall through to SUSPICIOUS
        if label in SUSPICIOUS:
            threats.append((label, path.relative_to(extracted_path)))
            if len(threats) >= 5:
                break

    if threats:
        first_label, first_file = threats[0]
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step6_threat_executable",
                        type=first_label, file=str(first_file)),
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP)
