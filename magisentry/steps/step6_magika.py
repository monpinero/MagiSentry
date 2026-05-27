"""Step 6 — Magika file-type scan (offline, ~3MB ML model).

Uses `trusted_deps.is_trusted_dep_file` to exempt native binaries
(.dll/.pyd/.so/.exe) that legitimately belong to one of MagiSentry's
own runtime dependencies (semgrep, magika, yara-python). The exemption
is package-scoped AND installed-checked — see trusted_deps.py for the
threat model.
"""
import sys
from pathlib import Path

from ..models import StepResult
from ..trusted_deps import is_trusted_dep_file

STEP = "step6_magika"

SUSPICIOUS = {
    "pebin", "pe", "exe", "dll", "msi",
    "elf", "macho", "dex", "apk",
    "bat", "cmd", "ps1",
    "jar", "class",
    "vba", "ole",
}

# Script labels that warrant a content-aware second look before raising
# THREAT. Build tools, install helpers, and CI fixtures legitimately
# ship `.bat`/`.cmd`/`.ps1` files that only echo / set / pause — flagging
# those as supply-chain malware is noise.
_SCRIPT_LABELS = {"bat", "cmd", "ps1"}

# Lines containing any of these markers are unambiguously dangerous —
# downloading + executing remote content from a shell script is the
# textbook supply-chain attack shape, regardless of surrounding context.
_SCRIPT_DANGEROUS = (
    "curl ", "curl.exe", "wget ", "wget.exe",
    "invoke-webrequest", "invoke-restmethod", "iwr ",
    "invoke-expression", "iex ", "iex(",
    "downloadstring", "downloadfile", "downloaddata",
    "certutil -urlcache", "certutil.exe -urlcache",
    "bitsadmin /transfer", "bitsadmin.exe /transfer",
    "start-bitstransfer",
    "new-object net.webclient",
    "powershell -enc", "powershell.exe -enc",
    "powershell -e ", "powershell.exe -e ",
    "powershell -encodedcommand",
    "rundll32",
    "regsvr32 /s /u /i:http",
    "mshta http", "mshta vbscript",
    "frombase64string",
)


def _script_looks_benign(path) -> bool:
    """Read the first 50 lines of a script and decide whether it's a
    benign build/install helper. Returns True only when no dangerous
    download/exec markers are present. Failure to read = treat as
    NOT-benign so the file stays a THREAT (safe default)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [next(f, "") for _ in range(50)]
    except (OSError, ValueError):
        return False
    blob = "\n".join(lines).lower()
    return not any(marker in blob for marker in _SCRIPT_DANGEROUS)


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
    warnings: list = []
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
        if label in SUSPICIOUS:
            # Centralised trusted-deps allow-list: exempts native
            # binaries owned by semgrep / magika / yara-python / etc.
            # Three-condition gate (package being scanned matches,
            # path matches a glob, dep is actually installed) is
            # enforced inside trusted_deps.is_trusted_dep_file.
            trusted, pkg_name = is_trusted_dep_file(
                path, package, archive_root=extracted_path,
            )
            if trusted:
                rel = path.relative_to(extracted_path)
                sys.stderr.write(
                    "[MagiSentry] "
                    + t.t("trusted_dep_skipped_magika",
                          file=str(rel), package=pkg_name)
                    + "\n"
                )
                continue
            # Fallback: legitimate console_scripts wheel layout
            #   {pkg}-{ver}.data/scripts/{name}.exe
            # kept as a defence-in-depth check in case a new dep ships
            # a CLI entry-point and isn't yet listed in TRUSTED_DEPS.
            parts = path.parts
            if "scripts" in parts:
                idx = parts.index("scripts")
                if idx > 0 and parts[idx - 1].endswith(".data"):
                    data_dir = parts[idx - 1]          # "magika-1.0.3.data"
                    pkg_base = data_dir.split("-")[0].lower()
                    if path.stem.lower() == pkg_base:
                        continue
            # Content-aware demotion for shell scripts. .bat/.cmd/.ps1
            # in build / install helpers is normal; we only escalate to
            # THREAT when the file's first 50 lines contain explicit
            # download-and-execute markers. Hard executables (.exe/.dll
            # /.elf/.msi/...) skip this branch and remain THREATs.
            if label in _SCRIPT_LABELS and _script_looks_benign(path):
                warnings.append(
                    t.t("step6_warning_benign_script",
                        type=label,
                        file=str(path.relative_to(extracted_path)))
                )
                continue
            threats.append((label, path.relative_to(extracted_path)))
            if len(threats) >= 5:
                break

    if threats:
        first_label, first_file = threats[0]
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step6_threat_executable",
                        type=first_label, file=str(first_file)),
            warnings=warnings,
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP, warnings=warnings)
