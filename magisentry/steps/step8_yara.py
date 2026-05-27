"""Step 8 — Yara pattern scan.

Optional: if `yara-python` is not installed, returns FAILURE with
`can_retry=False` — fail-secure offers Skip / Abort.

Uses `trusted_deps.is_trusted_dep_path` to skip YARA matching on files
belonging to MagiSentry's own runtime dependencies (semgrep, pip-audit,
magika, yara-python, winotify). Those packages legitimately contain
`os.environ` + `requests.post` + `TOKEN`/`API_KEY` strings (auth flow,
telemetry, etc.) that would trip credential_theft / env_exfiltration.
The exemption is package-scoped AND installed-checked — see
trusted_deps.py for the threat model.
"""
import sys
from pathlib import Path
from typing import List

from ..models import StepResult
from ..trusted_deps import is_trusted_dep_path

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
    far_matches: List[str] = []
    extracted_path = Path(extracted)
    for path in extracted_path.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        # Trusted-deps allow-list: skip YARA scan for files belonging
        # to MagiSentry's own runtime dependencies. Three-condition
        # gate (scanned package matches, path matches a glob, dep is
        # actually installed) is enforced inside trusted_deps.
        trusted, pkg_name = is_trusted_dep_path(
            path, package, archive_root=extracted_path,
        )
        if trusted:
            rel = path.relative_to(extracted_path)
            sys.stderr.write(
                "[MagiSentry] "
                + t.t("trusted_dep_skipped_yara",
                      file=str(rel), package=pkg_name)
                + "\n"
            )
            continue
        try:
            ms = rules.match(str(path), timeout=30)
        except Exception:
            continue
        for m in ms:
            # Proximity filter for the high-FP "needs N signals" rules.
            # YARA's `condition` block confirms that one env-read marker
            # + one secret keyword + one network call all exist in the
            # file, but says nothing about whether they're adjacent. In
            # a 5000-line file with `os.environ` at line 12 and
            # `requests.post` at line 4800 they are not the same code
            # path. Require the matched strings to sit within ~3000
            # bytes (≈ 50 lines) of each other; otherwise demote the
            # match to a warning rather than a THREAT.
            if m.rule in _PROXIMITY_RULES and not _matches_close(m):
                far_matches.append(f"{m.rule}:{path.name}")
                continue
            matched.append(f"{m.rule}:{path.name}")
            if len(matched) >= 10:
                break
        if len(matched) >= 10:
            break

    warnings: List[str] = []
    if far_matches:
        warnings.append(
            t.t("step8_warning_far_match",
                count=len(far_matches),
                rules=", ".join(far_matches[:5]))
        )

    if matched:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_yara", rules=", ".join(matched[:5])),
            warnings=warnings,
            can_retry=False,
        )
    return StepResult(status="OK", step=STEP, warnings=warnings)


# Rules whose "all of them" condition fires too easily when the
# matched strings are spread across an entire file. For these we
# additionally check that all matched offsets sit within a small
# window before raising THREAT.
_PROXIMITY_RULES = {"credential_theft", "env_exfiltration", "base64_exec"}
_PROXIMITY_WINDOW = 3000  # bytes ≈ 50 lines of typical source


def _matches_close(match) -> bool:
    """Return True if every matched string instance in `match` sits
    within `_PROXIMITY_WINDOW` bytes of the others.

    yara-python's API differs across versions:
      * 4.5.x+ exposes `match.strings` as a list of `StringMatch`
        objects with `.instances`, each instance has `.offset`.
      * older releases return a flat list of `(offset, ident, data)`
        3-tuples.
    Either way we extract every offset and span-check them. On any
    extraction error we conservatively return True — the proximity
    filter should NEVER let an attack through; demoting a real threat
    to a warning is worse than keeping an occasional FP."""
    try:
        offsets: List[int] = []
        for s in match.strings:
            instances = getattr(s, "instances", None)
            if instances is None:
                # Old API: each entry is (offset, identifier, data).
                if isinstance(s, tuple) and s:
                    offsets.append(int(s[0]))
                continue
            for inst in instances:
                off = getattr(inst, "offset", None)
                if off is not None:
                    offsets.append(int(off))
        if len(offsets) < 2:
            return True   # nothing to compare; keep as threat
        return (max(offsets) - min(offsets)) <= _PROXIMITY_WINDOW
    except Exception:
        return True
