"""Step 7 — Semgrep static analysis.

Optional: if the `semgrep` binary is not on PATH, returns FAILURE with
`can_retry=False` so fail-secure offers Skip rather than infinite Retry.
Yara is step 8, its own module (`step8_yara.py`) with its own config
toggle — that's why this file no longer mentions Yara.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from ..models import StepResult
from ._common import split_pkg

STEP = "step7_semgrep"


def _find_semgrep() -> str | None:
    """Locate the semgrep executable.

    Search order:
      1. uv tool isolation — semgrep.exe lives in the same Scripts/
         (Windows) or bin/ (POSIX) directory as the isolated Python.
         Derived from the same logic as _get_uv_python_path() in
         wizard.py so both helpers stay in sync.
      2. PATH fallback — covers manual / system-wide installs.

    Returns the full path string or None when not found anywhere.
    """
    import os
    from pathlib import Path as _Path
    from .._platform import IS_WINDOWS

    # --- 1. uv tool isolation ---
    if IS_WINDOWS:
        candidates = []
        for env_var in ("APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(env_var, "")
            if base:
                candidates.append(
                    _Path(base) / "uv" / "tools" / "magisentry"
                    / "Scripts" / "semgrep.exe"
                )
    else:
        candidates = [
            _Path.home() / ".local" / "share" / "uv" / "tools"
            / "magisentry" / "bin" / "semgrep"
        ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    # --- 2. PATH fallback ---
    return shutil.which("semgrep")


def _write_semgrep_bat(
    semgrep_bin: str,
    extracted: str,
) -> "tuple[Path, Path, Path, Path]":
    """Zapíše semgrep príkaz do .bat súboru — eliminuje cmd /c quote nesting.

    Vracia (bat_path, out_json, out_rc, out_err). Volajúci je zodpovedný
    za zmazanie všetkých štyroch súborov po použití.

    .bat MUSÍ mať CRLF konce riadkov (CLAUDE.md pravidlo) — inak cmd.exe
    interpretuje obsah ako jeden zlepený riadok a ticho zlyhá.
    """
    run_id = uuid.uuid4().hex
    tmp_dir = Path(tempfile.gettempdir())
    bat_path = tmp_dir / f"magisentry_sg_{run_id}.bat"
    out_json = tmp_dir / f"magisentry_sg_{run_id}.json"
    out_rc = tmp_dir / f"magisentry_sg_{run_id}.rc"
    out_err = tmp_dir / f"magisentry_sg_{run_id}.err"

    # Vnútri .bat cmd.exe parsuje normálne — žiadny triple-quote problém.
    # Cesty obalené v "" kvôli medzerám. CRLF povinné.
    # POZOR: medzera pred `>` v `echo %ERRORLEVEL% >` je POVINNÁ.
    # Bez nej cmd.exe interpretuje `0>` ako stdin redirektor (handle 0)
    # a .rc súbor ostane prázdny.
    bat_lines = (
        "@echo off\r\n"
        f'"{semgrep_bin}" '
        f"--config p/supply-chain --config p/secrets "
        f"--json --quiet --no-git-ignore "
        f'--output "{out_json}" "{extracted}" 2> "{out_err}"\r\n'
        f'echo %ERRORLEVEL% > "{out_rc}"\r\n'
    )
    bat_path.write_bytes(bat_lines.encode("utf-8"))
    return bat_path, out_json, out_rc, out_err


def _read_semgrep_result(out_json: Path) -> dict:
    """Bezpečne načíta semgrep JSON report (tolerantný k chybám kódovania)."""
    try:
        if out_json.exists():
            return json.loads(out_json.read_bytes().decode("utf-8", "replace"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        pass
    return {}


def _run_semgrep_wmi(
    semgrep_bin: str,
    extracted: str,
    timeout: int = 300,
) -> "tuple[int, dict]":
    """Run semgrep via WMI Win32_Process.Create to escape AI agent Job Object.

    Príkaz je v .bat súbore (žiadny cmd /c quote nesting). WMI spawnuje
    child pod WmiPrvSE.exe (service context) bez Job Object väzby, kde
    semgrep-core Unix.socketpair IPC funguje.

    Returns (returncode, report_dict).
    Raises OSError if WMI spawn fails.
    Raises TimeoutError if semgrep does not complete within `timeout` seconds.
    """
    bat_path, out_json, out_rc, out_err = _write_semgrep_bat(semgrep_bin, extracted)

    # cmd /c "<bat>" — jeden pár úvodzoviek okolo krátkej cesty k .bat.
    cmd_line = f'cmd /c "{bat_path}"'
    ps_cmd = cmd_line.replace("'", "''")
    ps_script = (
        "(Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        f"-Arguments @{{CommandLine='{ps_cmd}'}}).ProcessId"
    )

    def _cleanup() -> None:
        for f in (bat_path, out_json, out_rc, out_err):
            f.unlink(missing_ok=True)

    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
            stdin=subprocess.DEVNULL,
        )
        pid_str = r.stdout.strip()
        if r.returncode != 0 or not pid_str.isdigit():
            raise OSError(
                f"WMI spawn failed (rc={r.returncode}): "
                f"{(r.stderr or r.stdout)[:200]}"
            )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if out_rc.exists():
                try:
                    rc = int(out_rc.read_text(encoding="utf-8", errors="replace").strip())
                except (ValueError, OSError):
                    rc = 1
                report = _read_semgrep_result(out_json)
                _cleanup()
                return rc, report
            time.sleep(0.5)

        _cleanup()
        raise TimeoutError(f"semgrep WMI process timed out after {timeout}s")
    except BaseException:
        _cleanup()
        raise


def _run_semgrep_schtasks(
    semgrep_bin: str,
    extracted: str,
    timeout: int = 300,
) -> "tuple[int, dict]":
    """Fallback: run semgrep via Task Scheduler when WMI is unavailable.

    Príkaz je v .bat súbore — /TR len ukazuje na krátku cestu k nemu,
    čím sa zmestí pod schtasks 261-znakový limit a žiadny cmd /c
    quote nesting netreba. Task Scheduler service tiež beží mimo
    caller-ovho Job Object.

    Returns (returncode, report_dict).
    Raises OSError if task creation/run fails.
    Raises TimeoutError if semgrep does not complete within `timeout` seconds.
    """
    bat_path, out_json, out_rc, out_err = _write_semgrep_bat(semgrep_bin, extracted)
    task_name = f"MagiSentry_{uuid.uuid4().hex[:8]}"

    def _cleanup() -> None:
        subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True, timeout=10,
            stdin=subprocess.DEVNULL,
        )
        for f in (bat_path, out_json, out_rc, out_err):
            f.unlink(missing_ok=True)

    try:
        # /TR cieľ — krátky `cmd /c "<bat>"`. Cesta k .bat súboru je
        # ~100 znakov, hlboko pod 261-znakovým schtasks /TR limitom.
        tr_target = f'cmd /c "{bat_path}"'

        # Create a one-time task (date in the past forces immediate eligibility).
        r_create = subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", task_name,
                "/TR", tr_target,
                "/SC", "ONCE",
                "/SD", "01/01/2000",
                "/ST", "00:00",
                "/F",
            ],
            capture_output=True, timeout=15,
            stdin=subprocess.DEVNULL,
        )
        if r_create.returncode != 0:
            raise OSError(
                f"schtasks /Create failed (rc={r_create.returncode})"
            )

        # Trigger immediately.
        r_run = subprocess.run(
            ["schtasks", "/Run", "/TN", task_name],
            capture_output=True, timeout=15,
            stdin=subprocess.DEVNULL,
        )
        if r_run.returncode != 0:
            raise OSError(
                f"schtasks /Run failed (rc={r_run.returncode})"
            )

        # Poll for RC sentinel file.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if out_rc.exists():
                try:
                    rc = int(
                        out_rc.read_text(encoding="utf-8", errors="replace").strip()
                    )
                except (ValueError, OSError):
                    rc = 1
                report = _read_semgrep_result(out_json)
                return rc, report
            time.sleep(0.5)

        raise TimeoutError(f"semgrep schtasks process timed out after {timeout}s")

    finally:
        _cleanup()


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
    semgrep_bin = _find_semgrep()
    if semgrep_bin is None:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_not_installed"),
            possible_cause=t.t("step7_cause_not_installed"),
            recommendation=t.t("step7_recommend_not_installed"),
            can_retry=False,
        )

    from .._platform import IS_WINDOWS

    if IS_WINDOWS:
        # Windows: escape AI agent Job Object via WMI or Task Scheduler.
        # Direct subprocess.run inherits the Job Object → Unix.socketpair
        # EINVAL crash in semgrep-core OCaml runtime. See CLAUDE.md.
        rc = 1
        report: dict = {}
        wmi_error: str = ""
        schtasks_error: str = ""
        try:
            rc, report = _run_semgrep_wmi(str(semgrep_bin), str(extracted))
        except (OSError, TimeoutError, Exception) as _e:
            wmi_error = str(_e)
            try:
                rc, report = _run_semgrep_schtasks(str(semgrep_bin), str(extracted))
            except (OSError, TimeoutError, Exception) as _e2:
                schtasks_error = str(_e2)
                return StepResult(
                    status="FAILURE", step=STEP,
                    message=t.t("step7_failure_crash"),
                    possible_cause=(
                        t.t("step7_cause_crash")
                        + f" WMI: {wmi_error[:100]}"
                        + f" schtasks: {schtasks_error[:100]}"
                    ),
                    recommendation=t.t("step7_recommend_crash"),
                    can_retry=False,
                )
    else:
        # POSIX: direct subprocess — no Job Object issue on Linux/macOS.
        try:
            proc = subprocess.run(
                [semgrep_bin,
                 "--config", "p/supply-chain",
                 "--config", "p/secrets",
                 "--json", "--quiet", "--no-git-ignore", str(extracted)],
                capture_output=True, text=True, timeout=300,
                stdin=subprocess.DEVNULL,
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
                possible_cause=(
                    t.t("step7_cause_crash")
                    + " " + (proc.stderr or "")[:200]
                ),
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
        rc = proc.returncode

    # Normalize unexpected exit codes (e.g. OCaml crash 0xC0000005).
    if rc not in (0, 1):
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step7_failure_crash"),
            possible_cause=t.t("step7_cause_crash") + f" (rc={rc})",
            recommendation=t.t("step7_recommend_crash"),
            can_retry=False,
        )

    findings = report.get("results") or []
    # Test fixtures legitimately include "hardcoded credentials" like
    # `API_KEY = "fake-key-for-testing"`. Any well-tested package
    # will trip p/secrets in its `tests/`, `fixtures/`, `docs/`,
    # `examples/` trees. Split findings by path: if every hit is in
    # one of those buckets, downgrade to a warning instead of
    # blocking the install — a real attacker won't carefully hide
    # their payload inside `tests/`.
    real_findings: list = []
    test_findings: list = []
    for f in findings:
        path = (f.get("path") or "").replace("\\", "/").lower()
        if _is_test_path(path):
            test_findings.append(f)
        else:
            real_findings.append(f)

    name, _ = split_pkg(ecosystem, package)

    if real_findings:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step7_threat_pattern",
                        count=len(real_findings), package=name)
                    + "\n    " + _format_findings(real_findings),
            warnings=([_summarise_test_findings(test_findings, t)]
                      if test_findings else []),
            can_retry=False,
        )
    if test_findings:
        return StepResult(
            status="OK", step=STEP,
            warnings=[_summarise_test_findings(test_findings, t)],
        )
    return StepResult(status="OK", step=STEP)


_TEST_PATH_MARKERS = ("/tests/", "/test/", "/fixtures/",
                      "/docs/", "/examples/")


def _is_test_path(path_lower: str) -> bool:
    """Return True when the path lives under a directory that
    legitimately ships fake secrets / test patterns."""
    if not path_lower:
        return False
    # Prefix-anchored check too: "tests/foo" without a leading slash.
    if any(path_lower.startswith(m.lstrip("/")) for m in _TEST_PATH_MARKERS):
        return True
    return any(m in path_lower for m in _TEST_PATH_MARKERS)


def _format_findings(items: list) -> str:
    """Render up to 3 findings as `rule @ path:line`, summarising
    the rest with `... and N more`."""
    details = []
    for f in items[:3]:
        rule = f.get("check_id", "unknown-rule")
        path = f.get("path", "?")
        line = (f.get("start") or {}).get("line", "?")
        try:
            rel = "/".join(Path(path).parts[-2:])
        except Exception:
            rel = path
        details.append(f"{rule} @ {rel}:{line}")
    if len(items) > 3:
        details.append(f"... and {len(items) - 3} more")
    return "\n    ".join(details)


def _summarise_test_findings(items: list, t) -> str:
    """One-line warning summarising findings that all sit in test
    fixtures / docs / examples. The full list (first 5) is appended
    inline so the user still sees what was matched."""
    head = t.t("step7_warning_test_only", count=len(items))
    return head + "\n    " + _format_findings(items[:5])
