"""MagiSentry orchestrator and CLI entry point."""
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__, config as cfg_mod
from .i18n import Translator
from .models import Config, StepResult
from .self_audit import print_audit
from .steps import (
    step1_metadata, step2_osv, step3_pipaudit, step4_download,
    step5_virustotal, step6_magika, step7_semgrep, step7_yara,
)
from .wizard import run_wizard

# (config_key, module, locale_name_key)
STEPS = [
    ("registry_check", step1_metadata, "step1_name"),
    ("osv_check", step2_osv, "step2_name"),
    ("pip_audit", step3_pipaudit, "step3_name"),
    ("isolated_download", step4_download, "step4_name"),
    ("virustotal", step5_virustotal, "step5_name"),
    ("magika", step6_magika, "step6_name"),
    ("semgrep", step7_semgrep, "step7_name"),
    ("yara", step7_yara, "step7_yara_name"),
]

EXIT_OK = 0
EXIT_TECHNICAL = 1
EXIT_THREAT = 2


def _emit_threat_stderr(t: Translator, package: str,
                        threats: List[StepResult]) -> None:
    """Print a structured threat block to stderr. Claude Code surfaces
    stderr directly in its chat window, so this is the user-visible
    explanation when the hook blocks an install."""
    sys.stderr.write("\n" + t.t("stderr_threat_header") + "\n")
    sys.stderr.write(t.t("stderr_threat_package", package=package) + "\n")
    for tr in threats:
        step_name = t.t(tr.step.split("_", 1)[0] + "_name") if "_" in tr.step else tr.step
        reason = tr.message or t.t("stderr_threat_no_details")
        details = tr.possible_cause or tr.message or t.t("stderr_threat_no_details")
        sys.stderr.write(t.t("stderr_threat_reason", reason=reason) + "\n")
        sys.stderr.write(t.t("stderr_threat_step", step=step_name) + "\n")
        sys.stderr.write(t.t("stderr_threat_details", details=details) + "\n")
    sys.stderr.write("\n")
    sys.stderr.flush()


def _emit_failsecure_stderr(t: Translator, package: str) -> None:
    sys.stderr.write("\n" + t.t("stderr_failsecure_header") + "\n")
    sys.stderr.write(t.t("stderr_threat_package", package=package) + "\n")
    sys.stderr.write(t.t("stderr_threat_reason",
                         reason=t.t("stderr_failsecure_reason")) + "\n\n")
    sys.stderr.flush()


# ---------- update check ----------

def _check_for_update(t: Translator, config: Optional[Config] = None) -> None:
    try:
        import json
        with urllib.request.urlopen(
            "https://pypi.org/pypi/magisentry/json", timeout=5,
        ) as resp:
            latest = json.loads(resp.read().decode("utf-8")).get("info", {}).get("version")
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, ValueError):
        return
    if latest and latest != __version__:
        print(t.t("update_available", new=latest, cur=__version__))
        try:
            from .notifier import notify_update
            notify_update(t, __version__, latest, config)
        except Exception:
            pass


# ---------- I/O helpers ----------

def _ask(prompt: str) -> str:
    sys.stdout.write(prompt + " ")
    sys.stdout.flush()
    return sys.stdin.readline().strip()


def _print_result(t: Translator, n: int, name: str, result: StepResult) -> None:
    if result.status == "OK":
        print(t.t("scan_step_ok"))
        for w in result.warnings:
            print(t.t("scan_step_warning", message=w))
    elif result.status == "THREAT":
        print(t.t("scan_step_threat", message=result.message))
    else:
        print(t.t("scan_step_failure", message=result.message))
        if result.possible_cause:
            print("    " + result.possible_cause)
        if result.recommendation:
            print("    " + result.recommendation)


# ---------- step loop with fail-safe / fail-secure semantics ----------

def _run_step(mod, ecosystem, package, config, t, ctx) -> StepResult:
    return mod.run(ecosystem, package, config, t, ctx)


def _handle_failure(t: Translator, config: Config, result: StepResult,
                    rerun) -> Optional[StepResult]:
    """Return final StepResult after applying mode policy.
    `rerun` is a no-arg callable that reruns the step (for [R]).
    Returns None if user aborts."""
    if config.mode == "failsafe":
        print(t.t("scan_failsafe_warning"))
        return result  # treat as non-blocking; scanner moves on
    # fail-secure
    while True:
        if not result.can_retry:
            # offer only Skip / Abort — Retry is meaningless for this failure
            # (e.g. semgrep binary missing won't change between calls).
            choice = _ask(t.t("scan_skip_or_abort")).lower()
            if choice in ("s", "skip"):
                return result
            if choice in ("a", "abort", ""):
                return None
            print(t.t("scan_invalid_choice"))
            continue
        choice = _ask(t.t("scan_retry_or_skip")).lower()
        if choice in ("r", "retry"):
            new_result = rerun()
            _print_result(t, 0, "", new_result)
            if new_result.status != "FAILURE":
                return new_result
            result = new_result
            continue
        if choice in ("s", "skip"):
            return result
        if choice in ("a", "abort", ""):
            return None
        print(t.t("scan_invalid_choice"))


def _run_pipeline(steps, ecosystem: str, package: str, ctx: dict,
                  config: Config, t: Translator
                  ) -> Tuple[List[StepResult], bool, bool]:
    """Execute a list of (config_key, module, name_key) steps applying
    the standard threat / failure semantics. Shared by `scan` (full
    pipeline) and `scan_local_file` (local-archive subset).

    Returns (threats, failsecure_blocked, aborted)."""
    threats: List[StepResult] = []
    failsecure_blocked = False
    total = len(steps)
    for n, (key, mod, name_key) in enumerate(steps, start=1):
        name = t.t(name_key)
        print(t.t("scan_step_running", n=n, total=total, name=name))
        if not config.steps.get(key, False):
            print(t.t("scan_step_skipped"))
            continue

        result = _run_step(mod, ecosystem, package, config, t, ctx)
        _print_result(t, n, name, result)

        if result.status == "THREAT":
            threats.append(result)
            continue

        if result.status == "FAILURE":
            final = _handle_failure(
                t, config, result,
                lambda: _run_step(mod, ecosystem, package, config, t, ctx),
            )
            if final is None:
                return threats, failsecure_blocked, True
            if final.status == "THREAT":
                threats.append(final)
            elif final.status == "FAILURE" and config.mode == "failsecure":
                failsecure_blocked = True
    return threats, failsecure_blocked, False


def scan(ecosystem: str, package: str, config: Config, t: Translator) -> int:
    if cfg_mod.is_whitelisted(ecosystem, package):
        print(t.t("whitelist_skipping", package=package))
        return EXIT_OK
    print(t.t("scan_starting", ecosystem=ecosystem, package=package))
    ctx: dict = {}

    threats, failures_failsecure_blocked, aborted = _run_pipeline(
        STEPS, ecosystem, package, ctx, config, t,
    )
    if aborted:
        print(t.t("scan_user_abort"))
        return EXIT_THREAT if threats else EXIT_TECHNICAL

    if threats:
        print()
        print(t.t("threat_summary_header"))
        for tr in threats:
            print("  - " + tr.message)
        ans = _ask(t.t("scan_threat_continue_prompt")).lower()
        if ans not in ("y", "yes", "a", "ano", "áno"):
            print(t.t("scan_blocked_threat"))
            _emit_threat_stderr(t, package, threats)
            try:
                from .notifier import notify_threat
                notify_threat(t, package, threats, config)
            except Exception:
                pass
            try:
                from .supporter import record_scan
                record_scan(threat_blocked=True, t=t)
            except Exception:
                pass
            return EXIT_THREAT
        # User explicitly accepted risk — fall through to install.

    if failures_failsecure_blocked:
        print(t.t("scan_blocked_failure_secure"))
        _emit_failsecure_stderr(t, package)
        return EXIT_TECHNICAL

    print(t.t("scan_completed_ok"))
    rc = _do_install(ecosystem, package, t)
    try:
        from .supporter import record_scan, show_after_install_complete
        record_scan(threat_blocked=False, t=t)
        if rc == EXIT_OK:
            show_after_install_complete(t)
    except Exception:
        pass
    return rc


# ---------- local file scan (steps 3+5+6+7+8 only) ----------

# Steps that make sense for a *pre-existing* local archive. Registry
# metadata, OSV (needs a name@version), and isolated download all skip:
# we already have the file on disk, and a local .whl carries no PyPI
# identity to query.
LOCAL_FILE_STEPS = [
    ("pip_audit", step3_pipaudit, "step3_name"),
    ("virustotal", step5_virustotal, "step5_name"),
    ("magika", step6_magika, "step6_name"),
    ("semgrep", step7_semgrep, "step7_name"),
    ("yara", step7_yara, "step7_yara_name"),
]


def _unpack_to_temp(archive: Path) -> Path:
    """Extract a local package archive into a fresh tempdir.

    Stdlib only — zipfile / tarfile cover .whl/.zip/.egg and .tar.gz.
    Caller MUST `shutil.rmtree(tmpdir, ignore_errors=True)` in a finally
    block. On failure here the partial tempdir is cleaned up before the
    exception propagates."""
    tmpdir = Path(tempfile.mkdtemp(prefix="magisentry_local_"))
    try:
        name = archive.name.lower()
        if name.endswith((".whl", ".zip", ".egg")):
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(tmpdir)
        elif name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(tmpdir, filter="data")
        else:
            raise ValueError(f"Unsupported local archive type: {archive.name}")
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    return tmpdir


def scan_local_file(ecosystem: str, archive_path: str,
                    config: Config, t: Translator) -> int:
    """Scan a local package archive (.whl/.tar.gz/.zip/.egg).

    Runs only the steps that make sense without registry context:
    pip-audit, VirusTotal hash, Magika, Semgrep, Yara. The archive is
    unpacked into a tempdir which is unconditionally cleaned up.
    Threat/failure semantics match `scan()` so fail-safe vs fail-secure
    behave identically for local and remote packages."""
    archive = Path(archive_path).resolve()
    if not archive.exists() or not archive.is_file():
        print(t.t("scan_local_file_missing", path=str(archive)))
        return EXIT_TECHNICAL
    if cfg_mod.is_whitelisted(ecosystem, str(archive)):
        print(t.t("whitelist_skipping", package=str(archive)))
        return EXIT_OK
    print(t.t("scan_starting", ecosystem=ecosystem, package=str(archive)))

    tmpdir: Optional[Path] = None
    try:
        try:
            tmpdir = _unpack_to_temp(archive)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
            print(t.t("scan_local_file_unpack_failed",
                      path=str(archive), error=str(e)[:200]))
            return EXIT_TECHNICAL

        # Pre-populate ctx exactly as step 4 would have done for a
        # remote download: `archive` for VirusTotal hash, `extracted`
        # for Magika/Semgrep/Yara, plus a `local_archive` flag so
        # step3 (pip-audit) knows to point at the file path instead of
        # synthesising a `name==version` requirement.
        ctx: dict = {
            "archive": archive,
            "extracted": tmpdir,
            "local_archive": archive,
        }
        threats, failures_failsecure_blocked, aborted = _run_pipeline(
            LOCAL_FILE_STEPS, ecosystem, str(archive), ctx, config, t,
        )
        if aborted:
            print(t.t("scan_user_abort"))
            return EXIT_THREAT if threats else EXIT_TECHNICAL

        if threats:
            print()
            print(t.t("threat_summary_header"))
            for tr in threats:
                print("  - " + tr.message)
            ans = _ask(t.t("scan_threat_continue_prompt")).lower()
            if ans not in ("y", "yes", "a", "ano", "áno"):
                print(t.t("scan_blocked_threat"))
                _emit_threat_stderr(t, str(archive), threats)
                return EXIT_THREAT

        if failures_failsecure_blocked:
            print(t.t("scan_blocked_failure_secure"))
            _emit_failsecure_stderr(t, str(archive))
            return EXIT_TECHNICAL

        print(t.t("scan_completed_ok"))
        return _do_install(ecosystem, str(archive), t)
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------- single-step scanners (step 8 / step 9) ----------

def _scan_single_step(ecosystem: str, target: str, config: Config,
                       t: Translator, module_path: str,
                       config_key: str) -> int:
    """Used for ecosystems that don't fit the 7-step pipeline (vscode, docker).
    Runs exactly one step's `run()` and applies the same threat / failure
    semantics as a normal scan. If `config_key` is disabled in the user's
    config, the scan is skipped entirely (no-op pass-through)."""
    if not config.steps.get(config_key, True):
        print(t.t("scan_disabled_for_ecosystem",
                  ecosystem=ecosystem, key=config_key))
        return EXIT_OK
    if cfg_mod.is_whitelisted(ecosystem, target):
        print(t.t("whitelist_skipping", package=target))
        return EXIT_OK
    print(t.t("scan_starting", ecosystem=ecosystem, package=target))
    import importlib
    mod = importlib.import_module(module_path)
    ctx: dict = {}
    result = mod.run(ecosystem, target, config, t, ctx)
    _print_result(t, 0, ecosystem, result)

    if result.status == "THREAT":
        ans = _ask(t.t("scan_threat_continue_prompt")).lower()
        if ans not in ("y", "yes", "a", "ano", "áno"):
            print(t.t("scan_blocked_threat"))
            _emit_threat_stderr(t, target, [result])
            try:
                from .notifier import notify_threat
                notify_threat(t, target, [result])
            except Exception:
                pass
            return EXIT_THREAT
        return EXIT_OK
    if result.status == "FAILURE":
        if config.mode == "failsecure":
            _emit_failsecure_stderr(t, target)
            return EXIT_TECHNICAL
        print(t.t("scan_failsafe_warning"))
    print(t.t("scan_completed_ok"))
    return EXIT_OK


# ---------- final installation ----------

def _do_install(ecosystem: str, package: str, t: Translator) -> int:
    if ecosystem == "pip":
        cmd = [sys.executable, "-m", "pip", "install", package]
    else:
        npm = shutil.which("npm") or "npm"
        cmd = [npm, "install", package]
    print(t.t("scan_running_install", cmd=" ".join(cmd)))
    try:
        proc = subprocess.run(cmd)
        return EXIT_OK if proc.returncode == 0 else EXIT_TECHNICAL
    except FileNotFoundError:
        return EXIT_TECHNICAL


# ---------- CLI ----------

def _print_config(config: Config, t: Translator) -> None:
    print(t.t("cli_config_current"))
    print(f"  language: {config.language}")
    print(f"  mode: {config.mode}")
    print(f"  notifications: {'on' if config.notifications else 'off'}")
    for k, v in config.steps.items():
        print(f"  {k}: {'on' if v else 'off'}")


def _resolve_step_key(key: str) -> Optional[str]:
    """Accept either a current key (`registry_check`) or the legacy
    `stepN` form. Returns the canonical current key or None on miss."""
    if key in Config.default().steps:
        return key
    return Config.LEGACY_KEY_MAP.get(key)


def _handle_config_command(args: List[str], config: Optional[Config]) -> int:
    if config is None:
        config = Config.default()
    t = Translator(config.language)
    if not args:
        _print_config(config, t)
        return EXIT_OK
    arg = args[0]
    if arg == "--wizard":
        run_wizard()
        return EXIT_OK
    if arg == "--mode" and len(args) >= 2 and args[1] in ("failsafe", "failsecure"):
        config.mode = args[1]
    elif arg == "--lang" and len(args) >= 2:
        config.language = args[1]
    elif arg == "--notifications" and len(args) >= 2 and args[1] in ("on", "off"):
        config.notifications = (args[1] == "on")
    elif arg == "--enable" and len(args) >= 2:
        canonical = _resolve_step_key(args[1])
        if canonical is None:
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        config.steps[canonical] = True
    elif arg == "--disable" and len(args) >= 2:
        canonical = _resolve_step_key(args[1])
        if canonical is None:
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        config.steps[canonical] = False
    else:
        print(t.t("cli_usage"))
        return EXIT_TECHNICAL
    cfg_mod.save(config)
    print(Translator(config.language).t("cli_config_saved"))
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    config = cfg_mod.load()
    # `uninstall` must NEVER trigger the first-run wizard — that would force
    # the user to set up the tool just to tear it down again.
    # Short-circuit `--version` / `-V` before the first-run wizard so a
    # quick "is this on PATH?" check never triggers a setup flow.
    if argv and argv[0] in ("--version", "-V", "version"):
        print(f"magisentry {__version__}")
        return EXIT_OK
    if argv and argv[0] == "uninstall":
        from .uninstaller import uninstall
        t = Translator(config.language if config else "en")
        uninstall(t.t)
        return EXIT_OK
    # Short-circuit explicit `config --wizard` BEFORE the first-run check.
    # Without this, a fresh install invoked via `config --wizard` (the
    # path setup_windows.bat / setup_linux.sh / setup_mac.sh use) would
    # trigger the first-run wizard AND then re-enter the wizard via the
    # dispatch table below — running setup twice.
    if argv and argv[0] == "config" and len(argv) > 1 and argv[1] == "--wizard":
        run_wizard()
        return EXIT_OK
    if config is None and (not argv or argv[0] != "config"):
        # Either first run with no args, or an install command on a
        # machine without a config. Explicit `config --wizard` is handled
        # by the short-circuit above, so it never reaches this branch.
        boot = Translator("en")
        print(boot.t("cli_first_run"))
        config = run_wizard()

    if not argv:
        print(Translator(config.language if config else "en").t("cli_usage"))
        return EXIT_OK

    t = Translator(config.language if config else "en")
    _check_for_update(t, config)
    print_audit(t, config)

    cmd = argv[0]
    # `uninstall` is intercepted earlier (before the first-run wizard
    # check) so it doesn't reach this dispatch table.
    if cmd == "config":
        return _handle_config_command(argv[1:], config)
    if cmd == "audit":
        from .audit import run_audit
        return run_audit(argv[1:], config, t)
    if cmd in ("pip", "npm"):
        if len(argv) < 3 or argv[1] != "install":
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        package = argv[2]
        # Local-path classification only applies to pip — npm has its own
        # tarball semantics and we don't currently support local npm files.
        if cmd == "pip":
            from .hooks._shared import classify_arg
            kind = classify_arg(package)
            if kind == "local_dir":
                print(t.t("scan_local_dir_skipped", path=package))
                return EXIT_OK
            if kind == "local_file":
                return scan_local_file(cmd, package, config, t)
        return scan(cmd, package, config, t)
    if cmd == "vscode":
        if len(argv) < 3 or argv[1] != "install":
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        return _scan_single_step(cmd, argv[2], config, t,
                                 "magisentry.steps.step8_vscode",
                                 "vscode_scan")
    if cmd == "docker":
        if len(argv) < 3 or argv[1] != "build":
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        return _scan_single_step(cmd, argv[2], config, t,
                                 "magisentry.steps.step9_dockerfile",
                                 "dockerfile_scan")
    print(t.t("cli_unknown_command", cmd=cmd))
    print(t.t("cli_usage"))
    return EXIT_TECHNICAL


if __name__ == "__main__":
    sys.exit(main())
