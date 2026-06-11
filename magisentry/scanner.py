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
    step5_virustotal, step6_magika, step7_semgrep, step8_yara,
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
    ("yara", step8_yara, "step8_yara_name"),
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


# ---------- dependency update menu ----------

def _pip_upgrade(pkg: str, version: str, t: Translator) -> bool:
    """Run `pip install --upgrade <pkg>==<version>`. Returns True on
    success. Errors land on stderr but never propagate — the menu is
    advisory, never a hard scan failure."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "--upgrade", f"{pkg}=={version}"],
            check=False,
        )
        if proc.returncode == 0:
            print(t.t("dep_update_done", pkg=pkg, version=version))
            return True
        sys.stderr.write(
            "[MagiSentry] "
            + t.t("dep_upgrade_failed_exit", code=proc.returncode)
            + "\n"
        )
        return False
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write(
            "[MagiSentry] "
            + t.t("dep_upgrade_failed_error", error=str(exc))
            + "\n"
        )
        return False


def _handle_dep_updates(updates: list, config: Config, t: Translator) -> None:
    """Offer the [1]–[4] menu for each pending dep update.

    Non-blocking: never raises, never affects scan exit codes. EOFError
    or KeyboardInterrupt at the prompt breaks out of the loop silently
    so an AI agent with closed stdin can't be coerced into picking a
    default action. Any input other than 1/2/3/4 is treated as
    "remind me next time" — we don't write to config and move on."""
    import datetime
    for pkg, installed, latest in updates:
        try:
            print()
            print(t.t("dep_update_available",
                      pkg=pkg, cur=installed, new=latest))
            print(t.t("dep_update_menu"))
            choice = _ask("").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            # Update with full scan — reuse the standard 10-step pipeline
            # for our own deps. If it finds a threat, refuse to upgrade.
            print(t.t("dep_update_scanning", pkg=pkg, version=latest))
            rc = scan("pip", f"{pkg}=={latest}", config, t)
            if rc == EXIT_OK:
                _pip_upgrade(pkg, latest, t)
            else:
                print(t.t("dep_update_blocked", pkg=pkg))

        elif choice == "2":
            _pip_upgrade(pkg, latest, t)

        elif choice == "3":
            config.dep_skip[pkg] = latest
            cfg_mod.save(config)
            print(t.t("dep_update_skipped", pkg=pkg, version=latest))

        elif choice == "4":
            remind_at = (datetime.datetime.now() +
                         datetime.timedelta(hours=24)).isoformat(
                             timespec="seconds")
            config.dep_remind[pkg] = remind_at
            cfg_mod.save(config)
            print(t.t("dep_update_remind_later", pkg=pkg))
        # Empty input / other: silent skip — don't persist anything.


# ---------- integrity check ----------

def _check_integrity(t: Translator) -> None:
    """Warn on stderr if any source file changed since the last manifest.

    Non-blocking: never raises, never affects exit codes. Same pattern
    as `_check_path_order` — security signals belong on stderr where
    AI agent harnesses surface them, but the scan itself proceeds so
    the user is never locked out of their own tool."""
    try:
        from .integrity import check, has_manifest
        if not has_manifest():
            sys.stderr.write(
                "[MagiSentry] " + t.t("integrity_no_manifest") + "\n"
            )
            sys.stderr.flush()
            return
        changed = check()
        if changed:
            sys.stderr.write("\n" + t.t("integrity_warning") + "\n")
            for f in changed:
                sys.stderr.write("  " + t.t("integrity_file_changed", file=f) + "\n")
            sys.stderr.write("  " + t.t("integrity_run_update") + "\n\n")
            sys.stderr.flush()
    except Exception:
        pass  # Integrity check failure must never block scans.


def _handle_integrity_command(args: List[str], config: Optional[Config],
                              t: Translator) -> int:
    """`magisentry integrity update [--yes]`.

    Re-blesses the manifest after a legitimate code change. The [y/N]
    prompt is what stops an AI agent from silently re-hashing a
    tampered tree — closed stdin → cancel. `--yes` exists ONLY for
    the setup scripts (first-install bootstrap)."""
    from .integrity import build_manifest, save_manifest, _collect_files
    yes = "--yes" in args
    args = [a for a in args if a != "--yes"]
    if not args or args[0] != "update":
        print(t.t("integrity_usage"))
        return EXIT_TECHNICAL

    files = _collect_files()
    print(t.t("integrity_update_confirm", count=len(files)))
    if not yes:
        try:
            answer = input("[y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "y":
            print(t.t("integrity_update_cancelled"))
            return EXIT_OK

    print(t.t("integrity_update_scanning"))
    hashes = build_manifest()
    for label in sorted(hashes):
        print(f"  {label}")
    save_manifest(hashes)
    from .integrity import MANIFEST_PATH
    print(t.t("integrity_update_done",
              count=len(hashes), path=str(MANIFEST_PATH)))
    return EXIT_OK


# ---------- PATH order check ----------

def _check_path_order(t: Translator) -> None:
    """Warn if the MagiSentry shim dir is not the first `pip` on PATH.

    A correctly-installed shim makes EVERY `pip install` go through us
    first. If `which pip` resolves to a different directory, an AI agent
    can call the real pip and bypass scanning entirely. Non-blocking —
    we just emit a stderr warning so the user notices and fixes PATH.

    When the resolved pip lives under a system-wide `Python<digit>` /
    `python3` directory we add an extra explanatory line so the user
    knows why their user-PATH shim is being shadowed (Windows places
    system Python in machine-PATH which beats user-PATH; mirrored on
    Linux/macOS via system package managers). Detection is purely
    string-based — no filesystem queries — so it stays Non-blocking
    even on weird PATH layouts."""
    shim_pip = shutil.which("pip")
    if shim_pip is None:
        return
    shim_dir = str(Path(shim_pip).parent.resolve())
    ms_data = Path.home() / ".magisentry" / "bin"
    if not ms_data.exists():
        return
    ms_dir = str(ms_data.resolve())
    if shim_dir != ms_dir:
        import re as _re
        _is_system = bool(_re.search(r'[/\\][Pp]ython\d', shim_pip))
        sys.stderr.write(t.t("path_order_warning_header") + "\n")
        sys.stderr.write(t.t("path_order_warning_found",
                             found=shim_pip) + "\n")
        if _is_system:
            sys.stderr.write(
                t.t("path_order_warning_system_python") + "\n"
            )
        sys.stderr.write(
            t.t("path_order_warning_shim", shim_dir=str(ms_data)) + "\n"
        )
        sys.stderr.write(t.t("path_order_warning_agents_ok") + "\n")
        sys.stderr.write(t.t("path_order_warning_fix") + "\n")
        sys.stderr.flush()


# ---------- update check ----------

def _version_tuple(v: str) -> tuple:
    """Convert a version string to a comparable tuple.

    Simple major.minor.patch parser — no external dependency.
    Non-numeric segments (e.g. '1.0.3a1') fall back to 0 so
    the comparison degrades gracefully rather than crashing.
    Cross-platform: no OS-specific logic.
    """
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (ValueError, AttributeError):
        return (0,)


def _check_for_update(t: Translator, config: Optional[Config] = None) -> None:
    """Public wrapper — never lets a startup-check exception abort a scan.

    The update check is purely informational; a broken PyPI response, a
    terminal that can't encode a glyph, or any other failure mode must
    never block the user's `magisentry pip install …`. Mirrors the same
    swallow-everything pattern used by `check_uv_isolation`."""
    try:
        _check_for_update_impl(t, config)
    except Exception:
        return


def _check_for_update_impl(t: Translator, config: Optional[Config] = None) -> None:
    """Check PyPI for a newer MagiSentry release and offer an interactive
    [1]–[4] menu (Update+scan / Update / Skip / Remind later).

    Non-blocking: EOFError / KeyboardInterrupt silently exits so an AI
    agent with closed stdin is never stuck waiting for input. Network
    failures, malformed PyPI responses, and missing config all degrade
    to a quiet skip — never a hard scan failure."""
    # 1. Fetch latest version from PyPI (5s timeout).
    try:
        import json as _json
        with urllib.request.urlopen(
            "https://pypi.org/pypi/magisentry/json", timeout=5,
        ) as resp:
            latest = _json.loads(
                resp.read().decode("utf-8")
            ).get("info", {}).get("version")
    except Exception:
        return   # network unavailable — silently skip

    if not latest or _version_tuple(latest) <= _version_tuple(__version__):
        return   # already up to date or running a newer local build

    # 2. Honour skip / remind state.
    if config is not None:
        if config.self_skip == latest:
            return   # user permanently skipped this version
        if config.self_remind:
            try:
                import datetime
                remind_at = datetime.datetime.fromisoformat(config.self_remind)
                if datetime.datetime.now() < remind_at:
                    return   # still within remind window
            except (ValueError, TypeError):
                pass   # malformed timestamp — ignore and show menu

    # 3. Toast notification (non-blocking, best-effort).
    try:
        from .notifier import notify_update
        notify_update(t, __version__, latest, config)
    except Exception:
        pass

    # 4. Interactive menu.
    # Suppress update banner spam in AI agent hook context (non-interactive
    # stdin). In AI context (stdin is not a TTY), show the banner at most
    # once every 24 hours to avoid spamming when scanning many packages in
    # a single session (e.g. `pip install -r requirements.txt` with 50+
    # entries triggers 50 scans, and every one would otherwise re-print
    # the banner). In manual/interactive context (stdin IS a TTY), the
    # banner is always shown so the user never misses an update prompt.
    if not sys.stdin.isatty():
        _stamp_file = Path.home() / ".magisentry" / "hook_update_shown.txt"
        try:
            import datetime as _dt
            if _stamp_file.exists():
                _last = _dt.datetime.fromisoformat(
                    _stamp_file.read_text(encoding="utf-8").strip()
                )
                if _dt.datetime.now() - _last < _dt.timedelta(hours=24):
                    return  # shown recently — silent skip
            # Not shown recently — show once and save timestamp.
            _stamp_file.parent.mkdir(parents=True, exist_ok=True)
            _stamp_file.write_text(
                _dt.datetime.now().isoformat(), encoding="utf-8"
            )
        except Exception:
            return  # any I/O failure — silently skip banner in AI context
    try:
        print()
        print(t.t("self_update_available", new=latest, cur=__version__))
        print(t.t("self_update_menu"))
        choice = _ask("").strip()
    except (EOFError, KeyboardInterrupt):
        return   # AI agent with closed stdin — silently skip

    if choice == "1":
        # Scan the new version through the full pipeline before installing.
        print(t.t("self_update_scanning", version=latest))
        rc = scan("pip", f"magisentry=={latest}", config, t)
        if rc == EXIT_OK:
            _pip_upgrade_self(latest, t)
        else:
            print(t.t("self_update_blocked"))

    elif choice == "2":
        _pip_upgrade_self(latest, t)

    elif choice == "3":
        if config is not None:
            config.self_skip = latest
            cfg_mod.save(config)
        print(t.t("self_update_skipped", version=latest))

    elif choice == "4":
        if config is not None:
            import datetime
            remind_at = (
                datetime.datetime.now()
                + datetime.timedelta(hours=24)
            ).isoformat(timespec="seconds")
            config.self_remind = remind_at
            cfg_mod.save(config)
        print(t.t("self_update_remind_later"))
    # Empty input / other: silently skip — no state persisted.


def _pip_upgrade_self(version: str, t: Translator) -> None:
    """Run `pip install --upgrade magisentry==<version>` in a subprocess.
    Uses the same Python interpreter that is currently running."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install",
         f"magisentry=={version}", "--upgrade", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(t.t("self_update_done", version=version))
    else:
        print(t.t("self_update_no_pip", version=version))


# ---------- I/O helpers ----------

def _ask(prompt: str) -> str:
    sys.stdout.write(prompt + " ")
    sys.stdout.flush()
    try:
        return sys.stdin.readline().strip()
    except KeyboardInterrupt:
        # Ctrl+C mid-prompt should land softly: empty answer is treated
        # as Abort by every caller, and main()'s outer handler then
        # prints the friendly interrupt message.
        sys.stdout.write("\n")
        return ""


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
    # `git+https://...` (and friends) needs a different pipeline:
    # no PyPI/OSV identity, step 4 has to invoke pip download itself.
    # Route there before whitelisting / starting the standard banner.
    if ecosystem == "pip" and _is_git_url(package):
        return scan_git_url(package, config, t)
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
    ("yara", step8_yara, "step8_yara_name"),
]


# Steps that run for `git+https://` and friends. Steps 1 (PyPI metadata)
# and 2 (OSV) are skipped because a git URL has no registry identity to
# query. Step 4 (isolated download) runs INLINE in scan_git_url() — pip
# download is invoked directly there to fetch the URL into a tempdir.
# Step 3 (pip-audit) FAILURE is treated as a known limitation (no PyPI
# metadata to feed the auditor) and is non-blocking; an actual THREAT
# from pip-audit still blocks via the standard prompt.
GIT_URL_STEPS = [
    ("pip_audit",  step3_pipaudit,   "step3_name"),
    ("virustotal", step5_virustotal, "step5_name"),
    ("magika",     step6_magika,     "step6_name"),
    ("semgrep",    step7_semgrep,    "step7_name"),
    ("yara",       step8_yara,       "step8_yara_name"),
]

_GIT_STEP_DISPLAY_N = {
    "pip_audit":  3,
    "virustotal": 5,
    "magika":     6,
    "semgrep":    7,
    "yara":       8,
}


def _unpack_to_temp(archive: Path) -> Path:
    """Extract a local package archive into a fresh tempdir.

    Stdlib only — zipfile / tarfile cover .whl/.zip/.egg and .tar.gz.
    Caller MUST `shutil.rmtree(tmpdir, ignore_errors=True)` in a finally
    block. On failure here the partial tempdir is cleaned up before the
    exception propagates."""
    tmpdir = Path(tempfile.mkdtemp(prefix="magisentry_local_")).resolve()
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


# ---------- git+URL scan (steps 3+4+5+6+7+8, no PyPI/OSV) ----------

_GIT_URL_PREFIXES = (
    "git+https://", "git+http://", "git+ssh://", "git+git://",
)


def _is_git_url(spec: str) -> bool:
    return spec.startswith(_GIT_URL_PREFIXES)


def scan_git_url(url: str, config: Config, t: Translator) -> int:
    """Scan a `git+...://` install spec through steps 3–8.

    Pipeline shape:
      - Steps 1 + 2 (registry metadata, OSV) skipped — git URLs have
        no PyPI identity to query.
      - Step 4 (isolated download) runs INLINE here via `pip download`
        because step4_download.py expects a registry name+version.
      - Steps 3, 5–8 use the standard module dispatch with the same
        threat / failure semantics as `scan()` — except that a
        FAILURE in step 3 (pip-audit) is treated as a known
        limitation (git repos rarely ship the PyPI metadata pip-audit
        needs) and is non-blocking even in fail-secure mode. An
        actual THREAT from pip-audit still blocks normally.
    """
    print(t.t("scan_git_header", url=url))
    print(t.t("scan_git_skipping_steps"))

    pip_tmpdir = Path(tempfile.mkdtemp(prefix="magisentry_git_")).resolve()
    extracted: Optional[Path] = None
    threats: List[StepResult] = []
    failsecure_blocked = False
    aborted = False
    try:
        # ---- Step 4: isolated download via `pip download` ----
        print()
        print(t.t("scan_step_running", n=4, total=8,
                  name=t.t("step4_name")))
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "download",
                 "--no-deps", "--dest", str(pip_tmpdir), url],
                capture_output=True, text=True, timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print("  -> " + t.t("scan_git_download_failed"))
            sys.stderr.write(
                f"[MagiSentry] pip download crashed for {url}: {exc}\n"
            )
            return EXIT_TECHNICAL if config.mode == "failsecure" else EXIT_OK

        if proc.returncode != 0:
            print("  -> " + t.t("scan_git_download_failed"))
            sys.stderr.write(
                f"[MagiSentry] pip download failed for {url}\n"
                f"{(proc.stderr or '').strip()}\n"
            )
            return EXIT_TECHNICAL if config.mode == "failsecure" else EXIT_OK

        # `pip download` produces .whl when build succeeds; falls back
        # to .tar.gz / .zip otherwise. Pick the first archive we
        # recognise — there's only ever one with --no-deps.
        archives = [
            f for f in pip_tmpdir.iterdir()
            if f.is_file() and (
                f.suffix in (".whl", ".zip", ".egg")
                or f.name.endswith(".tar.gz")
                or f.name.endswith(".tgz")
            )
        ]
        if not archives:
            print("  -> " + t.t("scan_git_no_archive"))
            return EXIT_TECHNICAL if config.mode == "failsecure" else EXIT_OK
        archive = archives[0]
        print(f"  -> OK ({archive.name})")

        # Unpack once, reuse for steps 5–8 + step 3.
        try:
            extracted = _unpack_to_temp(archive)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
            print(t.t("scan_local_file_unpack_failed",
                      path=str(archive), error=str(e)[:200]))
            return EXIT_TECHNICAL if config.mode == "failsecure" else EXIT_OK

        # Same ctx contract as step4_download / scan_local_file: VT
        # hashes `archive`, Magika/Semgrep/Yara walk `extracted`, and
        # `local_archive` tells step3 to feed pip-audit a file path
        # rather than a synthesised name==version.
        ctx: dict = {
            "archive": archive,
            "extracted": extracted,
            "local_archive": archive,
        }

        # ---- Steps 3, 5–8 ----
        for config_key, mod, name_key in GIT_URL_STEPS:
            if not config.steps.get(config_key, True):
                continue
            display_n = _GIT_STEP_DISPLAY_N[config_key]
            step_name = t.t(name_key)
            print()
            print(t.t("scan_step_running", n=display_n, total=8,
                      name=step_name))
            result = _run_step(mod, "pip", url, config, t, ctx)
            _print_result(t, display_n, step_name, result)

            if result.status == "THREAT":
                threats.append(result)
                continue

            if result.status == "FAILURE":
                if config_key == "pip_audit":
                    # Expected for git URLs — pip-audit needs PyPI
                    # metadata which a bare git checkout typically
                    # lacks. Surface it as info, never block.
                    print("  " + t.t("scan_git_pipaudit_no_metadata"))
                    continue
                final = _handle_failure(
                    t, config, result,
                    lambda: _run_step(mod, "pip", url, config, t, ctx),
                )
                if final is None:
                    aborted = True
                    break
                if final.status == "THREAT":
                    threats.append(final)
                elif final.status == "FAILURE" and config.mode == "failsecure":
                    failsecure_blocked = True
    finally:
        if extracted is not None:
            shutil.rmtree(extracted, ignore_errors=True)
        shutil.rmtree(pip_tmpdir, ignore_errors=True)

    # ---- Standard threat / fail-secure post-processing ----
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
            _emit_threat_stderr(t, url, threats)
            try:
                from .notifier import notify_threat
                notify_threat(t, url, threats, config)
            except Exception:
                pass
            return EXIT_THREAT

    if failsecure_blocked:
        print(t.t("scan_blocked_failure_secure"))
        _emit_failsecure_stderr(t, url)
        return EXIT_TECHNICAL

    print(t.t("scan_completed_ok"))
    return _do_install("pip", url, t)


# ---------- single-step scanners (step 8 / step 9) ----------

def _scan_single_step(ecosystem: str, target: str, config: Config,
                       t: Translator, module_path: str,
                       config_key: str) -> int:
    """Used for ecosystems that don't fit the 8-step pipeline (vscode, docker).
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


def _parse_whitelist_target(target: str) -> Optional[Tuple[str, str]]:
    """Split `pip:requests` / `npm:lodash` into (ecosystem, package).
    Returns None for malformed input so the caller can print cli_usage."""
    if ":" not in target:
        return None
    ecosystem, _, pkg = target.partition(":")
    ecosystem = ecosystem.strip().lower()
    pkg = pkg.strip()
    if ecosystem not in ("pip", "npm") or not pkg:
        return None
    return ecosystem, pkg


def _handle_whitelist_command(args: List[str], config: Optional[Config],
                              t: Translator) -> int:
    """`magisentry whitelist [list | add <eco>:<pkg> | remove <eco>:<pkg>]`.

    Every mutation goes through `config.whitelist_add` /
    `whitelist_remove`, which gate the change behind a [y/N] prompt and
    write a timestamped line to `~/.magisentry/config_audit.log`."""
    force = "--force" in args
    args = [a for a in args if a != "--force"]
    if not args:
        print(t.t("cli_usage"))
        return EXIT_TECHNICAL
    sub = args[0]

    if sub == "list":
        entries = cfg_mod.whitelist_entries()
        if not entries:
            print(t.t("whitelist_list_empty"))
            return EXIT_OK
        print(t.t("whitelist_list_header"))
        for e in entries:
            print(f"  - {e}")
        return EXIT_OK

    if sub in ("add", "remove") and len(args) >= 2:
        parsed = _parse_whitelist_target(args[1])
        if parsed is None:
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        ecosystem, package = parsed
        entry = f"{ecosystem}:{package.split('==')[0].split('@')[0].lower()}"
        if sub == "add":
            result = cfg_mod.whitelist_add(ecosystem, package, force=force)
            if result == "added":
                print(t.t("whitelist_added", entry=entry))
            elif result == "already_exists":
                print(t.t("whitelist_already_exists", entry=entry))
            else:  # cancelled
                print(t.t("whitelist_cancelled"))
            return EXIT_OK
        # remove
        result = cfg_mod.whitelist_remove(ecosystem, package, force=force)
        if result == "removed":
            print(t.t("whitelist_removed", entry=entry))
        elif result == "not_found":
            print(t.t("whitelist_not_found", entry=entry))
        else:  # cancelled
            print(t.t("whitelist_cancelled"))
        return EXIT_OK

    print(t.t("cli_usage"))
    return EXIT_TECHNICAL


def _handle_config_command(args: List[str], config: Optional[Config]) -> int:
    if config is None:
        config = Config.default()
    t = Translator(config.language)
    if not args:
        _print_config(config, t)
        return EXIT_OK
    # Pull `--force` out of args before positional parsing so it can
    # appear anywhere (e.g. `config --mode failsecure --force`). Forced
    # writes skip the [y/N] prompt — intended for CI only.
    force = "--force" in args
    args = [a for a in args if a != "--force"]
    if not args:
        _print_config(config, t)
        return EXIT_OK
    arg = args[0]
    if arg == "--wizard":
        # Optional `--mode fresh|reinstall` selects how
        # `_install_optional_extra` treats already-installed extras.
        # Default "fresh" preserves the previous always-install
        # behaviour for callers that don't pass the flag.
        from .wizard import WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL
        wmode = WIZARD_MODE_FRESH
        for i, tok in enumerate(args[1:], start=1):
            if tok == "--mode" and i + 1 <= len(args) - 1:
                cand = args[i + 1]
                if cand in (WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL):
                    wmode = cand
            elif tok.startswith("--mode="):
                cand = tok.split("=", 1)[1]
                if cand in (WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL):
                    wmode = cand
        run_wizard(mode=wmode)
        return EXIT_OK
    # Each branch must compute `change_desc` describing the diff for
    # the audit log: "field: <old> → <new>". Without this an attacker
    # (or a confused AI agent) editing config.json silently is
    # invisible after the fact — the audit log is the only way back.
    change_desc: str
    if arg == "--mode" and len(args) >= 2 and args[1] in ("failsafe", "failsecure"):
        change_desc = f"mode: {config.mode} → {args[1]}"
        config.mode = args[1]
    elif arg == "--lang" and len(args) >= 2:
        change_desc = f"language: {config.language} → {args[1]}"
        config.language = args[1]
    elif arg == "--notifications" and len(args) >= 2 and args[1] in ("on", "off"):
        new_val = (args[1] == "on")
        change_desc = (f"notifications: {'on' if config.notifications else 'off'}"
                       f" → {args[1]}")
        config.notifications = new_val
    elif arg == "--enable" and len(args) >= 2:
        canonical = _resolve_step_key(args[1])
        if canonical is None:
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        old = bool(config.steps.get(canonical, False))
        change_desc = f"steps.{canonical}: {str(old).lower()} → true"
        config.steps[canonical] = True
    elif arg == "--disable" and len(args) >= 2:
        canonical = _resolve_step_key(args[1])
        if canonical is None:
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        old = bool(config.steps.get(canonical, False))
        change_desc = f"steps.{canonical}: {str(old).lower()} → false"
        config.steps[canonical] = False
    else:
        print(t.t("cli_usage"))
        return EXIT_TECHNICAL
    saved = cfg_mod.save_protected(config, change_desc, force=force)
    if not saved:
        print(t.t("config_cancelled"))
        return EXIT_OK
    print(Translator(config.language).t("cli_config_saved"))
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Catches Ctrl+C anywhere in the dispatch tree
    so users see a clean message instead of a Python traceback. The
    real work lives in `_main_impl` to keep this wrapper trivial."""
    # Force stdout/stderr to UTF-8 so emoji / Slovak diacritics never
    # crash a scan on a Windows console using cp1250. `errors="replace"`
    # is the belt-and-braces fallback for any byte the terminal cannot
    # render — we'd rather print `?` than abort the scan.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    try:
        return _main_impl(argv)
    except KeyboardInterrupt:
        # `main` runs OUTSIDE `_main_impl`, so we don't have a Translator
        # in scope. Load config + build a Translator inside try/except so
        # any failure (missing config, corrupted JSON, locale read error)
        # falls back to a hardcoded English message rather than crashing
        # the interrupt handler itself.
        try:
            from .i18n import Translator
            from .config import load as _load_config
            _cfg = _load_config()
            _lang = _cfg.language if _cfg else "en"
            _t = Translator(_lang)
            sys.stderr.write("\n" + _t.t("interrupted") + "\n")
        except Exception:
            sys.stderr.write("\n[MagiSentry] Interrupted by user.\n")
        return EXIT_TECHNICAL


def _main_impl(argv: Optional[List[str]] = None) -> int:
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
        from .wizard import WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL
        wmode = WIZARD_MODE_FRESH
        for i, tok in enumerate(argv[2:], start=2):
            if tok == "--mode" and i + 1 <= len(argv) - 1:
                cand = argv[i + 1]
                if cand in (WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL):
                    wmode = cand
            elif tok.startswith("--mode="):
                cand = tok.split("=", 1)[1]
                if cand in (WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL):
                    wmode = cand
        run_wizard(mode=wmode)
        return EXIT_OK
    # `integrity update --yes` is part of setup scripts and must run
    # BEFORE the first-run wizard check — otherwise a fresh install
    # would force the user through wizard setup just to bless the
    # initial manifest.
    if argv and argv[0] == "integrity":
        t = Translator(config.language if config else "en")
        return _handle_integrity_command(argv[1:], config, t)
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
    _check_path_order(t)
    _check_integrity(t)
    from .self_audit import check_uv_isolation
    check_uv_isolation(t)
    _check_for_update(t, config)
    pending_updates = print_audit(t, config)
    if pending_updates and config is not None:
        _handle_dep_updates(pending_updates, config, t)

    cmd = argv[0]
    # `uninstall` is intercepted earlier (before the first-run wizard
    # check) so it doesn't reach this dispatch table.
    if cmd == "config":
        return _handle_config_command(argv[1:], config)
    if cmd == "whitelist":
        return _handle_whitelist_command(argv[1:], config, t)
    if cmd == "audit":
        from .audit import run_audit
        return run_audit(argv[1:], config, t)
    if cmd == "self-audit":
        # Explicit user-facing verb. The startup block above (just
        # before this dispatch table) already ran `check_uv_isolation`
        # and `print_audit`, so the audit output is already on screen.
        # Re-invoking them here would print everything twice. The verb
        # exists purely as a documented entry point — its observable
        # effect is the startup audit + exit 0.
        return EXIT_OK
    if cmd in ("uv", "uvx"):
        # Route through the shim — same scan-then-exec semantics as the
        # `~/.magisentry/bin/uv.bat` shell shim. Lets `magisentry uv add
        # requests` work directly from the CLI without requiring the user
        # to invoke `uv` through PATH.
        from . import shim as shim_mod
        return shim_mod.main([cmd] + argv[1:])
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
                                 "magisentry.steps.step9_vscode",
                                 "vscode_scan")
    if cmd == "docker":
        if len(argv) < 3 or argv[1] != "build":
            print(t.t("cli_usage"))
            return EXIT_TECHNICAL
        return _scan_single_step(cmd, argv[2], config, t,
                                 "magisentry.steps.step10_dockerfile",
                                 "dockerfile_scan")
    print(t.t("cli_unknown_command", cmd=cmd))
    print(t.t("cli_usage"))
    return EXIT_TECHNICAL


if __name__ == "__main__":
    sys.exit(main())
