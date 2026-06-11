"""Setup wizard. Language is the FIRST question, before anything else."""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from ._platform import IS_WINDOWS, is_wsl
from .config import save
from .i18n import Translator
from .models import Config


# Wizard run-mode. "fresh" — first-time install, always (re)install
# optional extras. "reinstall" — invoked by setup_windows.bat menu [2],
# extras already installed at the right version are left alone, newer
# upstream versions surface as a Y/n/s prompt.
WIZARD_MODE_FRESH = "fresh"
WIZARD_MODE_REINSTALL = "reinstall"


def _get_uv_python_path() -> Optional[Path]:
    """Return the Python interpreter living inside the uv tool isolation
    for MagiSentry, or None when there is no such isolation.

    The wizard itself can be invoked via the SYSTEM python (e.g. when
    the user runs `python -m magisentry.scanner config --wizard`), but
    `semgrep` and `yara-python` live inside the uv tool venv. Probing
    those packages from the wrong interpreter would always say "not
    installed". Every install / version probe in this module routes
    through this helper so the answer reflects the uv-isolated state.

    Windows candidates (checked in order):
      1. `%APPDATA%\\uv\\tools\\magisentry\\Scripts\\python.exe` — this
         is uv's default on Windows because uv uses platformdirs which
         points `user_data_dir` to `%APPDATA%` (Roaming), not Local.
      2. `%LOCALAPPDATA%\\uv\\tools\\magisentry\\Scripts\\python.exe` —
         fallback for older / differently-configured uv installs that
         followed the Local convention.

    POSIX: `~/.local/share/uv/tools/magisentry/bin/python` (uv default
    on Linux/macOS via XDG_DATA_HOME)."""
    if IS_WINDOWS:
        candidates = [
            Path(os.environ.get("APPDATA", ""))
            / "uv" / "tools" / "magisentry" / "Scripts" / "python.exe",
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "uv" / "tools" / "magisentry" / "Scripts" / "python.exe",
        ]
    else:
        candidates = [
            Path.home() / ".local" / "share" / "uv" / "tools"
            / "magisentry" / "bin" / "python",
        ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _is_importable_in_uv(module_name: str) -> bool:
    """Probe whether `module_name` is importable inside the uv tool
    isolation. Falls back to `sys.executable` when MagiSentry is not
    installed via uv (e.g. development checkout still using legacy
    `pip install --user -e .`). Subprocess + 10s timeout to keep a
    misbehaving import from hanging the wizard."""
    uv_py = _get_uv_python_path()
    python = str(uv_py) if uv_py else sys.executable
    try:
        result = subprocess.run(
            [python, "-c", f"import {module_name}"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return False


KNOWN_BROKEN_VERSIONS: dict = {
    # Prázdne. semgrep 1.163.0-1.165.0 mali Windows RPC bug
    # (Unix.socketpair EINVAL v AI agent Job Object kontexte), ale
    # MagiSentry ho teraz obchádza: krok 7 spúšťa semgrep cez WMI /
    # Task Scheduler MIMO Job Object (step7_semgrep.py), kde funguje.
    # Overené na 1.165.0 aj 1.166.0. Mechanizmus ponechaný pre prípad,
    # že v budúcnosti bude treba zablokovať konkrétnu verziu balíka.
}


def _ask(prompt: str) -> str:
    sys.stdout.write(prompt + " ")
    sys.stdout.flush()
    return sys.stdin.readline().strip()


def _yes(answer: str, default_yes: bool = True) -> bool:
    if not answer:
        return default_yes
    return answer[:1].lower() in ("y", "a", "1")


def _choose_language() -> str:
    # Honour MAGISENTRY_LANG when set by the platform setup script
    # (setup_windows.bat / setup_linux.sh / setup_mac.sh) — the user has
    # already answered there, so don't ask twice.
    preset = os.environ.get("MAGISENTRY_LANG", "").strip().lower()
    if preset in ("en", "sk"):
        print(f"\n=== MagiSentry Setup / Nastavenie ({preset}) ===")
        return preset

    # Bilingual prompt — locales are not loaded yet.
    print("\n=== MagiSentry Setup / Nastavenie ===")
    while True:
        ans = _ask("Choose language / Zvoľte jazyk: [1] English  [2] Slovenčina:")
        if ans in ("1", "en", "english", ""):
            return "en"
        if ans in ("2", "sk", "slovak", "slovencina", "slovenčina"):
            return "sk"
        print("Invalid / Neplatné.")


def _choose_mode(t: Translator) -> str:
    print("\n" + t.t("wizard_mode_title"))
    print("  [1] " + t.t("wizard_mode_failsafe_desc"))
    print("  [2] " + t.t("wizard_mode_failsecure_desc"))
    while True:
        ans = _ask(t.t("wizard_mode_prompt"))
        if ans in ("1", "", "failsafe"):
            return "failsafe"
        if ans in ("2", "failsecure"):
            return "failsecure"


# (config_key, name_locale_key, desc_locale_key, needs_internet)
_STEP_NAMES = [
    ("registry_check", "step1_name", "step1_desc", True),
    ("osv_check", "step2_name", "step2_desc", True),
    ("pip_audit", "step3_name", "step3_desc", True),
    ("isolated_download", "step4_name", "step4_desc", True),
    ("virustotal", "step5_name", "step5_desc", True),
    ("magika", "step6_name", "step6_desc", False),
    ("semgrep", "step7_name", "step7_desc", False),
    ("yara", "step8_yara_name", "step8_yara_desc", False),
    ("vscode_scan", "step9_name", "step9_desc", True),
    ("dockerfile_scan", "step10_name", "step10_desc", True),
]


def _validate_vt_key(api_key: str) -> bool:
    """Cheap call to /users/<key> — returns 200 for a valid key."""
    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/users/" + api_key,
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        # 401/403 -> invalid; 429 -> rate limit but valid; 404 fallback also = bad
        return e.code == 429
    except (urllib.error.URLError, TimeoutError, OSError):
        # Network problem — don't fail the wizard, accept the key tentatively.
        return True


def _persist_vt_key(key: str) -> None:
    os.environ["VT_API_KEY"] = key
    if IS_WINDOWS:
        try:
            subprocess.run(["setx", "VT_API_KEY", key],
                           check=False, capture_output=True)
        except OSError:
            pass
    # On macOS / Linux we can't persist into the user's shell rc without
    # mutating it; the wizard prints the export line for the user instead.


def _newer(a: str, b: str) -> bool:
    """True iff version string `a` is strictly newer than `b`.

    Best-effort dotted comparison; same shape as the helper in
    `self_audit.py`. Imported version-comparison libs (`packaging`)
    are NOT pulled in deliberately — `packaging` isn't in
    install_requires and adding it just for one wizard prompt is
    over-engineered."""
    def key(s: str):
        out = []
        for part in s.split("."):
            num = ""
            for ch in part:
                if ch.isdigit():
                    num += ch
                else:
                    break
            out.append(int(num) if num else 0)
        return tuple(out)
    try:
        return key(a) > key(b)
    except (ValueError, TypeError):
        return False


def _check_package_status(pkg_name: str) -> dict:
    """Probe installed + PyPI state for `pkg_name`.

    Returns a dict with four keys:
      - installed: True iff importlib.metadata can resolve the package
      - current_version: installed version, or None
      - latest_version: latest version on PyPI, or None when offline
      - update_available: True iff installed and a newer PyPI version exists

    Network failures degrade `latest_version` to None — the wizard
    treats that the same as "already up to date", so an offline
    install doesn't spuriously prompt for an update it can't fetch."""
    result = {
        "installed": False,
        "current_version": None,
        "latest_version": None,
        "update_available": False,
        "latest_broken": False,
    }
    # The wizard's own interpreter is NOT a reliable place to ask "is
    # X installed?" — see `_get_uv_python_path` docstring. Probe via
    # subprocess against the uv-isolated python so the answer reflects
    # where `semgrep` / `yara` actually live.
    uv_py = _get_uv_python_path()
    python = str(uv_py) if uv_py else sys.executable
    try:
        proc = subprocess.run(
            [python, "-c",
             "import importlib.metadata as m; "
             f"print(m.version({pkg_name!r}))"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return result
    if proc.returncode == 0 and proc.stdout.strip():
        result["current_version"] = proc.stdout.strip()
        result["installed"] = True
    else:
        return result
    # PyPI JSON API — urllib only (project rule: no external HTTP libs).
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{pkg_name}/json", timeout=5,
        ) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["latest_version"] = (data.get("info") or {}).get("version")
    except (urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, ValueError):
        return result
    if result["latest_version"]:
        is_newer = _newer(
            result["latest_version"], result["current_version"],
        )
        if is_newer:
            broken = KNOWN_BROKEN_VERSIONS.get(pkg_name, [])
            is_broken = result["latest_version"] in broken
            if is_broken:
                # Latest PyPI version is known broken — do not offer
                # upgrade. Log it but keep update_available=False.
                result["update_available"] = False
                result["latest_broken"] = True
            else:
                result["update_available"] = True
    return result


def _pip_install_extra(extra: str, t: Translator,
                      version_pin: Optional[str] = None) -> bool:
    """Install the package for `extra` directly into the uv tool
    isolation (e.g. `pip install semgrep`, `pip install yara-python`).
    Uses the uv isolation Python when available, sys.executable
    as fallback.

    Why NOT `pip install magisentry[<extra>]`: MagiSentry is installed
    via `uv tool install --editable .` so pip sees `magisentry` as
    editable and either no-ops the extras resolution or lands the
    extra package next to the host python's site-packages. Installing
    the underlying package directly (`semgrep`, `yara-python`) goes
    where the uv-isolated interpreter expects — i.e. into the venv
    that the scanner actually runs out of.

    Returns True only when pip exits 0 — a final import check by the
    caller (`_verify_import`) confirms the package is actually loadable
    (pip success alone isn't enough if a constraint resolver picked a
    wheel for the wrong platform).
    """
    pkg = _extra_pkg(extra)
    if version_pin:
        spec = [f"{pkg}=={version_pin}"]
    else:
        spec = [pkg]
    # Install INTO the uv tool isolation, not the wizard's host
    # interpreter. The host python is typically the system Python and
    # would silently land semgrep / yara-python next to user packages
    # — invisible to the scanner running out of the uv venv.
    uv_py = _get_uv_python_path()
    python = str(uv_py) if uv_py else sys.executable
    try:
        result = subprocess.run(
            [python, "-m", "pip", "install", "--upgrade", *spec],
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _extra_pkg(extra: str) -> str:
    """Map the setup.py extra name to the PyPI package name it pulls.

    Identity for `semgrep`; `yara` extra installs `yara-python`."""
    return "yara-python" if extra == "yara" else extra


def _scan_then_install(extra: str, latest: str, t: Translator) -> bool:
    """Update path with full scan: invoke `magisentry pip install
    <pkg>==<latest>` as a subprocess so the new version goes through
    the regular 8-step pipeline before any bytes hit site-packages.
    Falls back to a normal pip install only if the scan returns
    exit 0."""
    pkg = _extra_pkg(extra)
    print(t.t("wizard_pkg_update_scan_first", package=pkg, latest=latest))
    try:
        rc = subprocess.run(
            ["magisentry", "pip", "install", f"{pkg}=={latest}"],
            check=False,
        ).returncode
    except (OSError, subprocess.SubprocessError):
        return False
    if rc != 0:
        return False
    return _pip_install_extra(extra, t, version_pin=latest)


def _install_optional_extra(extra: str, check_import: str,
                            t: Translator,
                            mode: str = WIZARD_MODE_FRESH) -> bool:
    """Ensure an optional extra is installed and importable.

    `extra` matches the setup.py `extras_require` key (e.g. "semgrep",
    "yara"). `check_import` is the top-level module name (`"semgrep"`,
    `"yara"`). `mode` is `"fresh"` (default — install if missing, leave
    existing installs alone) or `"reinstall"` (probe PyPI for a newer
    version and prompt to update). Returns True only when the module
    is actually importable at the end of this call."""
    already_installed = _is_importable_in_uv(check_import)

    pkg = _extra_pkg(extra)

    # Reinstall mode + already installed: check whether a newer version
    # exists and surface the Y/n/s choice. Up-to-date → silent skip.
    if already_installed and mode == WIZARD_MODE_REINSTALL:
        status = _check_package_status(pkg)
        if status.get("latest_broken"):
            # PyPI latest is on the KNOWN_BROKEN_VERSIONS list —
            # never offer the upgrade, but tell the user we deliberately
            # skipped it (so a stale install doesn't look like a bug).
            print(t.t("wizard_extra_update_broken",
                      extra=extra,
                      version=status.get("latest_version", "?")))
            return True
        if not status["update_available"]:
            print(t.t("wizard_pkg_up_to_date",
                      package=pkg, version=status["current_version"] or "?"))
            return True
        print(t.t("wizard_pkg_update_available",
                  package=pkg,
                  current=status["current_version"],
                  latest=status["latest_version"]))
        answer = _ask("").strip().lower()
        if answer == "n":
            print(t.t("wizard_pkg_update_skipped", package=pkg))
            return True
        if answer == "s":
            print(t.t("wizard_pkg_update_no_scan",
                      package=pkg, latest=status["latest_version"]))
            if _pip_install_extra(extra, t,
                                  version_pin=status["latest_version"]):
                return _verify_import(check_import, extra, t)
            print(t.t("wizard_extra_install_failed", extra=extra))
            return True   # keep step enabled — old version still works
        # Default ("" / "y" / anything else) → update with scan.
        if _scan_then_install(extra, status["latest_version"], t):
            return _verify_import(check_import, extra, t)
        print(t.t("wizard_extra_install_failed", extra=extra))
        return True   # old version still works

    if already_installed:
        return True

    # Fresh install path (also reinstall mode when nothing's there yet).
    print(t.t("wizard_extra_not_installed", extra=extra))
    answer = _ask(t.t("wizard_extra_install_prompt", extra=extra))
    if not _yes(answer, default_yes=True):
        print(t.t("wizard_extra_skip", extra=extra))
        return False

    print(t.t("wizard_extra_installing", extra=extra))
    if not _pip_install_extra(extra, t):
        print(t.t("wizard_extra_install_failed", extra=extra))
        return False
    return _verify_import(check_import, extra, t)


def _verify_import(check_import: str, extra: str, t: Translator) -> bool:
    """Confirm the module is importable after a pip install. pip's
    exit code isn't authoritative — a wheel for the wrong platform
    succeeds at install time and fails on first import. Probe runs
    inside the uv tool isolation (see `_is_importable_in_uv`)."""
    if not _is_importable_in_uv(check_import):
        print(t.t("wizard_extra_install_failed", extra=extra))
        return False
    print(t.t("wizard_extra_installed_ok", extra=extra))
    return True


def _vt_flow(t: Translator) -> bool:
    """Returns True if step5 should remain enabled."""
    has_account = _yes(_ask(t.t("wizard_vt_account_prompt")), default_yes=False)
    if not has_account:
        print(t.t("wizard_vt_register_instructions"))
    while True:
        key = _ask(t.t("wizard_vt_enter_key"))
        if not key:
            return False
        print(t.t("wizard_vt_validating"))
        if _validate_vt_key(key):
            _persist_vt_key(key)
            print(t.t("wizard_vt_key_saved"))
            return True
        print(t.t("wizard_vt_invalid_key"))


def run_wizard(mode: str = WIZARD_MODE_FRESH) -> Config:
    """Run the interactive setup wizard.

    `mode` is `"fresh"` (default — first-time install) or `"reinstall"`
    (invoked by setup_windows.bat menu [2]). The mode is forwarded to
    `_install_optional_extra` so an existing semgrep/yara install isn't
    silently re-pip-installed; a newer upstream version surfaces as a
    Y/n/s prompt instead."""
    if mode not in (WIZARD_MODE_FRESH, WIZARD_MODE_REINSTALL):
        mode = WIZARD_MODE_FRESH
    lang = _choose_language()
    t = Translator(lang)
    cfg = Config.default()
    cfg.language = lang

    print("\n" + t.t("wizard_welcome"))
    print(t.t("wizard_intro"))
    if is_wsl():
        print(t.t("wizard_wsl_detected"))

    cfg.mode = _choose_mode(t)

    print("\n" + t.t("wizard_notifications_intro"))
    cfg.notifications = _yes(_ask(t.t("wizard_notifications_prompt")),
                             default_yes=True)

    print()
    for n, (key, name_k, desc_k, needs_internet) in enumerate(_STEP_NAMES, start=1):
        # Compact per-step prompt: name + Y/N only. Descriptions, internet
        # requirement and price are documented in the README + hooks_guide;
        # showing them per-step made the wizard a wall of text.
        print(t.t("wizard_step_header", n=n, name=t.t(name_k)))
        enabled = _yes(_ask(t.t("wizard_step_enable_prompt")),
                       default_yes=cfg.steps[key])
        cfg.steps[key] = enabled

        if key == "virustotal" and enabled:
            cfg.steps[key] = _vt_flow(t)
        # Semgrep and Yara are pip *extras*, not part of [core].
        # If the user enables them but the binary is missing, offer
        # to `pip install magisentry[<extra>]` right here so the
        # first scan doesn't immediately FAILURE on a missing
        # dependency. Decline / install-fail → silently flip OFF.
        if key in ("semgrep", "yara") and enabled:
            check_mod = "yara" if key == "yara" else "semgrep"
            available = _install_optional_extra(key, check_mod, t, mode=mode)
            if not available:
                cfg.steps[key] = False
                print(t.t("wizard_extra_disabled", step=t.t(name_k)))
        print()

    path = save(cfg)
    print(t.t("wizard_summary_header"))
    print("  " + t.t("wizard_summary_lang", lang=cfg.language))
    print("  " + t.t("wizard_summary_mode",
                     mode=t.t("mode_" + cfg.mode)))
    for n, (key, name_k, _, _) in enumerate(_STEP_NAMES, start=1):
        line_key = "wizard_summary_enabled" if cfg.steps[key] else "wizard_summary_disabled"
        print(t.t(line_key, step=f"{n}. {t.t(name_k)}"))
    print(t.t("wizard_done", path=str(path)))
    try:
        from .supporter import show_after_install
        show_after_install(t)
    except Exception:
        pass
    return cfg
