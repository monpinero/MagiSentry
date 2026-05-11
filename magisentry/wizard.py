"""Setup wizard. Language is the FIRST question, before anything else."""
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

from ._platform import IS_WINDOWS, IS_MAC, IS_LINUX, is_wsl
from .config import save, CONFIG_PATH
from .i18n import Translator
from .models import Config


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
    ("yara", "step7_yara_name", "step7_yara_desc", False),
    ("vscode_scan", "step8_name", "step8_desc", True),
    ("dockerfile_scan", "step9_name", "step9_desc", True),
]


def _detect_shell_rc() -> str:
    """Best-effort detection of the user's shell rc file."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if shell.endswith("zsh") or (home / ".zshrc").exists():
        return str(home / ".zshrc")
    return str(home / ".bashrc")


def _print_vt_setup_instructions(t: Translator) -> None:
    """OS-specific reminder for persisting VT_API_KEY."""
    if IS_WINDOWS:
        print("  " + t.t("wizard_vt_persist_windows"))
    elif IS_MAC:
        rc = "~/.zshrc" if Path("~/.zshrc").expanduser().exists() else "~/.bashrc"
        print("  " + t.t("wizard_vt_persist_unix", rc=rc))
    elif IS_LINUX:
        rc = _detect_shell_rc().replace(str(Path.home()), "~")
        print("  " + t.t("wizard_vt_persist_unix", rc=rc))


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


def _install_optional_extra(extra: str, check_import: str,
                            t: Translator) -> bool:
    """Verify an optional extra is importable; if not, offer to install it.

    `extra` matches the setup.py `extras_require` key (e.g. "semgrep",
    "yara"). `check_import` is the top-level module name we try to
    import to confirm the install (e.g. "semgrep", "yara"). Returns
    True only when the module can actually be imported after this
    call — declining the prompt or a pip failure both return False
    so the caller can flip the corresponding step OFF and avoid a
    runtime failure on the very first scan."""
    try:
        __import__(check_import)
        return True
    except ImportError:
        pass

    print(t.t("wizard_extra_not_installed", extra=extra))
    answer = _ask(t.t("wizard_extra_install_prompt", extra=extra))
    if not _yes(answer, default_yes=True):
        print(t.t("wizard_extra_skip", extra=extra))
        return False

    print(t.t("wizard_extra_installing", extra=extra))
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", f"magisentry[{extra}]"],
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        print(t.t("wizard_extra_install_failed", extra=extra))
        return False
    if result.returncode != 0:
        print(t.t("wizard_extra_install_failed", extra=extra))
        return False
    # Verify the module is now importable — pip success isn't enough
    # if a constraint resolver picked a wheel for the wrong platform.
    try:
        __import__(check_import)
    except ImportError:
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
            _print_vt_setup_instructions(t)
            return True
        print(t.t("wizard_vt_invalid_key"))


def run_wizard() -> Config:
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
            available = _install_optional_extra(key, check_mod, t)
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
