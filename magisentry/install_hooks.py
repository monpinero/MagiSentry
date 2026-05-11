"""Universal hook installer for MagiSentry.

Drops the right configuration file (and/or shell shim) into the right place
for every supported AI tool. Run interactively (`--interactive`) to be asked
per-tool, or non-interactively with `--tool <name>` / `--all`.

Examples:
    python -m magisentry.install_hooks --interactive
    python -m magisentry.install_hooks --tool claude_code
    python -m magisentry.install_hooks --all
    python -m magisentry.install_hooks --uninstall --tool cursor

The "shell shim" install copies hooks/shell/{pip,npm,yarn,pnpm}.bat (or .sh)
into a directory and prepends that directory to the user PATH. This is the
only mechanism that catches *every* tool, including ones without a hook API.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .i18n import Translator

PKG_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PKG_ROOT.parent
HOOKS_DIR = REPO_ROOT / "hooks"

HOME = Path.home()
SHIM_DIR = HOME / ".magisentry" / "bin"


def _detect_language() -> str:
    """Resolve the active language: MAGISENTRY_LANG env var first
    (set by setup_windows.bat / setup_linux.sh / setup_mac.sh), then
    `~/.magisentry/config.json`'s `language` field, then "en"."""
    env = os.environ.get("MAGISENTRY_LANG", "").strip().lower()
    if env in ("en", "sk"):
        return env
    cfg_path = HOME / ".magisentry" / "config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            lang = (data.get("language") or "en").strip().lower()
            if lang in ("en", "sk"):
                return lang
        except (OSError, json.JSONDecodeError):
            pass
    return "en"


# Module-level translator — initialised once per process.
T = Translator(_detect_language())


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(T.t("ihooks_installed", path=str(dst)))


def _merge_json(target: Path, snippet: dict) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(T.t("ihooks_invalid_json", path=str(target)))
            target.replace(target.with_suffix(target.suffix + ".bak"))
    merged = {**existing}
    for k, v in snippet.items():
        if k.startswith("_"):
            continue
        if k in merged and isinstance(merged[k], list) and isinstance(v, list):
            merged[k] = merged[k] + v
        elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    target.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(T.t("ihooks_merged", path=str(target)))


# -------------------- shell shim (catches everyone) --------------------

def install_shell_shim() -> None:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    src_dir = HOOKS_DIR / "shell"
    suffix = ".bat" if os.name == "nt" else ".sh"
    # pip / pip3 / python(-m pip) cover every common Python install path
    # AI agents reach for. python.bat / python3.sh fall through to the
    # real interpreter for non-pip calls so unrelated scripts still run.
    common_shims = ("pip", "pip3", "npm", "yarn", "pnpm")
    platform_shims = ("python",) if os.name == "nt" else ("python3",)
    for tool in common_shims + platform_shims:
        src = src_dir / f"{tool}{suffix}"
        dst = SHIM_DIR / f"{tool}{suffix}"
        if src.exists():
            _copy(src, dst)
            if os.name != "nt":
                os.chmod(dst, 0o755)
    _prepend_path(SHIM_DIR)


def _prepend_path(directory: Path) -> None:
    directory_str = str(directory)
    if os.name == "nt":
        # Use the registry-based helper from _install_path. setx truncates
        # at 1024 chars and reading os.environ["PATH"] mixes system+user
        # scopes — both of which silently corrupt the user PATH on machines
        # with already-long PATHs.
        try:
            from ._install_path import _add_to_registry_path
            changed = _add_to_registry_path(directory_str)
            if changed:
                print(T.t("ihooks_path_prepended", path=directory_str))
            else:
                print(T.t("ihooks_path_exists", path=directory_str))
        except OSError as e:
            print(T.t("ihooks_path_failed", error=str(e), path=directory_str))
    else:
        rc = HOME / ".bashrc"
        line = f'export PATH="{directory_str}:$PATH"  # MagiSentry\n'
        if rc.exists() and line.strip() in rc.read_text(encoding="utf-8"):
            print(T.t("ihooks_bashrc_exists", path=directory_str))
            return
        with open(rc, "a", encoding="utf-8") as f:
            f.write("\n" + line)
        print(T.t("ihooks_bashrc_appended", line=line.strip()))


# -------------------- per-tool installers --------------------

def _project_or_global_dir(tool_subdir: str, global_path: Path) -> Path:
    """Use a project-local config if a project dir exists; else go global."""
    cwd = Path.cwd()
    project_marker = cwd / tool_subdir
    if project_marker.exists() or (cwd / ".git").exists():
        return cwd / tool_subdir
    return global_path


def install_claude_code() -> None:
    target_dir = _project_or_global_dir(".claude", HOME / ".claude")
    snippet = json.loads((HOOKS_DIR / "claude_code" / "settings.json").read_text(encoding="utf-8"))
    _merge_json(target_dir / "settings.json", snippet)


def install_cursor() -> None:
    target = _project_or_global_dir(".cursor", HOME / ".cursor") / "rules"
    src = HOOKS_DIR / "cursor" / "rules"
    _copy(src, target)


def install_windsurf() -> None:
    target = _project_or_global_dir(".windsurf", HOME / ".windsurf") / "rules"
    src = HOOKS_DIR / "windsurf" / "rules"
    _copy(src, target)


def install_continue() -> None:
    target = HOME / ".continue" / "config.json"
    snippet = json.loads((HOOKS_DIR / "continue" / "config.json").read_text(encoding="utf-8"))
    _merge_json(target, snippet)


def install_aider() -> None:
    target = Path.cwd() / ".aider.conf.yml"
    src = HOOKS_DIR / "aider" / ".aider.conf.yml"
    _copy(src, target)


def install_codex() -> None:
    install_shell_shim()  # codex has no hook API; rely on shim
    print(T.t("ihooks_codex_note"))


def install_gemini_cli() -> None:
    install_shell_shim()
    print(T.t("ihooks_gemini_note"))


def install_copilot() -> None:
    target = Path.cwd() / ".vscode" / "tasks.json"
    snippet = json.loads((HOOKS_DIR / "copilot" / "tasks.json").read_text(encoding="utf-8"))
    _merge_json(target, snippet)
    install_shell_shim()


def install_cline() -> None:
    target = Path.cwd() / ".vscode" / "tasks.json"
    snippet = json.loads((HOOKS_DIR / "cline" / "tasks.json").read_text(encoding="utf-8"))
    _merge_json(target, snippet)
    install_shell_shim()


TOOLS: Dict[str, Callable[[], None]] = {
    "claude_code": install_claude_code,
    "cursor": install_cursor,
    "windsurf": install_windsurf,
    "continue": install_continue,
    "aider": install_aider,
    "codex": install_codex,
    "gemini_cli": install_gemini_cli,
    "copilot": install_copilot,
    "cline": install_cline,
    "shell": install_shell_shim,  # the universal shim by itself
}


# -------------------- CLI --------------------

def _ask_yn(prompt: str) -> bool:
    sys.stdout.write(prompt + " " + T.t("ihooks_yn_suffix") + " ")
    sys.stdout.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="magisentry-install-hooks",
        description="Install MagiSentry hooks for AI coding agents.",
    )
    p.add_argument("--tool", choices=sorted(TOOLS), action="append", default=[])
    p.add_argument("--all", action="store_true",
                   help="Install hooks for every supported tool.")
    p.add_argument("--interactive", action="store_true",
                   help="Ask per tool. Recommended for first-time setup.")
    args = p.parse_args(argv)

    if not args.tool and not args.all and not args.interactive:
        p.print_help()
        return 0

    selected: List[str] = []
    if args.all:
        selected = list(TOOLS)
    elif args.tool:
        selected = args.tool
    elif args.interactive:
        print(T.t("ihooks_banner"))
        for name in TOOLS:
            if name == "shell":
                continue
            if _ask_yn(T.t("ihooks_per_tool_prompt", name=name)):
                selected.append(name)
        selected.append("shell")

    for name in selected:
        print(T.t("ihooks_tool_section", name=name))
        try:
            TOOLS[name]()
        except (OSError, json.JSONDecodeError, FileNotFoundError) as e:
            print(T.t("ihooks_error", error=str(e)))

    print(T.t("ihooks_done"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
