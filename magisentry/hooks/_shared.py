"""Shared helpers for hook entry-points.

A hook's only job is to extract the package being installed from whatever
payload the host AI tool gives us, then re-invoke `magisentry pip|npm install`.
The exit code determines whether the original install is allowed to proceed:
    0 -> allow
    2 -> block (threat detected, or fail-secure failure)
    1 -> internal error
"""
import os
import re
import shlex
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from ..scanner import main as scanner_main


# File extensions that mark a path as a local *package archive* — these
# get scanned through the local-file pipeline (steps 3+5+6+7+8). Plain
# directories are skipped entirely (editable / source installs).
LOCAL_PACKAGE_EXTS = (".whl", ".tar.gz", ".zip", ".egg")


def classify_arg(arg: str, is_editable: bool = False) -> str:
    """Classify a pip install positional argument.

    Returns one of:
        - "local_file"  : local package archive (.whl/.tar.gz/.zip/.egg)
        - "local_dir"   : path to a directory or editable install (skip)
        - "remote"      : ordinary PyPI package spec
    """
    if is_editable:
        return "local_dir"
    is_path = (
        arg in (".", "..")
        or arg.startswith(("./", "../", ".\\", "..\\"))
        or arg.startswith(("/", "\\"))
        or (len(arg) > 1 and arg[1] == ":")  # Windows drive letter, e.g. C:\
        or arg.startswith("file:")
    )
    if not is_path:
        return "remote"
    low = arg.lower()
    if any(low.endswith(e) for e in LOCAL_PACKAGE_EXTS):
        return "local_file"
    return "local_dir"


_INSTALL_VERBS = {
    "pip": {"install"},
    "npm": {"install", "i", "add"},
    "yarn": {"add"},
    "pnpm": {"install", "i", "add"},
}

# Used by parse_special_command (step 8 / step 9). Distinct API from
# parse_install_command because the "package" semantics differ.
_VSCODE_BINS = {"code", "code.cmd", "code.exe", "code-insiders",
                "codium", "vscodium"}
_DOCKER_BINS = {"docker", "docker.exe", "podman", "podman.exe",
                "buildah", "buildah.exe"}


def _strip_flags(tokens: List[str], ecosystem: str) -> List[str]:
    """Drop `-x`, `--flag`, `--flag=value` and `--flag value` pairs.

    Special case for pip: `-r FILE` / `--requirement FILE` is preserved as
    a sentinel `req:<path>` so requirements files can be expanded later."""
    out: List[str] = []
    skip_next = False
    flags_with_value = {
        "--index-url", "-i", "--extra-index-url",
        "--find-links", "-f", "--constraint", "-c", "--target", "-t",
        "--platform", "--python-version", "--implementation", "--abi",
        "--prefix", "--root", "--src", "--upgrade-strategy",
        "--registry", "--tag", "--global-style", "--save-prefix",
        # Editable installs always carry a path argument that we want to
        # skip alongside the flag — don't let the path leak through as a
        # positional and get classified as a remote package.
        "-e", "--editable",
    }
    requirement_flags = {"-r", "--requirement"}
    capture_req = False
    for tok in tokens:
        if capture_req:
            out.append(f"req:{tok}")
            capture_req = False
            continue
        if skip_next:
            skip_next = False
            continue
        if ecosystem == "pip" and tok in requirement_flags:
            capture_req = True
            continue
        if ecosystem == "pip" and "=" in tok and tok.startswith("--requirement="):
            out.append(f"req:{tok.split('=', 1)[1]}")
            continue
        if tok in flags_with_value:
            skip_next = True
            continue
        if tok.startswith("--") or (tok.startswith("-") and len(tok) > 1):
            continue
        out.append(tok)
    return out


def parse_install_command(command: str) -> Optional[Tuple[str, List[str]]]:
    """Parse a shell command. Return (ecosystem, [packages]) or None.

    Supports compound commands joined by `&&`, `;`, `|`, `||` — each segment
    is inspected independently and the FIRST install segment is returned.
    """
    # Split on common shell operators.
    segments = re.split(r"&&|\|\||;|\|", command)
    for seg in segments:
        try:
            # Non-POSIX on Windows so backslashes in paths survive.
            tokens = shlex.split(seg, posix=(os.name != "nt"))
            tokens = [t.strip('"').strip("'") for t in tokens]
        except ValueError:
            continue
        if not tokens:
            continue
        # Skip leading env assignments like `FOO=bar pip install ...`
        i = 0
        while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("-"):
            i += 1
        if i >= len(tokens):
            continue
        head = tokens[i]
        rest = tokens[i + 1:]

        ecosystem = _detect_ecosystem(head, rest)
        if ecosystem is None:
            continue
        # Find verb position.
        verb_idx = _find_verb(ecosystem, rest)
        if verb_idx is None:
            continue
        positionals = _strip_flags(rest[verb_idx + 1:], ecosystem)
        # Drop "global" / "--global" / "-g" leftovers handled by _strip_flags
        if positionals:
            return ecosystem, positionals
    return None


def _detect_ecosystem(head: str, rest: List[str]) -> Optional[str]:
    name = head.split("/")[-1].split("\\")[-1].lower()
    if name in ("pip", "pip3", "pip3.exe", "pip.exe"):
        return "pip"
    if name in ("python", "python3", "python.exe", "python3.exe", "py"):
        # `python -m pip install ...`
        if "-m" in rest:
            mi = rest.index("-m")
            if mi + 1 < len(rest) and rest[mi + 1] in ("pip",):
                return "pip"
        return None
    if name in ("npm", "npm.cmd", "npx"):
        return "npm"
    if name in ("yarn", "yarn.cmd"):
        return "yarn"
    if name in ("pnpm", "pnpm.cmd"):
        return "pnpm"
    return None


def _find_verb(ecosystem: str, rest: List[str]) -> Optional[int]:
    verbs = _INSTALL_VERBS.get(ecosystem, set())
    # For `python -m pip install ...`, skip past `-m pip`.
    skip = 0
    if rest[:2] == ["-m", "pip"]:
        skip = 2
    for idx in range(skip, len(rest)):
        if rest[idx] in verbs:
            return idx
    return None


def _expand_requirements_file(path: str) -> List[str]:
    """Read a pip requirements file and return one spec per non-comment line.

    Recursively expands nested `-r other.txt` / `-c constraints.txt` entries.
    Skips local paths, URLs, editable installs, and -e/--editable lines —
    those are out-of-scope for registry scanning and would need their own
    handler."""
    import os
    out: List[str] = []
    seen: set = set()

    def _walk(p: str) -> None:
        try:
            real = os.path.realpath(p)
        except OSError:
            return
        if real in seen:
            return
        seen.add(real)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return
        base = os.path.dirname(p) or "."
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("-r ", "--requirement ", "-r=", "--requirement=")):
                nested = line.split(None, 1)[1].lstrip("=").strip()
                _walk(os.path.join(base, nested))
                continue
            if line.startswith(("-c ", "--constraint ")):
                continue
            if line.startswith(("-e ", "--editable ", "-i ", "--index-url",
                                "--extra-index-url", "--find-links",
                                "--no-binary", "--only-binary",
                                "--pre", "--no-deps", "--trusted-host")):
                continue
            if line.startswith(("./", "/", "\\", ".\\", "file:",
                                "git+", "http://", "https://")):
                continue
            # Strip environment markers (`pkg==1.0; python_version<'3.10'`)
            spec = line.split(";", 1)[0].strip()
            # Strip extras: `pkg[extra1,extra2]==1.0` → `pkg==1.0`
            if "[" in spec and "]" in spec:
                head, _, rest = spec.partition("[")
                _, _, tail = rest.partition("]")
                spec = (head + tail).strip()
            if spec:
                out.append(spec)

    _walk(path)
    return out


def run_for_packages(ecosystem: str, packages: List[str]) -> int:
    """Run a magisentry scan for each package; returns highest exit code.

    `req:<path>` entries are expanded to per-line packages from the file.
    `ecosystem` may be one of pip / npm / yarn / pnpm / vscode / docker."""
    if ecosystem == "vscode":
        worst = 0
        for ext_id in packages:
            rc = scanner_main(["vscode", "install", ext_id])
            worst = max(worst, rc)
            if rc == 2:
                break
        return worst
    if ecosystem == "docker":
        worst = 0
        for path in packages:
            rc = scanner_main(["docker", "build", path])
            worst = max(worst, rc)
            if rc == 2:
                break
        return worst

    eco = "pip" if ecosystem == "pip" else "npm"
    expanded: List[str] = []
    for pkg in packages:
        if pkg.startswith("req:"):
            expanded.extend(_expand_requirements_file(pkg[4:]))
        else:
            expanded.append(pkg)

    worst = 0
    for pkg in expanded:
        if not pkg:
            continue
        if pkg.startswith(("git+https://", "git+http://",
                           "git+ssh://",   "git+git://")):
            # git VCS install — scanner handles steps 3–8 (no
            # PyPI/OSV identity to query, but we can still vet the
            # downloaded artefact).
            rc = scanner_main([eco, "install", pkg])
            worst = max(worst, rc)
            if rc == 2:
                break
            continue
        if pkg.startswith(("http://", "https://")):
            # Plain URL install (not git+) — out of scope for now.
            continue
        if eco == "pip":
            kind = classify_arg(pkg)
            if kind == "local_dir":
                # Plain directory or editable install — skip; we can't
                # statically analyse a project source tree the same way.
                continue
            if kind == "local_file":
                # Resolve to absolute so the scanner can find it even if
                # the host process changes cwd between hook and scan.
                pkg = str(Path(pkg).resolve())
        rc = scanner_main([eco, "install", pkg])
        worst = max(worst, rc)
        if rc == 2:
            break
    return worst


def parse_special_command(command: str) -> Optional[Tuple[str, List[str]]]:
    """Detect VS Code extension install (`code --install-extension X`) or
    Docker build (`docker build [OPTIONS] PATH`).

    Returns ("vscode", [extension_id, ...]) or ("docker", [path]) or None.
    """
    segments = re.split(r"&&|\|\||;|\|", command)
    for seg in segments:
        try:
            tokens = shlex.split(seg, posix=(os.name != "nt"))
            tokens = [t.strip('"').strip("'") for t in tokens]
        except ValueError:
            continue
        if not tokens:
            continue
        i = 0
        while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("-"):
            i += 1
        if i >= len(tokens):
            continue
        head = os.path.basename(tokens[i]).lower()
        rest = tokens[i + 1:]

        if head in _VSCODE_BINS:
            ext_ids: List[str] = []
            j = 0
            while j < len(rest):
                tok = rest[j]
                if tok in ("--install-extension", "-i"):
                    if j + 1 < len(rest):
                        ext_ids.append(rest[j + 1])
                        j += 2
                        continue
                if tok.startswith("--install-extension="):
                    ext_ids.append(tok.split("=", 1)[1])
                j += 1
            if ext_ids:
                return ("vscode", ext_ids)

        if head in _DOCKER_BINS:
            # Look for `docker build [opts] PATH`. PATH defaults to ".".
            if rest and rest[0] in ("build", "buildx"):
                # If buildx, the verb may be "buildx build".
                args = rest[1:] if rest[0] == "build" else rest[2:] if rest[1:2] == ["build"] else None
                if args is None:
                    continue
                # Skip option flags; pick the first positional that isn't an option value.
                skip = False
                target = None
                for tok in args:
                    if skip:
                        skip = False
                        continue
                    if tok.startswith("-"):
                        # Some flags carry a value: -t name, --tag x, -f file
                        if tok in ("-t", "--tag", "-f", "--file",
                                   "--build-arg", "--label", "--target",
                                   "--platform", "--cache-from", "--cache-to",
                                   "--secret", "--ssh", "--add-host"):
                            skip = True
                        continue
                    target = tok
                    break
                return ("docker", [target or "."])
    return None


def passthrough() -> int:
    """No install command found — allow the tool call to proceed."""
    return 0


def block_with_message(message: str) -> int:
    sys.stderr.write(message + "\n")
    return 2
