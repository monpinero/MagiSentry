r"""Step 9 — Dockerfile pre-build scan.

Triggered when an AI agent runs `docker build` in a directory containing
a Dockerfile. We never let the build start until every package referenced
by RUN pip/npm install commands has cleared steps 1+2+3 (metadata + OSV
+ pip-audit). We don't run steps 4-7 because we're scanning a build
recipe, not pulling artifacts ourselves.

Capabilities:
  - Multi-line `RUN ... \` continuation
  - Compound commands joined by `&&` / `;`
  - `pip install -r requirements.txt` reads the file from the build context
  - Best-effort ARG/ENV substitution (only literal defaults; no Docker
    eval semantics)

Limitations (documented):
  - No COPY --from / multi-stage cross-resolution
  - Heredocs (`RUN <<EOF ... EOF`) are read but treated as plain shell

`package` argument here is the path to the Dockerfile (or the build
context dir; the resolver picks `Dockerfile` if it's a directory).
Ecosystem string is `"docker"`.
"""
import re
from pathlib import Path
from typing import Dict, List, Tuple

from ..hooks._shared import _expand_requirements_file, parse_install_command
from ..models import StepResult
from ..steps import step1_metadata, step2_osv, step3_pipaudit

STEP = "step9_dockerfile"


def _resolve_dockerfile(target: str) -> Path:
    p = Path(target)
    if p.is_dir():
        return p / "Dockerfile"
    return p


def _expand_args_envs(text: str, args: Dict[str, str]) -> str:
    """Replace ${VAR} and $VAR with their default values where known."""
    def repl(m):
        var = m.group(1) or m.group(2)
        return args.get(var, m.group(0))
    text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, text)
    text = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", repl, text)
    return text


def _parse_dockerfile(path: Path) -> Tuple[List[Tuple[str, List[str]]], List[str]]:
    """Return ([(ecosystem, [packages]), ...], errors)."""
    if not path.exists():
        return [], [f"Dockerfile not found: {path}"]
    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    # Stitch line continuations.
    stitched: List[str] = []
    buf = ""
    for line in raw_lines:
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
        else:
            buf += line
            stitched.append(buf)
            buf = ""
    if buf:
        stitched.append(buf)

    args: Dict[str, str] = {}
    runs: List[str] = []
    for line in stitched:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        head, _, rest = s.partition(" ")
        head_u = head.upper()
        if head_u == "ARG" or head_u == "ENV":
            # ARG NAME=default  /  ENV NAME=value  /  ENV NAME value
            for token in rest.split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    args[k.strip()] = v.strip().strip('"').strip("'")
        elif head_u == "RUN":
            runs.append(_expand_args_envs(rest, args))

    findings: List[Tuple[str, List[str]]] = []
    base_dir = path.parent
    for run in runs:
        # Split on shell separators within the RUN.
        for segment in re.split(r"&&|\|\||;", run):
            parsed = parse_install_command(segment)
            if parsed is None:
                continue
            ecosystem, packages = parsed
            # Expand requirements files relative to the build context.
            expanded: List[str] = []
            for pkg in packages:
                if pkg.startswith("req:"):
                    rel = pkg[4:]
                    candidate = base_dir / rel
                    expanded.extend(_expand_requirements_file(str(candidate)))
                else:
                    expanded.append(pkg)
            if expanded:
                findings.append((ecosystem, expanded))
    return findings, []


def run(ecosystem, package, config, t, ctx):
    dockerfile = _resolve_dockerfile(package)
    findings, errors = _parse_dockerfile(dockerfile)
    if errors:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step9_failure_parse"),
            possible_cause="; ".join(errors),
            recommendation=t.t("step9_recommend_parse"),
            can_retry=False,
        )
    if not findings:
        return StepResult(status="OK", step=STEP,
                          warnings=[t.t("step9_no_installs",
                                        path=str(dockerfile))])

    # Run steps 1+2+3 against each extracted package.
    threats: List[str] = []
    warnings: List[str] = []
    sub_ctx: dict = {}
    for eco, packages in findings:
        for pkg in packages:
            for label, mod in (("step1", step1_metadata),
                               ("step2", step2_osv),
                               ("step3", step3_pipaudit)):
                # Skip pip-audit for npm — its run() already self-skips.
                result = mod.run(eco, pkg, config, t, sub_ctx)
                if result.status == "THREAT":
                    threats.append(f"{eco}:{pkg} -> {label}: {result.message}")
                elif result.status == "OK":
                    warnings.extend(
                        f"{eco}:{pkg} {w}" for w in result.warnings
                    )

    if threats:
        return StepResult(
            status="THREAT", step=STEP,
            message=t.t("step9_threat_summary", count=len(threats))
                    + "\n  " + "\n  ".join(threats[:10]),
            warnings=warnings,
            can_retry=False,
        )
    return StepResult(
        status="OK", step=STEP,
        warnings=[t.t("step9_clean", count=sum(len(p) for _, p in findings))]
                 + warnings,
    )
