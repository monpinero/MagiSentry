"""`magisentry audit` — sweep every dependency declared in the current
project (pyproject.toml + requirements*.txt + package.json) through
steps 1+2+3 and print a summary report. No package is downloaded or
installed; this is a pure metadata audit.
"""
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from .hooks._shared import _expand_requirements_file
from .i18n import Translator
from .models import Config, StepResult
from .steps import step1_metadata, step2_osv, step3_pipaudit


def _read_pyproject(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        try:
            import tomllib  # 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps = (data.get("project") or {}).get("dependencies") or []
    optional = (data.get("project") or {}).get("optional-dependencies") or {}
    out: List[str] = []
    for spec in deps:
        out.append(_normalise_pep508(spec))
    for group in optional.values():
        for spec in group:
            out.append(_normalise_pep508(spec))
    return [s for s in out if s]


def _normalise_pep508(spec: str) -> str:
    """Strip environment markers, extras, and whitespace."""
    spec = spec.split(";", 1)[0].strip()
    if "[" in spec and "]" in spec:
        head, _, rest = spec.partition("[")
        _, _, tail = rest.partition("]")
        spec = (head + tail).strip()
    return spec


def _read_package_json(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: List[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies"):
        for name, version in (data.get(key) or {}).items():
            v = re.sub(r"^[\^~>=<\s]+", "", str(version)).strip()
            if v and v not in ("*", "latest"):
                out.append(f"{name}@{v}")
            else:
                out.append(name)
    return out


def _collect(cwd: Path) -> Tuple[List[str], List[str]]:
    """Return (pip_specs, npm_specs)."""
    pip = _read_pyproject(cwd / "pyproject.toml")
    for req_name in ("requirements.txt", "requirements-dev.txt", "dev-requirements.txt"):
        rp = cwd / req_name
        if rp.exists():
            pip.extend(_expand_requirements_file(str(rp)))
    npm = _read_package_json(cwd / "package.json")
    # Dedup while preserving order.
    return list(dict.fromkeys(pip)), list(dict.fromkeys(npm))


def _audit_one(eco: str, pkg: str, config: Config,
               t: Translator) -> Dict[str, StepResult]:
    ctx: dict = {}
    return {
        "step1": step1_metadata.run(eco, pkg, config, t, ctx),
        "step2": step2_osv.run(eco, pkg, config, t, ctx),
        "step3": step3_pipaudit.run(eco, pkg, config, t, ctx),
    }


def run_audit(argv: List[str], config: Config, t: Translator) -> int:
    cwd = Path(argv[0]) if argv else Path.cwd()
    if cwd.is_file():
        cwd = cwd.parent
    pip_specs, npm_specs = _collect(cwd)
    total = len(pip_specs) + len(npm_specs)
    if total == 0:
        print(t.t("audit_no_manifests", path=str(cwd)))
        return 0

    print(t.t("audit_header", path=str(cwd), count=total))

    threats = 0
    failures = 0
    clean = 0
    rows: List[Tuple[str, str, str, str]] = []  # (eco, pkg, status, note)

    for eco, specs in (("pip", pip_specs), ("npm", npm_specs)):
        for pkg in specs:
            results = _audit_one(eco, pkg, config, t)
            statuses = [r.status for r in results.values()]
            if "THREAT" in statuses:
                threats += 1
                msgs = [r.message for r in results.values() if r.status == "THREAT"]
                rows.append((eco, pkg, "THREAT", "; ".join(msgs)[:160]))
            elif "FAILURE" in statuses:
                failures += 1
                rows.append((eco, pkg, "FAIL", ""))
            else:
                clean += 1
                w = []
                for r in results.values():
                    w.extend(r.warnings)
                rows.append((eco, pkg, "OK", "; ".join(w)[:120]))

    # Print report
    print()
    print(t.t("audit_table_header"))
    for eco, pkg, status, note in rows:
        marker = {"THREAT": "  [!]", "FAIL": "  [?]", "OK": "  [ok]"}[status]
        line = f"{marker} {eco:>4}  {pkg}"
        if note:
            line += f"\n        {note}"
        print(line)

    print()
    print(t.t("audit_summary",
              total=total, clean=clean, failures=failures, threats=threats))

    return 2 if threats else (1 if failures else 0)
