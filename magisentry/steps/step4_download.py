"""Step 4 — isolated download. NEVER runs setup.py / postinstall scripts."""
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import zipfile
from pathlib import Path

from ..models import StepResult
from ._common import split_pkg, http_json, http_get_bytes

STEP = "step4_download"


def _extract(archive: Path, dest: Path) -> None:
    if archive.suffix == ".whl" or archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
        return
    if archive.name.endswith((".tar.gz", ".tgz", ".tar.bz2")):
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter="data")
        return
    raise ValueError(f"Unknown archive type: {archive.name}")


def _pip_download(package: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="magisentry_pip_"))
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "download", package,
         "--no-deps", "--dest", str(tmp), "--disable-pip-version-check"],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(proc.stderr or proc.stdout)
    files = [p for p in tmp.iterdir() if p.is_file()]
    if not files:
        raise RuntimeError("pip download produced no files")
    return files[0]


def _npm_download(package: str) -> Path:
    name, version = split_pkg("npm", package)
    info = http_json(f"https://registry.npmjs.org/{name}", timeout=20)
    if not version:
        version = (info.get("dist-tags") or {}).get("latest")
        if not version:
            raise RuntimeError("no latest version")
    versions = info.get("versions") or {}
    meta = versions.get(version)
    if not meta:
        raise RuntimeError(f"version {version} not found")
    tarball_url = (meta.get("dist") or {}).get("tarball")
    if not tarball_url:
        raise RuntimeError("no tarball url")
    tmp = Path(tempfile.mkdtemp(prefix="magisentry_npm_"))
    archive = tmp / Path(tarball_url).name
    archive.write_bytes(http_get_bytes(tarball_url, timeout=120))
    return archive


def run(ecosystem, package, config, t, ctx):
    try:
        archive = _pip_download(package) if ecosystem == "pip" else _npm_download(package)
    except (RuntimeError, urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, OSError, subprocess.TimeoutExpired) as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step4_failure_download", package=package),
            possible_cause=t.t("step4_cause_download") + " " + str(e)[:200],
            recommendation=t.t("step4_recommend_download"),
            can_retry=True,
        )

    extracted = archive.parent / "_extracted"
    extracted.mkdir(exist_ok=True)
    try:
        _extract(archive, extracted)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
        return StepResult(
            status="FAILURE", step=STEP,
            message=t.t("step4_failure_download", package=package),
            possible_cause=t.t("step4_cause_download") + " " + str(e)[:200],
            recommendation=t.t("step4_recommend_download"),
            can_retry=True,
        )

    ctx["archive"] = archive
    ctx["extracted"] = extracted
    return StepResult(status="OK", step=STEP)
