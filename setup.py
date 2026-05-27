"""MagiSentry — supply-chain security scanner for AI coding agents.

Installable via:
    pip install -e .          (editable, from a clone)
    pip install .             (regular, from a clone)
    pip install magisentry    (once published to PyPI)

Console entry-point `magisentry` invokes `magisentry.scanner:main`.
"""
from pathlib import Path
from setuptools import setup, find_packages

ROOT = Path(__file__).parent
README = ROOT / "README.md"
LONG_DESCRIPTION = README.read_text(encoding="utf-8") if README.exists() else (
    "MagiSentry — universal supply-chain security scanner that intercepts "
    "package installations across all major AI coding agents and IDEs. "
    "Scans Python (pip) and JavaScript (npm/yarn) packages through a "
    "10-step scanner before installation."
)

setup(
    name="magisentry",
    version="1.0.3",
    description="Supply-chain security scanner for AI coding agents (pip + npm)",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.8",

    # Discover magisentry, magisentry.steps, magisentry.hooks, magisentry.locales
    packages=find_packages(exclude=("tests", "tests.*", "docs", "hooks", "setup")),

    # Bundle locale JSON files alongside the code.
    package_data={
        "magisentry": [
            "locales/*.json",
            "rules/*.yar",
            "donation.json",
        ],
    },
    include_package_data=True,

    install_requires=[
        # Pinned to exact versions for v1.0.3 — supply-chain hygiene.
        # Bumping is a deliberate release-time decision, never an
        # accidental side-effect of `pip install -U`.
        "magika==1.0.3",
        "pip-audit>=2.7.0",
        # winotify is the Windows toast backend. The platform marker
        # ensures pip skips it on Linux / macOS (where notify-send and
        # osascript are used instead) — clean and safe everywhere.
        "winotify==1.1.0; sys_platform=='win32'",
    ],
    extras_require={
        # `core` is intentionally empty — provides a stable name for
        # `pip install -e ".[core]"` in the cross-platform setup scripts.
        "core": [],
        # Optional sub-steps. Without them the corresponding scan
        # returns FAILURE/no-retry so fail-secure mode prompts Skip.
        # semgrep 1.161.0 and earlier pin `tomli~=2.0.1`, which clashes
        # with pip-audit 2.7.0+'s `tomli>=2.2.1`. 1.162.0 bumped semgrep
        # to `tomli~=2.4.0` — first version that resolves cleanly.
        # Pinned to ==1.162.0: semgrep 1.163.0 contains a Windows RPC
        # bug (semgrep-core crashes with 'Expected a number, got \'\'')
        # that makes all registry-based --config calls fail. Bump only
        # after confirming the fix in the target version.
        # Reported upstream: github.com/semgrep/semgrep/issues
        "semgrep": ["semgrep==1.162.0"],
        "yara": ["yara-python==4.5.4"],
        "all": ["semgrep==1.162.0", "yara-python==4.5.4"],
    },

    entry_points={
        "console_scripts": [
            "magisentry = magisentry.scanner:main",
            "magisentry-install-hooks = magisentry.install_hooks:main",
            # Exposed as a console script so setup_windows.bat can call
            # it via the uv-installed isolated environment instead of
            # the system Python. No-op on Linux/macOS — kept here for
            # cross-platform parity, never invoked by the Unix setup
            # scripts.
            "magisentry-install-path = magisentry._install_path:main",
        ],
    },

    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="security supply-chain pip npm scanner ai-agents claude-code cursor",
)
