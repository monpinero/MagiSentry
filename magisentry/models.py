"""Core data structures: StepResult and Config."""
from dataclasses import dataclass, field, asdict
from typing import ClassVar, List, Dict, Optional, Literal

Status = Literal["OK", "THREAT", "FAILURE"]


@dataclass
class StepResult:
    status: Status
    step: str
    message: str = ""
    possible_cause: str = ""
    recommendation: str = ""
    can_retry: bool = True
    warnings: List[str] = field(default_factory=list)


@dataclass
class Config:
    mode: str = "failsafe"           # "failsafe" | "failsecure"
    language: str = "en"
    notifications: bool = True       # cross-platform desktop popup
    steps: Dict[str, bool] = field(default_factory=lambda: {
        # 7-step pre-install pipeline (run in order)
        "registry_check": True,
        "osv_check": True,
        "pip_audit": True,
        "isolated_download": True,
        "virustotal": True,
        "magika": True,
        "semgrep": False,           # step 7 sub-A — needs `semgrep` binary
        "yara": False,              # step 7 sub-B — needs `yara-python`
        # Standalone scans (triggered by their own ecosystem commands)
        "vscode_scan": True,
        "dockerfile_scan": True,
    })

    # Dependency update prompt state. `dep_skip` records versions the
    # user explicitly skipped — the menu won't re-offer them until a
    # newer release lands. `dep_remind` stores ISO-8601 timestamps; we
    # silence the menu for that pkg until `now >= dep_remind[pkg]`.
    dep_skip: Dict[str, str] = field(default_factory=dict)
    dep_remind: Dict[str, str] = field(default_factory=dict)

    # Legacy step keys → current keys. Loaded configs from before the
    # rename are migrated transparently in `from_dict`. Class-level so it
    # doesn't leak into `to_dict` / `asdict` output.
    LEGACY_KEY_MAP: ClassVar[Dict[str, str]] = {
        "step1": "registry_check",
        "step2": "osv_check",
        "step3": "pip_audit",
        "step4": "isolated_download",
        "step5": "virustotal",
        "step6": "magika",
        "step7": "semgrep",  # old step7 ran semgrep; yara stays default-off
    }

    @staticmethod
    def default() -> "Config":
        return Config()

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Config":
        cfg = Config.default()
        cfg.mode = d.get("mode", cfg.mode)
        cfg.language = d.get("language", cfg.language)
        cfg.notifications = bool(d.get("notifications", cfg.notifications))
        steps = d.get("steps") or {}
        for legacy, current in cfg.LEGACY_KEY_MAP.items():
            if legacy in steps:
                cfg.steps[current] = bool(steps[legacy])
        for k in cfg.steps:
            if k in steps:
                cfg.steps[k] = bool(steps[k])
        cfg.dep_skip = dict(d.get("dep_skip") or {})
        cfg.dep_remind = dict(d.get("dep_remind") or {})
        return cfg
