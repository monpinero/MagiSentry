# MagiSentry — Hooks Guide

This guide covers how MagiSentry integrates with each supported AI coding
agent. The general idea is the same for every tool:

> **Goal:** every `pip install` / `npm install` / `yarn add` triggered by an
> AI agent — no matter the tool — must pass through the 7-layer scan first.

There are two layers of defence, and **both** are installed by
`python -m magisentry.install_hooks`:

| Layer | What it is | Catches |
|------|-----------|---------|
| **Tool-specific hook / rule** | A config file the agent natively respects (e.g. Claude Code's `PreToolUse` hook, Cursor's `.cursor/rules`). | The agent itself, when it follows its config. Cleanest UX. |
| **Universal shell shim** | A `pip.bat` / `pip.sh` (and `npm`, `yarn`, `pnpm`) placed first on `PATH`. | Anything that runs `pip install ...` in a shell, including agents that ignore their own rules. |

If a tool offers a real pre-tool hook (Claude Code), the hook is the primary
mechanism and the shim is a backstop. For tools without a real hook, the
shim is the *only* hard guarantee and the rules file is just UX polish.

---

## Quick start (Windows)

```bat
:: From a clone:
setup\setup_windows.bat

:: Or, after pip install magisentry:
python -m magisentry.install_hooks --interactive
```

The interactive installer asks per-tool. Pick the ones you use; the universal
shell shim is installed automatically as a backstop.

After installation, **open a new terminal** so the PATH change is visible.

---

## Per-tool integration

### Claude Code (Anthropic)

- Native `PreToolUse` hook: ✅
- Config: `.claude/settings.json` (project) or `~/.claude/settings.json` (global)
- File: [hooks/claude_code/settings.json](../hooks/claude_code/settings.json)
- Guard: `python -m magisentry.hooks.claude_code_guard` — reads the tool-call
  payload from stdin, runs the scanner, exits 2 to block.

### Cursor (Anysphere)

- Native pre-tool hook: ❌ (rules-based)
- Config: `.cursor/rules`
- File: [hooks/cursor/rules](../hooks/cursor/rules)
- Hard guarantee comes from the shell shim.

### Windsurf (Cognition)

- Native pre-tool hook: ❌
- Config: `.windsurf/rules`
- File: [hooks/windsurf/rules](../hooks/windsurf/rules)
- Hard guarantee comes from the shell shim.

### GitHub Copilot

- Native pre-tool hook: ❌
- Config: VS Code `.vscode/tasks.json` provides scanned-install tasks.
- File: [hooks/copilot/tasks.json](../hooks/copilot/tasks.json)
- Hard guarantee comes from the shell shim.

### Continue.dev

- Native pre-tool hook: ❌ (custom commands + rules)
- Config: `~/.continue/config.json`
- File: [hooks/continue/config.json](../hooks/continue/config.json)
- Adds a `/magisentry` slash-command and rules instructing the agent to use it.
- Hard guarantee comes from the shell shim.

### Cline

- Native pre-tool hook: ❌
- Config: VS Code `.vscode/tasks.json`
- File: [hooks/cline/tasks.json](../hooks/cline/tasks.json)
- Hard guarantee comes from the shell shim.

### Aider

- Native pre-tool hook: ❌
- Config: `.aider.conf.yml` in the project root
- File: [hooks/aider/.aider.conf.yml](../hooks/aider/.aider.conf.yml)
- Disables `auto-commits` and `dirty-commits` so a bypassed install can't be
  silently committed.
- Hard guarantee comes from the shell shim.

### Codex CLI (OpenAI)

- Native pre-tool hook: ❌
- Wrapper script: [hooks/codex/wrapper.cmd](../hooks/codex/wrapper.cmd) /
  [wrapper.sh](../hooks/codex/wrapper.sh) — runs `codex` with
  `CODEX_CONFIRM_EXEC=1` so any shell command requires your approval.
- Hard guarantee comes from the shell shim.

### Gemini CLI (Google)

- Native pre-tool hook: ❌
- Wrapper script: [hooks/gemini_cli/wrapper.cmd](../hooks/gemini_cli/wrapper.cmd) /
  [wrapper.sh](../hooks/gemini_cli/wrapper.sh)
- Hard guarantee comes from the shell shim.

---

## Universal shell shim

Located in `~/.magisentry/bin/` after install. Contains:

- `pip.bat` / `pip.sh`
- `npm.bat` / `npm.sh`
- `yarn.bat` / `yarn.sh`
- `pnpm.bat` / `pnpm.sh`

Each shim calls `python -m magisentry.shim <ecosystem> <args>`, which:

1. Parses the args. If it's an `install` / `add` / `i`, route through the
   scanner. Exit 2 → block. Exit 0 → fall through and exec the *real*
   `pip` / `npm` / `yarn` with the same args.
2. Otherwise (e.g. `pip list`, `npm test`) → exec the real binary
   transparently with no scanning.

The shim avoids infinite recursion by skipping its own directory when looking
up the real binary on PATH.

---

## requirements.txt

`magisentry pip install -r requirements.txt` is fully supported. The hook
parser recognises `-r FILE` and `--requirement=FILE`, reads the file
line by line (recursively expanding nested `-r other.txt`), and runs the
full 7-layer scan against each non-comment, non-local-path entry.

This catches a common attack vector: a malicious package buried inside a
requirements file that the user hasn't read.

Comments (`#`), environment markers (`pkg; python_version>="3.10"`), and
extras (`pkg[extra]==1.0`) are normalised away before scanning.

Skipped (out of scope for registry scanning): `-e`/`--editable`, local paths,
URLs, VCS specs (`git+https://...`), constraints files (`-c`).

---

## LM Studio

LM Studio runs models locally but has no built-in coding-agent loop or shell
execution. To benefit from MagiSentry, you need an **agent layer** that
talks to LM Studio and is itself one of the supported tools. Recommended:

- **Continue.dev** — point its model config at LM Studio's OpenAI-compatible
  endpoint (`http://localhost:1234/v1`). Then install the Continue hook:
  `python -m magisentry.install_hooks --tool continue`.
- **Cline** — same setup, install the Cline hook:
  `python -m magisentry.install_hooks --tool cline`.

LM Studio on its own is **not** in scope for MagiSentry hooks because it
does not initiate package installs. Any install your local model suggests
will be executed by the agent layer (Continue / Cline), and that's where the
hook lives.

---

## Verifying the install

```bat
:: Should run the full 7-layer scan, not raw pip:
pip install requests

:: Should block on CVE:
pip install urllib3==1.24.1
```

If `pip install` runs without the MagiSentry banner appearing, the shim
isn't first on PATH. Run `where pip` (Windows) / `which pip` (Linux/macOS)
— the first hit must be `~/.magisentry/bin/pip.bat` (or `.sh`).
