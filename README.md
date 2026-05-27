# 🛡️ MagiSentry

**Supply chain security scanner for AI coding agents.**  
Automatically scans Python (pip), JavaScript (npm/yarn), VS Code extensions and Dockerfiles through a 10-step scanner *before* anything is installed or built — so your AI agent can't be tricked into running malicious code.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/monpinero/MagiSentry/blob/main/LICENSE)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/monpinero/MagiSentry)
[![i18n: EN | SK](https://img.shields.io/badge/i18n-EN%20%7C%20SK-orange.svg)](https://github.com/monpinero/MagiSentry)
[![CI](https://github.com/monpinero/magisentry/actions/workflows/ci.yml/badge.svg)](https://github.com/monpinero/magisentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/magisentry.svg)](https://pypi.org/project/magisentry/)

[🇸🇰 Slovenská verzia](README.SK.md)

> [!WARNING]
> MagiSentry works by intercepting `pip` and `npm` commands. AI coding agents may attempt to bypass this protection.
> **Add this to your AI agent's system prompt or instructions file:**
> ```
> Always use `magisentry pip install` and `magisentry npm install`
> instead of calling pip or npm directly. Never modify MagiSentry
> configuration, settings, or source files without explicit user confirmation.
> ```

---

## About

I'm not a developer. I don't know Python, JavaScript, or any programming language. I'm an AI enthusiast who got curious about one question: when an AI coding agent runs `pip install`, does anyone actually check what gets installed?

I started digging. What I found was unsettling — supply chain attacks on open source packages are real, frequent, and growing fast. And AI agents are the perfect target: they install packages automatically, at speed, without asking questions.

The idea crystallised when I came across Magika — Google's open-source file-type detection engine. I realised it could be the foundation of something more: a scanner that intercepts packages before they reach an AI agent's environment. That insight became MagiSentry. The name reflects its origins — Magika at the core, Sentry as its purpose: a watchful guardian that checks what your AI agent is about to install.

Built with AI assistance, from scratch, with no prior coding experience. The code works. It's tested. It runs locally. And now it's here for anyone who wants it.

---

## Why MagiSentry?

### The threat is no longer hypothetical — it is accelerating

Supply chain attacks against open source registries (PyPI, npm, Docker Hub) have shifted from isolated incidents to a **sustained, industrialised campaign** targeting software developers across every major package registry and IDE extension marketplace simultaneously.

The numbers back this up:

- In 2025, attackers published **454,648 malicious npm packages** — nearly half a million in a single year (Sonatype, 2026)
- Across npm, PyPI, and Maven Central, new malicious packages rose **188% year-over-year**, surpassing 845,000 total (Sonatype, 2026)
- The average npm project pulls in **79 transitive dependencies** — a single compromised package can cascade through entire ecosystems within hours

The pattern is consistent: attackers gain access to a trusted maintainer account, inject malicious code into an official release, and distribute it through the same registries and CI/CD pipelines that development teams trust every day. The malicious version looks authentic because it comes through authentic channels.

### A timeline of real incidents

**September 8, 2025 — `debug` and `chalk` (npm)**
A maintainer of two of the most widely downloaded Node.js libraries was phished through a convincing fake 2FA reset email. The attacker published malicious versions of `debug`, `chalk`, and 16 related packages. These libraries collectively have **billions of weekly downloads**. The compromised versions were live for only ~2 hours — but that was enough for many production builds to pull them in automatically.

**March 24, 2026 — LiteLLM (PyPI) — TeamPCP campaign**
Malicious versions 1.82.7 and 1.82.8 of `litellm` — a Python LLM proxy library with millions of daily downloads — were published directly to PyPI, bypassing the project's normal GitHub-based release process. The payload harvested cloud credentials, API keys, and CI/CD secrets. The same TeamPCP threat group also compromised **Checkmarx** and **Trivy** — a security scanner running inside CI pipelines specifically to find vulnerabilities — which was then used as the delivery mechanism for credential-stealing malware across thousands of workflows.

**January–March 2026 — Glassworm campaign**
A coordinated malware campaign simultaneously targeted **OpenVSX, VS Code Marketplace, npm, and PyPI**. Compromised React Native npm packages were weaponised to deliver multi-stage malware using the Solana blockchain as a command-and-control channel, stealing developer credentials and crypto wallet data.

**April 21–23, 2026 — Three attacks in 48 hours**
Three distinct supply chain campaigns hit npm, PyPI, and Docker Hub within a single 48-hour window. The `CanisterSprawl` npm worm self-propagated by searching for npm publish tokens on infected machines and re-publishing itself; if a PyPI token was also found, it jumped ecosystems entirely. All three campaigns shared one objective: stealing API keys, cloud credentials, SSH keys, and CI/CD tokens from developer environments.

### Why AI coding agents make this worse

AI agents (`pip install`, `npm install`) act on instructions without manually reviewing what they install. They operate at speed, across many packages, often in CI environments with broad access to secrets. They are the ideal vector for a supply chain attack — high throughput, low human oversight, access to credentials.

### Why antivirus isn't enough

Antivirus scans files after the fact. MagiSentry intercepts before execution.

---

## How It Works

### Pipeline — runs automatically on every `pip install` / `npm install`

Every package passes through all 8 steps in sequence. A technical failure in any step is non-blocking by default (Fail Safe mode). A detected **threat** blocks the installation and waits for your confirmation.

| Step | Name | Tool |
|---|---|---|
| 1 | Registry metadata check | urllib (stdlib) |
| 2 | Known vulnerability check | OSV / osv.dev |
| 3 | Recursive dependency audit | pip-audit |
| 4 | Isolated download | pip download / npm pack |
| 5 | Hash reputation check | VirusTotal API |
| 6 | File-type verification | Magika (Google, local) |
| 7 | Static code analysis | Semgrep (local, optional) |
| 8 | Pattern matching | YARA (local, optional) |

### Standalone scanners — triggered automatically via hooks

| Scanner | Tool |
|---|---|
| VS Code extension scan | Open VSX + Marketplace + VT |
| Dockerfile analysis | local |
| Integrity check | local |

See [Usage](#usage) for commands.

These scanners activate automatically when your AI agent runs `code --install-extension` or `docker build` — no manual step needed.

---

## Supported AI Coding Tools

MagiSentry wraps the package manager command so that your AI agent's install requests are automatically intercepted — no changes to the agent needed.

| Tool | Integration type | Works out of the box |
|---|---|---|
| **Claude Code** | CLI wrapper | ✅ |
| **Cursor** | Terminal command override | ✅ |
| **Windsurf** | Terminal command override | ✅ |
| **Aider** | Pre-command hook | ✅ |
| **GitHub Copilot** | Terminal command override | ✅ |
| **Continue.dev** | Terminal command override | ✅ |
| **Cline** | Pre-command hook | ✅ |
| **Codex CLI** | CLI wrapper | ✅ |
| **Gemini CLI** | CLI wrapper | ✅ |

> Any tool that runs `pip install`, `npm install`, `magisentry vscode install`, or `magisentry docker build` in a terminal will be intercepted automatically once MagiSentry is set up.

### Additional protection — dangerous command blocking

MagiSentry intercepts shell commands that attempt to download and execute payloads outside of package managers.

> Details intentionally omitted.

### Warnings visible in all AI tools

MagiSentry outputs structured warnings to **stderr**, which means threat alerts appear directly in the interface of every supported AI coding tool — not just in the terminal. Claude Code, Cursor, Windsurf, Aider, Continue.dev, Cline and others all surface stderr output inline. Your agent sees the warning the same moment you do.

---

## Installation

**Requirements:** Python 3.8+, [uv](https://astral.sh/uv/), Git, Windows / Linux / macOS

**Quickstart (PyPI):**
```bash
pip install uv          # if uv is not installed yet
uv tool install magisentry
magisentry-install-hooks
```

`uv tool install` puts MagiSentry into its own isolated environment. Other `pip install` / `uv add` invocations on the same machine can never collide with MagiSentry's dependency pins (e.g. `magika==1.0.3`).

> **First-install bootstrap note**
> The very first install of `uv` itself and of MagiSentry is *not* scanned — a security tool cannot scan its own bootstrap. This is expected. Every subsequent install on the machine is protected.

> For the full setup (PATH integration, per-tool hooks, integrity manifest), use the platform setup scripts below.

```bash
# 1. Clone the repository
git clone https://github.com/monpinero/magisentry.git
cd magisentry
```

**Windows**
```bat
setup_windows.bat
setx VT_API_KEY "your_api_key_here"
```

**Linux / WSL**
```bash
chmod +x setup_linux.sh && ./setup_linux.sh
echo 'export VT_API_KEY="your_api_key_here"' >> ~/.bashrc && source ~/.bashrc
```

**macOS**
```bash
chmod +x setup_mac.sh && ./setup_mac.sh
echo 'export VT_API_KEY="your_api_key_here"' >> ~/.zshrc && source ~/.zshrc
```

Each setup script bootstraps `uv` if missing, migrates any prior `pip install --user` deployment to an isolated uv tool environment, installs MagiSentry from the local clone in editable mode (`uv tool install --editable .`), and registers the `magisentry` command in your PATH.

> **No VirusTotal key?** The scanner still works — Step 5 is skipped with a warning. All other steps remain fully functional.

> **VirusTotal free API** is intended for personal, non-commercial use. MagiSentry qualifies — it is a free, open-source tool for individual developers. Limit: 500 lookups/day, 4 requests/min.
> [Free registration → virustotal.com](https://www.virustotal.com)

### Optional extras

Install only what you need:

```bash
uv tool install "magisentry[semgrep]"   # Step 7 — static code analysis (Python 3.10+)
uv tool install "magisentry[yara]"      # Step 8 — pattern matching
uv tool install "magisentry[all]"       # everything
```

> Desktop notifications work automatically on all platforms — no extra install needed.

> If you installed via git clone, run these from the cloned directory.

> **Note:** MagiSentry pins semgrep to a tested version (`==1.162.0`).
> semgrep 1.163.0 contains a Windows RPC bug — if the wizard offers
> a semgrep update, decline it until the next MagiSentry release.

### Changing settings after installation

To change settings (enable/disable steps, update API key, change language) run the wizard directly:

```bash
magisentry config --wizard
```

Reinstall via the setup script is intentionally not available. Re-running the setup script on an already-installed system offers only **[1] Uninstall** and **[2] Cancel** — this protects the isolated environment from unintended dependency changes. For manual updates: `uv tool upgrade magisentry`.

---

## Usage

### Packages — pip
```bash
magisentry pip install requests
magisentry pip install "numpy==1.26.4"
magisentry pip install -r requirements.txt
```

> `pip3` and `python -m pip install` are also intercepted automatically.

### Packages — uv
```bash
magisentry uv add requests
magisentry uv pip install "numpy==1.26.4"
magisentry uv tool install ruff
```

> `uv add`, `uv pip install`, `uv tool install`, and `uvx install` are intercepted automatically. Non-install sub-commands (`uv sync`, `uv run`, `uv build`, `uv lock`, `uv venv`, ...) pass through without scanning.

### Running manually in PowerShell

If you are not using an AI coding agent, you can run MagiSentry directly in PowerShell before installing any package:

```bash
magisentry pip install requests
magisentry pip install "numpy==1.26.4"
magisentry pip install -r requirements.txt
```

This is the same command the hook sends automatically when Claude Code or another agent runs pip install — you are just calling it yourself. The full 10-step pipeline runs identically either way.

> **Tip:** Open a new PowerShell window after installation to make sure the magisentry command is available on PATH.

### Packages — npm / yarn
```bash
magisentry npm install lodash
magisentry yarn add axios
magisentry npm install              # scans full package.json
```

### Local archives — pip
```bash
magisentry pip install ./package.whl
magisentry pip install ./package.tar.gz
```

Local archives (`.whl`, `.tar.gz`, `.zip`) are scanned through steps 3, 5, 6, 7, and 8. Local directories are skipped.

### VS Code extensions
```bash
magisentry vscode install publisher.extension-name
```

### Dockerfile
```bash
magisentry docker build .
```

### Audit entire project at once
```bash
magisentry audit
```

Scans all dependencies found in `pyproject.toml`, `requirements.txt`, and `package.json` in the current directory in a single pass. Useful before committing or deploying.

### Updates

MagiSentry checks for new versions on every run. When an update is available, it offers an interactive menu:

```
[1] Update with full scan (recommended)
[2] Update without scan
[3] Skip this version
[4] Remind me later
```

Option [1] scans the new version through the full pipeline before installing it — MagiSentry checks itself before it updates itself.

### Whitelist management
```bash
magisentry whitelist list
magisentry whitelist add pip:requests
magisentry whitelist add npm:lodash
magisentry whitelist remove pip:requests
```

### Integrity check
```bash
magisentry integrity update
```

Run this once after installation to initialise the integrity manifest, and again after modifying MagiSentry's own source files. The manifest is stored locally per machine.

### Uninstall

**Option 1 — command line (all platforms):**
```bash
magisentry uninstall
```

**Option 2 — via setup script (all platforms):**
```bash
# Windows
setup_windows.bat        # choose [1] Uninstall

# Linux
./setup_linux.sh         # choose [1] Uninstall

# macOS
./setup_mac.sh           # choose [1] Uninstall
```

Both options remove `~/.magisentry/` config directory, clean up hooks, PATH entries, and run `uv tool uninstall magisentry`.

### Optional dependencies

MagiSentry's optional scan components are not removed automatically. To uninstall them manually:

```bash
uv tool run --from magisentry pip uninstall semgrep     # Step 7 — static code analysis
uv tool run --from magisentry pip uninstall yara-python # Step 8 — pattern matching
```

Core dependencies (magika, pip-audit) are part of the isolated uv environment and are intentionally left in place. Remove them manually only if needed:

```bash
uv tool run --from magisentry pip uninstall magika pip-audit winotify
```

---

When a threat is detected, the terminal displays a clear report and waits for your confirmation before proceeding:

```
when retry is possible    (fail_safe)    →   [R] Retry   [S] Skip   [A] Abort
when retry is not possible (fail_secure) →               [S] Skip   [A] Abort
```

You can also whitelist a package to suppress future warnings:
```bash
magisentry whitelist add pip:package-name
```

---

## Known issues

### Semgrep — first scan after installation may fail

When semgrep runs for the first time, it downloads rulesets (`p/supply-chain`,
`p/secrets`) from the internet into a local cache. If the connection is slow
or the server does not respond in time, the scan fails with:

```
[7/8] Semgrep — static code analysis
  -> FAILURE: Semgrep crashed while processing input.
```

**Workaround:** Run the same scan again. The second run uses the cached
rulesets and completes normally.

### Semgrep 1.163.0 — broken on Windows

semgrep 1.163.0 contains a Windows RPC bug that causes step 7 to crash on
every scan. MagiSentry pins semgrep to `==1.162.0` which works correctly.

If the wizard offers a semgrep update, decline it (choose **[3] Skip this
version**) until the next MagiSentry release confirms compatibility.

---

## Configuration & Data

### Local data directory

MagiSentry stores all its data in a single directory:

```
~/.magisentry/
├── config.json       # scanner configuration
├── counters.json     # scan statistics
└── bin/              # shell wrappers that intercept pip/npm commands
```

Running `magisentry uninstall` removes this directory automatically on all platforms.

### Fail Safe vs. Fail Secure

MagiSentry runs in **Fail Safe** mode by default. You can change this in `config.json`:

| Mode | Behaviour on tool error |
|---|---|
| `fail_safe` (default) | If a scan step crashes or times out, installation continues |
| `fail_secure` | If any scan step fails for any reason, installation is blocked |

```json
{
  "mode": "fail_safe",
  "steps": {
    "registry_check": true,
    "osv_check": true,
    "pip_audit": true,
    "isolated_download": true,
    "virustotal": true,
    "magika": true,
    "semgrep": false,
    "yara": false,
    "vscode_scan": true,
    "dockerfile_scan": true
  }
}
```

Set any step to `false` to skip it entirely. Steps 7 and 8 are disabled by default — enable them after installing the corresponding extras.

---

## What MagiSentry Detects

> Details intentionally omitted.

---

## Privacy

MagiSentry is designed to minimise cloud data exposure:

- **VirusTotal (Step 5, VS Code scan):** Only a **64-character SHA-256 hash** is sent — never the file itself.
- **OSV (Step 2):** Only the package name and version number are sent.
- **PyPI / npm / VS Code Marketplace (Steps 1, VS Code scan):** Only the package or extension name is queried — same as a normal install.
- **Steps 4, 6, 7, 8** (Magika, Semgrep, YARA): Run entirely **offline on your machine**. No data leaves.

> No source code, no file contents, no credentials are ever transmitted to any external service.

---

## Tool Cost Summary

| Tool | Free? | API Key needed? | Offline? |
|---|---|---|---|
| PyPI / npm API | Always free | No | No |
| OSV (Google) | Always free | No | No |
| pip-audit | Always free | No | No |
| pip download / npm pack | Always free | No | No |
| VirusTotal | Free (500/day) | Yes — free registration | No |
| Magika (Google) | Always free | No | **Yes** |
| Semgrep | Free (basic) | No | **Yes** |
| YARA | Always free | No | **Yes** |
| VS Code Marketplace API | Always free | No | No |
| Dockerfile analysis | Always free | No | **Yes** |
| uv (Astral) | Always free | No | **Yes** |

---

## License

MIT — see [LICENSE](https://github.com/monpinero/MagiSentry/blob/main/LICENSE) for details.

---

## Support the project

If MagiSentry caught something before it could do damage, consider supporting the project:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/monpinero)

XMR: `48W5FXBSBecjG6ApZH5KEtYMKZxiGVkJhdbCjXWGj9Ahe6R58LpZvhqSWHoftZCAgWKDez3HQ3teAD8mEUEPHYhnHT6SusB`

---

*MagiSentry — because your AI agent deserves a security guard.*
