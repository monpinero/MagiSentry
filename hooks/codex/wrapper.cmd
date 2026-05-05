@echo off
rem MagiSentry wrapper for Codex CLI (OpenAI) on Windows.
rem
rem Codex CLI executes shell commands directly. We rely on the universal
rem pip/npm shims (installed by `install_hooks.py --tool codex`) being first
rem on PATH. This wrapper additionally launches Codex with stricter shell
rem confirmation so a manual install attempt is visible to the user.
setlocal
set CODEX_CONFIRM_EXEC=1
where codex >nul 2>nul
if errorlevel 1 (
  echo MagiSentry: codex CLI not found on PATH. >&2
  exit /b 127
)
codex %*
exit /b %ERRORLEVEL%
