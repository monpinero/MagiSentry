@echo off
rem MagiSentry wrapper for Gemini CLI (Google) on Windows.
rem Like Codex, Gemini CLI runs shell commands directly. The universal
rem pip/npm shims do the heavy lifting; this wrapper just guarantees Gemini
rem runs in a shell where the shims are visible.
setlocal
where gemini >nul 2>nul
if errorlevel 1 (
  echo MagiSentry: gemini CLI not found on PATH. >&2
  exit /b 127
)
gemini %*
exit /b %ERRORLEVEL%
