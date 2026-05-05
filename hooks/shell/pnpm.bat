@echo off
rem MagiSentry shim for pnpm on Windows. Place its parent directory FIRST in PATH.
python -m magisentry.shim pnpm %*
exit /b %ERRORLEVEL%
