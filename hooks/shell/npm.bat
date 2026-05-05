@echo off
rem MagiSentry shim for npm on Windows. Place its parent directory FIRST in PATH.
python -m magisentry.shim npm %*
exit /b %ERRORLEVEL%
