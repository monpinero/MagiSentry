@echo off
rem MagiSentry shim for pip on Windows. Place its parent directory FIRST in PATH.
python -m magisentry.shim pip %*
exit /b %ERRORLEVEL%
