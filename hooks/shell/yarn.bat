@echo off
rem MagiSentry shim for yarn on Windows. Place its parent directory FIRST in PATH.
python -m magisentry.shim yarn %*
exit /b %ERRORLEVEL%
