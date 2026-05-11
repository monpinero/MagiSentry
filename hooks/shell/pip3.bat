@echo off
rem MagiSentry shim for pip3 on Windows.
python -m magisentry.shim pip %*
exit /b %ERRORLEVEL%
