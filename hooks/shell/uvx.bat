@echo off
rem MagiSentry shim for uvx on Windows. Place its parent directory FIRST in PATH.
rem Intercepts `uvx install`; passes through every other invocation.
python -m magisentry.shim uvx %*
exit /b %ERRORLEVEL%
