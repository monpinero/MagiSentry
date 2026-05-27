@echo off
rem MagiSentry shim for uv on Windows. Place its parent directory FIRST in PATH.
rem Intercepts `uv add`, `uv pip install`, `uv tool install`; passes through
rem every other `uv` subcommand (sync, run, build, lock, venv, ...).
python -m magisentry.shim uv %*
exit /b %ERRORLEVEL%
