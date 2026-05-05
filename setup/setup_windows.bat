@echo off
rem ============================================================
rem  MagiSentry - Windows installer
rem ============================================================
rem  1. Verifies Python is available.
rem  2. Installs MagiSentry in editable mode from the local source
rem     tree (the package is not yet on PyPI).
rem  3. Runs the setup wizard (language, mode, per-step opt-ins,
rem     VirusTotal key registration).
rem  4. Hands off to install_hooks.py for AI-tool integration.
rem ============================================================
setlocal ENABLEDELAYEDEXPANSION

echo.
echo === MagiSentry Windows installer ===
echo.

rem --- 0. Language choice (BEFORE any pip install) -----------------
rem Wizard reads MAGISENTRY_LANG and skips its own language prompt
rem when this is already set to en or sk.
echo Choose language / Zvolte jazyk:
echo [1] English
echo [2] Slovencina
echo.
choice /c 12 /n /m "Your choice / Vas vyber: "
if errorlevel 2 (set MAGISENTRY_LANG=sk) else (set MAGISENTRY_LANG=en)
echo.
echo Selected language: %MAGISENTRY_LANG%
echo.

rem --- 0b. Detect existing install --------------------------------
where magisentry >nul 2>&1
if %errorlevel% == 0 (
  echo.
  if "%MAGISENTRY_LANG%"=="sk" (
    echo MagiSentry je uz nainstalovany.
    echo [1] Preinstalovat / Aktualizovat
    echo [2] Odinstalovat
    echo [3] Zrusit
  ) else (
    echo MagiSentry is already installed.
    echo [1] Reinstall / Update
    echo [2] Uninstall
    echo [3] Cancel
  )
  echo.
  choice /c 123 /n /m "Your choice / Vas vyber: "
  if errorlevel 3 exit /b 0
  if errorlevel 2 (
    magisentry uninstall
    exit /b 0
  )
  rem errorlevel 1 = reinstall, fall through to pip install
)

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python is not on PATH. Install Python 3.8+ from https://python.org
  echo         and re-run this installer.
  exit /b 1
)

rem --- 1. Install in editable mode from local source ---------------
rem %~dp0 expands to the directory of this script (with trailing slash);
rem its parent is the project root that contains setup.py.
set "PROJECT_ROOT=%~dp0.."

if not exist "%PROJECT_ROOT%\setup.py" (
  echo [ERROR] setup.py not found at %PROJECT_ROOT%\setup.py
  echo         Run this script from inside a clone of the MagiSentry repo.
  exit /b 1
)

echo Installing MagiSentry in editable mode from local source...
echo   source: %PROJECT_ROOT%
python -m pip install --user --upgrade pip
python -m pip install --user -e "%PROJECT_ROOT%"
if errorlevel 1 (
  echo [ERROR] pip install -e failed. See output above.
  exit /b 1
)

rem --- 1b. Register Python user scripts dir on user PATH ----------
rem `pip install --user` drops magisentry.exe into a per-user scripts
rem dir that isn't on PATH by default. Without this, `magisentry`
rem won't be callable from a fresh terminal even though pip succeeded.
echo.
echo Registering PATH entries...
python -m magisentry._install_path
if errorlevel 1 (
  echo [WARN] PATH registration returned non-zero. You may need to add
  echo        the Python user scripts directory to PATH manually.
)

rem --- 2. First-run wizard ----------------------------------------
echo.
echo Launching the setup wizard...
python -m magisentry.scanner config --wizard
if errorlevel 1 (
  echo [WARN] Wizard exited with non-zero status. You can re-run it later via:
  echo        magisentry config --wizard
)

rem --- 3. Hook installation --------------------------------------
echo.
echo Installing AI-tool hooks (interactive)...
python -m magisentry.install_hooks --interactive
if errorlevel 1 (
  echo [WARN] Hook installer exited with non-zero status.
)

echo.
echo === Done. Open a NEW terminal, then try: magisentry pip install requests ===
echo.
endlocal
exit /b 0
