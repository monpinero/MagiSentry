@echo off
rem ============================================================
rem  MagiSentry - Windows installer (uv tool, v1.0.3+)
rem ============================================================
rem  1. Detect uv; bootstrap it via the official installer if missing.
rem  2. Migrate any pre-existing `pip install --user` deployment to uv.
rem  3. `uv tool install --editable .` from the local clone so dev
rem     changes propagate without reinstalling.
rem  4. Register ~/.magisentry/bin on PATH (for the shell shims).
rem  5. Run the setup wizard and the AI-tool hook installer.
rem  6. Build the initial integrity manifest.
rem ============================================================

rem Switch CMD to UTF-8 so Slovak characters render correctly.
chcp 65001 >nul

setlocal ENABLEDELAYEDEXPANSION

echo.
echo === MagiSentry Windows installer ===
echo.

rem --- 0. Language choice (BEFORE any installation work) -----------
echo Choose language / Zvolte jazyk:
echo [1] English
echo [2] Slovencina
echo.
choice /c 12 /n /m "Your choice / Vas vyber: "
if errorlevel 2 (set MAGISENTRY_LANG=sk) else (set MAGISENTRY_LANG=en)
echo.
echo Selected language: %MAGISENTRY_LANG%
echo.

rem --- 0b. Auto-detect + Action menu ------------------------------
rem Ak MagiSentry nie je nainstalovana - preskoc menu, instaluj.
rem Ak je nainstalovana - ponukni iba Odinstalovat alebo Zrusit.
rem Reinstal nie je v menu (bezpecnostny dovod: uv tool install
rem vzdy re-resolvuje celu izolaciu - potencialny vektor utoku).
rem Zmena nastaveni: magisentry config --wizard
set "MAGI_INSTALLED=0"
if exist "%APPDATA%\uv\tools\magisentry\Scripts\magisentry.exe" (
  set "MAGI_INSTALLED=1"
)

set "ACTION=1"
if "%MAGI_INSTALLED%"=="1" (
  if "%MAGISENTRY_LANG%"=="sk" (
    echo MagiSentry je uz nainstalovana.
    echo.
    echo [1] Odinstalovat
    echo [2] Zrusit
  ) else (
    echo MagiSentry is already installed.
    echo.
    echo [1] Uninstall
    echo [2] Cancel
  )
  echo.
  choice /c 12 /n /m "Your choice / Vas vyber: "
  set "ACTION=!errorlevel!"
  echo.
  if "!ACTION!"=="2" (
    if "%MAGISENTRY_LANG%"=="sk" (
      echo Zrusene. Nastavenia zmenite cez: magisentry config --wizard
    ) else (
      echo Cancelled. Change settings via: magisentry config --wizard
    )
    echo.
    pause >nul
    endlocal
    exit /b 0
  )
  rem When installed, [1] means Uninstall. Remap to action 3 so the
  rem existing uninstall path below handles it.
  set "ACTION=3"
) else (
  if "%MAGISENTRY_LANG%"=="sk" (
    echo MagiSentry nie je nainstalovana. Spustam instalaciu...
  ) else (
    echo MagiSentry not installed. Starting fresh installation...
  )
  echo.
)

rem --- 0c. Uninstall path -----------------------------------------
if "%ACTION%"=="3" (
  echo Uninstalling MagiSentry / Odinstalujem MagiSentry...
  rem Refresh PATH for this session so magisentry-install-hooks
  rem resolves to the uv tool deployment we're about to remove.
  rem Without this the next line would either not find the entry
  rem point or pick up a stale one from somewhere else.
  set "PATH=%APPDATA%\uv\tools\magisentry\Scripts;%PATH%"
  rem Clean up AI-tool hook entries BEFORE removing the binary —
  rem once magisentry-install-hooks is gone we can't run it.
  if "%MAGISENTRY_LANG%"=="sk" (
    echo Odstranujem AI-tool hooky...
  ) else (
    echo Removing AI-tool hooks...
  )
  magisentry-install-hooks --uninstall --all 2>nul
  rem Kill any running magisentry.exe — uv can't replace a locked
  rem binary on Windows, so this prevents the next install from
  rem hitting "file in use".
  taskkill /f /im magisentry.exe >nul 2>&1
  uv tool uninstall magisentry >nul 2>&1
  rem Fallback for installations that pre-date the uv migration —
  rem `pip uninstall` is a no-op if the package isn't there.
  python -m pip uninstall magisentry -y >nul 2>&1
  rem Clean up config + shim directory left by MagiSentry. Without
  rem this, a fresh reinstall would inherit stale ~/.magisentry/
  rem contents (config.json, integrity_manifest, shim batch files)
  rem and the "uninstall" wouldn't really feel uninstalled.
  if exist "%USERPROFILE%\.magisentry" (
    rmdir /s /q "%USERPROFILE%\.magisentry"
    if "%MAGISENTRY_LANG%"=="sk" (
      echo Konfiguracny priecinok vymazany.
    ) else (
      echo Config directory removed.
    )
  )
  if "%MAGISENTRY_LANG%"=="sk" (
    echo MagiSentry odinstalovana.
  ) else (
    echo MagiSentry uninstalled.
  )
  echo.
  pause >nul
  endlocal
  exit /b 0
)

rem --- 1. Ensure uv is present ------------------------------------
where uv >nul 2>nul
if errorlevel 1 (
  echo uv not found. Installing via the official installer...
  powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://astral.sh/uv/install.ps1 | iex"
  if errorlevel 1 (
    echo [ERROR] uv install failed. Install uv manually from https://astral.sh/uv/ and re-run.
    exit /b 1
  )
  rem The uv installer drops `uv.exe` into %USERPROFILE%\.local\bin and
  rem updates user PATH for new terminals, but the *current* CMD process
  rem still has the old PATH. Prepend the install dir so `uv` resolves
  rem immediately in this very session.
  set "PATH=%USERPROFILE%\.local\bin;%PATH%"
)

where uv >nul 2>nul
if errorlevel 1 (
  echo [ERROR] uv still not on PATH after install. Open a NEW terminal and re-run.
  exit /b 1
)
echo uv detected:
uv --version

rem --- 2a. Pre-install cleanup ------------------------------------
rem Fresh install: vzdy --force pre cistu izolaciu.
echo Preparing clean isolation...
taskkill /f /im magisentry.exe >nul 2>&1
uv tool uninstall magisentry >nul 2>&1

rem --- 2b. Migrate any pre-existing pip install -------------------
set "PIP_MAGI="
where magisentry >nul 2>nul
if not errorlevel 1 (
  for /f "delims=" %%P in ('where magisentry') do (
    echo %%P | findstr /I "\\uv\\" >nul
    if errorlevel 1 set "PIP_MAGI=%%P"
  )
)
if defined PIP_MAGI (
  echo Found existing pip installation. Migrating...
  python -m pip uninstall magisentry -y >nul 2>&1
  if exist "%USERPROFILE%\.magisentry\bin" (
    del /q "%USERPROFILE%\.magisentry\bin\*.bat" 2>nul
  )
) else (
  echo Fresh installation detected.
)

rem --- 3. Locate project root -------------------------------------
set "PROJECT_ROOT=%~dp0.."

if not exist "%PROJECT_ROOT%\setup.py" (
  echo [ERROR] setup.py not found at %PROJECT_ROOT%\setup.py
  echo         Run this script from inside a clone of the MagiSentry repo.
  exit /b 1
)

rem --- 4. Install via uv tool (editable from local clone) ---------
echo.
echo Installing MagiSentry via uv tool ^(editable from local clone^)...
echo   source: %PROJECT_ROOT%
uv tool install --force --editable "%PROJECT_ROOT%"
if errorlevel 1 (
  echo [ERROR] uv tool install failed. See output above.
  exit /b 1
)

rem --- 4b. Refresh PATH for this session --------------------------
rem `uv tool install` registered its bin dir on the user PATH for new
rem terminals, but this CMD process still has the old PATH. Prepend
rem the uv tool bin directory so the `magisentry` / `magisentry-install-hooks`
rem entry points resolve in this very session — without this, the
rem subsequent calls would fall through to the legacy pip install (or
rem fail with "not recognized") instead of the new uv-isolated copy.
rem uv ukladá tool izolácie do %APPDATA%\uv\tools\ (Roaming), NIE
rem do %LOCALAPPDATA%. platformdirs::user_data_dir na Windows = APPDATA.
set "PATH=%USERPROFILE%\.local\bin;%APPDATA%\uv\tools\magisentry\Scripts;%PATH%"

rem --- 5. Register ~/.magisentry/bin on PATH ----------------------
echo.
echo Registering PATH entries...
magisentry-install-path
if errorlevel 1 (
  echo [WARN] PATH registration returned non-zero. You may need to add
  echo        %USERPROFILE%\.magisentry\bin to PATH manually.
)

rem --- 6. First-run wizard ----------------------------------------
echo.
echo Launching the setup wizard...
magisentry config --wizard --mode=fresh
if errorlevel 1 (
  echo [WARN] Wizard exited with non-zero status. Re-run:
  echo        magisentry config --wizard
)

rem --- 7. Hook installation --------------------------------------
echo.
echo Installing AI-tool hooks (interactive)...
magisentry-install-hooks --interactive
if errorlevel 1 (
  echo [WARN] Hook installer exited with non-zero status.
)

rem --- 8. Build initial integrity manifest ------------------------
echo.
echo Building initial integrity manifest...
magisentry integrity update --yes
if errorlevel 1 (
  echo [WARN] Integrity manifest build returned non-zero status.
)

echo.
echo === Done. Open a NEW terminal, then try: magisentry pip install requests ===
echo.
echo Inštalácia dokončená. Stlač ľubovoľnú klávesu pre zatvorenie...
pause >nul
endlocal
exit /b 0
