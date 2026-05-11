@echo off
rem MagiSentry shim for python. Intercepts 'python -m pip install'.
if "%1"=="-m" if "%2"=="pip" (
    python -m magisentry.shim pip %3 %4 %5 %6 %7 %8 %9
    exit /b %ERRORLEVEL%
)
rem Not a pip call — find real python (skip our shim dir).
for %%D in ("%PATH:;=";"%") do (
    if /I not "%%~D"=="%~dp0" (
        if exist "%%~D\python.exe" (
            "%%~D\python.exe" %*
            exit /b %ERRORLEVEL%
        )
    )
)
echo magisentry: real python not found on PATH 1>&2
exit /b 127
