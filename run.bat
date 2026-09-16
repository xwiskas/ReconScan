@echo off
REM ReconScan launcher for Windows. Double-click this file.
REM Any arguments are passed through, so you can also run:  run.bat --lan
setlocal

set "APPDIR=%~dp0app"

REM Find a Python. The py launcher is the reliable one on Windows; fall back to
REM whatever `python` resolves to for installs that skipped it.
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
  where python >nul 2>&1 && set "PY=python"
)

if not defined PY (
  echo.
  echo   ReconScan needs Python 3.11 or newer, and none was found on this machine.
  echo.
  echo   Install it from https://www.python.org/downloads/ and tick
  echo   "Add python.exe to PATH" during setup, then run this file again.
  echo.
  pause
  exit /b 1
)

echo Starting ReconScan...
%PY% "%APPDIR%\launch.py" %*
set "CODE=%ERRORLEVEL%"

REM Keep the window open on failure so the message is readable after a
REM double-click, which would otherwise close it instantly.
if not "%CODE%"=="0" (
  echo.
  echo   ReconScan exited with code %CODE%.
  pause
)
exit /b %CODE%
