@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title Build Chameleon release

echo ==================================================
echo   Building Chameleon  -  single-file release .exe
echo ==================================================
echo.

rem --- locate Python ---
set "PY="
for /f "delims=" %%P in ('where python 2^>nul') do if not defined PY set "PY=%%P"
if not defined PY if exist "C:\Program Files\Python312\python.exe" set "PY=C:\Program Files\Python312\python.exe"
if not defined PY (
  echo [ERROR] Python was not found on PATH.
  echo         Install Python 3.10+ ^(64-bit^) from python.org and re-run this script.
  echo.
  pause
  exit /b 1
)
echo Using Python: %PY%
echo.

rem --- ensure build + runtime dependencies ---
echo Installing/checking build dependencies (pyinstaller, frida, pywebview, pythonnet)...
"%PY%" -m pip install --quiet --disable-pip-version-check pyinstaller frida pywebview pythonnet
if errorlevel 1 (
  echo [ERROR] Dependency installation failed. Check your internet connection.
  echo.
  pause
  exit /b 1
)
echo.

rem --- build (dead modules excluded, --optimize 2, no UPX) ---
echo Building... this can take a few minutes.
echo.
"%PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name Chameleon ^
  --add-data "ui;ui" --add-data "engine/agent.js;engine" ^
  --collect-all frida --collect-all pythonnet --collect-all clr_loader --collect-all webview ^
  --exclude-module tkinter --exclude-module PyQt5 --exclude-module PyQt6 ^
  --exclude-module PySide2 --exclude-module PySide6 --exclude-module PIL ^
  --exclude-module numpy --exclude-module pandas --exclude-module scipy ^
  --exclude-module matplotlib --exclude-module IPython --exclude-module pytest ^
  --exclude-module notebook --exclude-module sqlite3 ^
  --exclude-module webview.platforms.gtk --exclude-module webview.platforms.qt ^
  --exclude-module webview.platforms.cocoa --exclude-module webview.platforms.android ^
  --optimize 2 app.py

if errorlevel 1 (
  echo.
  echo [ERROR] Build failed. Scroll up for the PyInstaller error.
  echo.
  pause
  exit /b 1
)

echo.
if exist "dist\Chameleon.exe" (
  for %%F in ("dist\Chameleon.exe") do set "SZB=%%~zF"
  set /a SZMB=SZB/1048576
  echo [OK] Build complete.
  echo      Output : "%~dp0dist\Chameleon.exe"  ^(~!SZMB! MB^)
  echo.
  echo Run it as Administrator. The Microsoft Edge WebView2 runtime must be
  echo installed on the target machine ^(present on Win11 / current Win10/Server^).
) else (
  echo [ERROR] Build reported success but dist\Chameleon.exe was not found.
)
echo.
pause
