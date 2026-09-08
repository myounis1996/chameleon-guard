@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
  python "%~dp0app.py"
) else (
  "C:\Program Files\Python312\python.exe" "%~dp0app.py"
)
if %errorlevel% neq 0 pause
