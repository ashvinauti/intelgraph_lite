@echo off
rem Double-click to start IntelGraph Lite: dashboard + live monitoring.
rem Opens http://127.0.0.1:8765 in your browser. Close this window to stop.
cd /d "%~dp0"
if not exist ".venv\Scripts\iglite.exe" (
  echo IntelGraph Lite is not installed yet. Run setup.ps1 first - see docs\WINDOWS_SETUP.md
  pause
  exit /b 1
)
".venv\Scripts\iglite.exe" serve --watch --open
pause
