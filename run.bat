@echo off
rem ============================================================
rem  PC Monitor - start with a visible console window.
rem  Good for the first run: you can see logs and confirm ETW.
rem
rem  TIP: for full network stats (exact bytes per app + DNS),
rem  right-click this file and choose "Run as administrator".
rem  Without admin it still works, just without exact byte counts.
rem ============================================================
setlocal
cd /d "%~dp0"

set "PY="
where py  >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo  [ERROR] Python not found. Run install.bat first.
  pause
  exit /b 1
)

echo  Starting PC Monitor...  (close this window or press Ctrl+C to stop)
%PY% monitor.py
pause
