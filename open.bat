@echo off
rem ============================================================
rem  PC Monitor - open the app window.
rem  If the background collector is not running yet, it is
rem  started automatically first.
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

%PY% monitor.py --window
