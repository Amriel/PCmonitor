@echo off
rem ============================================================
rem  PC Monitor - stop the background collector cleanly.
rem  Asks the collector to quit via its API (with the session
rem  token from data\session.token), waits for it to flush the
rem  database, and only force-kills as a last resort.
rem ============================================================
setlocal
cd /d "%~dp0"

set "PY="
where py  >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )

set "GRACEFUL=0"
if defined PY (
  %PY% stopmon.py && set "GRACEFUL=1"
)

if "%GRACEFUL%"=="0" (
  echo  Graceful stop failed - closing by force:
  rem The headless collector has no window, so a window-title filter would
  rem miss it. Match by command line instead: only processes running
  rem monitor.py from THIS folder are touched.
  powershell -NoProfile -NonInteractive -Command ^
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe' or Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*%~dp0monitor.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
)
echo  Done.
timeout /t 1 >nul
