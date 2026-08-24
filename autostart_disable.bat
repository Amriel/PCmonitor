@echo off
rem ============================================================
rem  PC Monitor - remove the "start at logon" scheduled task.
rem  Run as administrator (same as when you enabled it).
rem ============================================================
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo  [!] Please run as administrator.
  pause
  exit /b 1
)
schtasks /End    /TN "PC Monitor" >nul 2>&1
schtasks /Delete /F /TN "PC Monitor"
if errorlevel 1 (
  echo  [i] No autostart task was found (nothing to remove).
) else (
  echo  [OK] Autostart removed. The monitor will no longer start at logon.
  echo      (It may still be running now - use stop.bat to stop it.)
)
echo.
pause
