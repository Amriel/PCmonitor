@echo off
rem ============================================================
rem  PC Monitor - run automatically at logon.
rem  Creates a Scheduled Task with highest privileges, so ETW
rem  (exact per-app network bytes + DNS) works automatically.
rem
rem  >>> RIGHT-CLICK this file and "Run as administrator" <<<
rem ============================================================
setlocal
cd /d "%~dp0"

rem --- must be admin to register a HIGHEST-privilege task ---
net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo  [!] Please run this file as administrator:
  echo      right-click autostart_enable.bat  ->  Run as administrator
  echo.
  pause
  exit /b 1
)

rem --- locate pythonw.exe (no console) ---
set "PYW="
for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do if not defined PYW set "PYW=%%i"
if not defined PYW (
  echo  [ERROR] pythonw.exe not found. Install Python 3 and run install.bat.
  pause
  exit /b 1
)

set "SCRIPT=%~dp0monitor.py"
set "TASK=PC Monitor"

schtasks /Create /F /TN "%TASK%" /SC ONLOGON /RL HIGHEST ^
  /TR "\"%PYW%\" \"%SCRIPT%\" --quiet"

if errorlevel 1 (
  echo  [ERROR] Could not create the scheduled task.
) else (
  echo.
  echo  [OK] "%TASK%" will now start automatically at logon (with admin rights).
  echo  Starting it now as well...
  schtasks /Run /TN "%TASK%" >nul 2>&1
  echo  Open the window with open.bat any time.
)
echo.
pause
