@echo off
rem ============================================================
rem  PC Monitor - uninstall.
rem  Removes autostart and shortcuts. Collected data in data\
rem  is kept - delete that folder manually if you want it gone.
rem ============================================================
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" -Uninstall
if errorlevel 1 pause
