@echo off
rem ============================================================
rem  PC Monitor - installer launcher.
rem  Just double-click this file. Everything else is automatic:
rem  it asks for admin rights ONCE, installs, sets up autostart
rem  and creates shortcuts. No console windows afterwards.
rem ============================================================
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
if errorlevel 1 pause
