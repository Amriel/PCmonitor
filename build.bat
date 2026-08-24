@echo off
rem ============================================================
rem  PC Monitor - build PCMonitor.exe + installer in one go.
rem
rem  Steps:
rem   1. read VERSION from monitor.py
rem   2. politely stop a running monitor (files must be free)
rem   3. PyInstaller  -> dist\PCMonitor\PCMonitor.exe (onedir)
rem   4. Inno Setup   -> dist\PCMonitor-Setup-X.Y.Z.exe
rem   5. copy the setup into updates\ - the RUNNING app offers
rem      to install it from its Settings page.
rem
rem  Needs: Python 3, Inno Setup 6 (ISCC.exe).
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PY="
where py  >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo  [ERROR] Python not found.
  pause & exit /b 1
)

rem --- version from monitor.py (line: VERSION = "1.1.0") ---
set "VER="
for /f "tokens=2 delims== " %%v in ('findstr /b /c:"VERSION" monitor.py') do set "RAWV=%%v"
set "VER=%RAWV:"=%"
if not defined VER (
  echo  [ERROR] Could not read VERSION from monitor.py
  pause & exit /b 1
)
echo  Building PC Monitor %VER% ...

rem --- deps ---
%PY% -m pip install --upgrade pyinstaller --quiet
if errorlevel 1 ( echo  [ERROR] pip install pyinstaller failed & pause & exit /b 1 )
%PY% -m pip install -r requirements.txt --quiet

rem --- stop a running monitor so PyInstaller can write files ---
%PY% stopmon.py

rem --- exe ---
if exist build rmdir /s /q build
if exist dist\PCMonitor rmdir /s /q dist\PCMonitor
%PY% -m PyInstaller pcmon.spec --noconfirm
if errorlevel 1 ( echo  [ERROR] PyInstaller failed & pause & exit /b 1 )
if not exist "dist\PCMonitor\PCMonitor.exe" (
  echo  [ERROR] dist\PCMonitor\PCMonitor.exe not produced
  pause & exit /b 1
)
rem The build\ folder is PyInstaller's scratch space. It contains a copy of
rem the exe WITHOUT its DLLs - clicking it gives "Failed to load Python DLL".
rem Remove it so the only exe left is the working one in dist\.
rmdir /s /q build 2>nul

rem --- installer (Inno Setup 6) ---
set "ISCC="
if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (
  echo  [WARN] Inno Setup 6 not found - exe is ready, installer skipped.
  echo         dist\PCMonitor\PCMonitor.exe
  pause & exit /b 0
)

"%ISCC%" /Qp /DAppVer=%VER% installer.iss
if errorlevel 1 ( echo  [ERROR] Inno Setup failed & pause & exit /b 1 )

rem --- SHA-256 next to the installer: attach BOTH files to the GitHub
rem     release, and the app will verify the download against this hash ---
certutil -hashfile "dist\PCMonitor-Setup-%VER%.exe" SHA256 ^
  | findstr /r "^[0-9a-f][0-9a-f]*$" > "dist\PCMonitor-Setup-%VER%.exe.sha256"

rem --- drop into updates\ so the app can self-update from Settings ---
if not exist updates mkdir updates
copy /y "dist\PCMonitor-Setup-%VER%.exe" "updates\" >nul

echo.
echo  ============================================
echo   Done.
echo   App:       dist\PCMonitor\PCMonitor.exe
echo   Installer: dist\PCMonitor-Setup-%VER%.exe
echo   Checksum:  dist\PCMonitor-Setup-%VER%.exe.sha256
echo              (copied to updates\ - the app will
echo               offer it in Settings -^> Updates)
echo.
echo   GitHub release (attach BOTH installer and .sha256):
echo     gh release create v%VER% dist\PCMonitor-Setup-%VER%.exe dist\PCMonitor-Setup-%VER%.exe.sha256 --title "PC Monitor %VER%"
echo  ============================================
pause
