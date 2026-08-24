; PC Monitor — сценарій інсталятора (Inno Setup 6).
; Збирається через build.bat: він передає версію як /DAppVer=X.Y.Z.
;
; Принципи:
;  - ставиться ДЛЯ КОРИСТУВАЧА (без прав адміністратора) у
;    %LocalAppData%\Programs\PC Monitor — як Opera чи сам Inno Setup;
;  - оновлення поверх: data\ (база, налаштування) НЕ чіпається ніколи;
;  - перед копіюванням чемно зупиняє запущений монітор (--stop через API)
;    і чекає, поки процес справді відпустить файли.

#ifndef AppVer
  #define AppVer "0.0.0"
#endif

[Setup]
AppId={{7F3B9C6E-5A21-4D8B-9F04-3C1A82D5E947}}
AppName=PC Monitor
AppVersion={#AppVer}
AppVerName=PC Monitor {#AppVer}
AppPublisher=Amriel
DefaultDirName={localappdata}\Programs\PC Monitor
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=PCMonitor-Setup-{#AppVer}
SetupIconFile=pcmon.ico
UninstallDisplayIcon={app}\PCMonitor.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no

[Languages]
Name: "ukrainian"; MessagesFile: "compiler:Languages\Ukrainian.isl"

; Автозапуску тут навмисно НЕМАЄ: апка має власний (Налаштування → «Запускати
; разом із Windows»), і він кращий — стартує через планувальник з правами
; адміністратора, тож ETW (точні байти мережі) працює. Два механізми поруч
; означали б подвійний старт при вході в систему.
[Tasks]
Name: "desktopicon"; Description: "Значок на робочому столі"; Flags: unchecked

[Files]
Source: "dist\PCMonitor\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\PC Monitor"; Filename: "{app}\PCMonitor.exe"
Name: "{autodesktop}\PC Monitor"; Filename: "{app}\PCMonitor.exe"; Tasks: desktopicon

[Run]
; postinstall без skipifsilent: після ТИХОГО оновлення (/VERYSILENT з апки)
; монітор теж має піднятись сам — сторінка чекає на нього і перезавантажиться.
Filename: "{app}\PCMonitor.exe"; Description: "Запустити PC Monitor"; \
  Flags: nowait postinstall

[UninstallRun]
Filename: "{app}\PCMonitor.exe"; Parameters: "--stop"; Flags: runhidden; \
  RunOnceId: "StopPCMonitor"

[UninstallDelete]
; згенеровані токени/кеші; базу даних (data\pcmon.sqlite3) свідомо лишаємо —
; раптом людина перевстановлює, а не прощається
Type: files; Name: "{app}\data\session.token"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  R: Integer;
begin
  Result := '';
  { Чемна зупинка запущеного монітора: --stop сам читає токен сесії,
    просить /api/quit і чекає, поки збирач допише базу. }
  if FileExists(ExpandConstant('{app}\PCMonitor.exe')) then
    Exec(ExpandConstant('{app}\PCMonitor.exe'), '--stop', '',
         SW_HIDE, ewWaitUntilTerminated, R);
  { Порт звільняється трохи раніше, ніж процес відпускає файли, — тому
    додатково чекаємо на СПРАВЖНЄ завершення процесів PCMonitor (до 25 с),
    а що не завершилось — закриваємо примусово (напр., осиротіле вікно). }
  Exec('powershell.exe',
       '-NoProfile -NonInteractive -Command "' +
       '$p = Get-Process PCMonitor -ErrorAction SilentlyContinue; ' +
       'if ($p) { $p | Wait-Process -Timeout 25 -ErrorAction SilentlyContinue; ' +
       'Get-Process PCMonitor -ErrorAction SilentlyContinue | ' +
       'Stop-Process -Force -ErrorAction SilentlyContinue }; ' +
       'Start-Sleep -Milliseconds 500"',
       '', SW_HIDE, ewWaitUntilTerminated, R);
end;
