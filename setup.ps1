# =====================================================================
#  PC Monitor — інсталятор
#
#  Один раз запитує права адміністратора, далі:
#    • ставить потрібні пакети Python
#    • реєструє автозапуск, який стартує ВЖЕ з правами — без UAC щоразу
#    • створює ярлики («Пуск» + робочий стіл)
#    • запускає монітор
#
#  Після цього .bat-файли не потрібні: ярлик відкриває вікно,
#  збір іде у фоні з моменту входу в Windows, без вікон консолі.
#
#  Запускати через install.bat (він підніме права).
#
#  ВАЖЛИВО про надійність:
#  Windows PowerShell 5.1 перетворює будь-який вивід зовнішньої програми
#  у потік помилок на ТЕРМІНАЛЬНУ помилку, якщо стоїть ErrorActionPreference
#  = Stop. Через це попередня версія тихо закривалась на кроці автозапуску
#  (schtasks пише «задачі не існує» в stderr). Тому тут: Continue за
#  замовчуванням, явна обробка помилок і повний лог у setup.log.
# =====================================================================
param(
    [switch]$Uninstall,
    [switch]$Elevated
)

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$AppName  = "PC Monitor"
$TaskName = "PC Monitor"
$Base     = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$Monitor  = Join-Path $Base "monitor.py"
$IconPath = Join-Path $Base "pcmon.ico"
$LogPath  = Join-Path $Base "setup.log"
$Port     = 8787

# читаємо порт із config.json, якщо він там інший
try {
    $cfgPath = Join-Path $Base "config.json"
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cfg.dashboard_port) { $Port = [int]$cfg.dashboard_port }
    }
} catch {}

function Log([string]$t) {
    try { Add-Content -Path $LogPath -Value ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $t) -Encoding UTF8 } catch {}
}
function Say ([string]$t, [string]$c = "Gray") { Write-Host $t -ForegroundColor $c; Log $t }
function Ok  ([string]$t) { Write-Host "  [+] $t" -ForegroundColor Green;  Log "OK: $t" }
function Warn([string]$t) { Write-Host "  [!] $t" -ForegroundColor Yellow; Log "WARN: $t" }
function Err ([string]$t) { Write-Host "  [x] $t" -ForegroundColor Red;    Log "ERR: $t" }

function Hold([string]$msg = "Enter — закрити") {
    Write-Host ""
    try { Read-Host "  $msg" | Out-Null } catch { Start-Sleep -Seconds 30 }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# невелика обгортка: HTTP-запит, який не валить скрипт і працює в PS 5.1
function Web([string]$path, [string]$method = "Get") {
    try {
        $p = @{ Uri = "http://127.0.0.1:$Port$path"; TimeoutSec = 3; UseBasicParsing = $true }
        if ($method -eq "Post") { $p.Method = "Post"; $p.Body = "{}"; $p.ContentType = "application/json" }
        return Invoke-WebRequest @p
    } catch { return $null }
}

function Stop-Monitor {
    Web "/api/quit" "Post" | Out-Null
    Start-Sleep -Seconds 2
    try {
        Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -like "*monitor.py*" } |
            ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }
    } catch {}
}

# --- самопідняття прав: єдиний UAC за весь час ------------------------
if (-not (Test-Admin)) {
    Say ""
    Say "  Потрібні права адміністратора — зараз Windows запитає дозвіл." Yellow
    Say "  Це ОДИН раз, під час встановлення. Далі запитів не буде." DarkGray
    Say ""
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Elevated")
    if ($Uninstall) { $a += "-Uninstall" }
    try {
        Start-Process powershell -Verb RunAs -ArgumentList $a -WorkingDirectory $Base
    } catch {
        Err "Запит прав відхилено. Без нього встановити не вийде."
        Hold
    }
    exit
}

# =====================================================================
#  Далі — все у великому try, щоб вікно НІКОЛИ не закривалось мовчки
# =====================================================================
try {

Set-Content -Path $LogPath -Value ("=== PC Monitor setup " + (Get-Date) + " ===") -Encoding UTF8
Log ("PSVersion: " + $PSVersionTable.PSVersion + " | Base: " + $Base + " | Port: " + $Port)

Say ""
Say "  ==========================================" Cyan
if ($Uninstall) {
    Say "        PC MONITOR — видалення" Cyan
} else {
    Say "        PC MONITOR — встановлення" Cyan
}
Say "  ==========================================" Cyan
Say ""

# =====================================================================
#  ВИДАЛЕННЯ
# =====================================================================
if ($Uninstall) {
    Say "  Зупиняю монітор…"
    Stop-Monitor
    Ok "зупинено"

    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        }
        Ok "автозапуск прибрано"
    } catch {
        cmd /c "schtasks /Delete /F /TN ""$TaskName""" 2>&1 | Out-Null
        Ok "автозапуск прибрано"
    }

    try {
        foreach ($f in @("Desktop", "StartMenu")) {
            $root = [Environment]::GetFolderPath($f)
            if (-not $root) { continue }
            $l = if ($f -eq "StartMenu") { Join-Path $root "Programs\$AppName.lnk" }
                 else { Join-Path $root "$AppName.lnk" }
            if (Test-Path $l) { Remove-Item $l -Force -ErrorAction SilentlyContinue }
        }
        Ok "ярлики видалено"
    } catch { Warn "ярлики прибрати не вдалося: $($_.Exception.Message)" }

    Say ""
    Say "  Готово. Зібрані дані НЕ видалено — вони лишились у папці data\." Green
    Say "  Хочеш стерти й історію — видали цю папку вручну." DarkGray
    Hold
    exit
}

# =====================================================================
#  1. Python
# =====================================================================
Say "  [1/5] Шукаю Python…"
$pyExe = $null
foreach ($c in @("python.exe", "python3.exe")) {
    $f = Get-Command $c -ErrorAction SilentlyContinue
    if ($f -and $f.Source -notlike "*WindowsApps*") { $pyExe = $f.Source; break }
}
if (-not $pyExe) {
    $f = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($f) {
        $out = & py -3 -c "import sys; print(sys.executable)" 2>&1
        if ($LASTEXITCODE -eq 0 -and $out) { $pyExe = ($out | Select-Object -Last 1).ToString().Trim() }
    }
}
if (-not $pyExe) {
    Warn "Python не знайдено."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say "      Можу поставити автоматично (Python 3.12)."
        $a = Read-Host "      Встановити? [Y/n]"
        if ($a -eq "" -or $a -match "^[YyТт]") {
            Say "      Встановлюю — це кілька хвилин…" DarkGray
            cmd /c "winget install -e --id Python.Python.3.12 --scope machine --accept-package-agreements --accept-source-agreements" 2>&1 | Out-Null
            $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                        [Environment]::GetEnvironmentVariable("Path", "User")
            $f = Get-Command "python.exe" -ErrorAction SilentlyContinue
            if ($f) { $pyExe = $f.Source }
        }
    }
}
if (-not $pyExe -or -not (Test-Path $pyExe)) {
    Err "Без Python встановити не вийде."
    Say "      Постав із python.org (галочка «Add python.exe to PATH»)," Yellow
    Say "      потім запусти install.bat ще раз." Yellow
    Hold
    exit 1
}
$pyDir  = Split-Path -Parent $pyExe
$pywExe = Join-Path $pyDir "pythonw.exe"
if (-not (Test-Path $pywExe)) { $pywExe = $pyExe; Warn "pythonw.exe не знайдено — можливе вікно консолі" }
$ver = (& $pyExe --version 2>&1 | Select-Object -First 1)
Ok "$ver"
Say "      $pyExe" DarkGray
Log "pyExe=$pyExe pywExe=$pywExe"

# =====================================================================
#  2. Пакети
# =====================================================================
Say ""
Say "  [2/5] Встановлюю пакети (psutil, pywebview, pywintrace, pystray, Pillow)…"
$req = Join-Path $Base "requirements.txt"
& $pyExe -m pip install --upgrade pip --quiet --disable-pip-version-check 2>&1 | Out-Null
$pipOut = & $pyExe -m pip install -r "$req" --disable-pip-version-check 2>&1
$pipCode = $LASTEXITCODE
Log ("pip exit=$pipCode`n" + ($pipOut -join "`n"))
if ($pipCode -eq 0) {
    Ok "пакети готові"
} else {
    Warn "частина пакетів не встановилась (деталі в setup.log):"
    $pipOut | Select-Object -Last 3 | ForEach-Object { Say "        $_" DarkGray }
}
# перевіряємо, що головне на місці
$chk = & $pyExe -c "import psutil, sys; sys.stdout.write('ok')" 2>&1
if ("$chk" -notlike "*ok*") {
    Err "psutil не встановився — монітор не запрацює. Дивись setup.log."
    Hold
    exit 1
}

# =====================================================================
#  3. Автозапуск
# =====================================================================
Say ""
Say "  [3/5] Налаштовую автозапуск…"

Say "        зупиняю те, що вже працює…" DarkGray
Stop-Monitor

$user = "$env:USERDOMAIN\$env:USERNAME"
$taskArgs = "`"$Monitor`" --quiet"
Log "task user=$user action=$pywExe $taskArgs"

# Через ScheduledTasks-модуль, а не schtasks.exe: немає проблем з лапками
# в шляхах і немає виводу в потік помилок, який ламав інсталятор.
$done = $false
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    $act  = New-ScheduledTaskAction -Execute $pywExe -Argument $taskArgs -WorkingDirectory $Base
    $trg  = New-ScheduledTaskTrigger -AtLogOn -User $user
    # RunLevel Highest — стартує вже з правами адміністратора і БЕЗ запиту UAC
    $prin = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
              -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $prin `
        -Settings $set -Description "Монітор ресурсів комп'ютера" -Force -ErrorAction Stop | Out-Null
    $done = $true
} catch {
    Warn "через модуль не вийшло ($($_.Exception.Message)) — пробую інакше"
    Log ("Register-ScheduledTask failed: " + $_.Exception.ToString())
}

if (-not $done) {
    # запасний шлях: schtasks.exe через cmd, щоб його вивід не ламав скрипт
    $tr = "\`"$pywExe\`" \`"$Monitor\`" --quiet"
    $cmdLine = "schtasks /Create /F /TN ""$TaskName"" /SC ONLOGON /RU ""$user"" /RL HIGHEST /TR ""$tr"""
    Log "fallback: $cmdLine"
    $o = cmd /c $cmdLine 2>&1
    Log ($o -join "`n")
    if ($LASTEXITCODE -eq 0) { $done = $true }
}

if ($done) {
    Ok "стартуватиме при вході в Windows"
    Ok "одразу з правами адміністратора, без UAC і без консолі"
} else {
    Err "автозапуск зареєструвати не вдалося (деталі в setup.log)"
    Warn "монітор усе одно можна відкривати ярликом вручну"
}

# =====================================================================
#  4. Ярлики
# =====================================================================
Say ""
Say "  [4/5] Створюю ярлики…"
try {
    $sh = New-Object -ComObject WScript.Shell
    $targets = @()
    foreach ($f in @("Desktop", "StartMenu")) {
        $root = [Environment]::GetFolderPath($f)
        if (-not $root) { continue }
        $targets += if ($f -eq "StartMenu") { Join-Path $root "Programs\$AppName.lnk" }
                    else { Join-Path $root "$AppName.lnk" }
    }
    foreach ($p in $targets) {
        $s = $sh.CreateShortcut($p)
        $s.TargetPath       = $pywExe
        $s.Arguments        = "`"$Monitor`" --window"
        $s.WorkingDirectory = $Base
        $s.Description      = "Монітор ресурсів комп'ютера"
        if (Test-Path $IconPath) { $s.IconLocation = "$IconPath,0" }
        $s.Save()
    }
    Ok "робочий стіл і меню «Пуск»"
} catch {
    Warn "не вдалося створити ярлики: $($_.Exception.Message)"
}

# =====================================================================
#  5. Запуск
# =====================================================================
Say ""
Say "  [5/5] Запускаю…"
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    Log ("Start-ScheduledTask failed: " + $_.Exception.Message)
    Start-Process $pywExe -ArgumentList "`"$Monitor`"", "--quiet" -WorkingDirectory $Base -WindowStyle Hidden
}

$st = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 800
    $r = Web "/api/status"
    if ($r -and $r.StatusCode -eq 200) {
        try { $st = $r.Content | ConvertFrom-Json } catch {}
        if ($st) { break }
    }
}

if ($st) {
    Ok "монітор працює"
    if ($st.admin) {
        Ok "права адміністратора є — мережа по програмах рахується точно"
    } else {
        Warn "працює без прав адміністратора — точні байти мережі недоступні"
    }
    Say "      ETW: $($st.etw)" DarkGray
} else {
    Warn "не дочекався відповіді монітора"
    Say "      Подивись logs\monitor.log і setup.log" DarkGray
}

Say ""
Say "  ==========================================" Green
Say "   Готово." Green
Say "  ==========================================" Green
Say ""
Say "   • Відкрити:   ярлик «PC Monitor» на робочому столі"
Say "   • Далі само:  стартує при вході в Windows, у фоні"
Say "   • Без консолі та без запитів прав"
Say "   • Видалити:   uninstall.bat"
Say ""

$open = Read-Host "  Відкрити зараз? [Y/n]"
if ($open -eq "" -or $open -match "^[YyТт]") {
    Start-Process $pywExe -ArgumentList "`"$Monitor`"", "--window" -WorkingDirectory $Base
    Start-Sleep -Seconds 2
}

} catch {
    # Головна страховка: вікно не має зникати мовчки НІКОЛИ
    Write-Host ""
    Write-Host "  [x] Несподівана помилка:" -ForegroundColor Red
    Write-Host "      $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "      рядок $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor DarkGray
    Log ("FATAL: " + $_.Exception.ToString())
    Log ("AT: " + $_.InvocationInfo.PositionMessage)
    Write-Host ""
    Write-Host "      Повний лог: $LogPath" -ForegroundColor DarkGray
    Write-Host "      Надішли цей файл — і я скажу, що не так." -ForegroundColor DarkGray
    Hold
    exit 1
}
