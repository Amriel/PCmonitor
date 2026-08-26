# -*- coding: utf-8 -*-
"""
PC Monitor — перевірки стану комп'ютера.

Усе тут ТІЛЬКИ ЧИТАЄ. Жодна перевірка нічого не змінює, не вимикає служби,
не чистить і не «оптимізує». Якщо щось знайдено — монітор пояснює, що це,
наскільки важливо і що з цим робити, а рішення лишає за тобою.

Перевірки запускаються ЛИШЕ на вимогу (кнопкою), бо деякі з них помітно
навантажують систему на кілька хвилин.

Що вміє:
  disk        — вільне місце та здоров'я дисків (SMART через WMI)
  drivers     — драйвери: непідписані, дуже старі, пристрої з помилками
  integrity   — цілісність системних файлів Windows (DISM / SFC)
  telemetry   — служби й задачі збору даних, налаштування приватності
  startup     — що стартує разом із Windows
  updates     — стан оновлень Windows
  events      — критичні помилки в журналі подій за тиждень
  power       — схема живлення (впливає на затримки та продуктивність)
  security    — стан захисту: Defender, брандмауер, шифрування
"""
import json
import logging
import re
import subprocess
import sys
import time

log = logging.getLogger("pcmon.health")
IS_WIN = sys.platform == "win32"

NO_WINDOW = 0x08000000 if IS_WIN else 0


def _ps(script, timeout=90):
    """Виконати PowerShell і повернути розібраний JSON (або None)."""
    if not IS_WIN:
        return None
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "replace").strip()
        if not out:
            return None
        data = json.loads(out)
        return [data] if isinstance(data, dict) else data
    except subprocess.TimeoutExpired:
        log.warning("PowerShell не вклався в %s с", timeout)
        return None
    except Exception as e:
        log.info("PowerShell помилка: %s", e)
        return None


def _run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        return (r.returncode,
                r.stdout.decode("utf-8", "replace", ) if r.stdout else "",
                r.stderr.decode("utf-8", "replace") if r.stderr else "")
    except subprocess.TimeoutExpired:
        return (-1, "", "перевищено час очікування")
    except Exception as e:
        return (-1, "", str(e))


def _res(status, title, detail="", items=None, fix=None, weight=1):
    """
    status: ok | warn | bad | info | skip
    """
    return {"status": status, "title": title, "detail": detail,
            "items": items or [], "fix": fix, "weight": weight}


# =====================================================================
#  ДИСКИ
# =====================================================================
def check_disk():
    out = []
    try:
        import psutil
        for p in psutil.disk_partitions(all=False):
            opts = (p.opts or "").lower()
            # пропускаємо приводи, образи та розділи лише для читання —
            # вони завжди «заповнені на 100%» і засмічували б результат
            if "cdrom" in opts or "ro" in opts.split(","):
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
            except Exception:
                continue
            if u.total <= 0:
                continue
            free_gb = u.free / 2**30
            pct = u.percent
            if pct >= 95 or free_gb < 5:
                st = "bad"
            elif pct >= 88 or free_gb < 15:
                st = "warn"
            else:
                st = "ok"
            out.append({"status": st, "name": p.mountpoint,
                        "text": f"зайнято {pct:.0f}% · вільно {free_gb:.0f} ГБ з "
                                f"{u.total/2**30:.0f} ГБ"})
    except Exception as e:
        return _res("skip", "Місце на дисках", f"не вдалося прочитати: {e}")

    # SMART
    smart = _ps("Get-CimInstance -Namespace root\\wmi -ClassName MSStorageDriver_FailurePredictStatus "
                "-ErrorAction SilentlyContinue | Select-Object InstanceName,PredictFailure | ConvertTo-Json -Compress",
                timeout=40)
    phys = _ps("Get-PhysicalDisk -ErrorAction SilentlyContinue | "
               "Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus | "
               "ConvertTo-Json -Compress", timeout=40)
    if phys:
        for d in phys:
            hs = (d.get("HealthStatus") or "").lower()
            st = "ok" if hs in ("healthy", "0") else ("warn" if hs else "info")
            if isinstance(d.get("HealthStatus"), int):
                st = "ok" if d["HealthStatus"] == 0 else "bad"
            out.append({"status": st,
                        "name": d.get("FriendlyName") or "диск",
                        "text": f"стан: {d.get('HealthStatus')} · {d.get('MediaType') or ''}"})
    if smart:
        for d in smart:
            if d.get("PredictFailure"):
                out.append({"status": "bad", "name": d.get("InstanceName", "диск"),
                            "text": "SMART попереджає про можливу відмову — зроби резервну копію"})

    worst = "ok"
    for i in out:
        if i["status"] == "bad":
            worst = "bad"
            break
        if i["status"] == "warn":
            worst = "warn"
    fix = None
    if worst != "ok":
        fix = ("Звільни місце: «Параметри → Система → Пам'ять → Тимчасові файли». "
               "Диску потрібно ~10–15% вільного простору, інакше Windows "
               "починає гальмувати.")
    return _res(worst, "Диски", items=out, fix=fix, weight=2)


# =====================================================================
#  ДРАЙВЕРИ
# =====================================================================
def check_drivers():
    if not IS_WIN:
        return _res("skip", "Драйвери", "лише для Windows")

    items = []
    bad = warn = 0

    # пристрої з помилками
    probs = _ps("Get-PnpDevice -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' } | "
                "Select-Object FriendlyName,Status,Class,InstanceId | ConvertTo-Json -Compress",
                timeout=60)
    if probs:
        for d in probs[:15]:
            items.append({"status": "bad", "name": d.get("FriendlyName") or "пристрій",
                          "text": f"стан: {d.get('Status')} · {d.get('Class') or ''}"})
            bad += 1

    # підписи й вік драйверів
    drv = _ps("Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | "
              "Where-Object { $_.DriverVersion } | "
              "Select-Object DeviceName,DriverVersion,DriverDate,IsSigned,Manufacturer | "
              "ConvertTo-Json -Compress", timeout=90)
    old_list, unsigned = [], []
    if drv:
        now = time.time()
        for d in drv:
            name = d.get("DeviceName") or ""
            if not name:
                continue
            if d.get("IsSigned") is False:
                unsigned.append(name)
            ds = d.get("DriverDate")
            ts = None
            if isinstance(ds, str):
                m = re.search(r"(\d{14})", ds) or re.search(r"/Date\((\d+)", ds)
                if m:
                    v = m.group(1)
                    try:
                        if len(v) == 14:
                            ts = time.mktime(time.strptime(v, "%Y%m%d%H%M%S"))
                        else:
                            ts = int(v) / 1000.0
                    except Exception:
                        ts = None
            if ts and (now - ts) > 6 * 365 * 86400:
                old_list.append((name, time.strftime("%Y", time.localtime(ts))))

    if unsigned:
        items.append({"status": "warn", "name": f"Без цифрового підпису: {len(unsigned)}",
                      "text": ", ".join(sorted(set(unsigned))[:6])})
        warn += 1
    if old_list:
        top = sorted(set(old_list), key=lambda x: x[1])[:6]
        items.append({"status": "info",
                      "name": f"Старші за 6 років: {len(set(old_list))}",
                      "text": ", ".join(f"{n} ({y})" for n, y in top)})

    if not items:
        return _res("ok", "Драйвери", "проблемних пристроїв не знайдено", weight=2)

    st = "bad" if bad else ("warn" if warn else "info")
    fix = None
    if bad:
        fix = ("Пристрої з помилками: відкрий «Диспетчер пристроїв» і подивись на "
               "позначені знаком оклику. Зазвичай допомагає встановлення драйвера "
               "з сайту виробника материнської плати або ноутбука.")
    elif warn:
        fix = ("Непідписані драйвери — не завжди погано (буває у старого заліза), "
               "але це і типовий спосіб закріпитись для шкідливого ПЗ. "
               "Перевір, чи впізнаєш ці пристрої.")
    return _res(st, "Драйвери", items=items, fix=fix, weight=2)


# =====================================================================
#  ЦІЛІСНІСТЬ СИСТЕМНИХ ФАЙЛІВ
# =====================================================================
def check_integrity(deep=False):
    """
    deep=False — швидка перевірка сховища компонентів (DISM ScanHealth, ~1–3 хв)
    deep=True  — повна перевірка системних файлів (SFC, ~5–15 хв)
    Обидві ТІЛЬКИ перевіряють, нічого не виправляють.
    """
    if not IS_WIN:
        return _res("skip", "Цілісність системи", "лише для Windows")

    if deep:
        code, out, _ = _run(["sfc", "/verifyonly"], timeout=1800)
        low = out.lower().replace("\x00", "")
        if "did not find any integrity violations" in low or "не виявлено порушень" in low:
            return _res("ok", "Цілісність системних файлів",
                        "порушень не знайдено (повна перевірка SFC)", weight=3)
        if "found integrity violations" in low or "виявлено порушення" in low:
            return _res("bad", "Цілісність системних файлів",
                        "знайдено пошкоджені системні файли",
                        fix=("Відкрий командний рядок від адміністратора і виконай:\n"
                             "  DISM /Online /Cleanup-Image /RestoreHealth\n"
                             "  sfc /scannow\n"
                             "Перший відновить сховище компонентів, другий — самі файли."),
                        weight=3)
        return _res("info", "Цілісність системних файлів",
                    "перевірка завершилась без однозначного результату", weight=3)

    code, out, _ = _run(["dism", "/Online", "/Cleanup-Image", "/ScanHealth"], timeout=1200)
    low = out.lower()
    if "no component store corruption" in low or "пошкодження сховища компонентів не виявлено" in low:
        return _res("ok", "Сховище компонентів Windows", "пошкоджень не знайдено", weight=3)
    if "repairable" in low or "можна відновити" in low:
        return _res("warn", "Сховище компонентів Windows",
                    "знайдено пошкодження, яке можна відновити",
                    fix=("Виконай від адміністратора:\n"
                         "  DISM /Online /Cleanup-Image /RestoreHealth"),
                    weight=3)
    if code != 0:
        return _res("info", "Сховище компонентів Windows",
                    "перевірка не завершилась (потрібні права адміністратора)", weight=3)
    return _res("info", "Сховище компонентів Windows", "результат невизначений", weight=3)


# =====================================================================
#  ТЕЛЕМЕТРІЯ ТА ПРИВАТНІСТЬ
# =====================================================================
TELEMETRY_SERVICES = {
    "DiagTrack": "Служба збору діагностичних даних Microsoft — головний канал телеметрії",
    "dmwappushservice": "Push-повідомлення WAP, використовується для діагностики",
}
TELEMETRY_TASKS = [
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    r"\Microsoft\Windows\Autochk\Proxy",
    r"\Microsoft\Windows\Feedback\Siuf\DmClient",
]


def check_telemetry():
    if not IS_WIN:
        return _res("skip", "Телеметрія", "лише для Windows")

    items = []
    active = 0

    svc = _ps("Get-Service -Name DiagTrack,dmwappushservice -ErrorAction SilentlyContinue | "
              "Select-Object Name,Status,StartType | ConvertTo-Json -Compress", timeout=30)
    for s in (svc or []):
        nm = s.get("Name")
        running = str(s.get("Status")) in ("4", "Running")
        stype = str(s.get("StartType"))
        auto = stype in ("2", "Automatic")
        if running or auto:
            active += 1
        items.append({
            "status": "warn" if running else ("info" if auto else "ok"),
            "name": nm,
            "text": (("працює" if running else "зупинена") +
                     f" · запуск: {'авто' if auto else stype}" +
                     " — " + TELEMETRY_SERVICES.get(nm, "")),
        })

    lvl = _ps("$p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection';"
              "$v=(Get-ItemProperty -Path $p -Name AllowTelemetry -ErrorAction SilentlyContinue)."
              "AllowTelemetry;"
              "if($null -eq $v){$p2='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection';"
              "$v=(Get-ItemProperty -Path $p2 -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry}"
              "@{Level=$v} | ConvertTo-Json -Compress", timeout=30)
    level_txt = "не задано (діють типові налаштування Windows)"
    lvl_status = "info"
    if lvl and lvl[0].get("Level") is not None:
        v = lvl[0]["Level"]
        names = {0: "Security — мінімум (лише Enterprise)",
                 1: "Basic — базова", 2: "Enhanced — розширена", 3: "Full — повна"}
        level_txt = names.get(v, str(v))
        lvl_status = "ok" if v in (0, 1) else "warn"
    items.append({"status": lvl_status, "name": "Рівень діагностичних даних", "text": level_txt})

    tasks = _ps("@(" + ",".join(
        f"'{t}'" for t in TELEMETRY_TASKS) + ") | ForEach-Object {"
        "$t=Get-ScheduledTask -TaskPath (Split-Path $_ -Parent).Replace('\\','\\')+'\\' "
        "-TaskName (Split-Path $_ -Leaf) -ErrorAction SilentlyContinue;"
        "if($t){[pscustomobject]@{Name=$t.TaskName;State=[string]$t.State}}} | ConvertTo-Json -Compress",
        timeout=45)
    on_tasks = [t for t in (tasks or []) if (t.get("State") or "").lower() == "ready"]
    if on_tasks:
        items.append({"status": "warn",
                      "name": f"Активні задачі збору даних: {len(on_tasks)}",
                      "text": ", ".join(t.get("Name", "") for t in on_tasks)})
        active += len(on_tasks)

    st = "warn" if active else "ok"
    fix = None
    if active:
        fix = ("Це стандартні механізми Windows, не шкідливе ПЗ — вони не крадуть "
               "файли. Але їх можна зменшити: «Параметри → Конфіденційність і "
               "захист → Діагностика й відгуки» → вимкнути необов'язкові дані. "
               "Службу DiagTrack можна перевести в «Вимкнено», система працює "
               "нормально; на роботі спершу спитай адміністратора.")
    return _res(st, "Телеметрія та приватність", items=items, fix=fix, weight=1)


# =====================================================================
#  АВТОЗАПУСК
# =====================================================================
def check_startup():
    if not IS_WIN:
        return _res("skip", "Автозапуск", "лише для Windows")
    # Те саме джерело, що й вкладка «Автозапуск»: записи з реальними id і
    # станом увімкнено/вимкнено. Завдяки цьому кожен рядок у результатах
    # перевірки має кнопку «Вимкнути» — тим самим штатним механізмом
    # (StartupApproved), яким користується Диспетчер задач. Нічого не
    # видаляється, увімкнути назад можна будь-коли.
    try:
        import startup_win
        data = startup_win.list_startup()
    except Exception as e:
        return _res("skip", "Автозапуск", f"не вдалося прочитати: {e}")
    items = []
    enabled_n = 0
    for it in (data.get("items") or []):
        en = bool(it.get("enabled", True))
        if en:
            enabled_n += 1
        cmd = it.get("command") or ""
        items.append({"status": "info" if en else "skip",
                      "name": it.get("name") or "?",
                      "text": (cmd[:110] + ("…" if len(cmd) > 110 else "")),
                      "sid": it.get("id"), "enabled": en,
                      "can": bool(it.get("can_toggle", True))})
    st = "ok" if enabled_n <= 8 else ("warn" if enabled_n <= 16 else "bad")
    fix = None
    if st != "ok":
        fix = (f"Увімкнених у автозапуску {enabled_n} — це помітно сповільнює "
               "вмикання комп'ютера. Зайве можна вимкнути прямо тут — кнопкою "
               "біля запису. Це не видалення: увімкнути назад можна будь-коли.")
    return _res(st, f"Автозапуск ({enabled_n})", items=items[:31], fix=fix, weight=1)


# =====================================================================
#  ОНОВЛЕННЯ
# =====================================================================
def check_updates():
    if not IS_WIN:
        return _res("skip", "Оновлення", "лише для Windows")
    data = _ps("$s=(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | "
               "Sort-Object InstalledOn -Descending | Select-Object -First 1);"
               "@{Last=$s.HotFixID;When=$s.InstalledOn} | ConvertTo-Json -Compress", timeout=45)
    if not data:
        return _res("info", "Оновлення Windows", "не вдалося прочитати", weight=1)
    d = data[0]
    when = d.get("When")
    ts = None
    if isinstance(when, str):
        m = re.search(r"/Date\((\d+)", when)
        if m:
            ts = int(m.group(1)) / 1000.0
        else:
            try:
                ts = time.mktime(time.strptime(when[:10], "%Y-%m-%d"))
            except Exception:
                ts = None
    if ts:
        days = (time.time() - ts) / 86400
        txt = f"останнє: {d.get('Last')} від {time.strftime('%Y-%m-%d', time.localtime(ts))} ({days:.0f} дн. тому)"
        st = "ok" if days < 60 else ("warn" if days < 120 else "bad")
        fix = None if st == "ok" else ("Оновлення довго не встановлювались. "
                                       "«Параметри → Центр оновлення Windows».")
        return _res(st, "Оновлення Windows", txt, fix=fix, weight=2)
    return _res("info", "Оновлення Windows", f"останнє: {d.get('Last')}", weight=1)


# =====================================================================
#  ЖУРНАЛ ПОДІЙ
# =====================================================================
def check_events():
    if not IS_WIN:
        return _res("skip", "Журнал подій", "лише для Windows")
    data = _ps("$t=(Get-Date).AddDays(-7);"
               "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=$t} "
               "-MaxEvents 400 -ErrorAction SilentlyContinue | "
               "Group-Object ProviderName | Sort-Object Count -Descending | "
               "Select-Object -First 8 Name,Count | ConvertTo-Json -Compress", timeout=90)
    if data is None:
        return _res("info", "Помилки в журналі подій", "не вдалося прочитати", weight=1)
    items = [{"status": "warn" if d.get("Count", 0) >= 20 else "info",
              "name": d.get("Name") or "?",
              "text": f"{d.get('Count')} помилок за тиждень"} for d in data]
    total = sum(d.get("Count", 0) for d in data)
    st = "ok" if total == 0 else ("info" if total < 20 else ("warn" if total < 100 else "bad"))
    fix = None
    if st in ("warn", "bad"):
        fix = ("Часті помилки від одного джерела — привід придивитись саме до "
               "нього (зазвичай драйвер або служба). Деталі: «Перегляд подій» "
               "→ Журнали Windows → Система.")
    return _res(st, f"Критичні помилки за тиждень ({total})", items=items, fix=fix, weight=1)


# =====================================================================
#  ЖИВЛЕННЯ
# =====================================================================
def check_power():
    if not IS_WIN:
        return _res("skip", "Живлення", "лише для Windows")
    code, out, _ = _run(["powercfg", "/getactivescheme"], timeout=20)
    name = out.strip()
    m = re.search(r"\((.+)\)", name)
    scheme = m.group(1) if m else name
    low = scheme.lower()
    if "економ" in low or "saver" in low:
        return _res("warn", "Схема живлення", scheme,
                    fix=("Режим економії помітно знижує швидкість і ЗБІЛЬШУЄ "
                         "затримки системи. Для стаціонарного ПК краще "
                         "«Збалансована» або «Висока продуктивність»."), weight=1)
    return _res("ok", "Схема живлення", scheme, weight=1)


# =====================================================================
#  БЕЗПЕКА
# =====================================================================
def check_security():
    if not IS_WIN:
        return _res("skip", "Захист", "лише для Windows")
    items = []
    worst = "ok"

    av = _ps("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct "
             "-ErrorAction SilentlyContinue | Select-Object displayName,productState | "
             "ConvertTo-Json -Compress", timeout=40)
    if av:
        for a in av:
            state = a.get("productState", 0)
            enabled = bool(state & 0x1000)
            items.append({"status": "ok" if enabled else "warn",
                          "name": a.get("displayName") or "антивірус",
                          "text": "увімкнено" if enabled else "вимкнено або не активний"})
            if not enabled:
                worst = "warn"
    fw = _ps("Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
             "Select-Object Name,Enabled | ConvertTo-Json -Compress", timeout=40)
    off = [f.get("Name") for f in (fw or []) if not f.get("Enabled")]
    if fw:
        if off:
            items.append({"status": "bad", "name": "Брандмауер",
                          "text": "вимкнено для профілів: " + ", ".join(map(str, off))})
            worst = "bad"
        else:
            items.append({"status": "ok", "name": "Брандмауер", "text": "увімкнено скрізь"})

    fix = None
    if worst != "ok":
        fix = "Перевір «Безпека Windows» — захист має бути ввімкнений."
    return _res(worst, "Захист системи", items=items, fix=fix, weight=2)


# =====================================================================
#  РЕЄСТР ПЕРЕВІРОК
# =====================================================================
def check_clipboard():
    try:
        import clipboard_win
        return clipboard_win.check()
    except Exception as e:
        return _res("skip", "Буфер обміну", f"не вдалося перевірити: {e}")


CHECKS = {
    "disk":      ("Диски та місце", check_disk, 10),
    "clipboard": ("Буфер обміну", check_clipboard, 10),
    "drivers":   ("Драйвери та пристрої", check_drivers, 90),
    "telemetry": ("Телеметрія та приватність", check_telemetry, 60),
    "startup":   ("Автозапуск", check_startup, 45),
    "updates":   ("Оновлення Windows", check_updates, 45),
    "events":    ("Помилки в журналі подій", check_events, 90),
    "power":     ("Схема живлення", check_power, 15),
    "security":  ("Захист системи", check_security, 45),
    "integrity": ("Цілісність системи (повільно)", check_integrity, 1200),
}

QUICK = ["disk", "clipboard", "power", "startup", "security", "updates", "telemetry"]
FULL = QUICK + ["drivers", "events"]
DEEP = FULL + ["integrity"]


def score(results):
    """Загальна оцінка стану 0..100 з ваговими коефіцієнтами."""
    pts = {"ok": 1.0, "info": 0.9, "warn": 0.55, "bad": 0.0, "skip": None}
    num = den = 0.0
    for r in results.values():
        p = pts.get(r.get("status"))
        if p is None:
            continue
        w = r.get("weight", 1)
        num += p * w
        den += w
    return round(100 * num / den) if den else None
