# -*- coding: utf-8 -*-
"""
PC Monitor — керування автозапуском програм і службами Windows.

ОБЕРЕЖНО ЗА ЗАМОВЧУВАННЯМ
Це єдине місце в моніторі, яке щось ЗМІНЮЄ в системі. Тому тут кілька
запобіжників:

  * ЖОДНОГО видалення. Записи автозапуску не стираються, а лише вимикаються
    штатним механізмом Windows — тим самим, яким користується Диспетчер задач.
    Увімкнути назад можна будь-коли й одним кліком.
  * Критичні служби Windows захищені списком і не вимикаються взагалі —
    навіть якщо дуже попросити. Вимкнення частини з них залишає систему
    без мережі, звуку чи можливості завантажитись.
  * Служби переводяться в «Вручну», а не «Вимкнено»: так вони не стартують
    самі, але система за потреби може їх підняти. Це помітно безпечніше.
  * Кожна зміна записується в журнал, щоб було видно, що саме змінювалось.

Читання працює без прав адміністратора; зміни потребують прав.
"""
import json
import logging
import os
import re
import subprocess
import sys
import time

log = logging.getLogger("pcmon.startup")
IS_WIN = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WIN else 0

# Гілки реєстру, де живе автозапуск програм.
# «StartupApproved» — саме там Windows тримає позначку «увімкнено/вимкнено»,
# і саме її змінює Диспетчер задач. Ми робимо так само.
RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", "user"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run", "machine"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
     "Run (32-біт)", "machine"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce", "user"),
]
APPROVED_RUN = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
APPROVED_RUN32 = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
APPROVED_FOLDER = (r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                   r"\StartupApproved\StartupFolder")

# Служби, які НЕ МОЖНА чіпати: без них система ламається.
# Список свідомо широкий — краще не дати вимкнути зайве, ніж залишити
# людину без мережі чи без можливості увійти в систему.
PROTECTED_SERVICES = {
    # ядро й вхід у систему
    "rpcss", "dcomlaunch", "rpcendpointmapper", "plugplay", "power", "profsvc",
    "themes", "userinit", "winlogon", "lsm", "samss", "eventlog", "schedule",
    "gpsvc", "brokerinfrastructure", "systemeventsbroker", "dcomlaunch",
    "coremessagingregistrar", "statereposervice", "usermanager", "timebrokersvc",
    # мережа
    "nsi", "dhcp", "dnscache", "netprofm", "nlasvc", "winhttpautoproxysvc",
    "lanmanworkstation", "lanmanserver", "netman", "wlansvc", "wcmsvc",
    "networkstore", "iphlpsvc",
    # безпека
    "windefend", "wscsvc", "securityhealthservice", "mpssvc", "bfe",
    "cryptsvc", "trustedinstaller", "wuauserv", "sgrmbroker",
    # звук, дисплей, вводу
    "audiosrv", "audioendpointbuilder", "themes", "uxsms", "dwm",
    # диск і файли
    "vss", "swprv", "storsvc", "wsearch", "fontcache",
}

SERVICE_START_TYPES = {
    0: "Завантажувач", 1: "Системна", 2: "Автоматично", 3: "Вручну", 4: "Вимкнено",
}


def _ps(script, timeout=60):
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
    except Exception as e:
        log.info("PowerShell: %s", e)
        return None


def is_admin():
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# =====================================================================
#  АВТОЗАПУСК ПРОГРАМ
# =====================================================================
def _read_approved(root, path):
    """Прочитати позначки увімкнено/вимкнено (двійкові значення)."""
    out = {}
    try:
        import winreg
        hive = winreg.HKEY_CURRENT_USER if root == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                # перший байт: парний = увімкнено, непарний = вимкнено
                try:
                    enabled = (val[0] & 1) == 0 if isinstance(val, bytes) and val else True
                except Exception:
                    enabled = True
                out[name.lower()] = enabled
    except FileNotFoundError:
        pass
    except Exception:
        log.debug("Не вдалося прочитати %s", path, exc_info=True)
    return out


def list_startup():
    """Усі записи автозапуску: реєстр + папка «Автозавантаження»."""
    if not IS_WIN:
        return {"supported": False, "reason": "лише для Windows", "items": []}
    import winreg

    # Позначки «увімкнено/вимкнено» Windows зберігає ОКРЕМО для записів
    # користувача (HKCU) і для записів «для всіх» (HKLM). Раніше ми читали й
    # писали лише HKCU — через це записи «для всіх» завжди показувались
    # увімкненими, а перемикач для них нічого не робив насправді.
    approved = {}
    for hv in ("HKCU", "HKLM"):
        approved.update({(hv, "run", k): v for k, v in
                         _read_approved(hv, APPROVED_RUN).items()})
        approved.update({(hv, "run32", k): v for k, v in
                         _read_approved(hv, APPROVED_RUN32).items()})
    folder_ok = {hv: _read_approved(hv, APPROVED_FOLDER) for hv in ("HKCU", "HKLM")}

    items = []
    for root, path, label, scope in RUN_KEYS:
        hive = winreg.HKEY_CURRENT_USER if root == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    key = name.lower()
                    hv = "HKLM" if scope == "machine" else "HKCU"
                    en = approved.get(
                        (hv, "run32" if "Wow6432" in path else "run", key))
                    items.append({
                        "id": f"reg|{root}|{path}|{name}",
                        "name": name,
                        "command": str(val)[:300],
                        "exe": _exe_from_cmd(str(val)),
                        "where": f"{label} ({'для всіх' if scope == 'machine' else 'для тебе'})",
                        "kind": "registry",
                        "scope": scope,
                        "enabled": True if en is None else en,
                        "can_toggle": (scope == "user") or is_admin(),
                    })
        except FileNotFoundError:
            continue
        except Exception:
            log.debug("Гілка %s недоступна", path, exc_info=True)

    # папка автозавантаження
    for base, scope, label in (
        (os.path.join(os.environ.get("APPDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "user", "Папка автозавантаження (для тебе)"),
        (os.path.join(os.environ.get("PROGRAMDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "machine", "Папка автозавантаження (для всіх)"),
    ):
        if not base or not os.path.isdir(base):
            continue
        try:
            for fn in os.listdir(base):
                if fn.lower().endswith(".ini"):
                    continue
                full = os.path.join(base, fn)
                hv = "HKLM" if scope == "machine" else "HKCU"
                items.append({
                    "id": f"file|{scope}|{full}",
                    "name": fn,
                    "command": full,
                    "exe": full,
                    "where": label,
                    "kind": "folder",
                    "scope": scope,
                    "enabled": folder_ok[hv].get(fn.lower(), True),
                    "can_toggle": (scope == "user") or is_admin(),
                })
        except Exception:
            pass

    items.sort(key=lambda x: (not x["enabled"], x["name"].lower()))
    return {"supported": True, "admin": is_admin(), "items": items}


def _exe_from_cmd(cmd):
    """Витягти шлях до програми з командного рядка автозапуску."""
    c = (cmd or "").strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c
    m = re.match(r"^(\S+\.exe)", c, re.I)
    return m.group(1) if m else c.split(" ")[0]


def set_startup(item_id, enable):
    """
    Увімкнути/вимкнути запис автозапуску.
    Нічого не видаляє: змінює лише штатну позначку Windows, ту саму, що й
    Диспетчер задач. Повернути назад можна будь-коли.
    """
    if not IS_WIN:
        return False, "лише для Windows"
    try:
        import winreg
        parts = item_id.split("|")
        if parts[0] == "reg":
            root, path, name = parts[1], parts[2], "|".join(parts[3:])
            approved = APPROVED_RUN32 if "Wow6432" in path else APPROVED_RUN
            hive_name = root                      # HKCU або HKLM — як у самого запису
        elif parts[0] == "file":
            # новий формат: file|scope|шлях; старий (file|шлях) теж підтримуємо,
            # щоб відкрита стара вкладка не ламалась після оновлення
            if parts[1] in ("user", "machine"):
                scope, full = parts[1], "|".join(parts[2:])
            else:
                full = "|".join(parts[1:])
                scope = ("machine"
                         if (os.environ.get("PROGRAMDATA", "\0").lower()
                             in full.lower()) else "user")
            # не os.path.basename: він орієнтується на роздільник поточної ОС,
            # а тут завжди шлях Windows
            name = full.replace("/", "\\").rstrip("\\").split("\\")[-1]
            approved = APPROVED_FOLDER
            hive_name = "HKLM" if scope == "machine" else "HKCU"
        else:
            return False, "невідомий запис"

        # Записи «для всіх» живуть у HKLM — і позначка теж має лягти в HKLM,
        # інакше Windows її просто не побачить, а ми покажемо хибний успіх.
        if hive_name == "HKLM" and not is_admin():
            return False, "для записів «для всіх» потрібні права адміністратора"
        hive = (winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM"
                else winreg.HKEY_CURRENT_USER)

        # Значення: 12 байтів. Перший байт 0x02 = увімкнено, 0x03 = вимкнено.
        val = bytes([0x02 if enable else 0x03]) + bytes(11)
        with winreg.CreateKeyEx(hive, approved, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, val)

        # Перевіряємо, що записалось саме те, що хотіли: мовчазний неуспіх тут
        # найгірший варіант — людина думає, що вимкнула, а воно стартує далі.
        try:
            with winreg.OpenKey(hive, approved) as k:
                back, _ = winreg.QueryValueEx(k, name)
            if not (isinstance(back, bytes) and back and
                    ((back[0] & 1) == 0) == bool(enable)):
                return False, "Windows не прийняв зміну"
        except Exception:
            return False, "зміну не вдалося підтвердити"

        log.info("Автозапуск «%s» (%s) -> %s", name, hive_name,
                 "увімкнено" if enable else "вимкнено")
        return True, ""
    except PermissionError:
        return False, "немає прав на зміну"
    except Exception as e:
        log.exception("Не вдалося змінити автозапуск")
        return False, str(e)


# =====================================================================
#  СЛУЖБИ
# =====================================================================
def list_services():
    if not IS_WIN:
        return {"supported": False, "reason": "лише для Windows", "items": []}

    data = _ps("Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
               "Select-Object Name,DisplayName,State,StartMode,PathName,Description,"
               "ProcessId,StartName | ConvertTo-Json -Compress", timeout=90)
    items = []
    for s in (data or []):
        nm = (s.get("Name") or "")
        low = nm.lower()
        protected = low in PROTECTED_SERVICES
        start = (s.get("StartMode") or "")
        state = (s.get("State") or "")
        path = s.get("PathName") or ""
        # службу Microsoft легко впізнати за шляхом у system32
        ms = "\\windows\\system32" in path.lower() or "\\windows\\syswow64" in path.lower()
        items.append({
            "name": nm,
            "title": s.get("DisplayName") or nm,
            "state": state,
            "start": start,
            "path": path[:250],
            "pid": s.get("ProcessId") or 0,
            "account": s.get("StartName") or "",
            "desc": (s.get("Description") or "")[:300],
            "microsoft": ms,
            "protected": protected,
            "can_change": (not protected) and is_admin(),
            # автоматичні служби сторонніх програм — головні кандидати
            "notable": (start.lower().startswith("auto") and not ms and not protected),
        })
    items.sort(key=lambda x: (not x["notable"], x["title"].lower()))
    return {"supported": True, "admin": is_admin(), "items": items,
            "protected_count": sum(1 for i in items if i["protected"])}


def scheduled_tasks(match=""):
    """Заплановані задачі, які запускають вказану програму."""
    if not IS_WIN:
        return []
    data = _ps("Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "
               "$t=$_; $a=($t.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) "
               "-join ' | '; "
               "[pscustomobject]@{Name=$t.TaskName;Path=$t.TaskPath;"
               "State=[string]$t.State;Action=$a} } | ConvertTo-Json -Compress",
               timeout=90)
    m = (match or "").lower()
    out = []
    for t in (data or []):
        act = (t.get("Action") or "")
        if m and m not in act.lower():
            continue
        out.append({"name": t.get("Name"), "path": t.get("Path"),
                    "state": t.get("State"), "action": act[:300]})
    return out


def who_starts(name, exe=""):
    """
    Хто запускає цю програму: служба, заплановане завдання чи запис
    автозапуску. Потрібно, коли процес сам відроджується після завершення.
    """
    if not IS_WIN:
        return {"supported": False}
    key = (name or "").lower().replace(".exe", "")
    base = os.path.basename(exe or "").lower() or (name or "").lower()

    res = {"supported": True, "services": [], "tasks": [], "startup": []}

    # служби, які запускають саме цей файл
    svc = _ps("Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
              "Select-Object Name,DisplayName,State,StartMode,PathName | "
              "ConvertTo-Json -Compress", timeout=90)
    for s in (svc or []):
        path = (s.get("PathName") or "").lower()
        if base and base in path:
            res["services"].append({
                "name": s.get("Name"), "title": s.get("DisplayName"),
                "state": s.get("State"), "start": s.get("StartMode"),
                "path": (s.get("PathName") or "")[:250],
                "protected": (s.get("Name") or "").lower() in PROTECTED_SERVICES,
            })

    # заплановані завдання
    try:
        res["tasks"] = scheduled_tasks(base or key)
    except Exception:
        pass

    # записи автозапуску
    try:
        su = list_startup()
        for i in su.get("items", []):
            hay = (i.get("command", "") + " " + i.get("exe", "")).lower()
            if base and base in hay:
                res["startup"].append(i)
    except Exception:
        pass

    return res


def set_service(name, mode):
    """
    Змінити режим запуску служби.

    mode: "manual" | "auto" | "disabled"
    Типово радимо «manual»: служба не стартує сама, але система може її
    підняти за потреби. «disabled» лишаємо можливим, але не радимо.
    Критичні служби не змінюються взагалі.
    """
    if not IS_WIN:
        return False, "лише для Windows"
    if not is_admin():
        return False, "потрібні права адміністратора"
    low = (name or "").lower()
    if low in PROTECTED_SERVICES:
        return False, ("це критична служба Windows — без неї система працює "
                       "неправильно, тому монітор її не змінює")
    mp = {"manual": "demand", "auto": "auto", "disabled": "disabled"}
    if mode not in mp:
        return False, "невідомий режим"
    try:
        r = subprocess.run(["sc", "config", name, f"start={mp[mode]}"],
                           capture_output=True, timeout=30, creationflags=NO_WINDOW)
        out = (r.stdout or b"").decode("utf-8", "replace")
        if r.returncode == 0:
            log.info("Служба %s -> %s", name, mode)
            return True, ""
        return False, out.strip()[:200] or f"код {r.returncode}"
    except Exception as e:
        log.exception("Не вдалося змінити службу")
        return False, str(e)


def service_action(name, action):
    """Запустити або зупинити службу (без зміни режиму запуску)."""
    if not IS_WIN:
        return False, "лише для Windows"
    if not is_admin():
        return False, "потрібні права адміністратора"
    if (name or "").lower() in PROTECTED_SERVICES:
        return False, "критичні служби не зупиняємо"
    if action not in ("start", "stop"):
        return False, "невідома дія"
    try:
        r = subprocess.run(["sc", action, name], capture_output=True,
                           timeout=45, creationflags=NO_WINDOW)
        if r.returncode == 0:
            return True, ""
        return False, (r.stdout or b"").decode("utf-8", "replace").strip()[:200]
    except Exception as e:
        return False, str(e)
