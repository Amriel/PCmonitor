# -*- coding: utf-8 -*-
"""
PC Monitor — які саме ДРАЙВЕРИ спричиняють затримки (per-driver DPC/ISR).

НАВІЩО
Звичайний замір затримок каже «винні драйвери», але не каже який. LatencyMon
для цього ставить власний драйвер у ядро. Нам це не потрібно: Windows уміє
віддавати ті самі дані сама, через ETW-трасування ядра — на цьому ж механізмі
працюють xperf і WPA від Microsoft.

ЯК ЦЕ ПРАЦЮЄ
1. Беремо список завантажених драйверів ядра з їхніми адресами в пам'яті
   (штатний API psapi, прав не потребує).
2. Записуємо коротку трасу подій ядра через wpr.exe — вбудований у Windows
   інструмент. Потрібні права адміністратора.
3. У трасі кожна подія DPC/ISR містить АДРЕСУ процедури драйвера. Зіставляємо
   адресу з таблицею з кроку 1 — і отримуємо ім'я файлу драйвера.
4. Рахуємо по кожному драйверу: скільки разів спрацював і скільки часу забрав.

Жодного власного драйвера, жодних змін Secure Boot, жодних конфліктів з
анти-чітами. Усе тільки читає.

ЯКЩО ВСТАНОВЛЕНО XPERF
Якщо в системі є xperf.exe (з безкоштовного Windows Performance Toolkit), беремо
його — він одразу віддає готовий звіт по драйверах і робить це точніше.
Інакше розбираємо трасу самі через tracerpt.exe, теж вбудований.
"""
import csv
import glob
import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

log = logging.getLogger("pcmon.dpcisr")
IS_WIN = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WIN else 0

SESSION = "PCMonitorDpcIsr"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =====================================================================
#  Список завантажених драйверів ядра з адресами
# =====================================================================
def kernel_modules():
    """
    Повертає відсортований список (базова_адреса, ім'я) усіх драйверів ядра.
    Використовує psapi — штатний API Windows, прав адміністратора не треба.
    """
    if not IS_WIN:
        return []
    try:
        import ctypes
        from ctypes import wintypes

        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                            wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
        psapi.EnumDeviceDrivers.restype = wintypes.BOOL
        psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p,
                                                   wintypes.LPWSTR, wintypes.DWORD]
        psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p,
                                                   wintypes.LPWSTR, wintypes.DWORD]

        needed = wintypes.DWORD(0)
        psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed))
        n = needed.value // ctypes.sizeof(ctypes.c_void_p)
        if n <= 0:
            return []
        arr = (ctypes.c_void_p * (n + 64))()
        if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return []
        n = needed.value // ctypes.sizeof(ctypes.c_void_p)

        mods = []
        buf = ctypes.create_unicode_buffer(512)
        for i in range(n):
            base = arr[i]
            if not base:
                continue
            name = ""
            if psapi.GetDeviceDriverBaseNameW(base, buf, 512):
                name = buf.value
            path = ""
            if psapi.GetDeviceDriverFileNameW(base, buf, 512):
                path = buf.value
            mods.append((int(base), name or "?", path))
        mods.sort(key=lambda x: x[0])
        return mods
    except Exception:
        log.exception("Не вдалося отримати список драйверів ядра")
        return []


def _map_addr(mods, addr, max_span=64 * 1024 * 1024):
    """Адреса -> ім'я драйвера (найближчий модуль, що починається не пізніше)."""
    if not mods or not addr:
        return None
    lo, hi = 0, len(mods) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if mods[mid][0] <= addr:
            best = mods[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if best and (addr - best[0]) <= max_span:
        return best
    return None


# =====================================================================
#  Пошук інструментів
# =====================================================================
def _which(name):
    p = shutil.which(name)
    if p:
        return p
    # типові місця Windows Performance Toolkit
    for pat in (r"C:\Program Files (x86)\Windows Kits\*\Windows Performance Toolkit\%s" % name,
                r"C:\Program Files\Windows Kits\*\Windows Performance Toolkit\%s" % name):
        for c in glob.glob(pat):
            if os.path.isfile(c):
                return c
    return None


def tools():
    return {
        "logman": _which("logman.exe"),
        "wpr": _which("wpr.exe"),
        "tracerpt": _which("tracerpt.exe"),
        "xperf": _which("xperf.exe"),
        "tracelog": _which("tracelog.exe"),
    }


def _run(cmd, timeout=300, cwd=None):
    """Виконати команду, повернути (код, вивід). Усе пишемо в лог."""
    try:
        log.info("ЗАПУСК: %s", " ".join(str(c) for c in cmd))
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW, cwd=cwd)
        out = (r.stdout or b"").decode("utf-8", "replace")
        err = (r.stderr or b"").decode("utf-8", "replace")
        txt = (out + ("\n" + err if err.strip() else "")).strip()
        log.info("КОД %s; вивід (перші 600): %s", r.returncode, txt[:600])
        return r.returncode, txt
    except subprocess.TimeoutExpired:
        log.warning("Команда не вклалася в %s с", timeout)
        return -1, f"перевищено час очікування ({timeout} с)"
    except Exception as e:
        log.exception("Помилка запуску")
        return -1, str(e)


def is_admin():
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# =====================================================================
#  Розбір готового звіту xperf (найточніший шлях)
# =====================================================================
_XPERF_ROW = re.compile(
    r"^\s*([\w\-.]+\.sys|[\w\-.]+\.exe|[\w\-.]+\.dll|Unknown)\s+.*?(\d[\d,\.]*)\s*$",
    re.I)


_MODULE_TOKEN = re.compile(r"\b([A-Za-z0-9_\-.]+\.(?:sys|exe|dll))\b", re.I)
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def _parse_xperf(text):
    """
    Розбір звіту `xperf -a dpcisr`.

    Формат цього звіту різниться між версіями Windows Performance Toolkit:
    десь колонки розділені комами, десь пробілами, назви секцій теж різні.
    Попередня версія вимагала ПРОБІЛ після імені модуля — а справжній xperf
    пише через КОМУ, тому не розпізнавалось жодного рядка.

    Тепер робимо незалежно від формату: у кожному рядку шукаємо назву модуля
    (щось.sys/.exe/.dll) і всі числа поруч. Рядки без модуля або без чисел
    просто пропускаємо.
    """
    drivers = {}
    section = None   # "dpc" | "isr" | None

    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        low = raw.lower()

        # заголовок секції
        if "isr" in low and not _MODULE_TOKEN.search(raw):
            if "dpc" in low:
                section = None          # спільна секція — визначимо по колонках
            else:
                section = "isr"
            continue
        if "dpc" in low and not _MODULE_TOKEN.search(raw):
            section = "dpc"
            continue

        m = _MODULE_TOKEN.search(raw)
        if not m:
            continue
        name = m.group(1)
        # числа після назви модуля
        tail = raw[m.end():]
        nums = _NUMBER.findall(tail.replace(",", " "))
        if not nums:
            continue
        try:
            vals = [float(x) for x in nums]
        except ValueError:
            continue

        d = drivers.setdefault(name, {"driver": name, "dpc_count": 0, "isr_count": 0,
                                      "usec": 0.0, "max_us": 0.0})
        cnt = int(vals[0]) if vals[0] >= 0 else 0
        if section == "isr":
            d["isr_count"] += cnt
        else:
            d["dpc_count"] += cnt
        # решта чисел: сумарний час і максимум. Беремо найбільше як максимум,
        # друге за порядком — як сумарний час (типовий порядок колонок).
        if len(vals) >= 2:
            d["usec"] += vals[1]
        if len(vals) >= 3:
            d["max_us"] = max(d["max_us"], max(vals[2:]))
    return [d for d in drivers.values()
            if d["dpc_count"] or d["isr_count"] or d["usec"]]


# =====================================================================
#  Розбір сирої траси через tracerpt (шлях без xperf)
# =====================================================================
_HEX0X = re.compile(r"^0x([0-9a-fA-F]{6,16})$")
_HEXBARE = re.compile(r"^[0-9a-fA-F]{12,16}$")
_DEC = re.compile(r"^\d{13,20}$")


def _scan_addr(row, lo, hi, start=0):
    """
    Знайти в рядку адресу процедури драйвера.

    Чому саме так: tracerpt складає корисне навантаження події у БЕЗІМЕННІ
    колонки в кінці рядка («User Data»), а не в колонку з назвою на кшталт
    «Routine». Перша версія шукала за назвою — і не знаходила нічого, тому всі
    драйвери виходили «невідомими». Тепер переглядаємо всі клітинки й беремо
    перше число, яке потрапляє в діапазон адрес завантажених драйверів —
    така перевірка сама себе валідує.
    """
    # йдемо з кінця: корисне навантаження зазвичай там
    for i in range(len(row) - 1, start - 1, -1):
        c = row[i].strip().strip('"')
        n = len(c)
        if n < 6 or n > 20:
            continue
        v = None
        m = _HEX0X.match(c)
        if m:
            v = int(m.group(1), 16)
        elif _HEXBARE.match(c):
            try:
                v = int(c, 16)
            except ValueError:
                v = None
        elif _DEC.match(c):
            try:
                v = int(c)
            except ValueError:
                v = None
        if v is not None and lo <= v <= hi:
            return v
    return None


def _parse_tracerpt_csv(path, mods, limit_rows=3_000_000):
    """
    Читаємо CSV-дамп подій ядра. Нас цікавлять події DPC та ISR — у них є
    адреса процедури драйвера. Зіставляємо адресу з таблицею модулів.
    """
    drivers = {}
    stats = {"rows": 0, "dpc": 0, "isr": 0, "mapped": 0, "unmapped": 0,
             "columns": None, "sample": None, "addr_range": None}

    # діапазон адрес, у якому взагалі можуть бути драйвери
    if mods:
        lo = mods[0][0]
        hi = mods[-1][0] + 64 * 1024 * 1024
        stats["addr_range"] = f"0x{lo:X}–0x{hi:X}"
    else:
        lo, hi = 0, 0

    def bump(name, kind, dur_us):
        d = drivers.setdefault(name, {"driver": name, "dpc_count": 0, "isr_count": 0,
                                      "usec": 0.0, "max_us": 0.0})
        d[f"{kind}_count"] += 1
        if dur_us:
            d["usec"] += dur_us
            d["max_us"] = max(d["max_us"], dur_us)

    try:
        with io.open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            rdr = csv.reader(f)
            header = None
            idx = {}
            for row in rdr:
                stats["rows"] += 1
                if stats["rows"] > limit_rows:
                    break
                if not row:
                    continue
                # шапка може зустрічатись не з першого рядка
                if header is None:
                    joined = ",".join(row).lower()
                    if "event name" in joined or "eventname" in joined:
                        header = [c.strip().strip('"') for c in row]
                        stats["columns"] = header
                        for i, c in enumerate(header):
                            idx[c.lower()] = i
                        continue
                    continue
                if stats["sample"] is None and len(row) > 4:
                    stats["sample"] = row[:16]

                def col(*names):
                    for nm in names:
                        i = idx.get(nm)
                        if i is not None and i < len(row):
                            v = row[i].strip().strip('"')
                            if v:
                                return v
                    return None

                ev = (col("event name", "eventname") or "").lower()
                typ = (col("type", "opcode name", "opcodename") or "").lower()
                if "dpc" in ev or "dpc" in typ:
                    kind = "dpc"
                elif "isr" in ev or "interrupt" in ev or "isr" in typ:
                    kind = "isr"
                else:
                    continue
                stats[kind] += 1

                # 1) спробувати іменовану колонку (раптом вона є)
                addr = None
                raw = col("routine", "dpcroutine", "isrroutine", "address")
                if raw:
                    m = re.search(r"0x([0-9a-fA-F]+)", raw)
                    if m:
                        addr = int(m.group(1), 16)
                    elif raw.isdigit():
                        addr = int(raw)
                    if addr is not None and not (lo <= addr <= hi):
                        addr = None
                # 2) головний шлях: пошук адреси серед усіх клітинок рядка
                if addr is None and lo:
                    addr = _scan_addr(row, lo, hi)
                dur = None
                dv = col("duration", "elapsed time", "delta")
                if dv:
                    try:
                        dur = float(dv.replace(",", ""))
                    except ValueError:
                        dur = None

                mod = _map_addr(mods, addr) if addr else None
                if mod:
                    stats["mapped"] += 1
                    bump(mod[1], kind, dur)
                else:
                    stats["unmapped"] += 1
                    bump("(невідомий драйвер)", kind, dur)
    except Exception as e:
        log.exception("Помилка розбору CSV")
        stats["error"] = str(e)
    return list(drivers.values()), stats


# =====================================================================
#  Головна операція
# =====================================================================
# Варіанти запуску трасування. Порядок важливий: спершу найлегші.
#
# ЧОМУ САМЕ logman: він пише РІВНО вказані події ядра і зупиняється миттєво.
# Попередня версія у разі невдачі відкочувалась на профіль wpr «GeneralProfile»,
# який записує геть усе (стеки, диск, файли) — файл роздувався до гігабайтів,
# а `wpr -stop` після цього зшивав трасу по десять хвилин. Саме через це
# інтерфейс і завис на «Зупиняю трасування». Більше такого відкоту нема.
# Перевірено на живій Windows 11: власне ім'я сесії для трасування ядра
# НЕ приймається (logman повертає помилку), а штатне «NT Kernel Logger» —
# працює. Тому воно й перше, щоб не гаяти час на завідомо марні спроби.
LOGMAN_ATTEMPTS = [
    ("NT Kernel Logger", "(dpc,isr,img,process)"),
    ("NT Kernel Logger", "(dpc,isr,img)"),
    ("NT Kernel Logger", "(dpc,isr)"),
    ("PCMonDpcIsr", "(dpc,isr,img,process)"),
]


class DpcIsrTrace:
    """Записує коротку трасу ядра і розкладає час по драйверах."""

    def __init__(self, seconds=15):
        self.seconds = max(5, min(120, int(seconds)))
        self.running = False
        self.progress = 0.0
        self.stage = ""
        self.result = None
        self.error = None
        self.cancelled = False
        self._session = None    # (спосіб, ім'я) активної сесії — для прибирання
        self.diag = []          # покроковий журнал для налагодження

    def cancel(self):
        """Перервати трасування на вимогу користувача."""
        self.cancelled = True
        self._say("Скасовано користувачем")
        self._cleanup()

    def _cleanup(self):
        """Гарантовано зупинити будь-яку сесію, яку ми могли залишити."""
        t = tools()
        try:
            if t.get("logman"):
                for name in ("PCMonDpcIsr", "NT Kernel Logger"):
                    _run([t["logman"], "stop", name, "-ets"], timeout=45)
        except Exception:
            pass
        try:
            if t.get("wpr"):
                _run([t["wpr"], "-cancel"], timeout=45)
        except Exception:
            pass

    def _say(self, stage, detail=""):
        self.stage = stage
        self.diag.append({"t": round(time.time(), 3), "stage": stage, "detail": detail[:800]})
        log.info("[%s] %s", stage, detail[:300])

    def run(self):
        self.running = True
        self.progress = 0.05
        tmp = None
        try:
            if not IS_WIN:
                raise RuntimeError("лише для Windows")
            if not is_admin():
                raise RuntimeError("потрібні права адміністратора — запусти монітор "
                                   "через install.bat або від імені адміністратора")
            t = tools()
            self._say("Пошук інструментів",
                      ", ".join(f"{k}={'є' if v else 'нема'}" for k, v in t.items()))
            if not t["wpr"] and not t["tracelog"]:
                raise RuntimeError("не знайдено wpr.exe — трасування недоступне")

            tmp = tempfile.mkdtemp(prefix="pcmon_dpc_")
            etl = os.path.join(tmp, "trace.etl")

            # --- 1. запис траси -------------------------------------------
            self._say("Готую трасування", "прибираю сесії від попередніх разів")
            self._cleanup()

            started = False
            # -- спосіб 1: logman (вбудований, легкий, зупиняється миттєво) --
            if t["logman"]:
                for name, keys in LOGMAN_ATTEMPTS:
                    if self.cancelled:
                        raise RuntimeError("скасовано")
                    rc, out = _run([t["logman"], "create", "trace", name,
                                    "-p", "Windows Kernel Trace", keys,
                                    "-o", etl, "-ets",
                                    "-bs", "64", "-nb", "16", "64"], timeout=90)
                    if rc == 0:
                        started = True
                        self._session = ("logman", name)
                        self._say("Трасування почалось", f"logman, сесія «{name}», події {keys}")
                        break
                    self._say("Спроба не вдалась", f"{name} {keys}: {out[:200]}")

            # -- спосіб 2: wpr із НАШИМ полегшеним профілем -------------------
            if not started and t["wpr"]:
                prof = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpcisr.wprp")
                if os.path.isfile(prof):
                    rc, out = _run([t["wpr"], "-start", f"{prof}!DpcIsrLight", "-filemode"],
                                   timeout=120)
                    if rc == 0:
                        started = True
                        self._session = ("wpr", None)
                        self._say("Трасування почалось", "wpr, полегшений профіль")
                    else:
                        self._say("wpr не прийняв профіль", out[:400])

            if not started:
                raise RuntimeError(
                    "не вдалося почати трасування подій ядра. Найчастіша причина — "
                    "монітор запущено без прав адміністратора. Деталі — у "
                    "технічних подробицях нижче.")

            # --- запис із можливістю перервати ------------------------------
            self._say("Записую", f"{self.seconds} с")
            t_end = time.time() + self.seconds
            while time.time() < t_end:
                if self.cancelled:
                    raise RuntimeError("скасовано")
                time.sleep(0.25)
                self.progress = 0.10 + 0.55 * (1 - (t_end - time.time()) / self.seconds)

            # --- зупинка ----------------------------------------------------
            self._say("Зупиняю трасування")
            kind, name = self._session
            if kind == "logman":
                rc, out = _run([t["logman"], "stop", name, "-ets"], timeout=120)
            else:
                # wpr зшиває трасу; для нашого легкого профілю це швидко,
                # але все одно з обмеженням часу
                rc, out = _run([t["wpr"], "-stop", etl], timeout=240)
            self._session = None
            if not os.path.isfile(etl):
                raise RuntimeError(f"трасу не збережено: {out[:300]}")
            size = os.path.getsize(etl)
            self._say("Трасу записано", f"{size/1048576:.1f} МБ")
            self.progress = 0.7

            # --- 2. список драйверів --------------------------------------
            mods = kernel_modules()
            self._say("Драйверів у пам'яті", str(len(mods)))

            # --- 3. розбір -------------------------------------------------
            drivers, source, stats = [], None, {}
            if t["xperf"]:
                self._say("Розбираю через xperf")
                rc, out = _run([t["xperf"], "-i", etl, "-a", "dpcisr"], timeout=600)
                if rc == 0 and out:
                    drivers = _parse_xperf(out)
                    source = "xperf"
                    self._say("xperf дав рядків", str(len(drivers)))
                    if not drivers:
                        # зберігаємо сирий звіт, щоб було видно справжній формат
                        try:
                            rp = os.path.join(BASE_DIR, "xperf_report.txt")
                            with io.open(rp, "w", encoding="utf-8", errors="replace") as f:
                                f.write(out)
                            self._say("Сирий звіт xperf збережено", rp)
                        except Exception:
                            pass
                        head = [l for l in out.splitlines() if l.strip()][:12]
                        self._say("Початок звіту xperf", " ⏎ ".join(head))
                else:
                    self._say("xperf не впорався", out[:300])

            if not drivers and t["tracerpt"]:
                self._say("Розбираю через tracerpt")
                csvf = os.path.join(tmp, "dump.csv")
                rc, out = _run([t["tracerpt"], etl, "-o", csvf, "-of", "CSV", "-y"],
                               timeout=900)
                if os.path.isfile(csvf):
                    self._say("CSV отримано", f"{os.path.getsize(csvf)/1048576:.1f} МБ")
                    drivers, stats = _parse_tracerpt_csv(csvf, mods)
                    source = "tracerpt"
                    self._say("Розібрано подій",
                              f"DPC={stats.get('dpc')} ISR={stats.get('isr')} "
                              f"впізнано={stats.get('mapped')} ні={stats.get('unmapped')}")
                    self._say("Діапазон адрес драйверів", stats.get("addr_range") or "?")
                    if stats.get("columns"):
                        self._say("Колонки CSV", ", ".join(stats["columns"][:18]))
                    if stats.get("sample"):
                        self._say("Приклад рядка", " | ".join(str(x) for x in stats["sample"]))
                    if stats.get("mapped", 0) == 0 and stats.get("dpc", 0):
                        self._say("Увага", "події знайдено, але жодної адреси не "
                                           "вдалося зіставити з драйвером — надішли "
                                           "ці подробиці розробнику")
                else:
                    self._say("tracerpt не дав CSV", out[:400])

            self.progress = 0.95
            if not drivers:
                raise RuntimeError(
                    "трасу записано, але розібрати її не вдалося. "
                    "Найнадійніше рішення — встановити безкоштовний Windows "
                    "Performance Toolkit (частина Windows ADK): тоді з'явиться "
                    "xperf.exe і розбір стане точним.")

            for d in drivers:
                d["total"] = d.get("dpc_count", 0) + d.get("isr_count", 0)
                if d.get("usec"):
                    d["avg_us"] = round(d["usec"] / max(1, d["total"]), 1)
            drivers.sort(key=lambda x: -(x.get("usec") or x.get("total") or 0))

            self.result = {
                "source": source,
                "seconds": self.seconds,
                "etl_mb": round(size / 1048576, 1),
                "modules": len(mods),
                "drivers": drivers[:40],
                "stats": stats,
                "hints": _driver_hints(drivers),
            }
            self._say("Готово", f"драйверів у звіті: {len(drivers)}")
        except Exception as e:
            self.error = "скасовано" if self.cancelled else str(e)
            self._say("Помилка", str(e))
        finally:
            # ЗАВЖДИ прибираємо за собою — щоб сесія трасування не лишилась
            # крутитись у фоні й не з'їдала диск
            try:
                if self._session:
                    self._cleanup()
                    self._session = None
            except Exception:
                pass
            self.running = False
            self.progress = 1.0
            if tmp:
                try:
                    shutil.rmtree(tmp, ignore_errors=True)
                except Exception:
                    pass

    def status(self):
        return {"running": self.running, "progress": round(self.progress, 3),
                "stage": self.stage, "error": self.error,
                "result": self.result, "diag": self.diag[-25:]}


def selftest():
    """
    Швидка перевірка (кілька секунд): чи взагалі працює трасування на цій
    машині. Пише 2-секундну трасу і одразу зупиняє. Потрібна, щоб не чекати
    хвилинами і не дізнаватись про проблему в кінці.
    """
    out = {"ok": False, "admin": is_admin(), "tools": tools(), "steps": []}

    def step(name, detail=""):
        out["steps"].append({"stage": name, "detail": str(detail)[:400]})

    if not IS_WIN:
        step("Перевірка", "не Windows")
        out["error"] = "лише для Windows"
        return out
    if not out["admin"]:
        out["error"] = ("потрібні права адміністратора — трасування подій ядра "
                        "без них Windows не дозволяє")
        step("Права", "немає прав адміністратора")
        return out

    t = out["tools"]
    step("Інструменти", ", ".join(f"{k}={'є' if v else 'нема'}" for k, v in t.items()))
    out["modules"] = len(kernel_modules())
    step("Драйверів у пам'яті", out["modules"])

    if not t.get("logman") and not t.get("wpr"):
        out["error"] = "не знайдено ні logman.exe, ні wpr.exe"
        return out

    tmp = tempfile.mkdtemp(prefix="pcmon_test_")
    etl = os.path.join(tmp, "t.etl")
    try:
        # прибрати можливі залишки
        if t.get("logman"):
            for nm in ("PCMonDpcIsr", "NT Kernel Logger"):
                _run([t["logman"], "stop", nm, "-ets"], timeout=30)
        if t.get("wpr"):
            _run([t["wpr"], "-cancel"], timeout=30)

        ok_name = None
        if t.get("logman"):
            for name, keys in LOGMAN_ATTEMPTS:
                rc, o = _run([t["logman"], "create", "trace", name,
                              "-p", "Windows Kernel Trace", keys,
                              "-o", etl, "-ets", "-bs", "64", "-nb", "8", "16"],
                             timeout=60)
                if rc == 0:
                    ok_name = name
                    step("Трасування стартує", f"{name} {keys}")
                    break
                step("Спроба не вдалась", f"{name} {keys}: {o[:200]}")
        if not ok_name:
            out["error"] = ("не вдалося почати трасування подій ядра — "
                            "подробиці в кроках вище")
            return out

        time.sleep(2)
        rc, o = _run([t["logman"], "stop", ok_name, "-ets"], timeout=60)
        step("Зупинка", f"код {rc}")
        size = os.path.getsize(etl) if os.path.isfile(etl) else 0
        step("Файл траси", f"{size/1024:.0f} КБ")
        if size <= 0:
            out["error"] = "трасу почато, але файл порожній"
            return out

        # чи вміємо розібрати
        if t.get("xperf"):
            out["parser"] = "xperf"
            step("Розбір", "буде через xperf — найточніший")
        elif t.get("tracerpt"):
            csvf = os.path.join(tmp, "d.csv")
            rc, o = _run([t["tracerpt"], etl, "-o", csvf, "-of", "CSV", "-y"], timeout=180)
            if os.path.isfile(csvf) and os.path.getsize(csvf) > 0:
                mods = kernel_modules()
                drivers, stats = _parse_tracerpt_csv(csvf, mods)
                out["parser"] = "tracerpt"
                step("Пробний розбір",
                     f"подій DPC={stats.get('dpc')} ISR={stats.get('isr')}, "
                     f"впізнано драйверів={len(drivers)}")
                if not stats.get("dpc") and not stats.get("isr"):
                    step("Увага", "у CSV не знайдено подій DPC/ISR — "
                                  "для точного розбору краще встановити xperf")
                    out["parse_warning"] = True
            else:
                step("tracerpt", f"CSV не створено: {o[:200]}")
                out["parse_warning"] = True
                out["parser"] = "tracerpt (невідомо)"
        else:
            out["error"] = "немає чим розібрати трасу (немає tracerpt і xperf)"
            return out

        out["ok"] = True
        return out
    except Exception as e:
        out["error"] = str(e)
        step("Помилка", str(e))
        return out
    finally:
        try:
            if t.get("logman"):
                for nm in ("PCMonDpcIsr", "NT Kernel Logger"):
                    _run([t["logman"], "stop", nm, "-ets"], timeout=30)
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


# Найвідоміші «важкі» драйвери — щоб підказати, що саме за файлом ховається
KNOWN_DRIVERS = {
    "ndis.sys": "мережева підсистема Windows — зазвичай страждає через драйвер адаптера",
    "nvlddmkm.sys": "драйвер відеокарти NVIDIA",
    "amdkmdag.sys": "драйвер відеокарти AMD",
    "igdkmd64.sys": "драйвер вбудованої графіки Intel",
    "tcpip.sys": "мережевий стек Windows",
    "storport.sys": "підсистема накопичувачів",
    "stornvme.sys": "драйвер NVMe-накопичувача",
    "usbxhci.sys": "контролер USB 3.0",
    "usbport.sys": "контролер USB",
    "hdaudbus.sys": "звукова шина HD Audio",
    "portcls.sys": "звукова підсистема",
    "wdf01000.sys": "каркас драйверів Windows — винен той драйвер, що на ньому",
    "acpi.sys": "керування живленням ACPI",
    "dxgkrnl.sys": "графічне ядро DirectX",
    "athw8x.sys": "Wi-Fi Atheros",
    "netwtw10.sys": "Wi-Fi Intel",
    "netwtw08.sys": "Wi-Fi Intel",
    "rt640x64.sys": "мережева карта Realtek",
    "e1d68x64.sys": "мережева карта Intel",
    "vmswitch.sys": "віртуальний комутатор Hyper-V (WSL, Docker)",
    "vmbus.sys": "шина Hyper-V (WSL, Docker)",
    "vboxnetflt.sys": "мережевий фільтр VirtualBox",
    "vmnetbridge.sys": "мережевий міст VMware",
    "killer": "мережева карта Killer — сумно відома причина затримок",
    "rtwlan": "Wi-Fi Realtek",
    "bthport.sys": "Bluetooth",
    "hidusb.sys": "USB-пристрої вводу",
}


def _driver_hints(drivers):
    out = []
    for d in drivers[:5]:
        nm = (d.get("driver") or "").lower()
        for key, why in KNOWN_DRIVERS.items():
            if isinstance(key, str) and key and key in nm:
                out.append(f"{d['driver']} — {why}")
                break
    if not out:
        out.append("Найбільше часу забрав драйвер угорі таблиці. Пошукай його ім'я "
                   "в інтернеті — так дізнаєшся, якому пристрою він належить.")
    out.append("Далі: онови саме цей драйвер із сайту виробника пристрою, "
               "а не через «Диспетчер пристроїв».")
    return out
