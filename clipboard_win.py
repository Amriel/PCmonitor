# -*- coding: utf-8 -*-
"""
PC Monitor — діагностика буфера обміну (Windows).

ЧОМУ БУФЕР ВЗАГАЛІ ЛАГАЄ
Буфер обміну в Windows — це одна спільна на всю систему річ, до якої програми
звертаються по черзі. Щоб щось покласти або взяти, програма мусить спершу
«відкрити» буфер, і поки він відкритий, усі інші чекають. Звідси два класичні
джерела гальм:

1) ХТОСЬ ТРИМАЄ БУФЕР ВІДКРИТИМ. Якщо програма відкрила буфер і не закрила
   (підвисла, крива обробка помилок) — уся система не може ні скопіювати, ні
   вставити. Це визначається точно: Windows каже, чиє вікно тримає буфер.

2) БАГАТО СЛУХАЧІВ. Кожну зміну буфера Windows розсилає всім програмам, які
   підписались: менеджери буфера, синхронізація між комп'ютерами, менеджери
   зображень, скріншотилки. Кожна отримує сповіщення і лізе читати вміст.
   З картинками це особливо помітно: знімок екрана 4K у буфері — це десятки
   мегабайтів, і кожен слухач копіює їх собі. Тому текст вставляється миттєво,
   а картинка «думає».

3) ВІДКЛАДЕНЕ МАЛЮВАННЯ. Програма може покласти в буфер не саму картинку, а
   обіцянку віддати її на запит. Тоді гальмує вже момент вставки, і винна
   програма-джерело, а не та, куди вставляєш.

Що робить цей модуль: заміряє, скільки НАСПРАВДІ триває звернення до буфера,
показує, хто тримає буфер і хто його власник, що зараз усередині та якого
розміру, і перелічує запущені програми, які відомо що стежать за буфером.

Безпечність: вміст буфера НЕ читається і нікуди не зберігається — лише типи
даних і їхній розмір. Уся робота йде в окремому потоці з жорстким обмеженням
часу, щоб підвислий буфер не підвісив монітор.
"""
import logging
import sys
import threading
import time

log = logging.getLogger("pcmon.clipboard")
IS_WIN = sys.platform == "win32"

# Стандартні формати буфера обміну
CF = {
    1: ("Текст", "text"),
    2: ("Растрове зображення (BITMAP)", "image"),
    3: ("Метафайл", "image"),
    6: ("TIFF", "image"),
    7: ("Текст OEM", "text"),
    8: ("Зображення DIB", "image"),
    9: ("Палітра", "other"),
    11: ("RIFF", "other"),
    12: ("Звук WAVE", "other"),
    13: ("Текст Unicode", "text"),
    14: ("Метафайл EMF", "image"),
    15: ("Список файлів", "files"),
    16: ("Локаль", "other"),
    17: ("Зображення DIBv5", "image"),
}

IMAGE_FORMAT_HINTS = ("png", "bitmap", "dib", "jpeg", "jpg", "gif", "tiff", "image")

# Програми, які, як відомо, стежать за буфером обміну.
# Це НЕ означає «шкідливі» — просто кожна з них додає роботи на кожну копію,
# і саме вони найчастіше винні в гальмах із картинками.
KNOWN_WATCHERS = {
    # синхронізація буфера між комп'ютерами — найважчий випадок для картинок
    "logioptionsplus_agent.exe": ("Logitech Options+ (Flow)",
                                  "синхронізує буфер між комп'ютерами — картинки "
                                  "передаються мережею, це помітно гальмує", "high"),
    "logioptions.exe": ("Logitech Options (Flow)", "синхронізація буфера між ПК", "high"),
    "mousewithoutborders.exe": ("Mouse Without Borders",
                                "спільний буфер між комп'ютерами", "high"),
    "synergy.exe": ("Synergy", "спільний буфер між комп'ютерами", "high"),
    "barrier.exe": ("Barrier", "спільний буфер між комп'ютерами", "high"),
    "input director.exe": ("Input Director", "спільний буфер між комп'ютерами", "high"),
    "rdpclip.exe": ("Буфер віддаленого робочого столу (сервер)",
                    "синхронізує буфер із RDP-сеансом", "high"),
    # Клієнти віддаленого робочого столу. Вони перехоплюють КОЖНЕ копіювання,
    # щоб передати його в сеанс. З великою картинкою це помітно, а якщо сеанс
    # відвалився чи гальмує — програма може тримати буфер відкритим, і тоді
    # копіювання не працює НІДЕ в системі, навіть поза RDP.
    "msrdc.exe": ("Remote Desktop / Windows App (клієнт)",
                  "перехоплює буфер, щоб передати його у віддалений сеанс — "
                  "часта причина зависань копіювання, особливо з картинками", "high"),
    "mstsc.exe": ("Підключення до віддаленого робочого столу",
                  "передає буфер у віддалений сеанс", "high"),
    "msrdcw.exe": ("Remote Desktop (вікно клієнта)",
                   "передає буфер у віддалений сеанс", "high"),
    "vmtoolsd.exe": ("VMware Tools", "синхронізація буфера з віртуальною машиною", "med"),
    "vboxtray.exe": ("VirtualBox Guest", "синхронізація буфера з ВМ", "med"),
    "teamviewer.exe": ("TeamViewer", "передає буфер віддаленій стороні", "med"),
    "anydesk.exe": ("AnyDesk", "передає буфер віддаленій стороні", "med"),
    "parsec.exe": ("Parsec", "передає буфер віддаленій стороні", "med"),
    # менеджери буфера
    "ditto.exe": ("Ditto", "менеджер буфера — зберігає історію копіювань", "med"),
    "copyq.exe": ("CopyQ", "менеджер буфера", "med"),
    "clipboardfusion.exe": ("ClipboardFusion", "менеджер буфера", "med"),
    "clipdiary.exe": ("Clipdiary", "менеджер буфера", "med"),
    "arsclip.exe": ("ArsClip", "менеджер буфера", "med"),
    "clipx.exe": ("ClipX", "менеджер буфера", "med"),
    "1clipboard.exe": ("1Clipboard", "менеджер буфера", "med"),
    "powertoys.exe": ("PowerToys", "історія буфера / розширене вставляння", "med"),
    # менеджери зображень і скріншотилки — реагують саме на картинки
    "eagle.exe": ("Eagle", "менеджер зображень — стежить за картинками в буфері", "high"),
    "sharex.exe": ("ShareX", "знімки екрана — перехоплює зображення", "med"),
    "greenshot.exe": ("Greenshot", "знімки екрана", "med"),
    "lightshot.exe": ("Lightshot", "знімки екрана", "med"),
    "snagit32.exe": ("Snagit", "знімки екрана", "med"),
    "snagiteditor.exe": ("Snagit Editor", "знімки екрана", "med"),
    "flameshot.exe": ("Flameshot", "знімки екрана", "med"),
    "picpick.exe": ("PicPick", "знімки екрана", "med"),
    # хмари й інше
    "megasync.exe": ("MEGAsync", "може перехоплювати зображення для вивантаження", "med"),
    "dropbox.exe": ("Dropbox", "перехоплення знімків екрана", "med"),
    "onedrive.exe": ("OneDrive", "перехоплення знімків екрана", "med"),
    "displayfusion.exe": ("DisplayFusion", "має функції роботи з буфером", "med"),
    "streamdeck.exe": ("Stream Deck", "може використовувати буфер у діях", "low"),
    "autohotkey.exe": ("AutoHotkey", "скрипти часто працюють із буфером", "low"),
    "phraseexpress.exe": ("PhraseExpress", "розгортання скорочень через буфер", "med"),
    "textexpander.exe": ("TextExpander", "розгортання скорочень через буфер", "med"),
    "punto.exe": ("Punto Switcher", "працює з буфером", "med"),
    "punto switcher.exe": ("Punto Switcher", "працює з буфером", "med"),
}


def _win():
    import ctypes
    from ctypes import wintypes
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    u.OpenClipboard.argtypes = [wintypes.HWND]
    u.OpenClipboard.restype = wintypes.BOOL
    u.CloseClipboard.restype = wintypes.BOOL
    u.GetOpenClipboardWindow.restype = wintypes.HWND
    u.GetClipboardOwner.restype = wintypes.HWND
    u.GetClipboardViewer.restype = wintypes.HWND
    u.GetClipboardSequenceNumber.restype = wintypes.DWORD
    u.EnumClipboardFormats.argtypes = [wintypes.UINT]
    u.EnumClipboardFormats.restype = wintypes.UINT
    u.GetClipboardFormatNameW.argtypes = [wintypes.UINT, wintypes.LPWSTR, ctypes.c_int]
    u.GetClipboardFormatNameW.restype = ctypes.c_int
    u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    u.GetWindowThreadProcessId.restype = wintypes.DWORD
    u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    u.GetClipboardData.argtypes = [wintypes.UINT]
    u.GetClipboardData.restype = wintypes.HANDLE
    k.GlobalSize.argtypes = [wintypes.HANDLE]
    k.GlobalSize.restype = ctypes.c_size_t
    return ctypes, wintypes, u, k


def _proc_of_hwnd(u, ctypes, wintypes, hwnd):
    """Яка програма стоїть за цим вікном."""
    if not hwnd:
        return None
    pid = wintypes.DWORD(0)
    try:
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    except Exception:
        return None
    if not pid.value:
        return None
    info = {"pid": pid.value, "name": None, "exe": None, "title": None,
            "class": None, "background": False}
    try:
        buf = ctypes.create_unicode_buffer(256)
        u.GetWindowTextW(hwnd, buf, 256)
        info["title"] = buf.value or None
        # вікно без заголовка = службове, невидиме. Саме такі лишаються
        # висіти у фоні після закриття програми і тримають буфер.
        info["background"] = not bool(buf.value)
        u.GetClassNameW(hwnd, buf, 256)
        info["class"] = buf.value or None
    except Exception:
        pass
    try:
        import psutil
        p = psutil.Process(pid.value)
        info["name"] = p.name()
        try:
            info["exe"] = p.exe()
        except Exception:
            pass
        try:
            info["started"] = int(p.create_time())
            par = p.parent()
            info["parent"] = par.name() if par else ""
        except Exception:
            pass
    except Exception:
        pass
    return info


def who_holds():
    """
    Хто ПРЯМО ЗАРАЗ тримає буфер відкритим — короткий рядок для повідомлень.

    Навмисно найдешевша перевірка з усіх: GetOpenClipboardWindow нічого не
    відкриває й нічого не читає, тож її можна викликати навіть тоді, коли буфер
    заблокований і повний diagnose() уже висить. Саме для такого випадку вона
    й потрібна — назвати винуватця, коли решта не встигла.
    """
    try:
        ctypes, wintypes, u, k = _win()
    except Exception:
        return ""
    try:
        hwnd = u.GetOpenClipboardWindow()
        if not hwnd:
            hwnd = u.GetClipboardOwner()
        info = _proc_of_hwnd(u, ctypes, wintypes, hwnd) if hwnd else None
    except Exception:
        return ""
    if not info:
        return ""
    nm = info.get("name") or "невідомий процес"
    return "%s (pid %s)" % (nm, info.get("pid"))


def _probe_once(ctypes, wintypes, u, k, read_sizes=True):
    """Одне звернення до буфера: заміряти час і зібрати відомості."""
    out = {"opened": False, "open_ms": None, "total_ms": None,
           "formats": [], "bytes": 0, "blocker": None, "retries": 0}
    t0 = time.perf_counter()

    # Відкриваємо з повторами: зайнятий буфер — норма, якщо ненадовго
    opened = False
    for attempt in range(5):
        if u.OpenClipboard(None):
            opened = True
            break
        out["retries"] = attempt + 1
        if attempt == 0:
            # хто саме тримає
            out["blocker"] = _proc_of_hwnd(u, ctypes, wintypes, u.GetOpenClipboardWindow())
        time.sleep(0.015)

    out["open_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    if not opened:
        out["total_ms"] = out["open_ms"]
        return out
    out["opened"] = True

    try:
        fmt = 0
        total = 0
        while True:
            fmt = u.EnumClipboardFormats(fmt)
            if not fmt:
                break
            if fmt in CF:
                fname, kind = CF[fmt]
            else:
                buf = ctypes.create_unicode_buffer(256)
                n = u.GetClipboardFormatNameW(fmt, buf, 256)
                fname = buf.value if n else f"формат #{fmt}"
                low = fname.lower()
                kind = "image" if any(h in low for h in IMAGE_FORMAT_HINTS) else "other"
            # ─── ВАЖЛИВО: розмір даних за замовчуванням НЕ читаємо ───────────
            # GetClipboardData змушує програму-джерело віддати дані ПРЯМО ЗАРАЗ,
            # і робить це, поки ми ТРИМАЄМО БУФЕР ВІДКРИТИМ. Якщо джерело
            # малює картинку на запит (відкладене малювання) і гальмує або
            # підвисло — блокується не лише монітор, а буфер обміну всієї
            # системи: жодне копіювання й вставка не працюють.
            #
            # Саме через це попередня версія РОБИЛА проблему з буфером гіршою
            # замість того щоб її діагностувати. Тепер читаємо лише перелік
            # форматів (це безпечно й не торкається даних), а розмір — тільки
            # якщо користувач свідомо попросив.
            size = None
            if read_sizes:
                try:
                    h = u.GetClipboardData(fmt)
                    if h:
                        size = int(k.GlobalSize(h))
                        total += size
                except Exception:
                    size = None
            out["formats"].append({"id": fmt, "name": fname, "kind": kind, "size": size})
        out["bytes"] = total
    finally:
        try:
            u.CloseClipboard()
        except Exception:
            pass
    out["total_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return out


def diagnose(timeout=8.0, read_sizes=False):
    """
    Повна діагностика буфера. Повертає словник із результатами.
    Виконується в окремому потоці з обмеженням часу — підвислий буфер
    не заблокує монітор.

    read_sizes=False за замовчуванням: вимірювання розміру даних вимагає
    їх зчитати, а це може підвісити буфер обміну всієї системи, якщо
    програма-джерело віддає дані повільно. Вмикається лише свідомо.
    """
    if not IS_WIN:
        return {"supported": False, "reason": "лише для Windows"}

    result = {}

    def work():
        try:
            ctypes, wintypes, u, k = _win()
            r = {"supported": True}
            r["seq"] = int(u.GetClipboardSequenceNumber())
            r["owner"] = _proc_of_hwnd(u, ctypes, wintypes, u.GetClipboardOwner())
            r["viewer"] = _proc_of_hwnd(u, ctypes, wintypes, u.GetClipboardViewer())
            held = _proc_of_hwnd(u, ctypes, wintypes, u.GetOpenClipboardWindow())
            r["held_by"] = held

            # три заміри підряд: перший може бути «холодним»
            probes = []
            for i in range(3):
                probes.append(_probe_once(ctypes, wintypes, u, k,
                                          read_sizes=(read_sizes and i == 0)))
                time.sleep(0.05)
            r["probes"] = probes
            ok = [p for p in probes if p["opened"]]
            r["open_ms_best"] = min((p["open_ms"] for p in ok), default=None)
            r["open_ms_worst"] = max((p["open_ms"] for p in ok), default=None)
            r["failed"] = len(probes) - len(ok)
            first = probes[0]
            r["formats"] = first["formats"]
            r["bytes"] = first["bytes"]
            r["blocker"] = next((p["blocker"] for p in probes if p.get("blocker")), None)
            result.update(r)
        except Exception as e:
            log.exception("Помилка діагностики буфера")
            result.update({"supported": True, "error": str(e)})

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {"supported": True, "hung": True,
                "error": "буфер обміну не відповідає — його хтось тримає"}
    if not result:
        return {"supported": True, "error": "не вдалося отримати дані"}
    return result


def is_wslg(exe_path):
    """
    Чи це msrdc.exe від WSLg, а не клієнт віддаленого робочого столу.

    Важлива різниця: WSL для показу графічних програм Linux використовує
    протокол RDP, і разом із ним ставить власну копію msrdc.exe у свою папку.
    Тобто процес називається як RDP-клієнт, але це насправді WSL — і поводиться
    він інакше: сам відроджується (його піднімає WSL) і працює навіть тоді,
    коли віддалений робочий стіл у системі вимкнено.
    """
    p = (exe_path or "").lower().replace("/", "\\")
    return any(m in p for m in (
        "\\wsl\\", "\\windowsapps\\microsoftcorporationii.windowssubsystemforlinux",
        "\\wslg", "\\lxss\\", "wsl2"))


def running_watchers():
    """Які з відомих «слухачів буфера» зараз запущені."""
    out = []
    try:
        import psutil
        seen = {}
        paths = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            nm = (p.info.get("name") or "").lower()
            if nm in KNOWN_WATCHERS:
                seen.setdefault(nm, []).append(p.info["pid"])
                if p.info.get("exe") and nm not in paths:
                    paths[nm] = p.info["exe"]
        for nm, pids in seen.items():
            title, why, level = KNOWN_WATCHERS[nm]
            exe = paths.get(nm, "")
            wslg = nm == "msrdc.exe" and is_wslg(exe)
            if wslg:
                # це не RDP-клієнт, а частина WSL — і причина, і рішення інші
                title = "WSLg (графіка Linux у WSL)"
                why = ("WSL показує графічні програми Linux через протокол RDP і "
                       "разом із цим СИНХРОНІЗУЄ БУФЕР ОБМІНУ, включно з "
                       "картинками. Тому кожне копіювання проходить через нього")
                level = "high"
            out.append({"name": nm, "title": title, "why": why, "exe": exe,
                        "wslg": wslg,
                        "level": level, "count": len(pids), "pids": pids})
        order = {"high": 0, "med": 1, "low": 2}
        out.sort(key=lambda x: order.get(x["level"], 9))
    except Exception:
        pass
    return out


class Watcher:
    """
    Постійне спостереження за буфером — щоб зловити САМЕ ТОЙ момент, коли
    копіювання зривається.

    Чому це потрібно: разова перевірка кнопкою показує стан «зараз», а збій
    (наприклад, знімок екрана не потрапив у буфер) триває секунду й зникає.
    Спостерігач бачить кожну зміну буфера і записує, що саме сталося.

    Навантаження мінімальне: раз на пів секунди питаємо в Windows лічильник
    змін буфера — це один системний виклик, без відкривання буфера. Заглядаємо
    всередину лише тоді, коли лічильник змінився.
    """

    def __init__(self, poll=0.5, keep=300):
        self.poll = poll
        self.keep = keep
        self.events = []
        self.running = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.last_seq = None

    def start(self):
        if not IS_WIN or self.running:
            return False
        self.running = True
        self._stop.clear()
        threading.Thread(target=self._run, name="clipwatch", daemon=True).start()
        return True

    def stop(self):
        self._stop.set()
        self.running = False

    def _add(self, ev):
        with self._lock:
            self.events.append(ev)
            if len(self.events) > self.keep:
                del self.events[:len(self.events) - self.keep]

    def _run(self):
        try:
            ctypes, wintypes, u, k = _win()
        except Exception as e:
            log.info("Спостереження за буфером недоступне: %s", e)
            self.running = False
            return

        self.last_seq = int(u.GetClipboardSequenceNumber())
        while not self._stop.is_set():
            self._stop.wait(self.poll)
            if self._stop.is_set():
                break
            try:
                seq = int(u.GetClipboardSequenceNumber())
                if seq == self.last_seq:
                    continue
                self.last_seq = seq

                # хто поклав — дізнаємось БЕЗ відкривання буфера
                owner = _proc_of_hwnd(u, ctypes, wintypes, u.GetClipboardOwner())
                held = _proc_of_hwnd(u, ctypes, wintypes, u.GetOpenClipboardWindow())

                # read_sizes=False — спостерігач НІКОЛИ не торкається даних буфера
                p = _probe_once(ctypes, wintypes, u, k, read_sizes=False)
                fmts = p.get("formats") or []
                imgs = [f for f in fmts if f["kind"] == "image"]

                # визначаємо, чи це схоже на збій
                problem = None
                if not p["opened"]:
                    problem = "не вдалося відкрити буфер — його хтось тримав"
                elif not fmts:
                    problem = ("буфер змінився, але виявився ПОРОЖНІМ — копіювання "
                               "зірвалося")
                elif p["open_ms"] and p["open_ms"] >= 200:
                    problem = f"дуже повільний доступ: {p['open_ms']:.0f} мс"

                # якщо буфер зараз важкий — робимо паузу, щоб не заважати
                if p.get("open_ms") and p["open_ms"] > 500:
                    log.info("Буфер відповідає повільно (%.0f мс) — пауза",
                             p["open_ms"])
                    self._stop.wait(3)

                self._add({
                    "ts": time.time(), "seq": seq,
                    "owner": (owner or {}).get("name"),
                    "owner_title": (owner or {}).get("title"),
                    "held_by": (held or {}).get("name"),
                    "open_ms": p.get("open_ms"),
                    "retries": p.get("retries"),
                    "formats": [f["name"] for f in fmts][:10],
                    "n_formats": len(fmts),
                    "bytes": p.get("bytes") or 0,
                    "has_image": bool(imgs),
                    "problem": problem,
                })
            except Exception:
                log.exception("Помилка спостереження за буфером")
                self._stop.wait(2)
        self.running = False

    def log(self, limit=60):
        with self._lock:
            evs = list(self.events)[-limit:]
        problems = [e for e in evs if e.get("problem")]
        return {"running": self.running, "events": list(reversed(evs)),
                "total": len(evs), "problems": len(problems)}


def check(diag=None):
    """
    Перевірка для вкладки «Здоров'я».
    diag — уже готовий результат diagnose(), щоб не звертатись до буфера двічі.
    """
    if not IS_WIN:
        return {"status": "skip", "title": "Буфер обміну",
                "detail": "лише для Windows", "items": [], "weight": 1}

    d = diag if diag is not None else diagnose()
    items = []
    status = "ok"
    fix_parts = []

    if d.get("hung") or d.get("error"):
        blocker = (d.get("blocker") or {})
        who = blocker.get("name") or "невідома програма"
        return {"status": "bad", "title": "Буфер обміну заблоковано",
                "detail": d.get("error", ""),
                "items": [{"status": "bad", "name": who,
                           "text": "тримає буфер відкритим — через це не працює "
                                   "ні копіювання, ні вставка"}],
                "fix": ("Закрий або перезапусти цю програму. Якщо повторюється — "
                        "прибери її з автозапуску."),
                "weight": 2}

    # 1. Чи хтось тримає буфер
    blocker = d.get("blocker")
    if blocker:
        bname = (blocker.get("name") or "").lower()
        items.append({"status": "bad",
                      "name": blocker.get("name") or f"pid {blocker.get('pid')}",
                      "text": "тримала буфер відкритим під час перевірки" +
                              (f" · вікно: {blocker['title']}" if blocker.get("title") else "")})
        status = "bad"
        bexe = (blocker.get("exe") or "")
        if bname == "msrdc.exe" and is_wslg(bexe):
            fix_parts.append(
                "Буфер тримає WSLg — частина WSL (Windows Subsystem for Linux).\n\n"
                "Це НЕ віддалений робочий стіл, хоча процес називається msrdc.exe. "
                "WSL показує графічні програми Linux через протокол RDP і разом із "
                "цим синхронізує буфер обміну між Windows і Linux, включно з "
                "картинками. Саме тому:\n"
                "• копіювання картинок гальмує або зривається;\n"
                "• процес відроджується щоразу, коли ти його завершуєш — його "
                "піднімає сама WSL;\n"
                "• це відбувається навіть із вимкненим віддаленим робочим столом.\n\n"
                "Найімовірніше WSL у тебе працює через Docker Desktop.\n\n"
                "РІШЕННЯ. Якщо графічні програми Linux не потрібні (для Docker і "
                "командного рядка вони не потрібні), вимкни WSLg. Створи або "
                "відредагуй файл C:\\Users\\<твоє ім'я>\\.wslconfig:\n\n"
                "    [wsl2]\n"
                "    guiApplications=false\n\n"
                "Потім виконай у командному рядку:  wsl --shutdown\n"
                "Після цього msrdc.exe більше не запускатиметься, а буфер "
                "перестане зависати. Docker працюватиме як і раніше.\n\n"
                "Тимчасовий варіант: просто виконати  wsl --shutdown  коли WSL "
                "не потрібна — процес зникне до наступного запуску Docker.")
        elif bname in ("msrdc.exe", "mstsc.exe", "msrdcw.exe", "rdpclip.exe"):
            bg = blocker.get("background")
            fix_parts.append(
                ("Буфер тримає клієнт віддаленого робочого столу, який ПРАЦЮЄ У "
                 "ФОНІ БЕЗ ВІКНА.\n\n"
                 "Це відома поведінка: після закриття вікна процес часто "
                 "лишається висіти. Вікна не видно, а він далі перехоплює кожне "
                 "копіювання — тому буфер ламається навіть тоді, коли ти нічого "
                 "не робиш через RDP.\n\n"
                 if bg else
                 "Буфер тримає клієнт віддаленого робочого столу. Він перехоплює "
                 "кожне копіювання, щоб передати його в сеанс.\n\n") +
                f"Що зробити:\n"
                f"• Просто зараз: завершити процес «{blocker.get('name')}» "
                f"(PID {blocker.get('pid')}) — кнопка нижче або Диспетчер задач. "
                "Буфер відпустить одразу, нічого не зламається.\n"
                "• Назавжди: у налаштуваннях підключення зняти галочку «Буфер "
                "обміну» в розділі «Локальні ресурси». Тоді копіювання між твоїм "
                "ПК і віддаленим не працюватиме, зате локальний буфер перестане "
                "зависати.\n"
                "• Також варто виходити з клієнта через меню, а не просто "
                "закривати вікно хрестиком.")
        else:
            fix_parts.append(f"Програма «{blocker.get('name')}» тримає буфер обміну. "
                             "Спробуй закрити її й перевірити знову.")

    # 2. Швидкість доступу
    best = d.get("open_ms_best")
    worst = d.get("open_ms_worst")
    if best is not None:
        if worst >= 200:
            st, note = "bad", "дуже повільно — це і є те гальмо, яке відчувається"
            status = "bad"
        elif worst >= 50:
            st, note = "warn", "помітна затримка"
            if status == "ok":
                status = "warn"
        else:
            st, note = "ok", "нормально"
        items.append({"status": st, "name": "Час доступу до буфера",
                      "text": f"{best:.1f}–{worst:.1f} мс — {note}"})
    if d.get("failed"):
        items.append({"status": "warn", "name": "Невдалі спроби відкрити буфер",
                      "text": f"{d['failed']} із 3 — буфер часто зайнятий"})
        if status == "ok":
            status = "warn"

    # 3. Що зараз усередині
    fmts = d.get("formats") or []
    if fmts:
        imgs = [f for f in fmts if f["kind"] == "image"]
        size = d.get("bytes") or 0
        names = ", ".join(f["name"] for f in fmts[:6])
        txt = f"{len(fmts)} форматів: {names}"
        if size:
            txt += f" · разом {size/1048576:.1f} МБ" if size > 1048576 else f" · {size/1024:.0f} КБ"
        st = "info"
        if imgs and size > 20 * 1024 * 1024:
            st = "warn"
            if status == "ok":
                status = "warn"
            fix_parts.append(
                f"Зараз у буфері зображення на {size/1048576:.0f} МБ. Кожна програма, "
                "що стежить за буфером, копіює його собі — звідси затримка саме з "
                "картинками. Копіюй менші зображення або зменш кількість таких програм.")
        items.append({"status": st, "name": "Зараз у буфері", "text": txt})
        if len(fmts) > 12:
            items.append({"status": "warn", "name": "Забагато форматів у буфері",
                          "text": f"{len(fmts)} — програма-джерело поклала багато "
                                  "варіантів того самого вмісту, це сповільнює вставку"})
            if status == "ok":
                status = "warn"
    else:
        items.append({"status": "info", "name": "Зараз у буфері", "text": "порожньо"})

    # 4. Власник вмісту
    own = d.get("owner")
    if own and own.get("name"):
        items.append({"status": "info", "name": "Останнім копіював",
                      "text": own["name"] + (f" · {own['title']}" if own.get("title") else "")})

    # 5. Хто стежить за буфером
    watchers = running_watchers()
    if watchers:
        high = [w for w in watchers if w["level"] == "high"]
        for w in watchers:
            items.append({
                "status": "warn" if w["level"] == "high" else "info",
                "name": w["title"],
                "text": w["why"] + (f" · {w['count']} процеси" if w["count"] > 1 else ""),
            })
        if high and status == "ok":
            status = "warn"
        if len(watchers) >= 3:
            fix_parts.append(
                f"За буфером стежать щонайменше {len(watchers)} програм. Кожна отримує "
                "сповіщення на КОЖНЕ копіювання і читає вміст — із картинками це "
                "складається у відчутну затримку. Найшвидший спосіб перевірити: "
                "закрий їх по черзі й дивись, коли зникне гальмо.")
        if high:
            fix_parts.append(
                "Найпідозріліші: " + ", ".join(w["title"] for w in high) +
                ". Синхронізація буфера між комп'ютерами й менеджери зображень "
                "найважче переносять великі картинки.")

    if not fix_parts and status == "ok":
        fix = None
    else:
        fix = "\n\n".join(fix_parts) if fix_parts else None

    n_watch = len(watchers)
    title = f"Буфер обміну ({n_watch} прогр. стежить)" if n_watch else "Буфер обміну"
    return {"status": status, "title": title, "items": items, "fix": fix, "weight": 1,
            "detail": (f"доступ {best:.0f}–{worst:.0f} мс" if best is not None else "")}
