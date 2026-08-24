"""
Керування процесами — те, заради чого зазвичай відкривають Диспетчер задач.

Тут навмисно немає нічого «розумного»: жодних евристик, жодних автоматичних
дій. Кожна дія відбувається тільки на прямий запит людини, і кожна має
запобіжники, бо помилка тут коштує втраченої роботи або перезавантаження.

Принципи, яких дотримуємось у всіх діях:
  * критичні процеси Windows не чіпаємо взагалі (PROTECTED);
  * ім'я процесу звіряємо з очікуваним — PID у Windows перевикористовуються,
    і без звірки можна влучити в зовсім інший процес;
  * сам монітор себе не завершує й не заморожує;
  * помилка — це завжди зрозумілий текст, а не код.
"""
import logging
import os
import re
import subprocess
import sys
import time

import psutil

log = logging.getLogger("pcmon.procctl")
IS_WIN = sys.platform.startswith("win")

# Процеси, без яких Windows не працює. Диспетчер задач їх теж не дає вбити.
PROTECTED = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
    "memory compression", "secure system", "system idle process", "idle",
    "audiodg.exe", "dwm.exe", "sihost.exe", "ctfmon.exe",
}

# Заморожувати можна не все: підвішений explorer забирає панель задач,
# підвішений аудіодрайвер — звук у всій системі.
NO_SUSPEND = PROTECTED | {"explorer.exe", "shellexperiencehost.exe",
                          "startmenuexperiencehost.exe", "searchhost.exe",
                          "textinputhost.exe", "applicationframehost.exe"}

# Пріоритети: назва -> (константа Windows, значення nice для Linux)
PRIORITIES = [
    ("idle",         "Мінімальний"),
    ("below_normal", "Нижче середнього"),
    ("normal",       "Звичайний"),
    ("above_normal", "Вище середнього"),
    ("high",         "Високий"),
    ("realtime",     "Реального часу"),
]


def _win_prio():
    return {
        "idle": psutil.IDLE_PRIORITY_CLASS,
        "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
        "normal": psutil.NORMAL_PRIORITY_CLASS,
        "above_normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
        "high": psutil.HIGH_PRIORITY_CLASS,
        "realtime": psutil.REALTIME_PRIORITY_CLASS,
    }


# nice для Linux — щоб та сама кнопка працювала й тут (зручно тестувати)
_NICE = {"idle": 19, "below_normal": 10, "normal": 0,
         "above_normal": -5, "high": -10, "realtime": -20}


def prio_name(value):
    """Зворотне перетворення: значення пріоритету -> наш ключ."""
    if IS_WIN:
        for k, v in _win_prio().items():
            if v == value:
                return k
        return "normal"
    try:
        n = int(value)
    except Exception:
        return "normal"
    if n >= 15:
        return "idle"
    if n >= 5:
        return "below_normal"
    if n <= -15:
        return "realtime"
    if n <= -8:
        return "high"
    if n < 0:
        return "above_normal"
    return "normal"


def _open(pid, expect_name=""):
    """
    Взяти процес із перевірками. Повертає (process, помилка).

    Звірка імені — не формальність: у Windows номери процесів швидко
    перевикористовуються, і поки список на екрані «застарів» на кілька секунд,
    під тим самим номером може вже працювати щось інше.
    """
    try:
        pid = int(pid)
    except Exception:
        return None, "невірний номер процесу"
    if pid <= 4:
        return None, "це системний процес — не чіпаємо"
    if pid == os.getpid():
        return None, "це сам монітор"
    try:
        p = psutil.Process(pid)
        nm = (p.name() or "").lower()
    except psutil.NoSuchProcess:
        return None, "процес уже завершився"
    except Exception as e:
        return None, str(e)
    if expect_name and nm != expect_name.lower():
        return None, (f"під номером {pid} зараз інший процес ({nm}) — "
                      "онови список і спробуй ще раз")
    return p, ""


def _gone(p):
    """Процес зупинився? «Зомбі» теж рахуємо зупиненим: він більше не
    виконується, просто чекає, поки батько забере його код виходу."""
    try:
        if not p.is_running():
            return True
        return p.status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True
    except Exception:
        return False


def _terminate(p, hard_after=4.0, total=7.0):
    """Ввічливо, потім примусово. Повертає (ok, помилка)."""
    t0 = time.time()
    try:
        p.terminate()
    except psutil.NoSuchProcess:
        return True, ""
    except psutil.AccessDenied:
        return False, "немає прав завершити цей процес"
    while time.time() - t0 < hard_after:
        if _gone(p):
            return True, ""
        time.sleep(0.15)
    try:
        p.kill()
    except psutil.NoSuchProcess:
        return True, ""
    except Exception:
        pass
    while time.time() - t0 < total:
        if _gone(p):
            return True, ""
        time.sleep(0.15)
    return _gone(p), ("" if _gone(p) else "процес не реагує навіть на примусове "
                                          "завершення")


# =====================================================================
#  ДІЇ
# =====================================================================
def kill(pid, expect_name="", tree=False):
    p, err = _open(pid, expect_name)
    if err:
        return {"ok": False, "error": err}
    nm = (p.name() or "").lower()
    if nm in PROTECTED:
        return {"ok": False, "error":
                f"«{nm}» — критичний процес Windows. Його завершення зламає "
                "систему або спричинить перезавантаження, тому монітор цього "
                "не робить."}

    victims = [p]
    if tree:
        try:
            kids = p.children(recursive=True)
        except Exception:
            kids = []
        # Свій же процес і захищені у список не потрапляють. Дітей завершуємо
        # ПЕРШИМИ: інакше батько встигне помітити падіння й перезапустити їх.
        me = os.getpid()
        kids = [c for c in kids
                if c.pid != me and (c.name() or "").lower() not in PROTECTED]
        victims = kids + [p]

    killed, failed = 0, []
    for v in victims:
        ok, e = _terminate(v)
        if ok:
            killed += 1
        else:
            try:
                failed.append(f"{v.name()} (pid {v.pid}): {e}")
            except Exception:
                failed.append(f"pid {v.pid}: {e}")
    log.info("Завершено %s: %d процес(ів)%s", nm, killed,
             " з помилками" if failed else "")
    if killed == 0:
        return {"ok": False, "error": failed[0] if failed else "не вдалося"}
    return {"ok": True, "killed": killed, "total": len(victims),
            "failed": failed,
            "note": (f"завершено {killed} із {len(victims)}" if len(victims) > 1
                     else "")}


# Заморожені НАМИ процеси. Потрібен саме власний облік, а не опитування
# системи: у Windows psutil не показує «заморожений» окремим станом, тож
# інакше ми б не змогли ані показати список, ані відморозити його назад.
# І головне — заморожений процес не відмерзне сам. Якщо закрити монітор і
# забути про нього, програма зависне назавжди, а причина буде невидима.
# Тому при зупинці монітора все заморожене відпускаємо (див. resume_all).
_SUSPENDED = {}


def frozen():
    """Список заморожених нами процесів, без тих, що вже завершились."""
    out = []
    for pid, meta in list(_SUSPENDED.items()):
        try:
            p = psutil.Process(pid)
            if p.name() != meta["name"]:
                raise psutil.NoSuchProcess(pid)
        except Exception:
            _SUSPENDED.pop(pid, None)
            continue
        out.append({"pid": pid, "name": meta["name"],
                    "since": meta["ts"], "seconds": int(time.time() - meta["ts"])})
    return out


def resume_all():
    """Відпустити все, що ми заморозили. Викликається при зупинці монітора."""
    freed = []
    for pid, meta in list(_SUSPENDED.items()):
        try:
            psutil.Process(pid).resume()
            freed.append(meta["name"])
        except Exception:
            pass
        _SUSPENDED.pop(pid, None)
    if freed:
        log.info("Відпущено заморожені процеси перед виходом: %s",
                 ", ".join(freed))
    return freed


def suspend(pid, expect_name="", resume=False):
    p, err = _open(pid, expect_name)
    if err:
        return {"ok": False, "error": err}
    nm = (p.name() or "").lower()
    if not resume and nm in NO_SUSPEND:
        return {"ok": False, "error":
                f"«{nm}» заморожувати не можна — від нього залежить робота "
                "самої системи (панель задач, звук, вхід у систему)."}
    try:
        if resume:
            p.resume()
        else:
            p.suspend()
    except psutil.AccessDenied:
        return {"ok": False, "error": "немає прав на цей процес"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "процес уже завершився"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    if resume:
        _SUSPENDED.pop(p.pid, None)
    else:
        _SUSPENDED[p.pid] = {"name": p.name(), "ts": time.time()}
    log.info("%s процес %s (pid %s)",
             "Відновлено" if resume else "Заморожено", nm, pid)
    return {"ok": True, "suspended": not resume, "frozen": frozen(),
            "note": ("відновлено" if resume else
                     "заморожено — процес нічого не робить, але лишається "
                     "в пам'яті. Монітор відпустить його автоматично при "
                     "виході, щоб програма не зависла назавжди.")}


def set_priority(pid, level, expect_name=""):
    p, err = _open(pid, expect_name)
    if err:
        return {"ok": False, "error": err}
    if level not in dict(PRIORITIES):
        return {"ok": False, "error": "невідомий пріоритет"}
    nm = (p.name() or "").lower()
    if nm in PROTECTED:
        return {"ok": False, "error": f"«{nm}» — системний процес, не чіпаємо"}
    if level == "realtime":
        # «Реального часу» здатний підвісити мишу й клавіатуру: такий процес
        # витісняє навіть драйвери вводу. Диспетчер задач тут теж попереджає.
        return {"ok": False, "error":
                "пріоритет «реального часу» монітор не ставить: процес із ним "
                "витісняє драйвери вводу, і система може перестати реагувати "
                "на мишу та клавіатуру. Постав «Високий» — різниця мінімальна."}
    try:
        p.nice(_win_prio()[level] if IS_WIN else _NICE[level])
    except psutil.AccessDenied:
        return {"ok": False, "error": "немає прав змінити пріоритет цього процесу"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "процес уже завершився"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    log.info("Пріоритет %s (pid %s) -> %s", nm, pid, level)
    return {"ok": True, "priority": level,
            "note": "діє лише до завершення процесу — при наступному запуску "
                    "пріоритет буде звичайний"}


def set_affinity(pid, cores, expect_name=""):
    p, err = _open(pid, expect_name)
    if err:
        return {"ok": False, "error": err}
    ncpu = psutil.cpu_count() or 1
    try:
        cores = sorted({int(c) for c in cores if 0 <= int(c) < ncpu})
    except Exception:
        return {"ok": False, "error": "невірний список ядер"}
    if not cores:
        return {"ok": False, "error": "треба лишити хоча б одне ядро"}
    try:
        p.cpu_affinity(cores)
    except psutil.AccessDenied:
        return {"ok": False, "error": "немає прав змінити прив'язку цього процесу"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "процес уже завершився"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    log.info("Прив'язка %s (pid %s) -> %s", p.name(), pid, cores)
    return {"ok": True, "affinity": cores,
            "note": f"процес працюватиме лише на {len(cores)} з {ncpu} ядер"}


def open_folder(pid=None, path=""):
    """Показати файл програми у Провіднику."""
    if not path and pid:
        p, err = _open(pid)
        if err:
            return {"ok": False, "error": err}
        try:
            path = p.exe()
        except Exception:
            return {"ok": False, "error": "не вдалося дізнатись шлях до файлу"}
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "файл не знайдено на диску"}
    if not IS_WIN:
        return {"ok": False, "error": "лише для Windows"}
    try:
        # /select підсвічує сам файл, а не просто відкриває теку
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


# =====================================================================
#  ЩО ЦЕ НАСПРАВДІ
# =====================================================================
# «pythonw.exe» — це не програма, це інтерпретатор. Під одним іменем можуть
# працювати п'ять зовсім різних задач, і по імені процесу їх не розрізнити.
# Те саме з node, java, electron, cmd, powershell. Тому для таких процесів
# справжня назва — це те, ЩО вони виконують, і дістати її можна лише з
# командного рядка.
INTERPRETERS = {
    "python.exe": "py", "pythonw.exe": "py", "python3.exe": "py", "python": "py",
    "python3": "py", "pythonw": "py",
    "node.exe": "js", "node": "js", "bun.exe": "js", "deno.exe": "js",
    "java.exe": "java", "javaw.exe": "java", "java": "java",
    "cmd.exe": "shell", "powershell.exe": "shell", "pwsh.exe": "shell",
    "wscript.exe": "script", "cscript.exe": "script",
    "rundll32.exe": "dll", "dllhost.exe": "dll", "regsvr32.exe": "dll",
    "electron.exe": "electron", "ruby.exe": "rb", "perl.exe": "pl",
    "php.exe": "php", "dotnet.exe": "dotnet",
}

_SCRIPT_EXT = (".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".jar", ".rb",
               ".pl", ".php", ".ps1", ".bat", ".cmd", ".vbs", ".dll", ".sh")


def _split_args(cmdline):
    """Розбити командний рядок Windows на аргументи, поважаючи лапки."""
    out, cur, q = [], "", False
    for ch in cmdline or "":
        if ch == '"':
            q = not q
        elif ch.isspace() and not q:
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def identify(name, cmdline, exe="", cwd=""):
    """
    Пояснити, ЩО виконує процес.

    Повертає {"kind", "what", "detail"}:
      kind   — тип ("py", "js", …) або "" для звичайної програми;
      what   — коротка назва задачі, придатна для списку;
      detail — звідки саме (тека), щоб відрізнити однойменні скрипти.
    """
    low = (name or "").lower()
    args_all = _split_args(cmdline)

    # svchost — та сама історія, що й python: 90 процесів з однією назвою.
    # Реальна відповідь на «що це» захована в ключі -k.
    if low == "svchost.exe":
        for i, a in enumerate(args_all):
            if a.lower() == "-k" and i + 1 < len(args_all):
                return {"kind": "svc", "what": "група служб " + args_all[i + 1],
                        "detail": "точні служби видно в «Автозапуску»"}
        return {"kind": "svc", "what": "службовий вузол", "detail": ""}

    kind = INTERPRETERS.get(low, "")
    if not kind:
        return {"kind": "", "what": "", "detail": ""}
    args = args_all[1:]                    # без самого інтерпретатора

    # шукаємо перший аргумент, схожий на файл скрипта
    script = ""
    for a in args:
        if a.startswith("-"):
            continue
        if a.lower().endswith(_SCRIPT_EXT):
            script = a
            break
    if not script:
        # варіанти без імені файлу: -m пакет, -jar файл, -c код
        for i, a in enumerate(args):
            if a in ("-m", "--module") and i + 1 < len(args):
                return {"kind": kind, "what": "модуль " + args[i + 1],
                        "detail": cwd or ""}
            if a == "-jar" and i + 1 < len(args):
                script = args[i + 1]
                break
            if a in ("-c", "-Command", "-EncodedCommand"):
                return {"kind": kind, "what": "код у командному рядку",
                        "detail": (" ".join(args[i + 1:]))[:120]}
        if not script:
            first = next((a for a in args if not a.startswith("-")), "")
            return {"kind": kind,
                    "what": first[:80] if first else "інтерактивний сеанс",
                    "detail": cwd or ""}

    norm = script.replace("/", "\\")
    base = norm.rstrip("\\").split("\\")[-1]
    folder = "\\".join(norm.split("\\")[:-1])
    if not folder and cwd:
        folder = cwd
    # для віртуальних середовищ корисніший проєкт, а не сам .venv
    parts = [p for p in folder.split("\\")
             if p and not re.fullmatch(r"[A-Za-z]:", p)      # не літера диска
             and p.lower() not in (".venv", "venv", "scripts", "bin", "env")]
    project = parts[-1] if parts else ""
    return {"kind": kind, "what": base,
            "detail": (folder + (f"  ·  проєкт: {project}" if project else ""))}


def pids_of(name):
    """Усі процеси з такою назвою. Таблиця «Зараз» групує саме за назвою."""
    low = (name or "").lower()
    out = []
    if not low:
        return out
    me = os.getpid()
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if (p.info.get("name") or "").lower() == low and p.info["pid"] != me:
                out.append(p.info["pid"])
        except Exception:
            continue
    return out


def act_by_name(name, action, **kw):
    """
    Та сама дія над усіма процесами програми.

    У таблиці «Зараз» рядок — це програма, а не процес: у Chrome їх бувають
    десятки. Тому кнопка в рядку має діяти на всю програму, як «Зняти
    завдання» у Диспетчері задач, а покерувати окремим процесом можна в картці.
    """
    low = (name or "").lower()
    if low in PROTECTED:
        return {"ok": False, "error":
                f"«{low}» — критичний процес Windows, монітор його не чіпає"}
    pids = pids_of(name)
    if not pids:
        return {"ok": False, "error": "процесів із такою назвою вже немає"}

    fn = {"kill": lambda pid: kill(pid, name, tree=True),
          "suspend": lambda pid: suspend(pid, name, resume=False),
          "resume": lambda pid: suspend(pid, name, resume=True),
          "priority": lambda pid: set_priority(pid, kw.get("level", ""), name),
          "affinity": lambda pid: set_affinity(pid, kw.get("cores") or [], name),
          }.get(action)
    if not fn:
        return {"ok": False, "error": "невідома дія"}

    done, errs = 0, []
    for pid in pids:
        r = fn(pid)
        if r.get("ok"):
            done += 1
        elif r.get("error") not in ("процес уже завершився",):
            errs.append(r.get("error", ""))
    if not done:
        return {"ok": False, "error": errs[0] if errs else "не вдалося"}
    return {"ok": True, "affected": done, "total": len(pids),
            "errors": errs[:3],
            "note": (f"застосовано до {done} із {len(pids)} процесів"
                     if len(pids) > 1 else "")}


# =====================================================================
#  ПОДРОБИЦІ ПРО ПРОЦЕС
# =====================================================================
def details(pid, expect_name=""):
    """Усе, що зазвичай шукають у властивостях процесу."""
    p, err = _open(pid, expect_name)
    if err:
        return {"error": err}
    out = {"pid": p.pid}
    with_ = lambda k, fn: out.__setitem__(k, _safe(fn))
    with p.oneshot():
        with_("name", p.name)
        with_("exe", p.exe)
        with_("cwd", p.cwd)
        with_("username", p.username)
        with_("status", p.status)
        with_("threads", p.num_threads)
        with_("ppid", p.ppid)
        with_("created", lambda: int(p.create_time()))
    try:
        cl = p.cmdline()
        out["cmdline"] = " ".join(cl) if cl else ""
    except Exception:
        out["cmdline"] = ""
    out["priority"] = prio_name(_safe(p.nice))
    try:
        out["affinity"] = p.cpu_affinity()
    except Exception:
        out["affinity"] = None
    out["ncpu"] = psutil.cpu_count() or 1
    try:
        out["parent"] = p.parent().name() if p.parent() else ""
    except Exception:
        out["parent"] = ""
    try:
        out["children"] = [{"pid": c.pid, "name": c.name()}
                           for c in p.children()][:40]
    except Exception:
        out["children"] = []
    try:
        out["files"] = [f.path for f in p.open_files()][:40]
    except Exception:
        out["files"] = None          # None = не дали подивитись, [] = їх немає
    try:
        out["conns"] = [{
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": c.status,
        } for c in p.net_connections("inet")][:40]
    except Exception:
        out["conns"] = None
    try:
        env = p.environ()
        # Змінні середовища можуть містити токени й ключі. Показуємо лише
        # назви та довжину — цього досить, щоб зрозуміти, з чим запущено,
        # і водночас нічого не витікає в експорт чи на екран.
        out["env_keys"] = sorted(env.keys())[:80]
        out["env_count"] = len(env)
    except Exception:
        out["env_keys"], out["env_count"] = None, None
    # У Windows «заморожений» не є окремим станом процесу, тому покладаємось
    # на власний облік і лише додатково звіряємось зі станом системи.
    # «pythonw.exe» саме по собі нічого не каже — розшифровуємо, що виконує
    out["role"] = identify(out.get("name") or "", out.get("cmdline") or "",
                           out.get("exe") or "", out.get("cwd") or "")
    out["suspended"] = (p.pid in _SUSPENDED
                        or out.get("status") == psutil.STATUS_STOPPED)
    out["protected"] = (out.get("name") or "").lower() in PROTECTED
    out["priorities"] = [{"key": k, "title": t} for k, t in PRIORITIES]
    return out


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default
