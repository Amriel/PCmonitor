#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PC Monitor — власний монітор ресурсів комп'ютера.

Що робить:
  * кожні кілька секунд опитує всі процеси (CPU, RAM, диск, життєвий цикл)
  * логує мережеві з'єднання по програмах (хто куди ходить)
  * з правами адміністратора — точні байти ↑/↓ по процесах і DNS-запити (ETW)
  * зберігає історію в SQLite (data/pcmon.sqlite3), агреговано по хвилинах
  * показує все у власному вікні-апці (Edge/Chrome у режимі --app, без браузерного UI)
  * підсвічує «підозрілі» процеси з поясненням причин
  * одною кнопкою експортує детальний звіт по апці у exports/ — файл для аналізу Claude

Безпека: всі дані лишаються на цьому ПК. Сервер слухає лише 127.0.0.1.
Навантаження: батчований запис раз на ~30 с, пріоритет процесу нижче нормального.

Запуск:  python monitor.py            — збирач + трей (+ вікно, якщо консоль)
         python monitor.py --window   — відкрити вікно (збирач стартує сам, якщо не працює)
         python monitor.py --export chrome.exe   — CLI-експорт звіту по апці
"""
import argparse
import hashlib
import itertools
import json
import logging
import logging.handlers
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# У замороженому вигляді (PyInstaller) «домом» програми є папка з exe:
# поруч лежать web/, streamdeck/, data/ — і оновлення просто замінює файли,
# не чіпаючи data/. У розробці — папка з monitor.py, як і було.
FROZEN = bool(getattr(sys, "frozen", False))
if FROZEN:
    BASE = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

import psutil  # noqa: E402
import suspicion  # noqa: E402

VERSION = "1.2.0"
IS_WIN = sys.platform == "win32"
GITHUB_REPO = "Amriel/PCmonitor"   # звідки апка бере нові релізи

# Без консолі (pythonw, зібраний exe) stdout/stderr — None, і будь-який
# print() падав би з AttributeError. Підставляємо «нікуди», щоб службові
# повідомлення просто зникали, а не валили програму.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
DATA_DIR = os.path.join(BASE, "data")
LOG_DIR = os.path.join(BASE, "logs")
EXPORT_DIR = os.path.join(BASE, "exports")
WEB_DIR = os.path.join(BASE, "web")
DB_PATH = os.path.join(DATA_DIR, "pcmon.sqlite3")
TOKEN_PATH = os.path.join(DATA_DIR, "session.token")
CONFIG_PATH = os.path.join(BASE, "config.json")
# Локальні оновлення: build.bat кладе сюди зібраний інсталятор, і апка сама
# пропонує його встановити. Жодних завантажень з інтернету — свідомо.
UPDATES_DIR = os.path.join(BASE, "updates")

DEFAULT_CONFIG = {
    "sample_interval": 5,          # с, опитування процесів
    "conn_poll_interval": 10,      # с, опитування з'єднань
    "flush_interval": 30,          # с, запис у базу
    "dashboard_port": 8787,        # лише 127.0.0.1
    "retention_minutes_days": 21,  # скільки днів тримати похвилинну деталізацію
    "retention_days": 365,         # денні підсумки, події, з'єднання, DNS
    "watch_raw_days": 7,           # сирі 5-секундні семпли для «стеження»
    "log_cmdline": False,          # писати командний рядок процесів (вимкнено для приватності)
    "etw_enabled": True,           # точні байти мережі + DNS (потрібен адмін)
    "gpu_enabled": True,           # завантаження GPU по процесах (лічильники Windows)
    "clipboard_watch": True,       # стежити за збоями буфера обміну
    # Стартувати одразу з правами адміністратора (для ETW — точних байтів
    # мережі по програмах). Якщо увімкнено автозапуск, підвищення йде через
    # задачу планувальника БЕЗ запиту UAC; інакше з'явиться звичайний запит.
    # Відмовився від UAC — монітор просто працює зі звичайними правами.
    "run_as_admin": True,
    # Мова інтерфейсу: "uk" або "en". Веб-сторінка тримає свій вибір у
    # браузері, а це значення — для решти (меню трея).
    "lang": "uk",
    # Оновлення з GitHub Releases (єдине мережеве звернення апки, і його
    # можна вимкнути). Раз на кілька годин: HTTPS-запит до api.github.com,
    # і якщо там новіша версія — інсталятор завантажується в updates\
    # з перевіркою SHA-256. ВСТАНОВЛЕННЯ — за кліком людини, якщо не
    # ввімкнено auto_install_updates.
    "github_updates": True,
    "auto_install_updates": False,
    # Виконання команд із вікна монітора. ВИМКНЕНО за замовчуванням свідомо:
    # це найпотужніша можливість застосунку, і вмикати її має людина, а не
    # оновлення. Команди виконуються від звичайного користувача навіть тоді,
    # коли монітор запущено від адміністратора (див. runcmd.py).
    "allow_commands": False,
    # Як рахувати пам'ять програми:
    #   "auto"    — як Диспетчер задач (унікальна пам'ять, USS). Якщо вимір почне
    #               коштувати задорого, монітор сам перемкнеться на "private".
    #   "private" — приватні байти: дешево, але трохи більше за Диспетчер
    #   "rss"     — робочий набір: НЕ підходить для браузерів, бо спільна пам'ять
    #               рахується стільки разів, скільки процесів (звідси «7 ГБ Opera»)
    "memory_metric": "auto",
    "sig_check": True,             # перевіряти цифровий підпис нових exe (PowerShell)
    "hash_new_exes": True,         # SHA-256 нових exe (для експорту/аналізу)
    "suspicion": {
        "suspicion_min_score": 35,
        "big_upload_mb": 200,
        "many_ips": 40,
        "night_cpu_pct": 15,
        "churn_count": 15,
    },
}

log = logging.getLogger("pcmon")
STOP = threading.Event()


# ---------------------------------------------------------------- утиліти ----
def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        else:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[pcmon] Не вдалося прочитати config.json ({e}) — використовую типові налаштування")
    return cfg


def setup_logging(console: bool):
    os.makedirs(LOG_DIR, exist_ok=True)
    if sys.stderr is None:
        # Запасний обробник logging пише в stderr, якого під pythonw не
        # існує, — і тоді сам запис у журнал кидав AttributeError
        # (саме це ховалося за «Не вдалося підняти наявне вікно»).
        logging.lastResort = logging.NullHandler()
    log.setLevel(logging.INFO)
    fh = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "monitor.log"), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    log.addHandler(fh)
    # «pcmon.etw» (та інші pcmon.*) — дочірні логери: їхні записи самі
    # піднімаються до обробників «pcmon». Додавати обробник ще й дочірньому
    # не можна — кожен рядок ETW писався в журнал двічі.
    logging.getLogger("pcmon.etw").setLevel(logging.INFO)
    # Під pythonw консолі немає (sys.stderr is None) — StreamHandler там
    # не просто марний, а падає всередині logging при кожному записі.
    if console and sys.stderr is not None:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
        log.addHandler(sh)


def is_public_ip(ip: str) -> bool:
    ip = ip.lower()
    if ":" in ip:  # IPv6
        return not (ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd")
                    or ip in ("::1", "::"))
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (10, 127, 0):
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    return True


def human_day(ts=None):
    return time.strftime("%Y-%m-%d", time.localtime(ts if ts is not None else time.time()))


def day_bounds(date_str):
    t0 = int(time.mktime(time.strptime(date_str, "%Y-%m-%d")))
    return t0, t0 + 86400


def sanitize_filename(s):
    return re.sub(r"[^\w.\-]+", "_", s)[:80] or "app"


# ------------------------------------------------------- автозапуск ----
TASK_NAME = "PC Monitor"


def _pythonw():
    """Шлях до pythonw.exe (запуск без вікна консолі)."""
    exe = sys.executable
    if IS_WIN:
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(pyw):
            return pyw
    return exe


def _self_cmd(*args):
    """
    Команда, щоб запустити ще одну копію ЦІЄЇ Ж програми.

    Єдине місце, яке знає різницю між розробкою і зібраним exe. У розробці —
    pythonw + monitor.py, у замороженому вигляді — сам PCMonitor.exe. Усі
    перезапуски (вікно, збирач, рестарт із налаштувань, автозапуск) ходять
    через цей хелпер, інакше зібрана версія шукала б monitor.py, якого нема.
    """
    if FROZEN:
        return [sys.executable, *args]
    return [_pythonw(), os.path.join(BASE, "monitor.py"), *args]


# ---------------------------------------------------------------- оновлення ----
_SETUP_RE = re.compile(r"^PCMonitor-Setup-(\d+)\.(\d+)\.(\d+)\.exe$", re.I)


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in str(s).split("."))
    except Exception:
        return (0,)


def find_update():
    """
    Найновіший інсталятор у папці updates/, новіший за поточну версію.

    Ім'я клієнта не питаємо і шляхів ззовні не приймаємо: сервер сам сканує
    СВОЮ папку за суворим шаблоном імені. Папка лежить поруч із програмою,
    тобто в тому самому колі довіри, що й сам код.
    """
    best = None
    try:
        for fn in os.listdir(UPDATES_DIR):
            m = _SETUP_RE.match(fn)
            if not m:
                continue
            v = tuple(int(x) for x in m.groups())
            if v > _ver_tuple(VERSION) and (best is None or v > best[0]):
                best = (v, os.path.join(UPDATES_DIR, fn))
    except OSError:
        pass
    if not best:
        return None
    return {"version": ".".join(map(str, best[0])), "file": best[1],
            "size": os.path.getsize(best[1])}


# стан останньої перевірки GitHub — щоб UI міг чесно сказати, що відбулось
_gh_state = {"last_check": 0, "latest": "", "error": "", "downloaded": ""}
_gh_lock = threading.Lock()


def _gh_get(url, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers={
        "User-Agent": f"PCMonitor/{VERSION}",
        "Accept": "application/vnd.github+json"})
    return urllib.request.urlopen(req, timeout=timeout)


def _download_verified(url, target, expect_sha=None, max_bytes=300 * 1024 * 1024):
    """Завантажити файл у target: потоково, з лімітом розміру і SHA-256."""
    import hashlib
    part = target + ".part"
    h = hashlib.sha256()
    total = 0
    with _gh_get(url, timeout=30) as r, open(part, "wb") as f:
        while True:
            chunk = r.read(256 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("файл завеликий — обриваю завантаження")
            h.update(chunk)
            f.write(chunk)
            if STOP.is_set():
                raise InterruptedError("монітор зупиняється")
    got = h.hexdigest().lower()
    if expect_sha and got != expect_sha.lower():
        try:
            os.remove(part)
        except OSError:
            pass
        raise ValueError(f"SHA-256 не збігається: очікував {expect_sha[:16]}…, "
                         f"отримав {got[:16]}… — файл відкинуто")
    os.replace(part, target)
    return got


def check_github_update(cfg, download=True):
    """
    Перевірити останній реліз на GitHub і, якщо він новіший, завантажити
    інсталятор у updates\\ — далі працює звичайний локальний механізм
    (find_update / install_update). Це ЄДИНЕ мережеве звернення монітора,
    воно вимикається одним перемикачем, іде тільки на api.github.com по
    HTTPS і приймає лише файл за суворим шаблоном імені з перевіркою
    SHA-256 (якщо в релізі є файл-хеш).
    """
    if not cfg.get("github_updates", True):
        return {"enabled": False}
    out = {"enabled": True, "repo": GITHUB_REPO}
    try:
        with _gh_get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest") as r:
            rel = json.loads(r.read().decode("utf-8"))
        assets = rel.get("assets") or []
        best = None
        for a in assets:
            m = _SETUP_RE.match(a.get("name") or "")
            if m:
                v = tuple(int(x) for x in m.groups())
                if best is None or v > best[0]:
                    best = (v, a)
        with _gh_lock:
            _gh_state["last_check"] = int(time.time())
        if not best:
            raise ValueError("у релізі немає файлу PCMonitor-Setup-X.Y.Z.exe")
        ver = ".".join(map(str, best[0]))
        with _gh_lock:
            _gh_state["latest"] = ver
            _gh_state["error"] = ""
        out["latest"] = ver
        out["newer"] = best[0] > _ver_tuple(VERSION)
        if not out["newer"] or not download:
            return out
        a = best[1]
        os.makedirs(UPDATES_DIR, exist_ok=True)
        target = os.path.join(UPDATES_DIR, a["name"])
        if not os.path.exists(target):
            # окремий файл-хеш поруч у релізі (його робить build.bat)
            sha = None
            for s in assets:
                if s.get("name") == a["name"] + ".sha256":
                    try:
                        with _gh_get(s["browser_download_url"], timeout=15) as rr:
                            sha = rr.read().decode("utf-8", "replace").split()[0]
                    except Exception:
                        log.warning("Не вдалося прочитати файл-хеш — "
                                    "перевірю лише цілісність за розміром")
                    break
            log.info("Завантажую оновлення %s з GitHub…", ver)
            _download_verified(a["browser_download_url"], target, expect_sha=sha)
            log.info("Оновлення %s завантажено%s", ver,
                     " і перевірено за SHA-256" if sha else "")
        with _gh_lock:
            _gh_state["downloaded"] = ver
        out["downloaded"] = True
        return out
    except Exception as e:
        msg = str(e)[:200]
        with _gh_lock:
            _gh_state["error"] = msg
            _gh_state["last_check"] = int(time.time())
        out["error"] = msg
        return out


def github_update_status():
    with _gh_lock:
        return dict(_gh_state)


def install_update():
    """Запустити інсталятор тихо і завершити монітор, щоб файли звільнились."""
    upd = find_update()
    if not upd:
        return {"ok": False, "error": "у папці updates немає новішого інсталятора"}
    flags = 0x00000008 | 0x08000000 if IS_WIN else 0  # DETACHED | NO_WINDOW
    try:
        # Інсталятор сам чекає, поки монітор завершиться (PrepareToInstall),
        # ставить нову версію поверх старої (data/ не чіпає) і запускає її.
        subprocess.Popen([upd["file"], "/VERYSILENT", "/SUPPRESSMSGBOXES",
                          "/NORESTART"], creationflags=flags, close_fds=True)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    log.info("Встановлюю оновлення %s — завершуюсь", upd["version"])
    threading.Thread(target=shutdown, daemon=True).start()
    return {"ok": True, "version": upd["version"]}


def cli_stop(cfg):
    """`--stop`: чемно зупинити запущений збирач (для інсталятора і скриптів)."""
    port = cfg.get("dashboard_port", 8787)
    import socket
    import urllib.request

    def port_open():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            s.close()
            return True
        except OSError:
            return False

    if not port_open():
        print("Монітор не запущено.")
        return 0
    token = ""
    try:
        with open(TOKEN_PATH, encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        pass
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/quit", data=b"{}",
            headers={"Content-Type": "application/json", "X-PCMon-Token": token})
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"Не вдалося попросити зупинку ({e}).")
        return 1
    for _ in range(30):
        if not port_open():
            print("Монітор зупинився чемно.")
            return 0
        time.sleep(0.5)
    print("Монітор не зупинився за 15 с.")
    return 1


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def autostart_status():
    """Чи налаштовано автозапуск при вході в Windows."""
    if not IS_WIN:
        return {"supported": False, "enabled": False, "reason": "лише для Windows"}
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                           capture_output=True, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return {"supported": True, "enabled": r.returncode == 0}
    except Exception as e:
        return {"supported": True, "enabled": False, "reason": str(e)}


def autostart_set(on):
    """Увімкнути/вимкнути автозапуск. Потребує прав адміністратора."""
    if not IS_WIN:
        return False, "лише для Windows"
    if not is_admin():
        return False, ("потрібні права адміністратора — запусти install.bat "
                       "або відкрий монітор від імені адміністратора")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        if on:
            user = os.environ.get("USERNAME", "")
            dom = os.environ.get("USERDOMAIN", "")
            who = f"{dom}\\{user}" if dom else user
            tr = subprocess.list2cmdline(_self_cmd("--quiet"))
            r = subprocess.run(
                ["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/SC", "ONLOGON",
                 "/RU", who, "/RL", "HIGHEST", "/TR", tr],
                capture_output=True, timeout=20, creationflags=flags)
        else:
            r = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                               capture_output=True, timeout=20, creationflags=flags)
        if r.returncode == 0:
            return True, ""
        msg = (r.stderr or r.stdout or b"").decode("utf-8", "replace").strip()
        return False, msg or f"код помилки {r.returncode}"
    except Exception as e:
        return False, str(e)


def save_config(patch):
    """Записати зміни в config.json, повернути оновлений конфіг."""
    cfg = load_config()
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)
    return cfg


# Трафік, який не вдалося прив'язати до жодної програми.
# Це не «невідома програма» — це переважно короткі завантажувачі й оновлювачі
# (інсталятори драйверів, служби оновлення), які встигають завершитись раніше,
# ніж ми запитаємо їхнє ім'я. Називаємо чесно, щоб цей рядок не читався
# як окрема підозріла програма.
UNATTRIBUTED = "(трафік без програми)"


# ---------------------------------------------------------------- схема БД ----
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS exe_info(
  exe TEXT PRIMARY KEY, name TEXT, first_seen INTEGER, size INTEGER, mtime INTEGER,
  sha256 TEXT, sig_status TEXT, sig_checked_at INTEGER, ignored INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS proc_instances(
  id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER, create_time INTEGER, name TEXT, exe TEXT,
  ppid INTEGER, parent_name TEXT, cmdline TEXT,
  started_ts INTEGER, ended_ts INTEGER, cpu_core_s REAL DEFAULT 0, preexisting INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_pi_name ON proc_instances(name, started_ts);
CREATE INDEX IF NOT EXISTS ix_pi_open ON proc_instances(ended_ts) WHERE ended_ts IS NULL;
CREATE TABLE IF NOT EXISTS app_minute(
  minute_ts INTEGER, name TEXT, exe TEXT, cpu_pct_avg REAL, cpu_pct_max REAL, cpu_core_s REAL,
  rss_max INTEGER, read_b INTEGER, write_b INTEGER, nproc INTEGER,
  cores_max REAL DEFAULT 0,
  PRIMARY KEY(minute_ts, name));
CREATE INDEX IF NOT EXISTS ix_am_name ON app_minute(name, minute_ts);
CREATE TABLE IF NOT EXISTS sys_minute(
  minute_ts INTEGER PRIMARY KEY, cpu_avg REAL, cpu_max REAL, ram_used INTEGER, ram_total INTEGER,
  read_b INTEGER, write_b INTEGER, sent_b INTEGER, recv_b INTEGER, nproc INTEGER,
  core_max REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS net_minute(
  minute_ts INTEGER, name TEXT, sent_b INTEGER, recv_b INTEGER, PRIMARY KEY(minute_ts, name));
CREATE INDEX IF NOT EXISTS ix_nm_name ON net_minute(name, minute_ts);
CREATE TABLE IF NOT EXISTS net_conn(
  name TEXT, raddr TEXT, rport INTEGER, proto TEXT, is_public INTEGER,
  first_ts INTEGER, last_ts INTEGER, times INTEGER DEFAULT 1, pid INTEGER,
  PRIMARY KEY(name, raddr, rport, proto));
CREATE INDEX IF NOT EXISTS ix_nc_last ON net_conn(last_ts);
CREATE TABLE IF NOT EXISTS dns_seen(
  name TEXT, domain TEXT, first_ts INTEGER, last_ts INTEGER, times INTEGER DEFAULT 1,
  PRIMARY KEY(name, domain));
CREATE INDEX IF NOT EXISTS ix_dns_last ON dns_seen(last_ts);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, name TEXT, exe TEXT,
  pid INTEGER, info TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS watchlist(name TEXT PRIMARY KEY, added_ts INTEGER);
CREATE TABLE IF NOT EXISTS watch_raw(
  ts INTEGER, name TEXT, pid INTEGER, cpu_pct REAL, rss INTEGER, read_b INTEGER, write_b INTEGER);
CREATE INDEX IF NOT EXISTS ix_wr ON watch_raw(name, ts);
CREATE TABLE IF NOT EXISTS app_day(
  day TEXT, name TEXT, exe TEXT, cpu_core_s REAL, cpu_pct_max REAL, rss_max INTEGER,
  read_b INTEGER, write_b INTEGER, sent_b INTEGER, recv_b INTEGER,
  nmin INTEGER, first_ts INTEGER, last_ts INTEGER, ninst INTEGER,
  cores_max REAL DEFAULT 0,
  PRIMARY KEY(day, name));
"""


# =====================================================================
#  АВТЕНТИФІКАЦІЯ
# =====================================================================
# API слухає лише 127.0.0.1, і доки всі ручки лише читали, цього вистачало.
# Щойно з'явились дії, що змінюють систему (завершити процес, виконати
# команду), самого лише «локального» вже мало: сторінка у вашому ж браузері
# може надіслати запит на 127.0.0.1 без вашого відома.
#
# Захист із двох незалежних шарів:
#   1. Токен сесії. Свіжий при кожному запуску, віддається лише всередині
#      нашої сторінки. Стороння сторінка запит надіслати може, але прочитати
#      нашу відповідь (а отже й дізнатись токен) браузер їй не дасть.
#   2. Перевірка походження. Заголовки Origin і Sec-Fetch-Site браузер
#      підставляє сам, і підробити їх зі сторінки неможливо.
API_TOKEN = secrets.token_urlsafe(32)


def _origin_ok(headers, port):
    """Запит прийшов із нашої ж сторінки, а не з чужого сайту?"""
    site = (headers.get("Sec-Fetch-Site") or "").lower()
    if site in ("cross-site", "same-site"):
        return False                      # інший сайт — навіть не розглядаємо
    origin = headers.get("Origin")
    if not origin:
        return True                       # не браузер (curl, скрипт) — вирішить токен
    allowed = {f"http://127.0.0.1:{port}", f"http://localhost:{port}",
               f"http://[::1]:{port}"}
    return origin in allowed


# Коди System.Management.Automation.SignatureStatus, як їх віддає PowerShell.
SIG_STATUS = {0: "Valid", 1: "UnknownError", 2: "NotSigned", 3: "HashMismatch",
              4: "NotTrusted", 5: "NotSupportedFileFormat", 6: "Incompatible"}

# Людські пояснення до кожного стану — щоб не змушувати гуглити англійський код.
SIG_HUMAN = {
    "Valid": ("підпис дійсний", "Файл підписаний і не змінювався після підписання."),
    "NotSigned": ("підпису немає",
                  "Це не обов'язково погано: багато дрібних утиліт не підписують."),
    "HashMismatch": ("файл не збігається з підписом",
                     "Підпис на місці, але він каже, що файл мав бути іншим — "
                     "тобто файл змінили вже після підписання."),
    "NotTrusted": ("підпису не довіряють",
                   "Підпис є, але його сертифікат не з довіреного кореня — "
                   "самопідписаний або прострочений ланцюжок."),
    "UnknownError": ("не вдалося перевірити", "Windows не змогла дати відповідь."),
    "NotSupportedFileFormat": ("формат не підтримує підпис", ""),
    "Incompatible": ("несумісний підпис", ""),
}


def _cn(subject):
    """З рядка сертифіката «CN=Maxon Computer GmbH, O=..., C=DE» лишити ім'я."""
    if not subject:
        return ""
    m = re.search(r"CN=([^,]+)", subject)
    return (m.group(1) if m else subject).strip().strip('"')[:120]


_DATE_MS_RE = re.compile(r"/Date\((-?\d+)")


def _certdate(v):
    """
    Дату «дійсний до» з PowerShell привести до вигляду 2028-03-06.

    ConvertTo-Json серіалізує .NET DateTime як об'єкт {"value": "/Date(…)/"},
    і якщо просто зробити str() від нього, у базу лягає уламок Python-репру
    на кшталт «{'value': '/Date(1836259199000)/', 'Date». Тому розбираємо
    і мілісекунди, і вже нормальний рядок.
    """
    if v is None or v == "":
        return ""
    if isinstance(v, dict):
        v = v.get("value") or v.get("DateTime") or ""
    s = str(v)
    m = _DATE_MS_RE.search(s)
    if m:
        try:
            return time.strftime("%Y-%m-%d", time.localtime(int(m.group(1)) / 1000))
        except Exception:
            return ""
    s = s.strip()
    # вже готовий рядок «2028-03-06» або «03/06/2028 00:00:00»
    return s[:40] if not s.startswith("{") else ""


def migrate_db(con):
    """
    Додає колонки, яких не було в ранніх версіях, не втрачаючи вже зібрані дані.
    Безпечно виконувати щоразу: якщо колонка вже є — нічого не робимо.
    """
    def cols(table):
        try:
            return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        except Exception:
            return set()

    # Старий підпис «(невідомо)» читався як окрема підозріла програма.
    # Перейменовуємо вже накопичене, щоб історія й нові дані сходились.
    for tbl in ("net_minute", "dns_seen", "net_conn"):
        try:
            con.execute(f"UPDATE {tbl} SET name=? WHERE name='(невідомо)'",
                        (UNATTRIBUTED,))
        except Exception:
            pass

    # «Ядра» — скільки ядер процесора реально з'їдала програма.
    # Потрібно, бо відсоток від УСЬОГО процесора приховує програму, яка
    # повністю завантажила одне ядро: на 32 ядрах це лише 3%.
    # Підпис: раніше зберігався лише код статусу. Через це монітор міг сказати
    # «підпис не збігається», але не міг сказати, ХТО підписав — а це якраз
    # найкорисніше: «Maxon Computer» і «невідомо хто» — зовсім різні новини.
    for table, col, decl in (
        ("app_minute", "cores_max", "REAL DEFAULT 0"),
        ("app_day", "cores_max", "REAL DEFAULT 0"),
        ("sys_minute", "core_max", "REAL DEFAULT 0"),
        ("exe_info", "sig_signer", "TEXT"),
        ("exe_info", "sig_message", "TEXT"),
        ("exe_info", "sig_issuer", "TEXT"),
        ("exe_info", "sig_ts", "TEXT"),
    ):
        if col not in cols(table):
            try:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            except Exception:
                log.exception("Не вдалося додати колонку %s.%s", table, col)

    # --- зіпсовані дати «дійсний до» --------------------------------------
    # Була помилка: дата сертифіката лягала в базу як уламок Python-репру
    # («{'value': '/Date(1836259199000)/', 'Date»). Мілісекунди в ньому цілі,
    # тому не стираємо рядок, а дораховуємо з нього нормальну дату.
    try:
        bad = con.execute(
            "SELECT exe, sig_ts FROM exe_info WHERE sig_ts LIKE '%/Date(%'"
        ).fetchall()
        for exe, raw in bad:
            con.execute("UPDATE exe_info SET sig_ts=? WHERE exe=? COLLATE NOCASE",
                        (_certdate(raw), exe))
        if bad:
            log.info("Виправив дату сертифіката у %d записах", len(bad))
    except Exception:
        pass

    # --- дублікати записів про запуски -----------------------------------
    # Була помилка: при кожному перезапуску монітора довгоживучі процеси
    # (svchost, opera тощо) записувались ЗАНОВО, бо збирач бачив їх як нові.
    # Через це «Запусків: 178» замість реальних одиниць. Прибираємо дублі,
    # лишаючи по одному рядку на кожен справжній процес, і ставимо захист.
    try:
        has_idx = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='ux_pi_inst'"
        ).fetchone()
        if not has_idx:
            dups = con.execute(
                "SELECT COUNT(*) FROM (SELECT pid, create_time FROM proc_instances "
                "WHERE create_time > 0 GROUP BY pid, create_time HAVING COUNT(*) > 1)"
            ).fetchone()[0]
            if dups:
                log.info("Прибираю дублікати запусків для %d процесів…", dups)
            # злити дублі: лишаємо найраніший рядок, беремо найпізніший кінець
            con.execute("""
                UPDATE proc_instances SET
                  ended_ts = (SELECT CASE WHEN SUM(p2.ended_ts IS NULL) > 0 THEN NULL
                                          ELSE MAX(p2.ended_ts) END
                              FROM proc_instances p2
                              WHERE p2.pid = proc_instances.pid
                                AND p2.create_time = proc_instances.create_time),
                  cpu_core_s = (SELECT MAX(p3.cpu_core_s) FROM proc_instances p3
                                WHERE p3.pid = proc_instances.pid
                                  AND p3.create_time = proc_instances.create_time)
                WHERE create_time > 0""")
            con.execute("""
                DELETE FROM proc_instances WHERE create_time > 0 AND id NOT IN (
                    SELECT MIN(id) FROM proc_instances WHERE create_time > 0
                    GROUP BY pid, create_time)""")
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_pi_inst "
                        "ON proc_instances(pid, create_time) WHERE create_time > 0")
    except Exception:
        log.exception("Не вдалося прибрати дублікати запусків")


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    try:
        con.executescript(SCHEMA)
        migrate_db(con)
        con.commit()
    finally:
        con.close()


def q(sql, args=()):
    """Читання: окреме read-only з'єднання на запит (WAL це дозволяє)."""
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, args).fetchall()]
    finally:
        con.close()


def q1(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


# ---------------------------------------------------------------- писар БД ----
class Writer(threading.Thread):
    """Єдиний потік, що пише в SQLite. Всі інші кладуть (sql, params) у чергу."""

    def __init__(self, cfg):
        super().__init__(name="writer", daemon=True)
        self.cfg = cfg
        self.jobs = []
        self.lock = threading.Lock()
        self.flock = threading.Lock()
        self.con = None
        self.last_retention_day = ""
        # Окремий сигнал завершення саме для писаря. Потрібен, щоб він закрив
        # базу ЛИШЕ після того, як збирач допише свої останні дані: раніше
        # з'єднання закривалось раніше і останні ~70 записів губились.
        self.finish = threading.Event()

    def push(self, sql, params=()):
        with self.lock:
            self.jobs.append((sql, params))

    def push_many(self, items):
        with self.lock:
            self.jobs.extend(items)

    def flush_now(self):
        self._flush()

    def exec_now(self, sql, params=()):
        """
        Виконати запис НЕГАЙНО і повернути кількість змінених рядків.

        push() нічого не повертає — і саме через це помилка «позначив як
        довірену, а попередження лишилось» була невидимою: запит не чіпав
        жодного рядка, а інтерфейс однаково рапортував успіх. Для рідкісних
        дій користувача потрібна відповідь «скільки насправді змінилось».
        Використовує те саме з'єднання писаря, щоб не заводити другого
        писача в базу.
        """
        self._flush()                      # спершу віддати те, що вже в черзі
        with self.flock:                   # перевірка з'єднання — під замком
            if self.con is None:
                return -1
            try:
                with self.con:
                    return self.con.execute(sql, params).rowcount
            except Exception:
                log.exception("Не вдалося виконати запит: %s", sql)
                return -1

    def _flush(self):
        """
        Записати чергу. Два правила, обидва народжені з реальної втрати даних:

        1. Перевірка з'єднання — ПІД тим самим замком, під яким іде запис.
           Раніше вона стояла зовні: інший потік встигав пройти перевірку,
           поки писар закривав базу, і падав на «Cannot operate on a closed
           database».
        2. Черга очищається лише ПІСЛЯ успішного запису. Раніше вона
           забиралась одразу, тож будь-яка помилка означала «732 операції
           втрачено» — саме так у логах і було.
        """
        with self.flock:
            if self.con is None:
                return
            with self.lock:
                jobs, self.jobs = self.jobs, []
            if not jobs:
                return
            try:
                with self.con:                    # транзакція
                    for sql, params in jobs:
                        self.con.execute(sql, params)
            except Exception:
                # повертаємо назад, у початок черги — спробуємо ще раз
                with self.lock:
                    self.jobs[:0] = jobs
                log.exception("Помилка запису в БД (%d операцій у черзі, "
                              "спробую ще раз)", len(jobs))

    def run(self):
        self.con = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        while not self.finish.is_set():
            self.finish.wait(self.cfg["flush_interval"])
            self._flush()
            if not self.finish.is_set():
                self._maybe_maintenance()
        # Кілька проходів наостанок: збирач, опитувач з'єднань і обробники
        # запитів могли покласти щось у чергу вже після сигналу зупинки.
        # Один прохід їх не забирав — і саме ці записи губились.
        for _ in range(6):
            self._flush()
            with self.lock:
                left = len(self.jobs)
            if not left:
                break
            time.sleep(0.25)
        with self.flock:
            leftover = None
            with self.lock:
                if self.jobs:
                    leftover = list(self.jobs)
                    self.jobs = []
            try:
                self.con.close()
            except Exception:
                pass
            self.con = None
        if leftover:
            # База вже закрита, але мовчки викидати дані не можна: складаємо
            # їх у файл поруч, щоб було видно, що саме не доїхало.
            log.error("Не встигли записати %d операцій — зберігаю у %s",
                      len(leftover), "logs/unsaved.jsonl")
            try:
                with open(os.path.join(LOG_DIR, "unsaved.jsonl"), "a",
                          encoding="utf-8") as f:
                    for sql, params in leftover:
                        f.write(json.dumps({"sql": sql, "params": list(params)},
                                           ensure_ascii=False) + "\n")
            except Exception:
                log.exception("Не вдалося зберегти незаписані операції")

    # ---- обслуговування: денні підсумки + ретенція -----------------------
    def _maybe_maintenance(self):
        today = human_day()
        if self.last_retention_day == today:
            return
        self.last_retention_day = today
        try:
            yesterday = human_day(time.time() - 86400)
            self.rollup_day(yesterday)
            now = int(time.time())
            cut_min = now - self.cfg["retention_minutes_days"] * 86400
            cut_all = now - self.cfg["retention_days"] * 86400
            cut_raw = now - self.cfg["watch_raw_days"] * 86400
            with self.flock, self.con:
                self.con.execute("DELETE FROM app_minute WHERE minute_ts < ?", (cut_min,))
                self.con.execute("DELETE FROM net_minute WHERE minute_ts < ?", (cut_min,))
                self.con.execute("DELETE FROM sys_minute WHERE minute_ts < ?", (cut_min,))
                self.con.execute("DELETE FROM watch_raw WHERE ts < ?", (cut_raw,))
                self.con.execute("DELETE FROM events WHERE ts < ?", (cut_all,))
                self.con.execute("DELETE FROM net_conn WHERE last_ts < ?", (cut_all,))
                self.con.execute("DELETE FROM dns_seen WHERE last_ts < ?", (cut_all,))
                self.con.execute("DELETE FROM proc_instances WHERE started_ts < ?", (cut_all,))
                self.con.execute("DELETE FROM app_day WHERE day < date('now', ?)",
                                 (f"-{self.cfg['retention_days']} days",))
            log.info("Обслуговування БД виконано (ретенція, підсумок за %s)", yesterday)
        except Exception:
            log.exception("Помилка обслуговування БД")

    def rollup_day(self, day):
        """Згорнути похвилинні дані дня у app_day (виживає після ретенції хвилин)."""
        t0, t1 = day_bounds(day)
        try:
            with self.flock, self.con:
                self.con.execute("""
                    INSERT OR REPLACE INTO app_day(
                        day, name, exe, cpu_core_s, cpu_pct_max, rss_max,
                        read_b, write_b, sent_b, recv_b, nmin, first_ts, last_ts,
                        ninst, cores_max)
                    SELECT ?, am.name, MAX(am.exe), SUM(am.cpu_core_s), MAX(am.cpu_pct_max),
                           MAX(am.rss_max), SUM(am.read_b), SUM(am.write_b),
                           COALESCE((SELECT SUM(nm.sent_b) FROM net_minute nm
                                     WHERE nm.name = am.name AND nm.minute_ts >= ? AND nm.minute_ts < ?), 0),
                           COALESCE((SELECT SUM(nm.recv_b) FROM net_minute nm
                                     WHERE nm.name = am.name AND nm.minute_ts >= ? AND nm.minute_ts < ?), 0),
                           COUNT(*), MIN(am.minute_ts), MAX(am.minute_ts),
                           COALESCE((SELECT COUNT(*) FROM proc_instances pi
                                     WHERE pi.name = am.name AND pi.started_ts < ?
                                       AND COALESCE(pi.ended_ts, ?) >= ?), 0),
                           MAX(COALESCE(am.cores_max, 0))
                    FROM app_minute am
                    WHERE am.minute_ts >= ? AND am.minute_ts < ?
                    GROUP BY am.name
                """, (day, t0, t1, t0, t1, t1, t1, t0, t0, t1))
        except Exception:
            log.exception("Не вдалося згорнути день %s", day)


# ------------------------------------------------------------- перевірка exe ----
class ExeInspector(threading.Thread):
    """Фонова перевірка нових exe: SHA-256 + цифровий підпис (PowerShell, батчами)."""

    def __init__(self, cfg, writer):
        super().__init__(name="exe-inspector", daemon=True)
        self.cfg = cfg
        self.writer = writer
        self.queue = []
        self.lock = threading.Lock()

    def submit(self, exe_path):
        if not exe_path:
            return
        with self.lock:
            if exe_path not in self.queue:
                self.queue.append(exe_path)

    def run(self):
        while not STOP.is_set():
            STOP.wait(45)
            with self.lock:
                batch, self.queue = self.queue[:24], self.queue[24:]
            if not batch:
                continue
            if self.cfg.get("hash_new_exes"):
                for p in batch:
                    self._hash(p)
            if IS_WIN and self.cfg.get("sig_check"):
                self._signatures(batch)

    def _hash(self, path):
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > 128 * 1024 * 1024:
                return
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
                    if STOP.is_set():
                        return
            self.writer.push("UPDATE exe_info SET sha256=? WHERE exe=?", (h.hexdigest(), path))
        except Exception:
            pass

    @staticmethod
    def check_signature(path):
        """Перевірити підпис одного файлу просто зараз і повернути результат."""
        if not IS_WIN:
            return {"error": "перевірка підпису доступна лише у Windows"}
        esc = path.replace("'", "''")
        cmd = ("$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
               "[pscustomobject]@{Status=[int]$s.Status; Message=$s.StatusMessage; "
               "Signer=$s.SignerCertificate.Subject; Issuer=$s.SignerCertificate.Issuer; "
               "NotAfter=$(if($s.SignerCertificate){"
               "$s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')})} "
               "| ConvertTo-Json -Compress" % esc)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, timeout=45,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            out = r.stdout.decode("utf-8", "replace").strip()
            if not out:
                return {"error": (r.stderr.decode("utf-8", "replace").strip()[:200]
                                  or "PowerShell нічого не повернув")}
            d = json.loads(out)
        except Exception as e:
            return {"error": str(e)}
        return {
            "status": SIG_STATUS.get(d.get("Status"), str(d.get("Status"))),
            "message": (d.get("Message") or "")[:300],
            "signer": _cn(d.get("Signer")),
            "issuer": _cn(d.get("Issuer")),
            "not_after": _certdate(d.get("NotAfter")),
            "checked_at": int(time.time()),
        }

    def _signatures(self, paths):
        try:
            plist = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
            # Беремо не лише код статусу, а й ХТО підписав і що саме сказала
            # Windows. Без цього монітор міг заявити «підпис не збігається»,
            # але не міг відповісти на головне питання — чий це підпис.
            cmd = (f"Get-AuthenticodeSignature -LiteralPath {plist} | "
                   f"Select-Object Path,Status,StatusMessage,"
                   f"@{{n='Signer';e={{$_.SignerCertificate.Subject}}}},"
                   f"@{{n='Issuer';e={{$_.SignerCertificate.Issuer}}}},"
                   f"@{{n='NotAfter';e={{if($_.SignerCertificate)"
                   f"{{$_.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')}}}}}} "
                   f"| ConvertTo-Json -Compress")
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            out = r.stdout.decode("utf-8", "replace").strip()
            if not out:
                return
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            now = int(time.time())
            for item in data:
                p, st = item.get("Path"), item.get("Status")
                status = SIG_STATUS.get(st, str(st))
                if p:
                    self.writer.push(
                        "UPDATE exe_info SET sig_status=?, sig_checked_at=?, "
                        "sig_signer=?, sig_issuer=?, sig_message=?, sig_ts=? "
                        "WHERE exe=? COLLATE NOCASE",
                        (status, now, _cn(item.get("Signer")), _cn(item.get("Issuer")),
                         (item.get("StatusMessage") or "")[:300],
                         _certdate(item.get("NotAfter")), p))
        except Exception as e:
            log.info("Перевірка підписів не вдалася (%s) — пропускаю батч", e)


# ---------------------------------------------------------------- збирач ----
class Sampler(threading.Thread):
    """Головний цикл: процеси, CPU/RAM/диск, життєвий цикл, похвилинна агрегація."""

    def __init__(self, cfg, writer, inspector):
        super().__init__(name="sampler", daemon=True)
        self.cfg = cfg
        self.writer = writer
        self.inspector = inspector
        self.ncpu = psutil.cpu_count() or 1
        self.pid_map = {}                     # pid -> name (нижній регістр)
        self.pid_miss = {}                    # pid -> коли не знайшли (негативний кеш)
        self.pid_lock = threading.Lock()
        self.dead_pids = OrderedDict()        # pid -> (name, ts) — грейс для ETW
        self.watchset = set()
        self.watch_lock = threading.Lock()
        self.known_exes = set()
        self.first_tick_done = False
        self.samples_total = 0
        self.started_at = int(time.time())
        # хвилинні акумулятори
        self.minute_idx = None
        self.acc = {}
        self.sys_acc = None
        self.prev = {}                        # (pid, ct) -> dict(busy, io_r, io_w)
        self.inst_cpu = {}                    # (pid, ct) -> накопичені core-секунди
        self.inst_meta = {}                   # (pid, ct) -> (name, exe)
        self.missing = {}                     # (pid, ct) -> к-сть підряд пропущених опитувань
        self.last_inst_sync = 0
        self.live = {"ts": 0, "ncpu": self.ncpu, "cpu_total": 0.0,
                     "ram_used": 0, "ram_total": 0, "apps": []}
        self.live_lock = threading.Lock()
        # серцебиття збирача: коли востаннє закінчив цикл і що робить зараз.
        # Потрібне, щоб «збирач зайнятий» могло назвати, чим саме.
        self.last_tick = time.time()
        self.doing = "щойно запустився"
        # Короткий ряд останніх замірів — для міні-графіка на клавішах
        # Stream Deck. Тримаємо в пам'яті, а не читаємо щоразу з бази:
        # клавіші оновлюються раз на секунду, і бігати по БД заради цього
        # означало б створити те саме навантаження, яке ми міряємо.
        self.hist = deque(maxlen=180)
        # датчики заліза (температури, відеопам'ять). Опитуємо рідше за все
        # інше: значення змінюються плавно, а деякі джерела коштують запуску
        # процесу — платити за це щосекунди безглуздо.
        self.sensors = {}
        self.sensors_ts = 0
        self.sensors_hist = deque(maxlen=180)
        # режим вимірювання пам'яті (див. коментар у DEFAULT_CONFIG)
        self.mem_metric = str(cfg.get("memory_metric", "auto")).lower()
        self.mem_mode = "uss" if self.mem_metric in ("auto", "uss") else self.mem_metric
        self.mem_slow_hits = 0
        # Якщо в минулому сеансі точний вимір уже виявився надто дорогим —
        # стартуємо одразу з дешевого режиму, а не вчимося цього заново
        # трьома повільними опитуваннями після кожного перезапуску.
        if self.mem_metric == "auto":
            try:
                r = q1("SELECT v FROM meta WHERE k='mem_mode_learned'")
                if r and r.get("v") == "private":
                    self.mem_mode = "private"
            except Exception:
                pass
        # GPU по процесах (лічильники Windows; None якщо вимкнено/недоступно)
        self.gpu = None
        if cfg.get("gpu_enabled", True) and IS_WIN:
            try:
                from gpu_win import GpuCounters
                g = GpuCounters()
                if g.start():
                    self.gpu = g
                else:
                    log.info("GPU: %s", g.status)
                    self.gpu_status = g.status
            except Exception as e:
                log.info("GPU-модуль не завантажився: %s", e)
        self.gpu_status = getattr(self, "gpu_status",
                                  "активний" if self.gpu else "недоступно")

        # спільні буфери мережі (наповнюють інші потоки)
        self.etw_acc = {}                     # pid -> [sent, recv]  (для хвилинної статистики)
        self.etw_live = {}                    # name -> [sent, recv]  (для живого перегляду)
        self.etw_lock = threading.Lock()
        self.dns_buf = []                     # (name, domain)
        self.dns_lock = threading.Lock()
        self.conn_acc = {}                    # (name, ip, port, proto) -> dict
        self.conn_lock = threading.Lock()
        self.prev_disk = None
        self.prev_net = None

    # ---- зовнішні колбеки -------------------------------------------------
    # Ім'я програми визначаємо ПРЯМО ЗАРАЗ, у момент події.
    #
    # Раніше ми складали в буфер сирі номери процесів, а розшифровували їх раз
    # на хвилину, коли зводили підсумок. Для довгих програм це працювало, а от
    # інсталятори й оновлювачі живуть секунди: до моменту розшифровки процесу
    # вже не існувало, і весь його трафік осідав у купі «(невідомо)». Саме
    # звідти бралися download.amd.com, ngx.download.nvidia.com і подібні —
    # це якраз короткі завантажувачі.
    def on_etw_bytes(self, pid, sent, recv):
        nm = self.resolve_pid(pid) or UNATTRIBUTED
        with self.etw_lock:
            e = self.etw_acc.get(nm)
            if e is None:
                self.etw_acc[nm] = [sent, recv]
            else:
                e[0] += sent
                e[1] += recv
            # окремий буфер для живого перегляду: спорожнюється щотіка
            lv = self.etw_live.get(nm)
            if lv is None:
                self.etw_live[nm] = [sent, recv]
            else:
                lv[0] += sent
                lv[1] += recv

    def on_etw_dns(self, pid, domain):
        nm = self.resolve_pid(pid) or UNATTRIBUTED
        with self.dns_lock:
            if len(self.dns_buf) < 5000:
                self.dns_buf.append((nm, domain))

    def resolve_pid(self, pid):
        """
        PID -> ім'я програми. ETW присилає події швидше, ніж ми встигаємо
        побачити нові процеси, тому шукаємо в кілька шарів: поточний знімок,
        нещодавно померлі, потім питаємо систему напряму і ЗАПАМ'ЯТОВУЄМО
        відповідь — інакше трафік коротких процесів осідав у «(невідомо)».
        """
        with self.pid_lock:
            name = self.pid_map.get(pid)
            if name:
                return name
            d = self.dead_pids.get(pid)
            miss = self.pid_miss.get(pid)
        if d:
            return d[0]
        if pid in (0, 4):
            return "system"
        # Негативний кеш: якщо процесу вже немає, не питати систему про той
        # самий номер на кожну подію. ETW їх присилає сотнями тисяч, і без
        # цього ми б самі створювали навантаження, яке міряємо.
        now = time.time()
        if miss and now - miss < 30:
            return None
        try:
            nm = psutil.Process(pid).name().lower()
            if nm:
                with self.pid_lock:
                    self.pid_map[pid] = nm
                return nm
        except Exception:
            pass
        with self.pid_lock:
            self.pid_miss[pid] = now
            if len(self.pid_miss) > 4000:
                self.pid_miss.clear()
        return None

    def set_watch(self, name, on):
        with self.watch_lock:
            if on:
                self.watchset.add(name.lower())
            else:
                self.watchset.discard(name.lower())

    # ---- головний цикл ----------------------------------------------------
    def run(self):
        self.load_watchlist()
        psutil.cpu_percent(None)  # прайм
        last_ts = time.time()
        # Тривалість інтервалу міряємо ГОДИННИКОМ, ЩО НЕ СТРИБАЄ.
        # Раніше брали різницю time.time(): якщо системний час зсунеться назад
        # (синхронізація з мережею, вихід зі сну), різниця виходила крихітною,
        # її обрізало до 0.5 с — і поділ спожитого часу на цю півсекунди давав
        # неможливі значення на кшталт «79 ядер» на 32-ядерній машині.
        last_mono = time.monotonic()
        interval = max(2, int(self.cfg["sample_interval"]))
        while not STOP.is_set():
            STOP.wait(interval)
            ts = time.time()
            mono = time.monotonic()
            dt = max(0.5, mono - last_mono)
            last_mono = mono
            last_ts = ts
            try:
                self.doing = "опитування процесів"
                self.tick(ts, dt)
                self.samples_total += 1
                self.doing = ""
                self.last_tick = time.time()
            except Exception:
                self.doing = "помилка останнього циклу"
                log.exception("Помилка семплінгу")
        # завершення: закрити відкриті інстанси й дозаписати хвилину
        now = int(time.time())
        self.finalize_minute()
        for key, meta in list(self.inst_meta.items()):
            pid, ct = key
            self.writer.push(
                "UPDATE proc_instances SET ended_ts=?, cpu_core_s=? "
                "WHERE pid=? AND create_time=? AND ended_ts IS NULL",
                (now, round(self.inst_cpu.get(key, 0.0), 2), pid, ct))
        self.writer.push("INSERT INTO events(ts,kind,name,info) VALUES(?,?,?,?)",
                         (now, "monitor_stop", "PC Monitor", "монітор зупинено"))
        self.writer.push("INSERT OR REPLACE INTO meta(k,v) VALUES('last_sample_ts',?)", (str(now),))

    def _read_sensors(self, its):
        """Температури й відеопам'ять — раз на 3 секунди, не частіше."""
        if its - self.sensors_ts < 3:
            return
        self.sensors_ts = its
        try:
            import sensors as _s
            d = _s.read_all()
        except Exception:
            log.debug("Датчики не прочитались", exc_info=True)
            return
        self.sensors = d
        g = (d.get("gpus") or [None])[0] or {}
        mt, mu = g.get("mem_total") or 0, g.get("mem_used") or 0
        self.sensors_hist.append((
            its,
            g.get("temp") or 0,
            round(mu / mt * 100, 1) if mt else 0,
            max([x["temp"] for x in (d.get("disks") or [])] or [0]),
        ))

    def load_watchlist(self):
        try:
            rows = q("SELECT name FROM watchlist")
            with self.watch_lock:
                self.watchset = {r["name"].lower() for r in rows}
        except Exception:
            pass

    def tick(self, ts, dt):
        its = int(ts)
        minute_idx = its // 60
        if self.minute_idx is None:
            self.minute_idx = minute_idx
        elif minute_idx != self.minute_idx:
            self.finalize_minute()
            self.minute_idx = minute_idx

        seen = {}
        tick_rss = {}
        tick_cnt = {}
        tick_pct = {}
        tick_io = {}      # lname -> байти диска за цей тік (читання+запис)
        tick_gpu = {}     # lname -> сумарний % GPU
        tick_cores = {}   # lname -> скільки ядер з'їдено сумарно
        tick_cores1 = {}  # lname -> найбільше ядер на ОДИН процес програми
        new_pid_map = {}

        # GPU: один знімок по всіх PID за тік
        gpu_by_pid = self.gpu.sample() if self.gpu else {}
        watch_rows = []
        with self.watch_lock:
            wset = set(self.watchset)

        attrs = ["pid", "name", "exe", "ppid", "create_time", "memory_info",
                 "cpu_times", "io_counters"]
        if self.cfg.get("log_cmdline"):
            attrs.append("cmdline")

        scan_t0 = time.time()
        for p in psutil.process_iter(attrs):
            info = p.info
            pid = info["pid"]
            if pid == 0:
                continue
            try:
                ct = int(info.get("create_time") or 0)
            except Exception:
                ct = 0
            key = (pid, ct)
            # Захищені процеси Windows (Registry, Secure System, Memory Compression)
            # інколи не віддають ім'я. Раніше всі вони зливались в одне «?»,
            # і виходила каша з різних процесів під однією назвою.
            name = (info.get("name") or "").strip()
            if not name:
                try:
                    name = (p.name() or "").strip()
                except Exception:
                    name = ""
            if not name:
                name = f"(системний pid {pid})"
            lname = name.lower()
            exe = info.get("exe") or ""
            new_pid_map[pid] = lname
            seen[key] = True

            # --- пам'ять ---------------------------------------------------
            # ВАЖЛИВО: rss (робочий набір) для багатопроцесних програм рахує
            # СПІЛЬНУ пам'ять у кожному процесі окремо. Тому проста сума по
            # Opera/Chrome дає втричі більше, ніж показує Диспетчер задач.
            # Диспетчер показує унікальну (приватну) пам'ять — це USS.
            mem = info.get("memory_info")
            rss = getattr(mem, "rss", 0) if mem else 0
            if self.mem_mode == "uss":
                try:
                    rss = p.memory_full_info().uss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass
            elif self.mem_mode == "private" and mem is not None:
                rss = getattr(mem, "private", None) or getattr(mem, "rss", 0)
            cpu_t = info.get("cpu_times")
            busy = (cpu_t.user + cpu_t.system) if cpu_t else None
            io = info.get("io_counters")
            io_r = getattr(io, "read_bytes", None) if io else None
            io_w = getattr(io, "write_bytes", None) if io else None

            prev = self.prev.get(key)
            d_busy = d_r = d_w = 0.0
            if prev:
                if busy is not None and prev["busy"] is not None:
                    d_busy = max(0.0, busy - prev["busy"])
                if io_r is not None and prev["io_r"] is not None:
                    d_r = max(0, io_r - prev["io_r"])
                if io_w is not None and prev["io_w"] is not None:
                    d_w = max(0, io_w - prev["io_w"])
            else:
                self.on_new_process(its, pid, ct, name, lname, exe, info)
            self.prev[key] = {"busy": busy, "io_r": io_r, "io_w": io_w}
            self.inst_cpu[key] = self.inst_cpu.get(key, 0.0) + d_busy
            self.inst_meta[key] = (lname, exe)

            # cores = скільки ЯДЕР з'їв процес. 1.0 = повністю зайняте одне ядро.
            # Саме це ловить однопотокове впирання, яке у відсотках від усього
            # процесора виглядає мізерно (на 32 ядрах ціле ядро = 3.1%).
            # Стеля — кількість ядер у системі. Один процес фізично не може
            # з'їсти більше, тож усе, що вище, — це похибка вимірювання, а не
            # спостереження. Показувати її як факт означало б брехати.
            cores = min(d_busy / dt, float(self.ncpu))
            pct = min(100.0, cores / self.ncpu * 100.0)
            tick_pct[lname] = tick_pct.get(lname, 0.0) + pct
            tick_cores[lname] = tick_cores.get(lname, 0.0) + cores
            if cores > tick_cores1.get(lname, 0.0):
                tick_cores1[lname] = cores   # найзавантаженіший процес програми
            tick_io[lname] = tick_io.get(lname, 0) + int(d_r) + int(d_w)
            g = gpu_by_pid.get(pid)
            if g:
                tick_gpu[lname] = tick_gpu.get(lname, 0.0) + g
            a = self.acc.get(lname)
            if a is None:
                a = self.acc[lname] = {"core_s": 0.0, "pct_max": 0.0, "rss_max": 0,
                                       "read_b": 0, "write_b": 0, "nproc": 0, "exe": exe,
                                       "cores_max": 0.0}
            a["core_s"] += d_busy
            a["pct_max"] = max(a["pct_max"], pct)
            a["read_b"] += int(d_r)
            a["write_b"] += int(d_w)
            if exe:
                a["exe"] = exe
            tick_rss[lname] = tick_rss.get(lname, 0) + rss
            tick_cnt[lname] = tick_cnt.get(lname, 0) + 1

            if lname in wset:
                watch_rows.append((its, lname, pid, round(pct, 2), rss, int(d_r), int(d_w)))

        # Самозахист: якщо точний вимір пам'яті раптом став дорогим (дуже багато
        # процесів), тихо переходимо на дешевий режим, щоб не вантажити систему.
        scan_ms = (time.time() - scan_t0) * 1000
        if self.mem_metric == "auto" and self.mem_mode == "uss":
            if scan_ms > 900:
                self.mem_slow_hits += 1
                if self.mem_slow_hits >= 3:
                    self.mem_mode = "private"
                    log.warning("Опитування займало %.0f мс — перемикаю вимір пам'яті "
                                "на дешевий режим 'private'", scan_ms)
                    # запам'ятати, щоб після перезапуску не вчитися заново
                    self.writer.push(
                        "INSERT OR REPLACE INTO meta(k,v) VALUES"
                        "('mem_mode_learned','private')", ())
            else:
                self.mem_slow_hits = 0
        self.last_scan_ms = round(scan_ms)

        for lname, v in tick_rss.items():
            a = self.acc.get(lname)
            if a:
                a["rss_max"] = max(a["rss_max"], v)
                a["nproc"] = max(a["nproc"], tick_cnt.get(lname, 0))
                a["cores_max"] = max(a.get("cores_max", 0.0),
                                     tick_cores.get(lname, 0.0))

        # зниклі процеси — з гістерезисом: пропуск в одному опитуванні (psutil
        # інколи не встигає перелічити всі процеси за раз) не має виглядати як
        # «процес помер і одразу перезапустився». Закриваємо інстанс лише після
        # 2 підряд промахів — це прибирає роздування лічильника запусків.
        for key in list(self.prev):
            if key in seen:
                self.missing.pop(key, None)
            else:
                self.missing[key] = self.missing.get(key, 0) + 1
        gone = [k for k, c in self.missing.items() if c >= 2]
        for key in gone:
            self.missing.pop(key, None)
            pid, ct = key
            lname, exe = self.inst_meta.get(key, ("?", ""))
            cpu_s = round(self.inst_cpu.pop(key, 0.0), 2)
            self.prev.pop(key, None)
            self.inst_meta.pop(key, None)
            self.writer.push(
                "UPDATE proc_instances SET ended_ts=?, cpu_core_s=? "
                "WHERE pid=? AND create_time=? AND ended_ts IS NULL", (its, cpu_s, pid, ct))
            if self.first_tick_done:
                self.writer.push(
                    "INSERT INTO events(ts,kind,name,exe,pid,info) VALUES(?,?,?,?,?,?)",
                    (its, "process_stop", lname, exe, pid,
                     f"завершився; CPU-час {cpu_s:.1f} с"))
            with self.pid_lock:
                self.dead_pids[pid] = (lname, its)
                while len(self.dead_pids) > 400:
                    self.dead_pids.popitem(last=False)

        with self.pid_lock:
            self.pid_map = new_pid_map
            cutoff = its - 90
            for dpid in [dp for dp, (_, dts) in self.dead_pids.items() if dts < cutoff]:
                self.dead_pids.pop(dpid, None)

        if watch_rows:
            self.writer.push_many([
                ("INSERT INTO watch_raw(ts,name,pid,cpu_pct,rss,read_b,write_b) "
                 "VALUES(?,?,?,?,?,?,?)", r) for r in watch_rows])

        # системні лічильники
        cpu_now = psutil.cpu_percent(None)
        # завантаження КОЖНОГО ядра окремо: показує, чи не впирається щось
        # в одне ядро, поки загальна цифра виглядає спокійною
        try:
            per_core = psutil.cpu_percent(None, percpu=True) or []
        except Exception:
            per_core = []
        core_max = max(per_core) if per_core else 0.0
        vm = psutil.virtual_memory()
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()
        s = self.sys_acc
        if s is None:
            s = self.sys_acc = {"cpu_sum": 0.0, "cpu_n": 0, "cpu_max": 0.0,
                                "core_max": 0.0,
                                "ram_used": 0, "ram_total": vm.total,
                                "read_b": 0, "write_b": 0, "sent_b": 0, "recv_b": 0, "nproc": 0}
        s["cpu_sum"] += cpu_now
        s["cpu_n"] += 1
        s["cpu_max"] = max(s["cpu_max"], cpu_now)
        s["core_max"] = max(s["core_max"], core_max)
        s["ram_used"] = max(s["ram_used"], vm.used)
        s["ram_total"] = vm.total
        s["nproc"] = max(s["nproc"], len(seen))
        if disk and self.prev_disk:
            s["read_b"] += max(0, disk.read_bytes - self.prev_disk.read_bytes)
            s["write_b"] += max(0, disk.write_bytes - self.prev_disk.write_bytes)
        if net and self.prev_net:
            s["sent_b"] += max(0, net.bytes_sent - self.prev_net.bytes_sent)
            s["recv_b"] += max(0, net.bytes_recv - self.prev_net.bytes_recv)
        self.prev_disk = disk
        self.prev_net = net

        # --- знімок «зараз»: УСІ запущені програми з усіма метриками ----------
        # Дані вже зібрані вище в цьому ж циклі, тож це майже безкоштовно.
        # Мережа береться з окремого живого буфера ETW і ділиться на інтервал,
        # щоб вийшла швидкість (Б/с), як у Диспетчері задач.
        with self.etw_lock:
            net_live, self.etw_live = self.etw_live, {}
        net_by_name = {}
        for nm, (sent, recv) in net_live.items():
            if nm == UNATTRIBUTED:
                continue          # у живій таблиці програм цьому не місце
            e = net_by_name.setdefault(nm, [0, 0])
            e[0] += sent
            e[1] += recv

        live_apps = []
        for lname, cnt in tick_cnt.items():
            net = net_by_name.get(lname, (0, 0))
            cores = tick_cores.get(lname, 0.0)
            cores1 = tick_cores1.get(lname, 0.0)
            live_apps.append({
                "name": lname,
                "cpu_pct": round(min(100.0, tick_pct.get(lname, 0.0)), 1),
                "cores": round(cores, 2),
                "cores1": round(cores1, 2),
                # програма впирається в одне ядро: найзавантаженіший її процес
                # майже повністю з'їв ядро, а в системі ще є вільні
                "core_bound": bool(cores1 >= 0.85 and self.ncpu > 2),
                "rss": tick_rss.get(lname, 0),
                "disk_bps": int(tick_io.get(lname, 0) / dt),
                "net_up_bps": int(net[0] / dt),
                "net_dn_bps": int(net[1] / dt),
                "net_bps": int((net[0] + net[1]) / dt),
                "gpu_pct": round(min(100.0, tick_gpu.get(lname, 0.0)), 1),
                "nproc": cnt,
                "exe": (self.acc.get(lname) or {}).get("exe", ""),
            })
        live_apps.sort(key=lambda x: -x["cpu_pct"])
        with self.live_lock:
            self.live = {
                "ts": its, "ncpu": self.ncpu, "cpu_total": round(cpu_now, 1),
                "ram_used": vm.used, "ram_total": vm.total,
                "interval": round(dt, 1),
                "per_core": [round(c, 1) for c in per_core],
                "core_max": round(core_max, 1),
                "gpu_ok": bool(self.gpu),
                "gpu_status": self.gpu_status,
                "mem_mode": self.mem_mode,
                "scan_ms": getattr(self, "last_scan_ms", 0),
                "etw_ok": bool(net_by_name) or None,
                "net_ok": bool(net_by_name) or None,
                "apps": live_apps,
            }
            self._read_sensors(its)
            # компактний зріз для клавіш Stream Deck (лише числа)
            self.hist.append((
                its,
                round(cpu_now, 1),
                round(core_max, 1),
                round(vm.used / vm.total * 100, 1) if vm.total else 0,
                round(max([a["gpu_pct"] for a in live_apps] or [0]), 1),
                int(sum(a["net_bps"] for a in live_apps)),
                int(sum(a["disk_bps"] for a in live_apps)),
            ))

        if not self.first_tick_done:
            self.first_tick_done = True
            self.writer.push("INSERT INTO events(ts,kind,name,info) VALUES(?,?,?,?)",
                             (its, "monitor_start", "PC Monitor",
                              f"монітор запущено; активних процесів: {len(seen)}"))

        # синхронізація CPU-часу довгоживучих інстансів кожні 10 хв
        if its - self.last_inst_sync > 600:
            self.last_inst_sync = its
            items = []
            for key, cpu_s in self.inst_cpu.items():
                pid, ct = key
                items.append((
                    "UPDATE proc_instances SET cpu_core_s=? "
                    "WHERE pid=? AND create_time=? AND ended_ts IS NULL",
                    (round(cpu_s, 2), pid, ct)))
            self.writer.push_many(items)

    def on_new_process(self, its, pid, ct, name, lname, exe, info):
        started = ct if ct > 0 else its
        preexisting = 0 if self.first_tick_done else 1
        cmdline = None
        if self.cfg.get("log_cmdline"):
            cl = info.get("cmdline")
            if cl:
                cmdline = " ".join(cl)[:500]
        parent_name = ""
        try:
            ppid = info.get("ppid") or 0
            with self.pid_lock:
                parent_name = self.pid_map.get(ppid, "")
        except Exception:
            ppid = 0
        # ON CONFLICT: якщо цей самий процес уже записаний (наприклад, монітор
        # перезапустили, а програма далі працює) — не створюємо новий запис,
        # а просто «відкриваємо» наявний. Інакше лічильник запусків роздувався.
        self.writer.push(
            "INSERT INTO proc_instances(pid,create_time,name,exe,ppid,parent_name,cmdline,"
            "started_ts,preexisting) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(pid,create_time) WHERE create_time > 0 DO UPDATE SET ended_ts=NULL, "
            "name=excluded.name, exe=COALESCE(NULLIF(excluded.exe,''), exe)",
            (pid, ct, lname, exe, ppid, parent_name, cmdline, started, preexisting))
        if exe and exe not in self.known_exes:
            self.known_exes.add(exe)
            size = mtime = None
            try:
                st = os.stat(exe)
                size, mtime = st.st_size, int(st.st_mtime)
            except Exception:
                pass
            self.writer.push(
                "INSERT INTO exe_info(exe,name,first_seen,size,mtime) VALUES(?,?,?,?,?) "
                "ON CONFLICT(exe) DO NOTHING", (exe, lname, its, size, mtime))
            self.inspector.submit(exe)
        if self.first_tick_done:
            self.writer.push(
                "INSERT INTO events(ts,kind,name,exe,pid,info) VALUES(?,?,?,?,?,?)",
                (its, "process_start", lname, exe, pid,
                 f"запущено{' (батько: ' + parent_name + ')' if parent_name else ''}"))

    def finalize_minute(self):
        if self.minute_idx is None:
            return
        m_ts = self.minute_idx * 60
        rows = []

        # мережа з ETW: pid -> назва
        with self.etw_lock:
            etw, self.etw_acc = self.etw_acc, {}
        net_by_name = {}
        for nm, (sent, recv) in etw.items():
            e = net_by_name.setdefault(nm, [0, 0])
            e[0] += sent
            e[1] += recv
        for nm, (sent, recv) in net_by_name.items():
            rows.append((
                "INSERT INTO net_minute(minute_ts,name,sent_b,recv_b) VALUES(?,?,?,?) "
                "ON CONFLICT(minute_ts,name) DO UPDATE SET "
                "sent_b=sent_b+excluded.sent_b, recv_b=recv_b+excluded.recv_b",
                (m_ts, nm, sent, recv)))

        # DNS
        with self.dns_lock:
            dns, self.dns_buf = self.dns_buf, []
        dns_agg = {}
        for nm, domain in dns:
            dkey = (nm, domain.lower())
            dns_agg[dkey] = dns_agg.get(dkey, 0) + 1
        now = int(time.time())
        for (nm, domain), cnt in dns_agg.items():
            rows.append((
                "INSERT INTO dns_seen(name,domain,first_ts,last_ts,times) VALUES(?,?,?,?,?) "
                "ON CONFLICT(name,domain) DO UPDATE SET last_ts=excluded.last_ts, "
                "times=times+excluded.times", (nm, domain, now, now, cnt)))

        # з'єднання
        with self.conn_lock:
            conns, self.conn_acc = self.conn_acc, {}
        for (nm, ip, port, proto), v in conns.items():
            rows.append((
                "INSERT INTO net_conn(name,raddr,rport,proto,is_public,first_ts,last_ts,times,pid)"
                " VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(name,raddr,rport,proto) DO UPDATE SET "
                "last_ts=excluded.last_ts, times=times+excluded.times, pid=excluded.pid",
                (nm, ip, port, proto, v["pub"], v["first"], v["last"], v["times"], v["pid"])))

        # активність апок за хвилину
        acc, self.acc = self.acc, {}
        watched = self.watchset
        for lname, a in acc.items():
            net_e = net_by_name.get(lname)
            active = (a["core_s"] > 0.05 or a["read_b"] > 0 or a["write_b"] > 0
                      or net_e is not None or lname in watched)
            if not active:
                continue
            avg_pct = min(100.0, a["core_s"] / 60.0 / self.ncpu * 100.0)
            rows.append((
                "INSERT OR REPLACE INTO app_minute(minute_ts,name,exe,cpu_pct_avg,cpu_pct_max,"
                "cpu_core_s,rss_max,read_b,write_b,nproc,cores_max) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (m_ts, lname, a["exe"], round(avg_pct, 2), round(a["pct_max"], 2),
                 round(a["core_s"], 3), a["rss_max"], a["read_b"], a["write_b"], a["nproc"],
                 round(a.get("cores_max", 0.0), 2))))

        # системна хвилина
        s, self.sys_acc = self.sys_acc, None
        if s and s["cpu_n"]:
            rows.append((
                "INSERT OR REPLACE INTO sys_minute(minute_ts,cpu_avg,cpu_max,ram_used,ram_total,"
                "read_b,write_b,sent_b,recv_b,nproc,core_max) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (m_ts, round(s["cpu_sum"] / s["cpu_n"], 2), round(s["cpu_max"], 2),
                 s["ram_used"], s["ram_total"], s["read_b"], s["write_b"],
                 s["sent_b"], s["recv_b"], s["nproc"], round(s.get("core_max", 0.0), 1))))

        rows.append(("INSERT OR REPLACE INTO meta(k,v) VALUES('last_sample_ts',?)",
                     (str(int(time.time())),)))
        self.writer.push_many(rows)


# --------------------------------------------------------- пулер з'єднань ----
class ConnPoller(threading.Thread):
    def __init__(self, cfg, sampler):
        super().__init__(name="conn-poller", daemon=True)
        self.cfg = cfg
        self.sampler = sampler
        self.warned = False

    def run(self):
        while not STOP.is_set():
            STOP.wait(self.cfg["conn_poll_interval"])
            try:
                self.poll()
            except psutil.AccessDenied:
                if not self.warned:
                    self.warned = True
                    log.warning("Немає доступу до списку з'єднань — пропускаю")
            except Exception:
                log.exception("Помилка пулера з'єднань")

    def poll(self):
        its = int(time.time())
        try:
            conns = psutil.net_connections("inet")
        except Exception:
            return
        smp = self.sampler
        for c in conns:
            if not c.raddr or not c.pid:
                continue
            ip = c.raddr.ip
            if ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::"):
                continue
            if getattr(c, "status", "") == "LISTEN":
                continue
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            nm = smp.resolve_pid(c.pid) or f"(pid {c.pid})"
            key = (nm, ip, c.raddr.port, proto)
            with smp.conn_lock:
                v = smp.conn_acc.get(key)
                if v is None:
                    smp.conn_acc[key] = {"first": its, "last": its, "times": 1,
                                         "pid": c.pid, "pub": 1 if is_public_ip(ip) else 0}
                else:
                    v["last"] = its
                    v["times"] += 1
                    v["pid"] = c.pid


# ------------------------------------------------------- аналітика для API ----
_day_cache = {}


def build_day(cfg, date, sampler=None):
    """Повний зріз дня по апках: ресурси + мережа + підозрілість."""
    now = time.time()
    cached = _day_cache.get(date)
    ttl = 30 if date == human_day() else 300
    if cached and now - cached[0] < ttl:
        return cached[1]

    t0, t1 = day_bounds(date)
    apps = {}

    am = q("""SELECT name, MAX(exe) exe, SUM(cpu_core_s) cpu_core_s, MAX(cpu_pct_max) cpu_pct_max,
                     MAX(rss_max) rss_max, SUM(read_b) read_b, SUM(write_b) write_b,
                     COUNT(*) nmin, MIN(minute_ts) first_ts, MAX(minute_ts) last_ts,
                     MAX(COALESCE(cores_max,0)) cores_max
              FROM app_minute WHERE minute_ts >= ? AND minute_ts < ? GROUP BY name""", (t0, t1))
    minutes_available = bool(am)
    if not am:
        am = q("SELECT * FROM app_day WHERE day = ?", (date,))
    if not am:
        # За цей день немає ЖОДНОГО виміру — монітор тоді не працював.
        # Раніше день усе одно наповнювався «привидами»: процеси, що були
        # запущені ще до першого старту монітора, потрапляли в кожен минулий
        # день лише тому, що тоді існували, — сотні рядків із нулями.
        result = {"date": date, "minutes_available": False, "apps": [],
                  "no_data": True}
        _day_cache[date] = (now, result)
        return result
    for r in am:
        apps[r["name"]] = {
            "name": r["name"], "exe": r.get("exe") or "",
            "cpu_core_s": round(r.get("cpu_core_s") or 0, 1),
            "cpu_pct_max": r.get("cpu_pct_max") or 0,
            "rss_max": r.get("rss_max") or 0,
            "read_b": r.get("read_b") or 0, "write_b": r.get("write_b") or 0,
            "sent_b": r.get("sent_b") or 0, "recv_b": r.get("recv_b") or 0,
            "nmin": r.get("nmin") or 0,
            "first_ts": r.get("first_ts"), "last_ts": r.get("last_ts"),
            "ninst": r.get("ninst") or 0,
            "cores_max": round(r.get("cores_max") or 0, 2),
        }

    if minutes_available:
        for r in q("""SELECT name, SUM(sent_b) s, SUM(recv_b) rcv FROM net_minute
                      WHERE minute_ts >= ? AND minute_ts < ? GROUP BY name""", (t0, t1)):
            a = apps.setdefault(r["name"], _empty_app(r["name"]))
            a["sent_b"] = r["s"] or 0
            a["recv_b"] = r["rcv"] or 0

    # з'єднання/порти/IP
    for r in q("""SELECT name, COUNT(DISTINCT CASE WHEN is_public=1 THEN raddr END) pub_ips,
                         COUNT(DISTINCT CASE WHEN is_public=1 THEN rport END) ports,
                         COUNT(*) nconn
                  FROM net_conn WHERE last_ts >= ? AND first_ts < ? GROUP BY name""", (t0, t1)):
        a = apps.setdefault(r["name"], _empty_app(r["name"]))
        a["pub_ips"] = r["pub_ips"] or 0
        a["nconn"] = r["nconn"] or 0
        a["odd_ports"] = 0  # уточнимо нижче
    odd = q("""SELECT name, COUNT(DISTINCT rport) n FROM net_conn
               WHERE last_ts >= ? AND first_ts < ? AND is_public = 1
                 AND rport NOT IN ({}) GROUP BY name""".format(
        ",".join(str(p) for p in suspicion.COMMON_PORTS)), (t0, t1))
    for r in odd:
        if r["name"] in apps:
            apps[r["name"]]["odd_ports"] = r["n"]

    for r in q("""SELECT name, COUNT(*) n FROM dns_seen
                  WHERE last_ts >= ? AND first_ts < ? GROUP BY name""", (t0, t1)):
        a = apps.setdefault(r["name"], _empty_app(r["name"]))
        a["dns_count"] = r["n"]

    # інстанси
    for r in q("""SELECT name, COUNT(DISTINCT pid || '-' || create_time) n,
                         MIN(started_ts) fs, MAX(COALESCE(ended_ts, ?)) le,
                         AVG(CASE WHEN ended_ts IS NOT NULL THEN ended_ts - started_ts END) avg_life,
                         COUNT(DISTINCT CASE WHEN ended_ts IS NULL
                               THEN pid || '-' || create_time END) running
                  FROM proc_instances
                  WHERE started_ts < ? AND COALESCE(ended_ts, ?) >= ? GROUP BY name""",
               (int(now), t1, t1, t0)):
        a = apps.setdefault(r["name"], _empty_app(r["name"]))
        a["ninst"] = r["n"]
        a["avg_life_s"] = r["avg_life"]
        a["running"] = bool(r["running"])
        if not a.get("first_ts"):
            a["first_ts"] = r["fs"]
        a["proc_first_ts"] = r["fs"]
        a["proc_last_ts"] = r["le"]

    # exe_info
    # Зіставляємо шляхи БЕЗ огляду на регістр: у Windows це один і той самий
    # файл, а раніше різниця у великих/малих літерах призводила до того, що
    # позначка «довіряю» не підхоплювалась і попередження не зникало.
    exes = {a["exe"] for a in apps.values() if a.get("exe")}
    if exes:
        marks = ",".join("?" for _ in exes)
        info_by_exe = {}
        for r in q(f"SELECT * FROM exe_info WHERE exe COLLATE NOCASE IN ({marks})",
                   tuple(exes)):
            info_by_exe[(r["exe"] or "").lower()] = r
        for a in apps.values():
            r = info_by_exe.get((a.get("exe") or "").lower())
            if r:
                a["first_seen_ts"] = r["first_seen"]
                a["sig_status"] = r["sig_status"]
                a["sig_signer"] = r.get("sig_signer")
                a["sha256"] = r["sha256"]
                a["ignored"] = bool(r["ignored"])

    # нічна активність (лише якщо є хвилини)
    if minutes_available:
        for r in q("""SELECT name, MAX(cpu_pct_avg) m FROM app_minute
                      WHERE minute_ts >= ? AND minute_ts < ?
                        AND CAST(strftime('%H', minute_ts, 'unixepoch', 'localtime') AS INTEGER)
                            BETWEEN 2 AND 5
                      GROUP BY name""", (t0, t1)):
            if r["name"] in apps:
                apps[r["name"]]["night_cpu_max"] = r["m"]

    # watch-мітки
    watch = {r["name"] for r in q("SELECT name FROM watchlist")}
    scfg = cfg.get("suspicion", {})
    day_start_ts = t0 if date == human_day() else None
    # скільки днів монітор уже спостерігає — доки бази для порівняння нема,
    # правило «нова програма» вимикається, інакше в перший день усе «нове»
    baseline_days = None
    try:
        r = q1("SELECT v FROM meta WHERE k='installed_at'")
        if r:
            baseline_days = (now - int(r["v"])) / 86400.0
    except Exception:
        pass
    out = []
    for a in apps.values():
        a["watching"] = a["name"] in watch
        a["day_start_ts"] = day_start_ts
        a["baseline_days"] = baseline_days
        score, reasons = suspicion.evaluate(a, scfg)
        a["suspicion_score"] = score
        a["suspicion_reasons"] = reasons
        a["suspicious"] = (score >= suspicion.threshold(scfg)) and not a.get("ignored")
        a["kernel"] = (a["name"] in suspicion.KERNEL_PSEUDO
                       and not suspicion.has_real_path(a.get("exe")))
        a.pop("day_start_ts", None)
        a.pop("baseline_days", None)
        out.append(a)
    out.sort(key=lambda x: -(x.get("cpu_core_s") or 0))
    result = {"date": date, "minutes_available": minutes_available, "apps": out}
    _day_cache[date] = (now, result)
    return result


def _empty_app(name):
    return {"name": name, "exe": "", "cpu_core_s": 0, "cpu_pct_max": 0, "rss_max": 0,
            "read_b": 0, "write_b": 0, "sent_b": 0, "recv_b": 0, "nmin": 0,
            "first_ts": None, "last_ts": None, "ninst": 0}


def app_detail(cfg, date, name):
    t0, t1 = day_bounds(date)
    day = build_day(cfg, date)
    summary = next((a for a in day["apps"] if a["name"] == name.lower()), None)
    minutes = q("""SELECT minute_ts, cpu_pct_avg, cpu_pct_max, rss_max, read_b, write_b, nproc
                   FROM app_minute WHERE name=? AND minute_ts>=? AND minute_ts<?
                   ORDER BY minute_ts""", (name.lower(), t0, t1))
    net = q("""SELECT minute_ts, sent_b, recv_b FROM net_minute
               WHERE name=? AND minute_ts>=? AND minute_ts<? ORDER BY minute_ts""",
            (name.lower(), t0, t1))
    conns = q("""SELECT raddr, rport, proto, is_public, times, first_ts, last_ts
                 FROM net_conn WHERE name=? AND last_ts>=? AND first_ts<?
                 ORDER BY times DESC LIMIT 300""", (name.lower(), t0, t1))
    domains = q("""SELECT domain, times, first_ts, last_ts FROM dns_seen
                   WHERE name=? AND last_ts>=? AND first_ts<?
                   ORDER BY times DESC LIMIT 300""", (name.lower(), t0, t1))
    instances = q("""SELECT pid, started_ts, ended_ts, cpu_core_s, exe, ppid, parent_name,
                            preexisting
                     FROM proc_instances WHERE name=? AND started_ts<?
                       AND COALESCE(ended_ts, ?) >= ?
                     ORDER BY started_ts DESC LIMIT 500""", (name.lower(), t1, t1, t0))
    return {"date": date, "name": name.lower(), "summary": summary, "minutes": minutes,
            "net_minutes": net, "connections": conns, "domains": domains,
            "instances": instances}


def export_diagnostics(ctx, date=None, days=3):
    """
    Загальний звіт про роботу самої програми і системи — один файл, який
    можна надіслати на аналіз. Сюди входить усе, що потрібно, щоб зрозуміти
    і стан комп'ютера, і чи правильно працює монітор.

    Свідомо НЕ входить: вміст буфера обміну, командні рядки (якщо їх запис
    вимкнено), імена користувачів — лише те, що стосується роботи системи.
    """
    date = date or human_day()
    now = int(time.time())
    rep = {
        "_readme": ("Загальний діагностичний звіт PC Monitor. Містить стан "
                    "системи, зведення по програмах, результати перевірок і "
                    "журнал роботи самого монітора. Надішли цей файл у чат "
                    "Claude і попроси проаналізувати."),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "monitor_version": VERSION,
        "date": date,
    }

    # --- машина ---------------------------------------------------------
    try:
        vm = psutil.virtual_memory()
        rep["machine"] = {
            "hostname": socket.gethostname(),
            "os": sys.platform,
            "os_detail": platform.platform() if 'platform' in globals() else "",
            "python": sys.version.split()[0],
            "cpu_count": psutil.cpu_count(),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "ram_total": vm.total,
            "boot_time": int(psutil.boot_time()),
            "uptime_h": round((now - psutil.boot_time()) / 3600, 1),
        }
        try:
            rep["machine"]["cpu"] = platform.processor()
        except Exception:
            pass
    except Exception as e:
        rep["machine"] = {"error": str(e)}

    # --- стан монітора --------------------------------------------------
    db_size = 0
    for s in ("", "-wal", "-shm"):
        try:
            db_size += os.path.getsize(DB_PATH + s)
        except OSError:
            pass
    rep["monitor"] = {
        "uptime_s": now - ctx.started_at,
        "admin": is_admin(),
        "etw": ctx.etw.status if ctx.etw else "вимкнено",
        "etw_events": ctx.etw.events_seen if ctx.etw else 0,
        "gpu": getattr(ctx.sampler, "gpu_status", "?") if ctx.sampler else "?",
        "mem_mode": getattr(ctx.sampler, "mem_mode", "?") if ctx.sampler else "?",
        "scan_ms": getattr(ctx.sampler, "last_scan_ms", 0) if ctx.sampler else 0,
        "samples": ctx.sampler.samples_total if ctx.sampler else 0,
        "db_size": db_size,
        "autostart": autostart_status(),
        "config": load_config(),
        "clipwatch": bool(ctx.clipwatch),
    }

    # --- зараз ----------------------------------------------------------
    if ctx.sampler:
        with ctx.sampler.live_lock:
            lv = dict(ctx.sampler.live)
        lv["apps"] = sorted(lv.get("apps", []),
                            key=lambda a: -(a.get("cpu_pct") or 0))[:40]
        rep["now"] = lv

    # --- дні --------------------------------------------------------------
    rep["days"] = []
    for i in range(days):
        d = human_day(time.time() - i * 86400)
        try:
            dd = build_day(ctx.cfg, d)
        except Exception as e:
            rep["days"].append({"date": d, "error": str(e)})
            continue
        apps = sorted(dd["apps"], key=lambda a: -(a.get("cpu_core_s") or 0))[:30]
        t0, t1 = day_bounds(d)
        tot = q1("""SELECT AVG(cpu_avg) cpu_avg, MAX(cpu_max) cpu_max,
                           MAX(COALESCE(core_max,0)) core_max, MAX(ram_used) ram_max,
                           SUM(sent_b) sent, SUM(recv_b) recv, SUM(read_b) rd,
                           SUM(write_b) wr, COUNT(*) minutes
                    FROM sys_minute WHERE minute_ts>=? AND minute_ts<?""", (t0, t1))
        rep["days"].append({
            "date": d, "totals": tot,
            "suspicious": [{"name": a["name"], "score": a["suspicion_score"],
                            "reasons": a["suspicion_reasons"], "exe": a.get("exe")}
                           for a in dd["apps"] if a.get("suspicious")],
            "top_apps": [{k: a.get(k) for k in
                          ("name", "exe", "cpu_core_s", "cores_max", "rss_max",
                           "read_b", "write_b", "sent_b", "recv_b", "ninst",
                           "pub_ips", "dns_count", "suspicion_score")}
                         for a in apps],
        })

    # --- перевірки здоров'я / затримки / буфер ---------------------------
    try:
        rep["health"] = ctx.health.status() if ctx.health else None
    except Exception as e:
        rep["health"] = {"error": str(e)}
    try:
        rep["latency"] = ctx.latency.status() if ctx.latency else None
    except Exception as e:
        rep["latency"] = {"error": str(e)}
    try:
        rep["dpcisr"] = ctx.dpcisr.status() if ctx.dpcisr else None
    except Exception as e:
        rep["dpcisr"] = {"error": str(e)}
    try:
        if ctx.clipwatch:
            rep["clipboard_log"] = ctx.clipwatch.log(limit=80)
        if IS_WIN:
            import clipboard_win
            rep["clipboard_watchers"] = clipboard_win.running_watchers()
    except Exception as e:
        rep["clipboard_log"] = {"error": str(e)}

    # --- мережа зведено ---------------------------------------------------
    rep["network"] = {
        "top_domains": q("""SELECT name, domain, times, last_ts FROM dns_seen
                            ORDER BY times DESC LIMIT 60"""),
        "top_connections": q("""SELECT name, raddr, rport, proto, times, last_ts
                                FROM net_conn WHERE is_public=1
                                ORDER BY times DESC LIMIT 60"""),
    }

    # --- нові програми ---------------------------------------------------
    cut = now - days * 86400
    rep["new_executables"] = q("""SELECT exe, name, first_seen, size, sha256, sig_status
                                  FROM exe_info WHERE first_seen >= ?
                                  ORDER BY first_seen DESC LIMIT 120""", (cut,))

    # --- журнал самого монітора ------------------------------------------
    rep["monitor_log_tail"] = []
    try:
        lp = os.path.join(LOG_DIR, "monitor.log")
        if os.path.exists(lp):
            with open(lp, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            rep["monitor_log_tail"] = [x.rstrip() for x in lines[-400:]]
    except Exception as e:
        rep["monitor_log_tail"] = [f"(не вдалося прочитати: {e})"]

    # --- звіт xperf, якщо лишився ----------------------------------------
    try:
        xr = os.path.join(BASE, "xperf_report.txt")
        if os.path.exists(xr):
            with open(xr, "r", encoding="utf-8", errors="replace") as f:
                rep["xperf_report_head"] = f.read(8000)
    except Exception:
        pass

    os.makedirs(EXPORT_DIR, exist_ok=True)
    fname = f"pcmonitor_diagnostics_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(EXPORT_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1, default=str)
    return path


# Процеси, які не можна завершувати: без них система ламається або
# перезавантажується. Список навмисно з запасом.
UNKILLABLE = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
    "memory compression", "secure system", "system idle process", "idle",
    "audiodg.exe", "dwm.exe", "sihost.exe", "ctfmon.exe",
}


SD_PLUGIN_ID = "com.pcmon.metrics.sdPlugin"


def streamdeck_dir():
    """Тека плагінів Stream Deck, якщо програма встановлена."""
    if not IS_WIN:
        return None
    base = os.environ.get("APPDATA")
    if not base:
        return None
    p = os.path.join(base, "Elgato", "StreamDeck", "Plugins")
    return p if os.path.isdir(os.path.dirname(p)) else None


def install_streamdeck(cfg):
    """
    Покласти плагін у теку Stream Deck.

    Порт монітора підставляємо у файли плагіна ПІД ЧАС встановлення. Інакше
    людині довелось би вписувати його вручну в кожну клавішу, а помилка в
    одній цифрі виглядала б як «плагін не працює».
    """
    src = os.path.join(BASE, "streamdeck", SD_PLUGIN_ID)
    if not os.path.isdir(src):
        return {"ok": False, "error": "файли плагіна не знайдено поруч із монітором"}
    plugins = streamdeck_dir()
    if not plugins:
        return {"ok": False, "error":
                "Stream Deck не знайдено. Встанови програму Elgato Stream Deck "
                "і спробуй ще раз."}
    dst = os.path.join(plugins, SD_PLUGIN_ID)
    port = str(cfg.get("dashboard_port", 8805))

    running = [p.info["pid"] for p in psutil.process_iter(["pid", "name"])
               if (p.info.get("name") or "").lower() == "streamdeck.exe"]
    try:
        os.makedirs(dst, exist_ok=True)
        for root, _dirs, files in os.walk(src):
            rel = os.path.relpath(root, src)
            out = os.path.join(dst, rel) if rel != "." else dst
            os.makedirs(out, exist_ok=True)
            for fn in files:
                s, d = os.path.join(root, fn), os.path.join(out, fn)
                if fn.endswith((".html", ".json")):
                    txt = open(s, encoding="utf-8").read().replace('"8787"',
                                                                   f'"{port}"')
                    with open(d, "w", encoding="utf-8") as f:
                        f.write(txt)
                else:
                    shutil.copyfile(s, d)
    except PermissionError:
        return {"ok": False, "error":
                "немає прав на запис у теку Stream Deck — закрий Stream Deck "
                "і спробуй ще раз"}
    except Exception as e:
        log.exception("Не вдалося встановити плагін Stream Deck")
        return {"ok": False, "error": str(e)}

    log.info("Плагін Stream Deck встановлено: %s", dst)
    return {"ok": True, "path": dst, "port": port, "running": bool(running),
            "note": ("Stream Deck зараз запущений — перезапусти його, щоб він "
                     "побачив плагін." if running else
                     "Запусти Stream Deck — плагін буде в списку дій "
                     "у категорії «PC Monitor».")}


def kill_process(pid, expect_name=""):
    """
    Завершити процес — те саме, що робить Диспетчер задач.

    Запобіжники: критичні процеси Windows не чіпаємо взагалі; ім'я звіряється
    з очікуваним, щоб не влучити в чужий процес, якщо PID уже перевикористали.
    Дані на диску це не змінює — просто зупиняє програму.
    """
    try:
        pid = int(pid)
    except Exception:
        return False, "невірний номер процесу"
    if pid <= 4:
        return False, "це системний процес — не чіпаємо"
    try:
        p = psutil.Process(pid)
        nm = (p.name() or "").lower()
    except psutil.NoSuchProcess:
        return False, "процес уже завершився"
    except Exception as e:
        return False, str(e)

    if nm in UNKILLABLE:
        return False, (f"«{nm}» — критичний процес Windows. Його завершення "
                       "зламає систему або спричинить перезавантаження, тому "
                       "монітор цього не робить.")
    if expect_name and nm != expect_name.lower():
        return False, (f"під цим номером зараз інший процес ({nm}) — "
                       "оновіть список і спробуйте ще раз")
    if pid == os.getpid():
        return False, "це сам монітор"   # захист від самогубства
    def gone():
        """Процес справді зупинився? «Зомбі» теж рахуємо як зупинений —
        він уже не виконується, просто чекає, поки батько його прибере."""
        try:
            if not p.is_running():
                return True
            return p.status() == psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return True
        except Exception:
            return False

    try:
        p.terminate()                    # спершу ввічливо
        for _ in range(20):
            if gone():
                break
            time.sleep(0.2)
        if not gone():
            p.kill()                     # якщо не реагує — примусово
            for _ in range(15):
                if gone():
                    break
                time.sleep(0.2)
        if not gone():
            return False, "процес не реагує навіть на примусове завершення"
        log.info("Завершено процес %s (pid %s) на запит користувача", nm, pid)
        return True, ""
    except psutil.AccessDenied:
        return False, ("немає прав завершити цей процес — спробуй запустити "
                       "монітор від імені адміністратора")
    except Exception as e:
        return False, str(e)


def process_card(ctx, name, date=None):
    """
    Повна картка однієї програми: живі дані по кожному процесу + історія.
    Потрібна, щоб із будь-якої вкладки можна було відкрити програму й
    побачити все про неї, а не лише рядок у таблиці.
    """
    lname = (name or "").strip().lower()
    if not lname:
        return {"error": "не вказано назву"}
    date = date or human_day()

    # --- живі процеси з цим ім'ям ---------------------------------------
    procs = []
    total = {"cpu": 0.0, "rss": 0, "threads": 0, "handles": 0}
    ncpu = psutil.cpu_count() or 1

    # З'єднання беремо ОДИН раз на всю систему і групуємо по pid.
    # Раніше для кожного процесу викликалось p.net_connections(), а цей виклик
    # на Windows щоразу перебирає всю системну таблицю з'єднань. Для браузера
    # з 30 процесів це 30 повних перебирань — картка «збирала дані» десятками
    # секунд і виглядала як зависання.
    conns_by_pid = {}
    t_conn = time.time()
    try:
        for c in psutil.net_connections("inet"):
            if c.pid and c.raddr:
                conns_by_pid[c.pid] = conns_by_pid.get(c.pid, 0) + 1
    except Exception:
        conns_by_pid = None      # немає доступу — просто не показуємо колонку
    conn_ms = round((time.time() - t_conn) * 1000)

    # --- КРОК 1: знайти потрібні процеси ДЕШЕВО --------------------------
    # Раніше тут стояв process_iter із повним списком атрибутів (exe, username,
    # memory_info, cmdline...). psutil бере ці атрибути для КОЖНОГО процесу в
    # системі, а не лише для тих, чиє ім'я збіглося. На машині з 400 процесами
    # це 400 звернень до токена процесу й до LookupAccountSid заради 12 рядків,
    # які нам справді потрібні. Саме через це картка «збирала дані» вічно.
    # Тепер перебираємо лише pid+name (це майже безкоштовно), а дорогі поля
    # питаємо тільки в тих процесів, що збіглися.
    t_scan = time.time()
    targets = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if (p.info.get("name") or "").lower() == lname:
                targets.append(p)
        except Exception:
            continue
    find_ms = round((time.time() - t_scan) * 1000)

    # --- КРОК 2: подробиці лише по знайдених ------------------------------
    MAX_PROCS = 80                       # межа для родин на кшталт chrome.exe
    BUDGET_S = 6.0                       # більше цього не збираємо — краще
    deadline = time.time() + BUDGET_S    # неповна картка, ніж «зависла» картка
    partial = len(targets) > MAX_PROCS
    pname_cache = {}                     # ppid → ім'я батька, щоб не питати двічі

    def _pname(pid):
        if not pid:
            return ""
        if pid not in pname_cache:
            try:
                pname_cache[pid] = psutil.Process(pid).name()
            except Exception:
                pname_cache[pid] = ""
        return pname_cache[pid]

    for p in targets[:MAX_PROCS]:
        if time.time() > deadline:
            partial = True
            break
        try:
            with p.oneshot():            # psutil кешує syscall-и в цьому блоці
                mem = p.memory_info()
                rss = getattr(mem, "rss", 0) if mem else 0
                row = {
                    "pid": p.pid,
                    "ppid": p.ppid(),
                    "rss": rss,
                    "threads": p.num_threads(),
                    "status": p.status(),
                    "started": int(p.create_time() or 0),
                }
                for key, fn in (("exe", p.exe), ("user", p.username),
                                ("nice", p.nice)):
                    try:
                        row[key] = str(fn() or "")
                    except Exception:
                        row[key] = ""
                if ctx.cfg.get("log_cmdline"):
                    try:
                        cl = p.cmdline()
                        row["cmdline"] = " ".join(cl)[:400] if cl else ""
                    except Exception:
                        row["cmdline"] = ""
                try:
                    io = p.io_counters()
                    row["read_b"] = io.read_bytes
                    row["write_b"] = io.write_bytes
                except Exception:
                    pass
            row["parent"] = _pname(row["ppid"])
            row["conns"] = (conns_by_pid.get(row["pid"], 0)
                            if conns_by_pid is not None else None)
            procs.append(row)
            total["rss"] += rss
            total["threads"] += row["threads"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    procs.sort(key=lambda r: -r["rss"])
    scan_ms = round((time.time() - t_conn) * 1000)

    # --- живий зріз від збирача (CPU/диск/мережа/GPU за інтервал) --------
    live = None
    if ctx.sampler:
        with ctx.sampler.live_lock:
            for a in (ctx.sampler.live.get("apps") or []):
                if a["name"] == lname:
                    live = dict(a)
                    break

    # --- історія --------------------------------------------------------
    day = build_day(ctx.cfg, date)
    summary = next((a for a in day["apps"] if a["name"] == lname), None)
    t0, t1 = day_bounds(date)
    minutes = q("""SELECT minute_ts, cpu_pct_avg, rss_max, read_b, write_b,
                          COALESCE(cores_max,0) cores_max
                   FROM app_minute WHERE name=? AND minute_ts>=? AND minute_ts<?
                   ORDER BY minute_ts""", (lname, t0, t1))
    netmin = q("""SELECT minute_ts, sent_b, recv_b FROM net_minute
                  WHERE name=? AND minute_ts>=? AND minute_ts<? ORDER BY minute_ts""",
               (lname, t0, t1))
    conns = q("""SELECT raddr, rport, proto, is_public, times, last_ts FROM net_conn
                 WHERE name=? ORDER BY last_ts DESC LIMIT 80""", (lname,))
    domains = q("""SELECT domain, times, last_ts FROM dns_seen WHERE name=?
                   ORDER BY times DESC LIMIT 60""", (lname,))
    events = q("""SELECT ts, kind, pid, info FROM events WHERE name=? AND ts>=? AND ts<?
                  ORDER BY ts DESC LIMIT 60""", (lname, t0, t1))
    hist = q("""SELECT day, cpu_core_s, rss_max, sent_b, recv_b, ninst
                FROM app_day WHERE name=? ORDER BY day DESC LIMIT 14""", (lname,))
    exe = (procs[0]["exe"] if procs else (summary or {}).get("exe") or "")
    info = q1("SELECT * FROM exe_info WHERE exe=? COLLATE NOCASE", (exe,)) if exe else None
    watching = bool(q1("SELECT 1 FROM watchlist WHERE name=?", (lname,)))

    return {
        "name": lname, "date": date, "exe": exe, "ncpu": ncpu,
        "processes": procs, "nproc": len(procs), "total": total,
        "live": live, "summary": summary, "exe_info": info,
        "minutes": minutes, "net_minutes": netmin,
        "connections": conns, "domains": domains,
        "events": events, "history": hist,
        "watching": watching,
        "running": bool(procs),
        "partial": partial, "nfound": len(targets),
        # скільки коштував збір — щоб було видно, якщо щось знову гальмує
        "timing": {"connections_ms": conn_ms, "find_ms": find_ms,
                   "total_ms": scan_ms},
    }


def export_app(cfg, name, date=None):
    """Детальний звіт по апці → exports/*.json (файл для аналізу Claude)."""
    date = date or human_day()
    lname = name.lower()
    detail = app_detail(cfg, date, lname)
    exe = (detail.get("summary") or {}).get("exe") or ""
    exe_row = q1("SELECT * FROM exe_info WHERE exe=? COLLATE NOCASE", (exe,)) if exe else None
    events = q("""SELECT ts, kind, pid, info FROM events
                  WHERE name=? AND ts>=? AND ts<? ORDER BY ts LIMIT 1000""",
               (lname, *day_bounds(date)))
    history = q("""SELECT day, cpu_core_s, rss_max, read_b, write_b, sent_b, recv_b, nmin, ninst
                   FROM app_day WHERE name=? ORDER BY day DESC LIMIT 30""", (lname,))
    watch_raw = q("""SELECT ts, pid, cpu_pct, rss, read_b, write_b FROM watch_raw
                     WHERE name=? AND ts>=? AND ts<? ORDER BY ts LIMIT 20000""",
                  (lname, *day_bounds(date)))
    all_domains = q("""SELECT domain, times, first_ts, last_ts FROM dns_seen WHERE name=?
                       ORDER BY times DESC LIMIT 500""", (lname,))
    all_conns = q("""SELECT raddr, rport, proto, is_public, times, first_ts, last_ts
                     FROM net_conn WHERE name=? ORDER BY times DESC LIMIT 500""", (lname,))
    report = {
        "_readme": ("Звіт згенеровано PC Monitor. Це детальний лог по одній програмі "
                    "для аналізу: просто перекинь цей файл у чат Claude і попроси "
                    "проаналізувати поведінку програми."),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "monitor_version": VERSION,
        "machine": {"hostname": socket.gethostname(), "os": sys.platform,
                    "cpu_count": psutil.cpu_count(),
                    "ram_total": psutil.virtual_memory().total},
        "app": lname,
        "date": date,
        "executable": exe_row or {"exe": exe},
        "day": detail,
        "events": events,
        "history_days": history,
        "domains_all_time": all_domains,
        "connections_all_time": all_conns,
        "watch_raw_samples": watch_raw,
        "suspicion": {
            "score": (detail.get("summary") or {}).get("suspicion_score", 0),
            "reasons": (detail.get("summary") or {}).get("suspicion_reasons", []),
            "note": "Евристики-підказки, не антивірусний вердикт.",
        },
    }
    os.makedirs(EXPORT_DIR, exist_ok=True)
    fname = f"{sanitize_filename(lname)}_{date}_{time.strftime('%H%M%S')}.json"
    path = os.path.join(EXPORT_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    return path


# ------------------------------------------------------------- HTTP-сервер ----
class HealthRunner:
    """
    Виконує перевірки стану у фоновому потоці, щоб інтерфейс не завмирав:
    деякі перевірки тривають хвилини. Одночасно — тільки одне сканування.
    """

    SAVED = os.path.join(DATA_DIR, "health_last.json")

    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.mode = None
        self.queue = []
        self.done = {}
        self.current = None
        self.started_at = 0
        self.finished_at = 0
        # Результати останнього сканування переживають перезапуск монітора:
        # без цього після кожного оновлення вкладка «Здоров'я» стояла
        # порожня, а діагностичний звіт виходив без результатів перевірок.
        try:
            if os.path.exists(self.SAVED):
                with open(self.SAVED, encoding="utf-8") as f:
                    saved = json.load(f)
                import health
                self.done = {k: v for k, v in (saved.get("results") or {}).items()
                             if k in health.CHECKS}
                self.queue = [k for k in (saved.get("plan") or list(self.done))
                              if k in health.CHECKS]
                self.mode = saved.get("mode")
                self.started_at = saved.get("started_at") or 0
                self.finished_at = saved.get("finished_at") or 0
        except Exception:
            log.exception("Не вдалося прочитати збережені результати перевірок")

    def _save(self):
        try:
            with self.lock:
                data = {"results": self.done, "plan": list(self.queue),
                        "mode": self.mode, "started_at": self.started_at,
                        "finished_at": self.finished_at}
            with open(self.SAVED, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception:
            log.exception("Не вдалося зберегти результати перевірок")

    def start(self, mode="quick"):
        import health
        plan = {"quick": health.QUICK, "full": health.FULL, "deep": health.DEEP}.get(
            mode, health.QUICK)
        with self.lock:
            if self.running:
                return False
            self.running = True
            self.mode = mode
            self.queue = list(plan)
            self.done = {}
            self.current = None
            self.started_at = time.time()
            self.finished_at = 0
        threading.Thread(target=self._run, name="health", daemon=True).start()
        return True

    def _run(self):
        import health
        try:
            for key in list(self.queue):
                if STOP.is_set():
                    break
                with self.lock:
                    self.current = key
                title, fn, _ = health.CHECKS[key]
                t0 = time.time()
                try:
                    res = fn()
                except Exception as e:
                    log.exception("Перевірка %s впала", key)
                    res = {"status": "skip", "title": title,
                           "detail": f"помилка: {e}", "items": [], "weight": 1}
                res["key"] = key
                res.setdefault("title", title)
                res["took"] = round(time.time() - t0, 1)
                with self.lock:
                    self.done[key] = res
        finally:
            with self.lock:
                self.running = False
                self.current = None
                self.finished_at = time.time()
            self._save()

    def status(self):
        import health
        with self.lock:
            done = dict(self.done)
            running = self.running
            cur = self.current
            queue = list(self.queue)
            mode = self.mode
            started = self.started_at
            finished = self.finished_at
        total = len(queue) or 1
        return {
            "running": running, "mode": mode,
            "current": cur,
            "current_title": (health.CHECKS.get(cur, ("", None, 0))[0] if cur else None),
            "progress": round(len(done) / total, 3),
            "total": total, "completed": len(done),
            "plan": [{"key": k, "title": health.CHECKS[k][0],
                      "est": health.CHECKS[k][2]} for k in queue],
            "results": done,
            "score": health.score(done) if done else None,
            "started_at": started, "finished_at": finished,
        }


class Ctx:
    """Спільний контекст для HTTP-обробника."""
    cfg = None
    sampler = None
    writer = None
    etw = None
    started_at = 0
    health = None
    latency = None
    dpcisr = None
    clipwatch = None


# =====================================================================
#  ХТО ЗАРАЗ ЗАЙМАЄ МОНІТОР
# =====================================================================
# Коли інтерфейс не дочекався відповіді, сказати «збирач зайнятий» — це майже
# те саме, що не сказати нічого. Тому кожна тривала робота реєструється тут, і
# є окрема ручка /api/ping, яка НІЧОГО не робить: не чіпає ані базу, ані блокування,
# які тримає повільна операція. Тож вона відповідає навіть тоді, коли все інше стоїть.
_BUSY = {}                      # id -> {what, since, kind, detail}
_BUSY_LOCK = threading.Lock()
_BUSY_SEQ = itertools.count(1)

# Людські назви замість шляхів у ручках — щоб у вікні було зрозуміло написано.
_BUSY_TITLES = {
    "/api/clipboard": "перевірка буфера обміну",
    "/api/process": "картка програми",
    "/api/apps": "підсумок за день",
    "/api/overview": "огляд дня",
    "/api/startup": "список автозапуску",
    "/api/health": "перевірка здоров'я",
    "/api/latency": "вимір затримок",
    "/api/dpcisr": "трасування драйверів",
    "/api/export": "експорт звіту",
    "/api/export_all": "загальний експорт",
    "/api/whostarts": "пошук, хто запускає програму",
    "/api/kill": "завершення процесу",
    "/api/proc": "дія над процесом",
    "/api/run": "виконання команди",
    "/api/run_probe": "перевірка рівня прав",
    "/api/recheck_sig": "перевірка підпису",
    "/api/update_install": "встановлення оновлення",
}


class busy:
    """Позначити, що зараз виконується щось тривале."""

    def __init__(self, what, detail=""):
        self.what = what
        self.detail = detail
        self.id = None

    def __enter__(self):
        self.id = next(_BUSY_SEQ)
        with _BUSY_LOCK:
            _BUSY[self.id] = {"what": self.what, "detail": self.detail,
                              "since": time.time(),
                              "thread": threading.current_thread().name}
        return self

    def __exit__(self, *exc):
        with _BUSY_LOCK:
            _BUSY.pop(self.id, None)
        return False


def busy_now(min_s=0.0):
    """Що виконується прямо зараз, довше за min_s секунд."""
    now = time.time()
    with _BUSY_LOCK:
        rows = [dict(v, id=k) for k, v in _BUSY.items()]
    out = []
    for r in rows:
        held = now - r["since"]
        if held >= min_s:
            out.append({"what": r["what"], "detail": r.get("detail") or "",
                        "seconds": round(held, 1)})
    out.sort(key=lambda r: -r["seconds"])
    return out


def make_handler(ctx: Ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PCMonitor/" + VERSION

        def log_message(self, fmt, *args):
            pass  # не спамимо в консоль

        # ---- helpers ----
        def _json(self, obj, code=200, cors=False):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cors:
                # лише для /api/sd — див. коментар біля неї
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path, ctype):
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_error(404)
                return
            # Токен сесії підставляємо в саму сторінку. Стороння веб-сторінка
            # прочитати його не може: браузер не дасть їй прочитати ВІДПОВІДЬ
            # з нашого походження. Тож надіслати запит вона ще спробує, а от
            # підписати його правильним токеном — уже ні.
            if body[:200].lstrip()[:5].lower() == b"<!doc" or b"__PCMON_TOKEN__" in body:
                body = body.replace(b"__PCMON_TOKEN__", API_TOKEN.encode())
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            # сторінку не можна вбудовувати в чужий фрейм
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
            except Exception:
                return {}

        def _qs(self):
            from urllib.parse import urlparse, parse_qs
            u = urlparse(self.path)
            return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

        # ---- GET ----
        def do_GET(self):
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                self.send_error(403)
                return
            path, qs = self._qs()
            date = qs.get("date") or human_day()

            # НАЙПЕРШЕ і без жодних блокувань: ця відповідь має пройти навіть
            # тоді, коли решта сервера стоїть — інакше вона марна.
            # ── дані для клавіш Stream Deck ───────────────────────────────
            # Плагін живе у власному вікні Chromium усередині Stream Deck,
            # тобто для нас це СТОРОННЄ походження — без дозволу CORS браузер
            # не дасть йому прочитати відповідь. Тому дозвіл тут є, але саме
            # тому ця ручка віддає ЛИШЕ числа: жодних назв програм, шляхів,
            # доменів. Навіть якщо її прочитає чужа сторінка, вона дізнається
            # хіба що завантаження процесора — не більше, ніж видно на око.
            if path == "/api/sd":
                s = ctx.sampler
                rows = list(s.hist) if s else []
                cur = rows[-1] if rows else None
                t = getattr(s, "sensors", None) or {}
                g = (t.get("gpus") or [None])[0] or {}
                mt, mu = g.get("mem_total") or 0, g.get("mem_used") or 0
                self._json({
                    "ok": True,
                    "gpu_temp": g.get("temp"),
                    "gpu_fan": g.get("fan"),
                    "gpu_power": g.get("power_w"),
                    "vram_used": mu, "vram_total": mt,
                    "vram_free": (mt - mu) if mt else None,
                    "vram_pct": round(mu / mt * 100, 1) if mt else None,
                    "disk_temp": max([d["temp"] for d in (t.get("disks") or [])
                                      ] or [0]) or None,
                    "ncpu": (s.ncpu if s else 0),
                    "age": (round(time.time() - s.last_tick, 1)
                            if s and s.last_tick else None),
                    "cpu": cur[1] if cur else 0,
                    "core_max": cur[2] if cur else 0,
                    "ram_pct": cur[3] if cur else 0,
                    "ram_used": (s.live.get("ram_used") if s else 0),
                    "ram_total": (s.live.get("ram_total") if s else 0),
                    "gpu": cur[4] if cur else 0,
                    "net": cur[5] if cur else 0,
                    "disk": cur[6] if cur else 0,
                    # ряди для міні-графіка (найстаріше -> найновіше)
                    "series": {
                        "cpu": [r[1] for r in rows],
                        "core_max": [r[2] for r in rows],
                        "ram_pct": [r[3] for r in rows],
                        "gpu": [r[4] for r in rows],
                        "net": [r[5] for r in rows],
                        "disk": [r[6] for r in rows],
                        "gpu_temp": [r[1] for r in (s.sensors_hist if s else [])],
                        "vram_pct": [r[2] for r in (s.sensors_hist if s else [])],
                        "disk_temp": [r[3] for r in (s.sensors_hist if s else [])],
                    },
                }, cors=True)
                return

            if path == "/api/ping":
                self._json({
                    "ok": True, "t": time.time(),
                    "busy": busy_now(0.3),
                    "sampler_age": (round(time.time() - ctx.sampler.last_tick, 1)
                                    if getattr(ctx, "sampler", None)
                                    and getattr(ctx.sampler, "last_tick", 0) else None),
                    "sampler_doing": (getattr(ctx.sampler, "doing", "")
                                      if getattr(ctx, "sampler", None) else ""),
                })
                return

            _b = busy(_BUSY_TITLES.get(path) or path,
                      qs.get("name", "") or qs.get("date", ""))
            _b.__enter__()
            try:
                if path == "/" or path == "/index.html":
                    self._file(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
                elif path == "/chart.umd.js":
                    self._file(os.path.join(WEB_DIR, "chart.umd.js"),
                               "application/javascript; charset=utf-8")
                elif path == "/i18n_en.js":
                    self._file(os.path.join(WEB_DIR, "i18n_en.js"),
                               "application/javascript; charset=utf-8")
                elif path == "/api/status":
                    self._json(self.status())
                elif path == "/api/update":
                    gh = None
                    if qs.get("check") == "1":
                        # ручна перевірка: сходити на GitHub просто зараз
                        # (і завантажити, якщо є новіше)
                        gh = check_github_update(ctx.cfg)
                    self._json({"version": VERSION, "frozen": FROZEN,
                                "updates_dir": UPDATES_DIR,
                                "available": find_update(),
                                "github": gh or {"enabled": bool(
                                    ctx.cfg.get("github_updates", True)),
                                    **github_update_status()}})
                elif path == "/api/temps":
                    import sensors as _s
                    self._json(_s.read_all(force=qs.get("force") == "1"))
                elif path == "/api/days":
                    rows = q("""SELECT DISTINCT date(minute_ts,'unixepoch','localtime') d
                                FROM sys_minute
                                UNION SELECT DISTINCT day FROM app_day
                                ORDER BY d DESC LIMIT 400""")
                    days = sorted({r["d"] for r in rows if r["d"]}, reverse=True)
                    today = human_day()
                    if today not in days:
                        days.insert(0, today)
                    self._json({"days": days})
                elif path == "/api/overview":
                    self._json(self.overview(date))
                elif path == "/api/apps":
                    self._json(build_day(ctx.cfg, date))
                elif path == "/api/live":
                    if ctx.sampler:
                        with ctx.sampler.live_lock:
                            self._json(dict(ctx.sampler.live))
                    else:
                        self._json({"ts": 0, "apps": []})
                elif path == "/api/app":
                    self._json(app_detail(ctx.cfg, date, qs.get("name", "")))
                elif path == "/api/events":
                    t0, t1 = day_bounds(date)
                    rows = q("""SELECT ts, kind, name, exe, pid, info FROM events
                                WHERE ts>=? AND ts<? ORDER BY ts DESC LIMIT 800""", (t0, t1))
                    self._json({"events": rows})
                elif path == "/api/settings":
                    cfg = load_config()
                    db_size = 0
                    try:
                        db_size = sum(os.path.getsize(DB_PATH + s)
                                      for s in ("", "-wal", "-shm")
                                      if os.path.exists(DB_PATH + s))
                    except OSError:
                        pass
                    trusted = q("SELECT exe, name FROM exe_info WHERE ignored=1 ORDER BY name")
                    watch = q("SELECT name FROM watchlist ORDER BY name")
                    days = q1("SELECT COUNT(DISTINCT date(minute_ts,'unixepoch','localtime')) n "
                              "FROM sys_minute") or {}
                    inst = q1("SELECT v FROM meta WHERE k='installed_at'")
                    self._json({
                        "config": cfg,
                        "autostart": autostart_status(),
                        "admin": is_admin(),
                        "etw": ctx.etw.status if ctx.etw else "вимкнено в налаштуваннях",
                        "gpu": (ctx.sampler.gpu_status if ctx.sampler else "?"),
                        "mem_mode": (ctx.sampler.mem_mode if ctx.sampler else "?"),
                        "scan_ms": getattr(ctx.sampler, "last_scan_ms", 0) if ctx.sampler else 0,
                        "db_size": db_size,
                        "db_path": DB_PATH,
                        "base_dir": BASE,
                        "exports_dir": EXPORT_DIR,
                        "days_collected": days.get("n", 0),
                        "installed_at": int(inst["v"]) if inst else None,
                        "trusted": trusted,
                        "watch": [r["name"] for r in watch],
                        "version": VERSION,
                        "python": sys.version.split()[0],
                        "tray": tray_pin_status(),
                    })
                elif path == "/api/health":
                    self._json(ctx.health.status())
                elif path == "/api/latency":
                    self._json(ctx.latency.status() if ctx.latency
                               else {"running": False, "result": None})
                elif path == "/api/startup":
                    import startup_win
                    self._json({"startup": startup_win.list_startup(),
                                "services": (startup_win.list_services()
                                             if qs.get("services") == "1" else None)})
                elif path == "/api/whostarts":
                    nm = qs.get("name", "")
                    exe = qs.get("exe", "")
                    out = {"name": nm}
                    try:
                        import startup_win
                        out.update(startup_win.who_starts(nm, exe))
                    except Exception as e:
                        out["error"] = str(e)
                    # хто був батьком за останні запуски + як часто відроджується
                    try:
                        cut = int(time.time()) - 7 * 86400
                        out["parents"] = q("""SELECT parent_name, COUNT(*) n,
                                                     MAX(started_ts) last
                                              FROM proc_instances
                                              WHERE name=? AND started_ts>=?
                                                AND parent_name<>''
                                              GROUP BY parent_name
                                              ORDER BY n DESC LIMIT 10""",
                                           (nm.lower(), cut))
                        out["restarts"] = q("""SELECT started_ts, ended_ts, pid, ppid,
                                                      parent_name
                                               FROM proc_instances WHERE name=?
                                               ORDER BY started_ts DESC LIMIT 25""",
                                            (nm.lower(),))
                        h = q1("""SELECT COUNT(*) n FROM proc_instances
                                  WHERE name=? AND started_ts >= ?""",
                               (nm.lower(), int(time.time()) - 3600))
                        out["starts_last_hour"] = (h or {}).get("n", 0)
                    except Exception as e:
                        out["hist_error"] = str(e)
                    self._json(out)
                elif path == "/api/process":
                    self._json(process_card(ctx, qs.get("name", ""), date))
                elif path == "/api/dpcisr":
                    if ctx.dpcisr:
                        self._json(ctx.dpcisr.status())
                    else:
                        info = {}
                        try:
                            import dpcisr as _d
                            info = {"tools": _d.tools(), "admin": _d.is_admin(),
                                    "modules": len(_d.kernel_modules())}
                        except Exception as e:
                            info = {"error": str(e)}
                        self._json({"running": False, "result": None,
                                    "never_run": True, **info})
                elif path == "/api/clipboard":
                    # окремий швидкий замір — щоб можна було перевірити саме
                    # в момент, коли буфер гальмує
                    try:
                        import clipboard_win
                        # ОДИН виклик diagnose замість двох: кожен звертається
                        # до буфера, а зайві звернення самі стають навантаженням
                        want_sizes = qs.get("sizes") == "1"

                        # Замір робимо в окремому потоці з жорстким лімітом часу.
                        # Причина: якщо буфер тримає інша програма (а ми саме це
                        # й діагностуємо), звернення до нього може зависнути на
                        # десятки секунд. Раніше в такому разі з'єднання рвалося
                        # і в інтерфейсі з'являлось безглузде «Failed to fetch».
                        # Тепер зависання саме по собі стає відповіддю.
                        box = {}

                        def _work():
                            try:
                                r = clipboard_win.diagnose(read_sizes=want_sizes)
                                r["watchers"] = clipboard_win.running_watchers()
                                r["check"] = clipboard_win.check(diag=r)
                                box["ok"] = r
                            except Exception as ex:
                                box["err"] = str(ex)

                        limit = 25 if want_sizes else 10
                        th = threading.Thread(target=_work, name="clipcheck",
                                              daemon=True)
                        t_clip = time.time()
                        th.start()
                        th.join(timeout=limit)

                        if "ok" in box:
                            d = box["ok"]
                            d["log"] = ctx.clipwatch.log() if ctx.clipwatch else None
                            d["took_ms"] = round((time.time() - t_clip) * 1000)
                            self._json(d)
                        elif "err" in box:
                            self._json({"supported": False, "error": box["err"]})
                        else:
                            # не встигли — це вже діагноз
                            who = ""
                            try:
                                who = clipboard_win.who_holds() or ""
                            except Exception:
                                pass
                            self._json({
                                "supported": True, "timed_out": True,
                                "limit_s": limit,
                                "holder": who,
                                "log": ctx.clipwatch.log() if ctx.clipwatch else None,
                                "error":
                                    "Буфер обміну не відповів за %d с — його тримає "
                                    "інша програма%s. Це і є те гальмо, яке ти ловиш. "
                                    "Спробуй ще раз через кілька секунд."
                                    % (limit, (": " + who) if who else ""),
                            })
                    except Exception as e:
                        self._json({"supported": False, "error": str(e)})
                elif path == "/api/suspicion":
                    d = build_day(ctx.cfg, date)
                    self._json({"date": date,
                                "apps": [a for a in d["apps"] if a.get("suspicious")]})
                else:
                    self.send_error(404)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                # Браузер закрив з'єднання, не дочекавшись відповіді (перейшов
                # на іншу вкладку, перезавантажив сторінку). Це не помилка
                # монітора — не лякаємо журнал трасуванням.
                log.debug("Клієнт розірвав з'єднання під час %s", path)
            except Exception as e:
                log.exception("API-помилка %s", path)
                self._json({"error": str(e)}, 500)
            finally:
                _b.__exit__(None, None, None)

        # ---- POST ----
        def do_POST(self):
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                self.send_error(403)
                return
            path, _ = self._qs()

            # Кожен POST щось МІНЯЄ — тут і стоїть перевірка.
            port = ctx.cfg.get("dashboard_port", 8805)
            if not _origin_ok(self.headers, port):
                log.warning("Відхилено запит %s зі стороннього походження: %s",
                            path, self.headers.get("Origin"))
                self._json({"error": "запит із стороннього сайту відхилено"}, 403)
                return
            if not secrets.compare_digest(
                    self.headers.get("X-PCMon-Token") or "", API_TOKEN):
                log.warning("Відхилено запит %s без дійсного токена сесії", path)
                self._json({"error": "недійсний токен сесії — перезавантаж сторінку "
                                     "(Ctrl+R): після перезапуску монітора токен новий"},
                           403)
                return

            body = self._body()
            _b = busy(_BUSY_TITLES.get(path) or path,
                      str(body.get("name") or body.get("id") or ""))
            _b.__enter__()
            try:
                if path == "/api/kill":
                    ok, err = kill_process(body.get("pid"), body.get("name", ""))
                    self._json({"ok": ok, "error": err})
                elif path == "/api/startup":
                    import startup_win
                    what = body.get("what")
                    if what == "app":
                        ok, err = startup_win.set_startup(body.get("id", ""),
                                                          bool(body.get("enable")))
                    elif what == "service":
                        ok, err = startup_win.set_service(body.get("name", ""),
                                                          body.get("mode", "manual"))
                    elif what == "service_action":
                        ok, err = startup_win.service_action(body.get("name", ""),
                                                             body.get("action", ""))
                    else:
                        ok, err = False, "невідома дія"
                    self._json({"ok": ok, "error": err})
                elif path == "/api/export_all":
                    p = export_diagnostics(ctx, body.get("date"),
                                           int(body.get("days", 3)))
                    self._json({"ok": True, "file": p,
                                "basename": os.path.basename(p),
                                "size": os.path.getsize(p),
                                "hint": "Надішли цей файл у чат Claude — "
                                        "він містить усе потрібне для аналізу."})
                elif path == "/api/export":
                    name = body.get("name", "")
                    if not name:
                        self._json({"error": "не вказано назву"}, 400)
                        return
                    p = export_app(ctx.cfg, name, body.get("date"))
                    self._json({"ok": True, "file": p, "basename": os.path.basename(p),
                                "hint": "Кинь цей файл у чат Claude і попроси проаналізувати."})
                elif path == "/api/watch":
                    name = (body.get("name") or "").lower()
                    on = bool(body.get("on"))
                    if on:
                        ctx.writer.push("INSERT OR REPLACE INTO watchlist(name,added_ts) "
                                        "VALUES(?,?)", (name, int(time.time())))
                    else:
                        ctx.writer.push("DELETE FROM watchlist WHERE name=?", (name,))
                    if ctx.sampler:
                        ctx.sampler.set_watch(name, on)
                    ctx.writer.flush_now()
                    _day_cache.clear()
                    self._json({"ok": True, "watching": on})
                elif path == "/api/run":
                    import runcmd
                    if not ctx.cfg.get("allow_commands", False):
                        self._json({"ok": False, "error":
                                    "виконання команд вимкнено. Увімкни його в "
                                    "налаштуваннях (⚙), якщо справді потрібно."})
                        return
                    cmdtext = (body.get("cmd") or "").strip()
                    as_admin = bool(body.get("admin"))
                    # Кожну команду записуємо в журнал подій ДО виконання —
                    # щоб слід лишився навіть якщо вона підвісить монітор.
                    ctx.writer.push(
                        "INSERT INTO events(ts,kind,name,info) VALUES(?,?,?,?)",
                        (int(time.time()), "command", "PC Monitor",
                         ("[адміністратор] " if as_admin else "") + cmdtext[:400]))
                    ctx.writer.flush_now()
                    self._json(runcmd.run(cmdtext, as_admin=as_admin,
                                          cwd=body.get("cwd") or None,
                                          timeout=body.get("timeout") or 60))
                elif path == "/api/run_probe":
                    import runcmd
                    self._json(runcmd.probe())
                elif path == "/api/proc":
                    # усе керування процесами однією ручкою
                    import procctl
                    act = body.get("action", "")
                    pid = body.get("pid")
                    nm = body.get("name", "")
                    if act == "kill":
                        self._json(procctl.kill(pid, nm, tree=False))
                    elif act == "kill_tree":
                        self._json(procctl.kill(pid, nm, tree=True))
                    elif act == "suspend":
                        self._json(procctl.suspend(pid, nm, resume=False))
                    elif act == "resume":
                        self._json(procctl.suspend(pid, nm, resume=True))
                    elif act == "priority":
                        self._json(procctl.set_priority(pid, body.get("level", ""), nm))
                    elif act == "affinity":
                        self._json(procctl.set_affinity(pid, body.get("cores") or [], nm))
                    elif act == "open_folder":
                        self._json(procctl.open_folder(pid, body.get("path", "")))
                    elif act == "details":
                        self._json(procctl.details(pid, nm))
                    elif act == "frozen":
                        self._json({"ok": True, "frozen": procctl.frozen()})
                    elif act in ("app_kill", "app_suspend", "app_resume",
                                 "app_priority", "app_affinity"):
                        self._json(procctl.act_by_name(
                            nm, act[4:], level=body.get("level", ""),
                            cores=body.get("cores") or []))
                    else:
                        self._json({"ok": False, "error": "невідома дія"})
                elif path == "/api/sd_install":
                    self._json(install_streamdeck(ctx.cfg))
                elif path == "/api/recheck_sig":
                    exe = body.get("exe") or ""
                    if not exe:
                        self._json({"error": "не вказано файл"}, 400)
                        return
                    res = ExeInspector.check_signature(exe)
                    if not res.get("error"):
                        ctx.writer.exec_now(
                            "UPDATE exe_info SET sig_status=?, sig_checked_at=?, "
                            "sig_signer=?, sig_issuer=?, sig_message=?, sig_ts=? "
                            "WHERE exe=? COLLATE NOCASE",
                            (res["status"], res["checked_at"], res["signer"],
                             res["issuer"], res["message"], res["not_after"], exe))
                        _day_cache.clear()
                        h = SIG_HUMAN.get(res["status"])
                        res["human"] = h[0] if h else ""
                        res["explain"] = h[1] if h else ""
                    self._json(res)
                elif path == "/api/trust":
                    name = (body.get("name") or "").lower()
                    exe = body.get("exe") or ""
                    on = 1 if body.get("on") else 0
                    # COLLATE NOCASE: у Windows шлях без різниці великих і малих
                    # літер, а SQLite за замовчуванням порівнює побайтово. Через
                    # це «C:\Program Files\...» і «C:\PROGRAM FILES\...» були для
                    # бази різними рядками — запит не змінював НІЧОГО, а ми
                    # однаково відповідали «ok». Саме так і зникала позначка.
                    n = 0
                    if exe:
                        n = ctx.writer.exec_now(
                            "UPDATE exe_info SET ignored=? WHERE exe=? COLLATE NOCASE",
                            (on, exe))
                    if n <= 0 and name:
                        n = ctx.writer.exec_now(
                            "UPDATE exe_info SET ignored=? WHERE name=? COLLATE NOCASE",
                            (on, name))
                    if n <= 0 and exe:
                        # запису ще нема (інспектор не дійшов) — створюємо
                        ctx.writer.exec_now(
                            "INSERT INTO exe_info(exe,name,first_seen,ignored) "
                            "VALUES(?,?,?,?) ON CONFLICT(exe) DO UPDATE SET ignored=?",
                            (exe, name, int(time.time()), on, on))
                        n = 1
                    _day_cache.clear()
                    if n <= 0:
                        self._json({"ok": False, "changed": 0,
                                    "error": "не знайшов цю програму в базі — "
                                             "позначку нема куди записати"})
                    else:
                        self._json({"ok": True, "changed": n, "ignored": bool(on)})
                elif path == "/api/settings":
                    patch = body.get("config") or {}
                    # захист від дурних значень
                    if "sample_interval" in patch:
                        patch["sample_interval"] = max(1, min(60, int(patch["sample_interval"])))
                    if "conn_poll_interval" in patch:
                        patch["conn_poll_interval"] = max(2, min(300, int(patch["conn_poll_interval"])))
                    if "dashboard_port" in patch:
                        patch["dashboard_port"] = max(1024, min(65535, int(patch["dashboard_port"])))
                    if "retention_minutes_days" in patch:
                        patch["retention_minutes_days"] = max(1, min(3650, int(patch["retention_minutes_days"])))
                    if "retention_days" in patch:
                        patch["retention_days"] = max(1, min(3650, int(patch["retention_days"])))
                    cfg = save_config(patch)
                    # що застосується лише після перезапуску збирача
                    needs_restart = any(k in patch for k in (
                        "sample_interval", "conn_poll_interval", "flush_interval",
                        "dashboard_port", "etw_enabled", "gpu_enabled",
                        "memory_metric", "log_cmdline"))
                    ctx.cfg.update(cfg)
                    _day_cache.clear()
                    self._json({"ok": True, "config": cfg, "needs_restart": needs_restart})
                elif path == "/api/health":
                    mode = body.get("mode", "quick")
                    started = ctx.health.start(mode)
                    self._json({"ok": started,
                                "error": "" if started else "сканування вже виконується"})
                elif path == "/api/latency":
                    act = body.get("action", "start")
                    if act == "stop":
                        if ctx.latency:
                            ctx.latency.stop()
                        self._json({"ok": True})
                    else:
                        if ctx.latency and ctx.latency.running:
                            self._json({"ok": False, "error": "замір уже виконується"})
                        else:
                            from latency import LatencyTest
                            ctx.latency = LatencyTest(int(body.get("seconds", 20)))
                            ctx.latency.start()
                            self._json({"ok": True})
                elif path == "/api/dpcisr":
                    act = body.get("action", "start")
                    if act == "cancel":
                        if ctx.dpcisr:
                            ctx.dpcisr.cancel()
                        self._json({"ok": True})
                    elif act == "selftest":
                        import dpcisr as _d
                        self._json(_d.selftest())
                    elif ctx.dpcisr and ctx.dpcisr.running:
                        self._json({"ok": False, "error": "трасування вже виконується"})
                    else:
                        from dpcisr import DpcIsrTrace
                        ctx.dpcisr = DpcIsrTrace(int(body.get("seconds", 15)))
                        threading.Thread(target=ctx.dpcisr.run,
                                         name="dpcisr", daemon=True).start()
                        self._json({"ok": True})
                elif path == "/api/autostart":
                    ok, msg = autostart_set(bool(body.get("on")))
                    self._json({"ok": ok, "error": msg, "autostart": autostart_status()})
                elif path == "/api/restart":
                    self._json({"ok": True})
                    threading.Thread(target=lambda: restart(), daemon=True).start()
                elif path == "/api/vacuum":
                    ctx.writer.flush_now()
                    before = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
                    con = sqlite3.connect(DB_PATH, timeout=60)
                    try:
                        con.execute("VACUUM")
                        con.commit()
                    finally:
                        con.close()
                    after = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
                    self._json({"ok": True, "before": before, "after": after,
                                "saved": max(0, before - after)})
                elif path == "/api/purge":
                    # стерти історію старішу за N днів (0 = всю)
                    days = max(0, int(body.get("days", 0)))
                    cut = int(time.time()) - days * 86400
                    ctx.writer.flush_now()
                    con = sqlite3.connect(DB_PATH, timeout=60)
                    try:
                        with con:
                            for t, col in (("app_minute", "minute_ts"), ("net_minute", "minute_ts"),
                                           ("sys_minute", "minute_ts"), ("watch_raw", "ts"),
                                           ("events", "ts"), ("proc_instances", "started_ts")):
                                con.execute(f"DELETE FROM {t} WHERE {col} < ?", (cut,))
                            con.execute("DELETE FROM net_conn WHERE last_ts < ?", (cut,))
                            con.execute("DELETE FROM dns_seen WHERE last_ts < ?", (cut,))
                            con.execute("DELETE FROM app_day WHERE day < date(?, 'unixepoch')", (cut,))
                    finally:
                        con.close()
                    _day_cache.clear()
                    self._json({"ok": True})
                elif path == "/api/open_folder":
                    target = body.get("what") or "base"
                    p = {"base": BASE, "exports": EXPORT_DIR, "data": DATA_DIR,
                         "logs": LOG_DIR}.get(target, BASE)
                    os.makedirs(p, exist_ok=True)
                    if IS_WIN:
                        os.startfile(p)  # noqa
                    self._json({"ok": True, "path": p})
                elif path == "/api/open_exports":
                    os.makedirs(EXPORT_DIR, exist_ok=True)
                    if IS_WIN:
                        os.startfile(EXPORT_DIR)  # noqa
                    self._json({"ok": True, "path": EXPORT_DIR})
                elif path == "/api/update_install":
                    self._json(install_update())
                elif path == "/api/tray":
                    self._json(tray_pin_set(bool(body.get("pin"))))
                elif path == "/api/elevate":
                    if is_admin():
                        self._json({"ok": False,
                                    "error": "монітор уже працює з правами адміністратора"})
                    else:
                        self._json({"ok": True})
                        threading.Thread(target=restart_elevated,
                                         daemon=True).start()
                elif path == "/api/quit":
                    self._json({"ok": True})
                    threading.Thread(target=shutdown, daemon=True).start()
                else:
                    self.send_error(404)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                log.debug("Клієнт розірвав з'єднання під час %s", path)
            except Exception as e:
                log.exception("API-помилка %s", path)
                self._json({"error": str(e)}, 500)
            finally:
                _b.__exit__(None, None, None)

        # ---- складені відповіді ----
        def status(self):
            db_size = 0
            try:
                db_size = os.path.getsize(DB_PATH)
            except OSError:
                pass
            admin = False
            if IS_WIN:
                try:
                    import ctypes
                    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                except Exception:
                    pass
            return {
                "app": "pcmon", "version": VERSION, "frozen": FROZEN,
                # вкладка «Зараз» показує термінал лише коли команди дозволені
                "commands": bool(ctx.cfg.get("allow_commands")),
                "started_at": ctx.started_at, "uptime_s": int(time.time()) - ctx.started_at,
                "admin": admin,
                "etw": ctx.etw.status if ctx.etw else "вимкнено в налаштуваннях",
                "etw_events": ctx.etw.events_seen if ctx.etw else 0,
                "samples": ctx.sampler.samples_total if ctx.sampler else 0,
                "db_size": db_size,
                "port": ctx.cfg["dashboard_port"],
                "watch": sorted(ctx.sampler.watchset) if ctx.sampler else [],
                "exports_dir": EXPORT_DIR,
            }

        def overview(self, date):
            t0, t1 = day_bounds(date)
            series = q("""SELECT minute_ts, cpu_avg, ram_used, ram_total, sent_b, recv_b,
                                 read_b, write_b, nproc
                          FROM sys_minute WHERE minute_ts>=? AND minute_ts<?
                          ORDER BY minute_ts""", (t0, t1))
            tot = q1("""SELECT AVG(cpu_avg) cpu_avg, MAX(cpu_max) cpu_max, MAX(ram_used) ram_max,
                               MAX(ram_total) ram_total, SUM(sent_b) sent, SUM(recv_b) recv,
                               SUM(read_b) rd, SUM(write_b) wr, MAX(nproc) nproc
                        FROM sys_minute WHERE minute_ts>=? AND minute_ts<?""", (t0, t1)) or {}
            starts = q1("""SELECT COUNT(*) n FROM events
                           WHERE ts>=? AND ts<? AND kind='process_start'""", (t0, t1)) or {}
            newexe = q1("SELECT COUNT(*) n FROM exe_info WHERE first_seen>=? AND first_seen<?",
                        (t0, t1)) or {}
            d = build_day(ctx.cfg, date)
            susp = [a for a in d["apps"] if a.get("suspicious")]
            # «Зараз» беремо з живого знімка збирача. Раніше тут викликався
            # psutil.cpu_percent(None) з потоку HTTP — і оскільки збирач щойно
            # викликав його ж, різниця виходила нульовою і картка показувала 0%.
            now_info = None
            if date == human_day() and ctx.sampler:
                with ctx.sampler.live_lock:
                    lv = ctx.sampler.live
                    if lv.get("ts"):
                        now_info = {"cpu": lv.get("cpu_total", 0),
                                    "ram_used": lv.get("ram_used", 0),
                                    "ram_total": lv.get("ram_total", 0)}
            return {"date": date, "series": series, "totals": tot,
                    "apps_active": len(d["apps"]), "starts": starts.get("n", 0),
                    "new_exes": newexe.get("n", 0),
                    "suspicious": [{"name": a["name"], "score": a["suspicion_score"],
                                    "reasons": a["suspicion_reasons"]} for a in susp],
                    "now": now_info}

    return Handler


# ----------------------------------------------------------------- трей ----
def _tray_reg_entries():
    """
    Записи нашої іконки в реєстрі Windows 11.

    Кожна іконка трея має ключ у HKCU\\Control Panel\\NotifyIconSettings
    зі шляхом до exe, підказкою і полем IsPromoted (1 = завжди видима на
    панелі, 0 = у «шухляді» за стрілкою). Це той самий перемикач, що в
    Параметрах Windows, — ми лише клацаємо його програмно.

    Свою іконку впізнаємо за підказкою «PC Monitor…» або за іменем
    PCMonitor.exe — для dev-версії exe це python, і сам по собі він
    нічого не каже.
    """
    import winreg
    base = r"Control Panel\NotifyIconSettings"
    found = []
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as root:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break
            try:
                with winreg.OpenKey(root, sub) as sk:
                    def val(name):
                        try:
                            return winreg.QueryValueEx(sk, name)[0]
                        except OSError:
                            return None
                    exep = str(val("ExecutablePath") or "")
                    tip = str(val("InitialTooltip") or "")
                    exe_name = exep.replace("/", "\\").rstrip("\\").split("\\")[-1]
                    if ("pc monitor" in tip.lower()
                            or exe_name.lower() == "pcmonitor.exe"):
                        found.append({"key": base + "\\" + sub,
                                      "pinned": val("IsPromoted") == 1})
            except OSError:
                pass
    return found


def tray_pin_status():
    if not IS_WIN:
        return {"supported": False, "reason": "лише для Windows"}
    try:
        entries = _tray_reg_entries()
    except OSError:
        return {"supported": False,
                "reason": "механізм закріплення є лише у Windows 11"}
    return {"supported": True, "found": len(entries),
            "pinned": bool(entries) and all(e["pinned"] for e in entries)}


def tray_pin_set(on):
    if not IS_WIN:
        return {"ok": False, "error": "лише для Windows"}
    import winreg
    try:
        entries = _tray_reg_entries()
    except OSError:
        return {"ok": False, "error": "механізм закріплення є лише у Windows 11"}
    if not entries:
        return {"ok": False, "error": "запис іконки ще не з'явився в реєстрі — "
                                      "переконайся, що значок у треї видно, і спробуй ще раз"}
    changed = 0
    for e in entries:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, e["key"], 0,
                                winreg.KEY_SET_VALUE) as sk:
                winreg.SetValueEx(sk, "IsPromoted", 0, winreg.REG_DWORD,
                                  1 if on else 0)
                changed += 1
        except OSError as err:
            return {"ok": False, "error": f"не вдалося записати в реєстр: {err}"}
    return {"ok": True, "changed": changed, "pinned": bool(on)}


def start_tray(cfg):
    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception:
        log.info("pystray/Pillow недоступні — працюю без іконки в треї")
        return None
    img = Image.new("RGBA", (64, 64), (16, 19, 26, 255))
    d = ImageDraw.Draw(img)
    for i, h in enumerate((22, 38, 30)):
        x = 10 + i * 16
        d.rectangle((x, 54 - h, x + 12, 54), fill=(74, 222, 128, 255))
    def _open(icon, item):
        open_window(cfg)
    def _exports(icon, item):
        os.makedirs(EXPORT_DIR, exist_ok=True)
        if IS_WIN:
            os.startfile(EXPORT_DIR)  # noqa
    def _quit(icon, item):
        icon.stop()
        shutdown()
    en = str(cfg.get("lang", "uk")).lower() == "en"
    menu = pystray.Menu(
        pystray.MenuItem("Open PC Monitor" if en else "Відкрити PC Monitor",
                         _open, default=True),
        pystray.MenuItem("Exports folder" if en else "Папка експортів", _exports),
        pystray.MenuItem("Quit (stop monitoring)" if en
                         else "Вийти (зупинити моніторинг)", _quit))
    icon = pystray.Icon("PC Monitor", img,
                        "PC Monitor — collecting stats" if en
                        else "PC Monitor — збирає статистику", menu)
    t = threading.Thread(target=icon.run, name="tray", daemon=True)
    t.start()
    return icon


# ------------------------------------------------------------ вікно-апка ----
def find_app_browser():
    if not IS_WIN:
        return None
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    lad = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(lad, r"Google\Chrome\Application\chrome.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def focus_existing_window():
    """
    Якщо вікно монітора вже відкрите — підняти його наперед, а не плодити нове.
    Раніше кожен клік у треї відкривав ще одну копію.
    """
    if not IS_WIN:
        return False
    try:
        import ctypes
        from ctypes import wintypes
        u = ctypes.WinDLL("user32", use_last_error=True)
        u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        u.FindWindowW.restype = wintypes.HWND
        u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        u.SetForegroundWindow.argtypes = [wintypes.HWND]
        u.IsWindowVisible.argtypes = [wintypes.HWND]

        hwnd = u.FindWindowW(None, "PC Monitor")
        if not hwnd:
            return False
        SW_RESTORE = 9
        u.ShowWindow(hwnd, SW_RESTORE)
        u.SetForegroundWindow(hwnd)
        log.info("Вікно вже відкрите — підняв наперед")
        return True
    except Exception:
        log.exception("Не вдалося підняти наявне вікно")
        return False


# pid уже запущеного вікна, щоб не плодити копії
_window_proc = None


def window_alive():
    global _window_proc
    if _window_proc is None:
        return False
    try:
        if _window_proc.poll() is None:
            return True
    except Exception:
        pass
    _window_proc = None
    return False


def open_window(cfg, native=True):
    """
    Відкрити вікно монітора.

    Порядок спроб:
      1. СПРАВЖНЄ нативне вікно (pywebview + системний WebView2). Власний значок
         на панелі задач, власний процес, ніякого браузера. Це і є «апка».
         Запускається окремим процесом, бо GUI-цикл має жити в головному потоці.
      2. Якщо pywebview не встановлений — браузер у режимі --app з ізольованим
         профілем (вікно без вкладок, але це все ще браузер).
      3. У найгіршому разі — звичайна вкладка.
    """
    url = f"http://127.0.0.1:{cfg['dashboard_port']}/"

    # --- 0. вікно вже відкрите? підняти його, а не плодити нове ----------
    if focus_existing_window():
        return True
    if window_alive():
        log.info("Вікно вже запускається — не відкриваю ще одне")
        return True

    # --- 1. нативне вікно окремим процесом -------------------------------
    if native:
        try:
            import app_window
            if app_window.available():
                kwargs = {}
                if IS_WIN:
                    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                global _window_proc
                _window_proc = subprocess.Popen(_self_cmd("--native-window"), **kwargs)
                return True
        except Exception:
            log.exception("Нативне вікно не вдалося, пробую браузерний режим")

    # --- 2. браузер у режимі застосунку -----------------------------------
    browser = find_app_browser()
    if browser:
        profile = os.path.join(DATA_DIR, "browser_profile")
        os.makedirs(profile, exist_ok=True)
        args = [
            browser,
            f"--app={url}",
            f"--user-data-dir={profile}",     # <- через це вікно точно буде своє
            "--window-size=1360,920",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--no-service-autorun",
        ]
        try:
            subprocess.Popen(args, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True
        except Exception:
            log.exception("Не вдалося відкрити вікно-апку, відкриваю у браузері")
    webbrowser.open(url)
    return True


def collector_running(cfg):
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{cfg['dashboard_port']}/api/status", timeout=1.5) as r:
            return json.load(r).get("app") == "pcmon"
    except Exception:
        return False


def ensure_collector(cfg):
    if collector_running(cfg):
        return True
    kwargs = {}
    if IS_WIN:
        kwargs["creationflags"] = 0x00000008 | 0x08000000  # DETACHED | CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(_self_cmd("--quiet"), **kwargs)
    for _ in range(50):
        time.sleep(0.5)
        if collector_running(cfg):
            return True
    return False


# ------------------------------------------------------------------ main ----
_httpd = None
_restart_requested = False
_restart_elevated = False


def restart():
    """Перезапустити збирач, щоб застосувати налаштування."""
    global _restart_requested
    _restart_requested = True
    log.info("Перезапуск на запит із налаштувань…")
    shutdown()


def try_admin_relaunch(cfg):
    """
    Стартуємо без прав, а в налаштуваннях run_as_admin — перезапуститися
    підвищено. Повертає "task" (піднято через планувальник), "uac" (запущено
    копію через запит UAC) або None (лишаємось як є). При "task"/"uac" цьому
    процесу слід тихо вийти.

    Порядок спроб:
      1. Задача планувальника (автозапуск): зареєстрована з найвищими
         правами, тому `schtasks /Run` піднімає монітор БЕЗ запиту UAC.
      2. Звичайний «Запуск від імені адміністратора» (ShellExecuteW runas) —
         з запитом UAC. Відмова — не помилка: працюємо зі звичайними правами.
    """
    if not IS_WIN or is_admin() or not cfg.get("run_as_admin", True):
        return None
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        q_ = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                            capture_output=True, timeout=10, creationflags=flags)
        if q_.returncode == 0:
            r = subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME],
                               capture_output=True, timeout=15, creationflags=flags)
            if r.returncode == 0:
                for _ in range(40):
                    time.sleep(0.5)
                    if collector_running(cfg):
                        log.info("Піднявся через задачу планувальника — без UAC")
                        return "task"
    except Exception:
        pass
    try:
        import ctypes
        args = [a for a in sys.argv[1:]] or ["--quiet"]
        cmd = _self_cmd(*args)
        r = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", cmd[0], subprocess.list2cmdline(cmd[1:]), None, 1)
        if r > 32:
            return "uac"
        log.info("UAC відхилено (код %s) — працюю зі звичайними правами", r)
    except Exception:
        log.exception("Не вдалося піднятись — працюю зі звичайними правами")
    return None


def restart_elevated():
    """
    Перезапустити збирач З ПРАВАМИ АДМІНІСТРАТОРА (для ETW — точних байтів
    мережі). Покаже стандартний запит UAC. Якщо людина відмовить — монітор
    підніметься назад зі звичайними правами, а не зникне.
    """
    global _restart_requested, _restart_elevated
    _restart_requested = True
    _restart_elevated = True
    log.info("Перезапуск від імені адміністратора…")
    shutdown()


def shutdown():
    if STOP.is_set():
        return
    log.info("Зупиняюся…")
    # Заморожений процес сам не відмерзне. Якщо не відпустити його тут,
    # програма лишиться підвішеною після виходу монітора, і людина навіть
    # не здогадається, чому вона не відповідає.
    try:
        import procctl
        procctl.resume_all()
    except Exception:
        log.exception("Не вдалося відпустити заморожені процеси")
    STOP.set()
    try:
        if _httpd:
            threading.Thread(target=_httpd.shutdown, daemon=True).start()
    except Exception:
        pass


def run_collector(cfg, with_tray=True, console=False):
    global _httpd
    init_db()

    # одинак: перевірити, чи порт вільний
    if collector_running(cfg):
        print("PC Monitor уже запущено — відкриваю вікно.")
        open_window(cfg)
        return 0

    # низький пріоритет, щоб не заважати роботі/іграм
    try:
        me = psutil.Process()
        if IS_WIN:
            me.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            try:
                me.ionice(psutil.IOPRIO_LOW)
            except Exception:
                pass
        else:
            me.nice(5)
    except Exception:
        pass

    # закрити «хвости» після минулого запуску
    con = sqlite3.connect(DB_PATH, timeout=15)
    try:
        last = con.execute("SELECT v FROM meta WHERE k='last_sample_ts'").fetchone()
        last_ts = int(last[0]) if last else int(time.time())
        con.execute("UPDATE proc_instances SET ended_ts=? WHERE ended_ts IS NULL", (last_ts,))
        con.commit()
    except Exception:
        pass
    finally:
        con.close()

    writer = Writer(cfg)
    inspector = ExeInspector(cfg, writer)
    sampler = Sampler(cfg, writer, inspector)
    poller = ConnPoller(cfg, sampler)

    etw = None
    if cfg.get("etw_enabled"):
        try:
            from etw_net import EtwNet
            etw = EtwNet(on_bytes=sampler.on_etw_bytes, on_dns=sampler.on_etw_dns)
            etw.start()
        except Exception as e:
            log.warning("ETW-модуль не завантажився: %s", e)

    ctx = Ctx()
    ctx.cfg = cfg
    ctx.sampler = sampler
    ctx.writer = writer
    ctx.etw = etw
    ctx.started_at = int(time.time())
    ctx.health = HealthRunner()
    ctx.latency = None
    ctx.dpcisr = None
    # постійне спостереження за буфером обміну: ловить моменти, коли
    # копіювання зривається (разова перевірка кнопкою їх не застає)
    ctx.clipwatch = None
    if cfg.get("clipboard_watch", True) and IS_WIN:
        try:
            import clipboard_win
            w = clipboard_win.Watcher()
            if w.start():
                ctx.clipwatch = w
                log.info("Спостереження за буфером обміну увімкнено")
        except Exception:
            log.exception("Не вдалося увімкнути спостереження за буфером")

    try:
        _httpd = ThreadingHTTPServer(("127.0.0.1", cfg["dashboard_port"]), make_handler(ctx))
    except OSError as e:
        print(f"Не вдалося зайняти порт {cfg['dashboard_port']}: {e}")
        return 1

    writer.start()
    inspector.start()
    sampler.start()
    poller.start()
    threading.Thread(target=_httpd.serve_forever, name="http", daemon=True).start()

    # Фонова перевірка оновлень на GitHub: перший раз за 2 хвилини після
    # старту, далі кожні 6 годин. Лише коли ввімкнено в налаштуваннях.
    def _gh_loop():
        STOP.wait(120)
        while not STOP.is_set():
            try:
                if cfg.get("github_updates", True):
                    r = check_github_update(cfg)
                    if r.get("downloaded") and cfg.get("auto_install_updates"):
                        log.info("Автовстановлення оновлення (увімкнено в налаштуваннях)")
                        install_update()
            except Exception:
                log.exception("Перевірка оновлень з GitHub не вдалася")
            STOP.wait(6 * 3600)
    threading.Thread(target=_gh_loop, name="ghupdate", daemon=True).start()

    # Токен сесії — у файл, щоб stop.bat міг чемно попросити зупинку.
    # Без цього stop.bat отримував 403 і завершував монітор силоміць
    # (taskkill /f), а це обривало останній запис у базу. Файл лежить поруч
    # із базою і читається лише цим користувачем; сторінка з браузера файлів
    # читати не вміє, тож захист від чужих сайтів не слабшає.
    try:
        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(API_TOKEN)
    except Exception:
        log.exception("Не вдалося записати файл токена сесії")

    # відновити «за вчора» денний підсумок, якщо його нема
    writer.push("INSERT OR IGNORE INTO meta(k,v) VALUES('installed_at',?)",
                (str(int(time.time())),))

    tray = start_tray(cfg) if with_tray else None

    url = f"http://127.0.0.1:{cfg['dashboard_port']}/"
    log.info("PC Monitor %s запущено: %s (ETW: %s)", VERSION, url,
             etw.status if etw else "вимкнено")
    if console:
        print(f"PC Monitor працює.  Вікно: {url}")
        print(f"ETW (точні байти мережі): {etw.status if etw else 'вимкнено'}")
        print("Зупинити: Ctrl+C або stop.bat")
        open_window(cfg)

    try:
        while not STOP.is_set():
            STOP.wait(1)
    except KeyboardInterrupt:
        pass
    shutdown()

    # Кожен крок зупинки — під жорстким таймаутом і з заміром часу.
    # Причина: зупинка ETW (pywintrace) може дожовувати буфери ХВИЛИНАМИ,
    # і перезапуск із налаштувань виглядав як «збирач помер» на 2-3 хв.
    # Потоки daemon — покинути завислий крок безпечно, процес все одно
    # завершується.
    def _timed_stop(name, fn, timeout):
        t0 = time.monotonic()
        th = threading.Thread(target=lambda: fn(), name="stop-" + name, daemon=True)
        th.start()
        th.join(timeout)
        took = time.monotonic() - t0
        if th.is_alive():
            log.warning("Зупинка: %s завис (чекав %.1f с) — покидаю", name, took)
        elif took > 1:
            log.info("Зупинка: %s — %.1f с", name, took)

    t_stop = time.monotonic()
    if etw:
        _timed_stop("ETW", etw.stop, 10)
    # Порядок важливий: спершу даємо збирачу дописати свої останні дані
    # (він закриває відкриті процеси), і лише потім зупиняємо писаря.
    sampler.join(timeout=8)
    if sampler.gpu:
        _timed_stop("GPU-лічильники", sampler.gpu.stop, 5)
    writer.finish.set()
    writer.join(timeout=15)
    log.info("Зупинка зайняла %.1f с", time.monotonic() - t_stop)
    try:
        os.remove(TOKEN_PATH)   # токен мертвої сесії нікому не потрібен
    except OSError:
        pass
    if tray:
        _timed_stop("трей", tray.stop, 5)

    if _restart_requested:
        log.info("Стартую наново з новими налаштуваннями")
        time.sleep(1.5)          # дати ОС звільнити порт
        cmd = _self_cmd("--quiet")
        started = False
        if _restart_elevated and IS_WIN:
            try:
                import ctypes
                # «runas» — той самий механізм, що й «Запуск від імені
                # адміністратора» в провіднику: з'являється запит UAC.
                r = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", cmd[0],
                    subprocess.list2cmdline(cmd[1:]), None, 1)
                started = r > 32          # <=32 — відмова UAC чи помилка
                if not started:
                    log.warning("UAC відхилено (код %s) — стартую зі "
                                "звичайними правами", r)
            except Exception:
                log.exception("Не вдалося піднятись — стартую звичайно")
        if not started:
            try:
                kwargs = {}
                if IS_WIN:
                    kwargs["creationflags"] = 0x00000008 | 0x08000000
                else:
                    kwargs["start_new_session"] = True
                subprocess.Popen(cmd, **kwargs)
            except Exception:
                log.exception("Не вдалося перезапуститись")
        return 0

    log.info("Зупинено.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="PC Monitor — монітор ресурсів")
    ap.add_argument("--window", action="store_true", help="відкрити вікно-апку")
    ap.add_argument("--native-window", action="store_true",
                    help="внутрішнє: показати нативне вікно в цьому процесі")
    ap.add_argument("--status", action="store_true", help="статус у консоль")
    ap.add_argument("--export", metavar="NAME", help="експорт звіту по апці")
    ap.add_argument("--date", metavar="YYYY-MM-DD", help="дата для --export")
    ap.add_argument("--vacuum", action="store_true", help="стиснути базу")
    ap.add_argument("--no-tray", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="фоновий режим без консолі")
    ap.add_argument("--stop", action="store_true",
                    help="чемно зупинити запущений збирач і дочекатись зупинки")
    args = ap.parse_args()

    cfg = load_config()
    if args.stop:
        return cli_stop(cfg)

    console = not args.quiet and sys.stdout is not None and sys.stdout.isatty()
    setup_logging(console)

    # Одразу з правами адміністратора (run_as_admin у config.json).
    # Стосується лише запусків, що піднімають збирач; --status/--export
    # і сусідство з уже запущеним монітором прав не потребують.
    if (IS_WIN and not (args.status or args.export or args.vacuum)
            and not collector_running(cfg)):
        mode = try_admin_relaunch(cfg)
        if mode == "task":
            # задача стартує збирач у фоні; інтерактивному запуску — вікно
            if args.window or args.native_window or not args.quiet:
                open_window(cfg)
            return 0
        if mode == "uac":
            return 0     # підвищена копія повторить цей самий запуск сама

    if args.native_window:
        # Нативне вікно ЖИВЕ В ГОЛОВНОМУ ПОТОЦІ цього процесу (вимога Windows GUI).
        init_db()
        if not ensure_collector(cfg):
            print("Не вдалося запустити збирач.")
            return 1
        import app_window
        url = f"http://127.0.0.1:{cfg['dashboard_port']}/"
        icon = os.path.join(BASE, "pcmon.ico")
        if not app_window.run(url, icon=icon):
            open_window(cfg, native=False)  # відкат на браузерний режим
        return 0

    if args.window:
        init_db()
        if not ensure_collector(cfg):
            print("Не вдалося запустити збирач. Спробуй run.bat і подивись логи в logs/.")
            return 1
        open_window(cfg)
        return 0
    if args.status:
        init_db()
        if collector_running(cfg):
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{cfg['dashboard_port']}/api/status", timeout=2) as r:
                print(json.dumps(json.load(r), ensure_ascii=False, indent=2))
        else:
            print("Збирач не запущений.")
        return 0
    if args.export:
        init_db()
        p = export_app(cfg, args.export, args.date)
        print(f"Готово: {p}\nКинь цей файл у чат Claude і попроси проаналізувати.")
        return 0
    if args.vacuum:
        init_db()
        con = sqlite3.connect(DB_PATH)
        con.execute("VACUUM")
        con.close()
        print("Базу стиснуто.")
        return 0

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: shutdown())
        except Exception:
            pass
    return run_collector(cfg, with_tray=not args.no_tray, console=console)


if __name__ == "__main__":
    sys.exit(main())
