# -*- coding: utf-8 -*-
"""
PC Monitor — евристики «підозрілих» процесів.

Бальна система: кожне правило додає бали і людську причину українською.
Це ПІДКАЗКИ для уваги, а не антивірусний вердикт — фінальне рішення за людиною.
"""
import re

# Імена системних процесів Windows, які часто підробляють шкідливі програми.
SYSTEM_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "dwm.exe", "conhost.exe",
    "runtimebroker.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "spoolsv.exe", "dllhost.exe", "searchindexer.exe", "fontdrvhost.exe",
    "audiodg.exe", "wmiprvse.exe", "system", "registry", "taskmgr.exe",
}

# Легітимні шляхи для системних імен (нижній регістр, початок шляху).
SYSTEM_PATH_PREFIXES = (
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
    "c:\\windows\\explorer.exe", "c:\\windows\\",
)

# Процеси ядра Windows, які ВЗАГАЛІ не мають файлу на диску.
# psutil для них повертає замість шляху просто назву («Registry», «System»),
# і це нормально, а не ознака маскування.
KERNEL_PSEUDO = {
    "system", "registry", "secure system", "memory compression",
    "memcompression", "system idle process", "idle",
    "vmmem", "vmmemwsl",          # обгортки пам'яті віртуальних машин / WSL
}


def has_real_path(exe):
    """
    Чи є `exe` справжнім шляхом до файлу.

    Важливо: у процесів ядра Windows файлу на диску немає, і замість шляху
    там опиняється просто назва («Registry»). Усі правила, що дивляться на
    шлях або підпис, для таких процесів не мають сенсу — інакше кожен
    системний процес позначався б як «маскується».
    """
    e = (exe or "").strip().replace("/", "\\")
    if not e:
        return False
    # справжній шлях має розділювач або починається з літери диска
    return "\\" in e or (len(e) > 2 and e[1] == ":")

# Програми, для яких великий трафік і багато IP — норма.
NET_HEAVY_WHITELIST = {
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "opera_gx.exe",
    "brave.exe", "vivaldi.exe", "steam.exe", "steamwebhelper.exe",
    "discord.exe", "telegram.exe", "spotify.exe", "qbittorrent.exe",
    "utorrent.exe", "onedrive.exe", "dropbox.exe", "megasync.exe",
    "epicgameslauncher.exe",
    "battle.net.exe", "gog galaxy.exe", "skype.exe", "zoom.exe", "viber.exe",
    "slack.exe", "obs64.exe", "nvidia web helper.exe", "wsappx",
    "svchost.exe",  # windows update тощо
}

# Порти, які вважаємо «звичайними» для виходу в інтернет.
COMMON_PORTS = {80, 443, 53, 123, 8080, 8443, 993, 995, 587, 465, 22, 21,
                3478, 3479, 5222, 5228, 1900, 5353}

# Підозрілі місця запуску: (regex по шляху в нижньому регістрі, бали, причина)
PATH_RULES = [
    (re.compile(r"\\appdata\\local\\temp\\"), 28, "Запускається з тимчасової папки (Temp)"),
    (re.compile(r"\\windows\\temp\\"), 28, "Запускається з C:\\Windows\\Temp"),
    (re.compile(r"\\downloads\\"), 18, "Запускається прямо з папки «Завантаження»"),
    (re.compile(r"\$recycle\.bin"), 45, "Запускається з Кошика (!)"),
    (re.compile(r"^[a-z]:\\programdata\\[^\\]+\.exe$"), 22, "Виконуваний файл лежить прямо в корені ProgramData"),
    (re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\roaming\\[^\\]+\.exe$"), 22, "Виконуваний файл прямо в корені AppData\\Roaming"),
    (re.compile(r"\\users\\public\\"), 20, "Запускається з папки Public"),
    (re.compile(r"^[a-z]:\\[^\\]+\.exe$"), 15, "Виконуваний файл лежить у корені диска"),
]

# Інсталятори ЖИВУТЬ у Temp — це їхня нормальна поведінка, а не маскування:
# Inno Setup розпаковує себе в \Temp\is-XXXXX.tmp\, VS Code — CodeSetup-*.tmp,
# браузерні завантаження запускаються зі scoped_dir*. Штрафувати їх повним
# балом за Temp означало б лякати на кожне оновлення програм.
INSTALLER_RE = re.compile(
    r"(\\temp\\is-[a-z0-9]+\.tmp\\|setup[^\\]*\.(tmp|exe)$|install[^\\]*\.(tmp|exe)$"
    r"|\\scoped_dir\d+_\d+\\|\\msi[a-z0-9]+\.tmp$|_installer\.exe$)")

# Сегменти шляху з версією: \2.1.257-win32-x64\, \app-1.0.9253\, \151.0.4129.101\
VERSION_SEG_RE = re.compile(r"\\[^\\]*\d+\.\d+(\.\d+)*[^\\]*\\")

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|mp3|mp4|avi|zip|rar)\.(exe|scr|com|bat|cmd|pif)$")

BAD_SIG = {"hashmismatch": ("Цифровий підпис НЕ збігається з файлом (файл змінено!)", 35),
           "nottrusted": ("Цифровий підпис не є довіреним", 25),
           "notsigned": ("Виконуваний файл без цифрового підпису", 12)}


def _fmt_mb(n):
    try:
        return f"{n / (1024 * 1024):.0f} МБ"
    except Exception:
        return "?"


def evaluate(app, cfg=None):
    """
    app — словник з полями (усі необов'язкові, чого нема — правило пропускається):
      name, exe, sent_b, recv_b, pub_ips (к-сть унікальних публічних IP),
      odd_ports (к-сть нетипових портів), ninst, avg_life_s,
      first_seen_ts, day_start_ts, sig_status, night_cpu_max (макс CPU% у 02-06),
      dns_count, ignored
    Повертає (score:int, reasons:list[str]).
    """
    cfg = cfg or {}
    name = (app.get("name") or "").lower()
    exe = (app.get("exe") or "").lower().replace("/", "\\")

    # Назви в дужках — це наші власні службові рядки, а не програми:
    # «(трафік без програми)», «(системний pid 428)». Оцінювати їх на
    # підозрілість безглуздо: у них немає ані файлу, ані поведінки, зате
    # зведений трафік легко набирає балів і лякає без причини.
    if name.startswith("(") and name.endswith(")"):
        return 0, []

    score = 0
    reasons = []

    def add(pts, why):
        nonlocal score
        score += pts
        reasons.append(f"+{pts} · {why}")

    # Чи це процес ядра Windows без файлу на диску (Registry, System тощо).
    # Для таких усі правила про шлях і підпис не застосовні.
    real_path = has_real_path(exe)
    kernel = (name in KERNEL_PSEUDO) and not real_path

    # 1. Ім'я системного процесу, але шлях не системний (маскування)
    #    Перевіряємо ЛИШЕ коли шлях справжній: інакше «Registry» без файлу
    #    на диску помилково виглядав як підробка (це був хибний спрацьовуй).
    if name in SYSTEM_NAMES and real_path:
        if not any(exe.startswith(p) for p in SYSTEM_PATH_PREFIXES):
            add(45, f"Ім'я системного процесу «{name}», але шлях не системний: {app.get('exe')}")

    # 2. Подвійне розширення (report.pdf.exe)
    if DOUBLE_EXT_RE.search(name):
        add(30, "Подвійне розширення в імені файлу — класичне маскування")

    # 3. Підозріле місце запуску
    installer = bool(real_path and INSTALLER_RE.search(exe))
    if real_path:
        for rx, pts, why in PATH_RULES:
            if rx.search(exe):
                if installer and "Temp" in why:
                    # інсталятор у Temp — так і має бути; лишаємо легку
                    # позначку, щоб він усе ж був видимий у списку
                    add(6, "Інсталятор запущено з Temp — звично для встановлення програм")
                else:
                    add(pts, why)
                break

    # 4. Стан цифрового підпису
    sig = (app.get("sig_status") or "").lower()
    if sig in BAD_SIG and real_path and not exe.startswith("c:\\windows\\"):
        why, pts = BAD_SIG[sig]
        add(pts, why)

    # 5. Мережеві аномалії (для не-мережевих за природою програм)
    sent = app.get("sent_b") or 0
    recv = app.get("recv_b") or 0
    if name not in NET_HEAVY_WHITELIST:
        big_upload = int(cfg.get("big_upload_mb", 200)) * 1024 * 1024
        if sent > big_upload:
            add(18, f"Великий вихідний трафік за день: {_fmt_mb(sent)}")
        if sent > 50 * 1024 * 1024 and recv > 0 and sent > 3 * recv:
            add(15, f"Відвантажує значно більше, ніж завантажує (↑{_fmt_mb(sent)} проти ↓{_fmt_mb(recv)})")
        pub_ips = app.get("pub_ips") or 0
        if pub_ips > int(cfg.get("many_ips", 40)):
            add(10, f"З'єднання з великою кількістю різних IP: {pub_ips}")
        odd = app.get("odd_ports") or 0
        if odd > 5:
            add(10, f"Використовує нетипові порти назовні ({odd} шт.)")

    # 6. Активність уночі
    night = app.get("night_cpu_max") or 0
    if night >= float(cfg.get("night_cpu_pct", 15)):
        add(8, f"Помітна активність уночі 02:00–06:00 (до {night:.0f}% CPU)")

    # 7. Часті перезапуски
    ninst = app.get("ninst") or 0
    avg_life = app.get("avg_life_s")
    if ninst >= int(cfg.get("churn_count", 15)) and avg_life is not None and avg_life < 120:
        add(12, f"Часто перезапускається: {ninst} запусків, середнє життя {avg_life:.0f} с")

    # 8. Новачок — виконуваний файл вперше з'явився сьогодні.
    #    Має сенс, лише коли монітор працює вже кілька днів: у перші дні він
    #    щойно знайомиться з системою, і «новим» виглядає геть усе, включно
    #    з Windows. Для процесів ядра правило не застосовне взагалі.
    fs = app.get("first_seen_ts")
    ds = app.get("day_start_ts")
    baseline_days = app.get("baseline_days")
    min_baseline = float(cfg.get("new_exe_min_days", 3))
    # Програма з версією в шляху (\2.1.257-win32-x64\, \app-1.0.9253\) після
    # оновлення отримує НОВИЙ шлях — і виглядала «вперше побаченою», хоча
    # це та сама програма. Якщо це ім'я вже бачили раніше під іншим шляхом
    # (name_seen_before), або шлях версійний — новизна не рахується.
    seen_before = bool(app.get("name_seen_before"))
    versioned = bool(real_path and VERSION_SEG_RE.search(exe))
    if (fs and ds and fs >= ds and not kernel and not seen_before
            and (baseline_days is None or baseline_days >= min_baseline)):
        if versioned:
            add(4, "Нова версія відомої програми (шлях містить номер версії)")
        else:
            add(10, "Цей виконуваний файл сьогодні з'явився вперше за весь час спостереження")

    return score, reasons


def threshold(cfg=None):
    return int((cfg or {}).get("suspicion_min_score", 35))
