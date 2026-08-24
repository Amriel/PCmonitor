"""
Виконання команд із монітора.

Головна складність тут не «запустити команду», а **не дати їй зайвих прав**.

Монітор запускається з правами адміністратора (інакше немає ETW і трасування
драйверів). Якби команди просто успадковували ці права, кожна помилка в
набраному рядку діяла б на всю систему. Тому за замовчуванням ми навмисно
знижуємо права: беремо «обмежений» токен, який Windows створює в парі до
елевованого (це той самий токен, з яким працює звичайний Провідник), і
запускаємо команду з ним.

Ключове правило цього модуля: **якщо знизити права не вдалося — ми не
виконуємо команду взагалі**. Мовчки виконати її від адміністратора, обіцяючи
зворотне, було б гірше, ніж відмовити.

Рівень прав ми не декларуємо, а ПЕРЕВІРЯЄМО: `probe()` запускає whoami і
дивиться, чи справді група адміністраторів вимкнена.
"""
import logging
import os
import subprocess
import sys
import tempfile
import time

log = logging.getLogger("pcmon.runcmd")
IS_WIN = sys.platform.startswith("win")

MAX_OUTPUT = 200_000        # більше в вікно все одно не влізе
DEFAULT_TIMEOUT = 60

# Команди, які монітор не виконує в жодному режимі. Це не «захист від хакера»
# (той просто відкриє cmd) — це захист від друкарської помилки о третій ночі.
# Кожна з них незворотна й діє на всю систему.
BLOCKED = [
    ("format ", "форматування диска"),
    ("mkfs", "форматування диска"),
    ("del /s /q c:\\", "рекурсивне видалення системного диска"),
    ("rd /s /q c:\\", "рекурсивне видалення системного диска"),
    ("rmdir /s /q c:\\", "рекурсивне видалення системного диска"),
    ("remove-item -path c:\\ -recurse", "рекурсивне видалення системного диска"),
    ("diskpart", "розмітка дисків"),
    ("cipher /w", "затирання вільного місця"),
    ("vssadmin delete shadows", "видалення точок відновлення"),
    ("wbadmin delete", "видалення резервних копій"),
    ("bcdedit", "зміна завантажувача"),
]


def check_blocked(cmd):
    low = " ".join((cmd or "").lower().split())
    for frag, why in BLOCKED:
        if frag in low:
            return why
    return ""


# =====================================================================
#  WINDOWS: обмежений токен
# =====================================================================
def _win():
    import ctypes
    from ctypes import wintypes
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    return ctypes, wintypes, a, k


TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_LINKED_TOKEN = 19          # TokenLinkedToken
TOKEN_ELEVATION = 20             # TokenElevation
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
LOGON_WITH_PROFILE = 0x00000001
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400


def is_elevated():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _limited_token():
    """
    Обмежений («не-адмінський») токен, парний до нашого елевованого.

    Windows при елевації створює пару токенів: повний і обмежений. Другий —
    рівно те, з чим працює звичайна програма користувача. Беремо саме його,
    а не «якогось користувача»: так команда виконається від того самого
    облікового запису, просто без адміністративних прав.

    Повертає (handle, помилка). handle треба закрити через CloseHandle.
    """
    ctypes, wintypes, a, k = _win()
    hproc = k.GetCurrentProcess()
    htok = wintypes.HANDLE()
    if not a.OpenProcessToken(hproc, TOKEN_QUERY | TOKEN_DUPLICATE,
                              ctypes.byref(htok)):
        return None, "не вдалося відкрити токен процесу"
    try:
        class TOKEN_LINKED(ctypes.Structure):
            _fields_ = [("LinkedToken", wintypes.HANDLE)]
        linked = TOKEN_LINKED()
        need = wintypes.DWORD(0)
        ok = a.GetTokenInformation(htok, TOKEN_LINKED_TOKEN,
                                   ctypes.byref(linked), ctypes.sizeof(linked),
                                   ctypes.byref(need))
        if not ok or not linked.LinkedToken:
            return None, ("Windows не дала обмеженого токена — таке буває, коли "
                          "контроль облікових записів (UAC) вимкнено повністю")
        # робимо з нього первинний токен, придатний для запуску процесу
        dup = wintypes.HANDLE()
        if not a.DuplicateTokenEx(linked.LinkedToken,
                                  0x02000000,          # MAXIMUM_ALLOWED
                                  None, SECURITY_IMPERSONATION, TOKEN_PRIMARY,
                                  ctypes.byref(dup)):
            k.CloseHandle(linked.LinkedToken)
            return None, "не вдалося підготувати обмежений токен"
        k.CloseHandle(linked.LinkedToken)
        return dup, ""
    finally:
        k.CloseHandle(htok)


def _run_with_token(token, cmdline, cwd, out_path, timeout):
    """
    Запустити команду з переданим токеном.

    Вивід не читаємо через канали, а перенаправляємо у файл самим cmd:
    так не треба возитися зі спадковими дескрипторами й ризикувати
    взаємоблокуванням, коли команда пише багато й ніхто не читає.
    """
    ctypes, wintypes, a, k = _win()

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD)]

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    a.CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]

    full = 'cmd.exe /d /s /c "%s" > "%s" 2>&1' % (cmdline, out_path)
    buf = ctypes.create_unicode_buffer(full)
    ok = a.CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, None, buf,
                                   CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                                   None, cwd or None,
                                   ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        err = ctypes.get_last_error()
        return None, f"не вдалося запустити з обмеженими правами (код {err})"
    try:
        rc = k.WaitForSingleObject(pi.hProcess, int(timeout * 1000))
        if rc == 0x102:                       # WAIT_TIMEOUT
            k.TerminateProcess(pi.hProcess, 1)
            return None, "timeout"
        code = wintypes.DWORD(0)
        k.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        return code.value, ""
    finally:
        k.CloseHandle(pi.hProcess)
        k.CloseHandle(pi.hThread)


# =====================================================================
#  ПУБЛІЧНЕ
# =====================================================================
def run(cmd, as_admin=False, cwd=None, timeout=DEFAULT_TIMEOUT):
    """
    Виконати команду. Повертає словник із виводом і фактичним рівнем прав.

    as_admin=False (типово) — знижуємо права до звичайного користувача.
    as_admin=True — успадковуємо права монітора; це має бути свідомий вибір
    людини на кожен запуск, а не налаштування «увімкнув і забув».
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return {"ok": False, "error": "порожня команда"}
    why = check_blocked(cmd)
    if why:
        return {"ok": False, "error":
                f"монітор не виконує таких команд: {why}. Це незворотна дія на "
                "всю систему — якщо вона справді потрібна, зроби її свідомо в "
                "окремому вікні терміналу."}
    timeout = max(1, min(600, int(timeout or DEFAULT_TIMEOUT)))
    t0 = time.time()

    # ---- не Windows (або монітор і так без прав адміністратора) -------
    if not IS_WIN:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               timeout=timeout, cwd=cwd or None)
            out = (r.stdout or b"").decode("utf-8", "replace")
            err = (r.stderr or b"").decode("utf-8", "replace")
            return _done(cmd, r.returncode, out + err, t0, "звичайний користувач")
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"команда не завершилась за {timeout} с",
                    "timeout": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    elevated = is_elevated()
    if as_admin or not elevated:
        # Нічого знижувати не треба: або людина свідомо просила адміністратора,
        # або монітор і так працює без цих прав.
        level = "адміністратор" if (as_admin and elevated) else "звичайний користувач"
        try:
            r = subprocess.run(f'cmd.exe /d /s /c "{cmd}"', capture_output=True,
                               timeout=timeout, cwd=cwd or None,
                               creationflags=CREATE_NO_WINDOW)
            out = (r.stdout or b"").decode("cp866", "replace")
            err = (r.stderr or b"").decode("cp866", "replace")
            return _done(cmd, r.returncode, out + err, t0, level)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"команда не завершилась за {timeout} с",
                    "timeout": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ---- монітор елевований, а команду треба виконати без цих прав ----
    token, err = _limited_token()
    if not token:
        # Свідомо НЕ виконуємо. Мовчазне виконання від адміністратора замість
        # обіцяного зниження прав — саме та поведінка, через яку потім не
        # розуміють, чому команда зробила більше, ніж мала.
        return {"ok": False, "error":
                f"не вдалося знизити права ({err}). Команду не виконано: "
                "монітор не запускає від адміністратора те, що просили "
                "запустити від користувача. Постав галочку «цього разу від "
                "адміністратора», якщо це саме те, що потрібно."}
    fd, out_path = tempfile.mkstemp(prefix="pcmon_cmd_", suffix=".txt")
    os.close(fd)
    try:
        code, err = _run_with_token(token, cmd.replace('"', '""'),
                                    cwd, out_path, timeout)
        if err == "timeout":
            return {"ok": False, "error": f"команда не завершилась за {timeout} с",
                    "timeout": True}
        if err:
            return {"ok": False, "error": err}
        try:
            with open(out_path, "rb") as f:
                raw = f.read(MAX_OUTPUT + 1)
        except OSError:
            raw = b""
        return _done(cmd, code, raw.decode("cp866", "replace"), t0,
                     "звичайний користувач")
    finally:
        try:
            import ctypes
            ctypes.WinDLL("kernel32").CloseHandle(token)
        except Exception:
            pass
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _done(cmd, code, out, t0, level):
    cut = len(out) > MAX_OUTPUT
    if cut:
        out = out[:MAX_OUTPUT] + "\n… (вивід обрізано)"
    log.info("Команда «%s» [%s] -> код %s", cmd[:120], level, code)
    return {"ok": True, "code": code, "output": out, "truncated": cut,
            "level": level, "took_ms": round((time.time() - t0) * 1000)}


def probe():
    """
    Перевірити НА ДІЛІ, з якими правами виконуються команди.

    Не «ми так налаштували», а «ось що каже сама Windows». Без цього обіцянка
    про знижені права лишалась би обіцянкою, яку неможливо перевірити.
    """
    if not IS_WIN:
        r = run("id -un && id -Gn")
        return {"supported": False, "monitor_elevated": is_elevated(),
                "output": (r.get("output") or "").strip()[:400]}
    out = {"supported": True, "monitor_elevated": is_elevated()}
    for key, admin in (("user", False), ("admin", True)):
        r = run("whoami /groups", as_admin=admin, timeout=25)
        if not r.get("ok"):
            out[key] = {"ok": False, "error": r.get("error")}
            continue
        text = r.get("output") or ""
        # S-1-5-32-544 — вбудована група «Адміністратори».
        line = next((ln for ln in text.splitlines() if "S-1-5-32-544" in ln), "")
        enabled = bool(line) and "Deny" not in line and "заборон" not in line.lower()
        out[key] = {"ok": True, "admin_group_enabled": enabled,
                    "line": line.strip()[:200] or "групу адміністраторів не знайдено"}
    return out
