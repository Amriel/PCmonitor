# -*- coding: utf-8 -*-
"""
PC Monitor — СПРАВЖНЄ нативне вікно застосунку.

Чому окремий модуль: попередній підхід («Edge у режимі --app») давав вікно без
вкладок, але це все одно був Edge — окремий значок Edge на панелі задач, процес
msedge.exe у списку, і взагалі відчуття браузера. Це не те.

Тут використовується pywebview: він створює **нормальне вікно Windows** з власним
заголовком і власним пунктом на панелі задач. Усередині вікна малює WebView2 —
системний рушій, який уже вбудований у Windows 10/11 (той самий, на якому
працюють Пошта, Параметри та інші штатні застосунки). Тобто:

  * на панелі задач — «PC Monitor», а не Edge;
  * у Диспетчері задач — власний процес, а не вкладка браузера;
  * ніякого адресного рядка, вкладок, закладок, меню браузера;
  * вікно згортається/розгортається/змінює розмір як звичайна програма.

Якщо pywebview з якоїсь причини недоступний, monitor.py тихо відкотиться до
старого способу (браузер у режимі --app) — застосунок не зламається.
"""
import logging
import sys
import threading

log = logging.getLogger("pcmon.window")

WINDOW_TITLE = "PC Monitor"


def available():
    """Чи можемо ми показати справжнє нативне вікно."""
    try:
        import webview  # noqa: F401
        return True
    except Exception:
        return False


def _set_taskbar_identity():
    """
    Щоб Windows показував вікно як окремий застосунок з власним значком,
    а не групував його з Python. Робиться до створення вікна.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Amriel.PCMonitor.1")
    except Exception:
        pass


def _apply_icon_when_ready(icon_path, tries=60):
    """
    Поставити вікну наш значок замість типового значка Python.

    pywebview не дає задати іконку напряму, тому робимо це самі: чекаємо, поки
    вікно з'явиться, знаходимо його за заголовком і надсилаємо WM_SETICON.
    Виконується у фоновому потоці, бо головний зайнятий циклом вікна.
    """
    if sys.platform != "win32" or not icon_path:
        return
    import os
    if not os.path.isfile(icon_path):
        log.info("Файл значка не знайдено: %s", icon_path)
        return
    try:
        import ctypes
        from ctypes import wintypes
        import time as _t

        u = ctypes.WinDLL("user32", use_last_error=True)
        u.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        u.FindWindowW.restype = wintypes.HWND
        u.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                                 ctypes.c_int, ctypes.c_int, wintypes.UINT]
        u.LoadImageW.restype = wintypes.HANDLE
        u.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                   ctypes.c_void_p, ctypes.c_void_p]

        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x00000010
        LR_DEFAULTSIZE = 0x00000040
        WM_SETICON = 0x0080
        ICON_SMALL, ICON_BIG = 0, 1

        hwnd = None
        for _ in range(tries):
            hwnd = u.FindWindowW(None, WINDOW_TITLE)
            if hwnd:
                break
            _t.sleep(0.25)
        if not hwnd:
            log.info("Вікно не знайшлося — значок не поставив")
            return

        big = u.LoadImageW(None, icon_path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
        small = u.LoadImageW(None, icon_path, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        if not big:
            big = u.LoadImageW(None, icon_path, IMAGE_ICON, 0, 0,
                               LR_LOADFROMFILE | LR_DEFAULTSIZE)
        if big:
            u.SendMessageW(hwnd, WM_SETICON, ctypes.c_void_p(ICON_BIG), big)
        if small:
            u.SendMessageW(hwnd, WM_SETICON, ctypes.c_void_p(ICON_SMALL), small)
        log.info("Значок вікна встановлено")
    except Exception:
        log.exception("Не вдалося поставити значок вікна")


def run(url, width=1400, height=940, icon=None):
    """
    Відкрити нативне вікно і крутити його цикл подій.

    УВАГА: має викликатися з ГОЛОВНОГО потоку — на Windows GUI-цикл інакше
    не працює. Функція блокує виконання, доки користувач не закриє вікно.
    Повертає True, якщо вікно показали; False — якщо не вийшло (тоді
    викликач має відкотитися до браузерного режиму).
    """
    try:
        import webview
    except Exception as e:
        log.info("pywebview недоступний (%s) — використаю браузерний режим", e)
        return False

    _set_taskbar_identity()
    # значок ставимо з фонового потоку — головний зараз піде в цикл вікна
    if icon:
        threading.Thread(target=_apply_icon_when_ready, args=(icon,),
                         daemon=True).start()
    try:
        webview.create_window(
            WINDOW_TITLE,
            url,
            width=width,
            height=height,
            min_size=(940, 620),
            background_color="#0e1116",   # щоб не блимало білим під час старту
            text_select=True,             # дозволити виділяти й копіювати текст
            confirm_close=False,
        )
        # gui=None -> сам обере доступний рушій (на Windows це WebView2/EdgeChromium)
        webview.start()
        return True
    except Exception as e:
        log.warning("Не вдалося створити нативне вікно (%s) — браузерний режим", e)
        return False
