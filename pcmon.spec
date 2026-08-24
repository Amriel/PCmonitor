# -*- mode: python ; coding: utf-8 -*-
# PC Monitor — збірка в один exe-каталог (PyInstaller, режим onedir).
#
# Чому onedir, а не onefile: onefile при кожному запуску розпаковує себе
# в Temp (повільний старт, антивіруси нервують, а наша ж перевірка
# підозрілості карає запуск із Temp). У onedir усе лежить чесно поруч
# з exe: web/, streamdeck/, дані — і оновлення просто замінює файли,
# не чіпаючи data/.
#
# Збирати: build.bat (він же робить інсталятор).

hidden = [
    # локальні модулі, які monitor.py імпортує всередині функцій —
    # статичний аналіз їх бачить, але перелічуємо явно, щоб збірка
    # не зламалась від майбутнього рефакторингу
    "health", "startup_win", "clipboard_win", "app_window", "procctl",
    "runcmd", "sensors", "dpcisr", "latency", "etw_net", "gpu_win", "pdh",
    "suspicion", "stopmon",
]
try:  # pywebview: нативне вікно; якщо не встановлений — апка вміє без нього
    from PyInstaller.utils.hooks import collect_submodules
    hidden += collect_submodules("webview")
except Exception:
    pass

a = Analysis(
    ["monitor.py"],
    pathex=["."],
    datas=[
        ("web", "web"),
        ("streamdeck", "streamdeck"),
        ("pcmon.ico", "."),
        ("dpcisr.wprp", "."),
    ],
    hiddenimports=hidden,
    excludes=["tkinter", "unittest", "pydoc_data", "test"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="PCMonitor",
    icon="pcmon.ico",
    console=False,            # фонова програма; логи — у logs/monitor.log
    contents_directory=".",   # плоска розкладка: web/ поруч з exe, як у розробці
)
coll = COLLECT(exe, a.binaries, a.datas, name="PCMonitor")
