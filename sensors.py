"""
Температури й датчики заліза — без власного драйвера.

Про межу можливостей чесно, бо вона тут принципова:

  * Температура ВІДЕОКАРТИ, її пам'ять, вентилятор і споживання доступні
    повністю. NVIDIA віддає їх через nvml.dll, яка ставиться разом із
    драйвером. Нічого додаткового не потрібно.

  * Температура ДИСКІВ доступна через штатні засоби Windows (SMART).

  * Температура ПРОЦЕСОРА й материнської плати — НЕ доступна. Ці значення
    лежать у регістрах MSR і портах вводу-виводу, куди звичайна програма
    не має доступу в принципі. Їх читають лише через драйвер рівня ядра —
    саме тому LibreHardwareMonitor і HWiNFO тягнуть із собою власний
    (WinRing0 / PawnIO). Ми свій не ставимо свідомо: підписаний драйвер
    із довільним доступом до пам'яті — це рівно той інструмент, яким
    користуються зловмисники, і Microsoft такі драйвери блокує.

    Єдине, що лишається в межах користувацького режиму, — теплові зони
    ACPI. На ноутбуках вони зазвичай є і показують щось осмислене, на
    настільних платах — часто одна зона «на весь корпус» або взагалі
    нічого. Ми їх читаємо, але чесно підписуємо, що це не CPU.
"""
import ctypes
import logging
import os
import re
import subprocess
import sys
import time

log = logging.getLogger("pcmon.sensors")
IS_WIN = sys.platform.startswith("win")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# =====================================================================
#  NVIDIA — через nvml.dll (без запуску сторонніх процесів)
# =====================================================================
class _NvmlMemory(ctypes.Structure):
    _fields_ = [("total", ctypes.c_ulonglong),
                ("free", ctypes.c_ulonglong),
                ("used", ctypes.c_ulonglong)]


class _NvmlUtil(ctypes.Structure):
    _fields_ = [("gpu", ctypes.c_uint), ("memory", ctypes.c_uint)]


_nvml = None
_nvml_state = "не пробували"


def _load_nvml():
    """
    Знайти й ініціалізувати nvml.dll.

    Викликається один раз: ініціалізація коштує помітно, а бібліотека або є,
    або її не буде й далі.
    """
    global _nvml, _nvml_state
    if _nvml is not None or _nvml_state.startswith("недоступно"):
        return _nvml
    if not IS_WIN:
        _nvml_state = "недоступно: не Windows"
        return None
    paths = ["nvml.dll",
             os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                          "NVIDIA Corporation", "NVSMI", "nvml.dll"),
             os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                          "System32", "nvml.dll")]
    for p in paths:
        try:
            lib = ctypes.CDLL(p)
        except OSError:
            continue
        init = getattr(lib, "nvmlInit_v2", None) or getattr(lib, "nvmlInit", None)
        if init is None:
            continue
        if init() != 0:
            _nvml_state = "недоступно: nvml.dll не ініціалізувалась"
            return None
        _nvml = lib
        _nvml_state = "активний"
        log.info("NVML підключено (%s)", p)
        return lib
    _nvml_state = "недоступно: nvml.dll не знайдено (немає драйвера NVIDIA)"
    return None


def _nvml_str(fn, handle, size=96):
    buf = ctypes.create_string_buffer(size)
    if fn(handle, buf, ctypes.c_uint(size)) != 0:
        return ""
    return buf.value.decode("utf-8", "replace")


def nvidia():
    """Дані по кожній відеокарті NVIDIA. Порожній список, якщо їх немає."""
    lib = _load_nvml()
    if not lib:
        return []
    out = []
    try:
        n = ctypes.c_uint()
        cnt = (getattr(lib, "nvmlDeviceGetCount_v2", None)
               or getattr(lib, "nvmlDeviceGetCount"))
        if cnt(ctypes.byref(n)) != 0:
            return []
        get_h = (getattr(lib, "nvmlDeviceGetHandleByIndex_v2", None)
                 or getattr(lib, "nvmlDeviceGetHandleByIndex"))
        for i in range(n.value):
            h = ctypes.c_void_p()
            if get_h(ctypes.c_uint(i), ctypes.byref(h)) != 0:
                continue
            d = {"index": i, "name": _nvml_str(lib.nvmlDeviceGetName, h) or "NVIDIA GPU"}

            t = ctypes.c_uint()
            # 0 = NVML_TEMPERATURE_GPU
            if lib.nvmlDeviceGetTemperature(h, ctypes.c_uint(0),
                                            ctypes.byref(t)) == 0:
                d["temp"] = t.value

            m = _NvmlMemory()
            if lib.nvmlDeviceGetMemoryInfo(h, ctypes.byref(m)) == 0:
                d["mem_total"] = m.total
                d["mem_used"] = m.used
                d["mem_free"] = m.free

            u = _NvmlUtil()
            if lib.nvmlDeviceGetUtilizationRates(h, ctypes.byref(u)) == 0:
                d["load"] = u.gpu
                d["mem_load"] = u.memory

            f = ctypes.c_uint()
            if lib.nvmlDeviceGetFanSpeed(h, ctypes.byref(f)) == 0:
                d["fan"] = f.value

            p = ctypes.c_uint()
            if lib.nvmlDeviceGetPowerUsage(h, ctypes.byref(p)) == 0:
                d["power_w"] = round(p.value / 1000.0, 1)

            out.append(d)
    except Exception as e:
        log.info("NVML не віддав дані: %s", e)
        return []
    return out


def nvidia_smi():
    """
    Запасний шлях, якщо nvml.dll не знайшлась, але nvidia-smi є.

    Дорожчий (запуск процесу), тому лише як запасний.
    """
    if not IS_WIN:
        return []
    q = ("name,temperature.gpu,memory.total,memory.used,memory.free,"
         "utilization.gpu,fan.speed,power.draw")
    try:
        r = subprocess.run(["nvidia-smi", f"--query-gpu={q}",
                            "--format=csv,noheader,nounits"],
                           capture_output=True, timeout=12,
                           creationflags=NO_WINDOW)
        txt = r.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return []
    out = []
    for i, line in enumerate(l for l in txt.splitlines() if l.strip()):
        p = [x.strip() for x in line.split(",")]
        if len(p) < 6:
            continue

        def num(v, mul=1):
            try:
                return int(float(v) * mul)
            except Exception:
                return None
        d = {"index": i, "name": p[0], "temp": num(p[1]),
             "mem_total": num(p[2], 1 << 20), "mem_used": num(p[3], 1 << 20),
             "mem_free": num(p[4], 1 << 20), "load": num(p[5])}
        if len(p) > 6:
            d["fan"] = num(p[6])
        if len(p) > 7:
            try:
                d["power_w"] = round(float(p[7]), 1)
            except Exception:
                pass
        out.append({k: v for k, v in d.items() if v is not None})
    return out


# =====================================================================
#  ДИСКИ — температура з SMART, штатними засобами Windows
# =====================================================================
def _ps(cmd, timeout=25):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", cmd],
                           capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "replace").strip()
        if not out:
            return None
        import json
        d = json.loads(out)
        return d if isinstance(d, list) else [d]
    except Exception as e:
        log.debug("PowerShell не відповів: %s", e)
        return None


def disks():
    """Температура накопичувачів. Її віддає сам диск, драйвер не потрібен."""
    if not IS_WIN:
        return []
    data = _ps(
        "Get-PhysicalDisk | ForEach-Object { $c = $_ | "
        "Get-StorageReliabilityCounter -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{Name=$_.FriendlyName; Media=$_.MediaType; "
        "Temp=$c.Temperature; TempMax=$c.TemperatureMax; Wear=$c.Wear} } | "
        "ConvertTo-Json -Compress")
    out = []
    for d in (data or []):
        t = d.get("Temp")
        if t in (None, 0):
            continue
        out.append({"name": d.get("Name") or "диск",
                    "media": d.get("Media") or "",
                    "temp": t, "temp_max": d.get("TempMax"),
                    "wear": d.get("Wear")})
    return out


# =====================================================================
#  ТЕПЛОВІ ЗОНИ ACPI — єдине, що лишається без драйвера
# =====================================================================
def thermal_zones():
    """
    Зони ACPI. На настільних платах їх або немає, або це не процесор —
    тому назви лишаємо як є й ніде не підписуємо їх як «CPU».
    """
    if not IS_WIN:
        return []
    data = _ps("Get-CimInstance -Namespace root/wmi "
               "-ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | "
               "Select-Object InstanceName,CurrentTemperature | "
               "ConvertTo-Json -Compress")
    out = []
    for d in (data or []):
        raw = d.get("CurrentTemperature")
        if not raw:
            continue
        # значення в десятих кельвіна
        c = raw / 10.0 - 273.15
        if not (-20 < c < 150):
            continue
        name = (d.get("InstanceName") or "зона").split("\\")[-1]
        out.append({"name": name, "temp": round(c, 1)})
    return out


# =====================================================================
#  ЗІБРАТИ ВСЕ
# =====================================================================
_cache = {"ts": 0, "data": None}
_slow_ts = {"disks": 0, "zones": 0}
_slow = {"disks": [], "zones": []}


def read_all(force=False):
    """
    Усі доступні датчики.

    Швидке (відеокарта) опитуємо щоразу, повільне (диски, зони ACPI —
    там PowerShell) — раз на пару хвилин: температура диска не змінюється
    ривками, а платити за неї запуском процесу щосекунди безглуздо.
    """
    now = time.time()
    if not force and _cache["data"] and now - _cache["ts"] < 2:
        return _cache["data"]

    gpus = nvidia()
    src_gpu = "nvml" if gpus else ""
    if not gpus:
        gpus = nvidia_smi()
        src_gpu = "nvidia-smi" if gpus else ""

    for key, fn, every in (("disks", disks, 300), ("zones", thermal_zones, 300)):
        if force or now - _slow_ts[key] > every:
            try:
                _slow[key] = fn()
            except Exception:
                log.exception("Датчики %s не прочитались", key)
                _slow[key] = []
            _slow_ts[key] = now

    out = {
        "ts": int(now),
        "gpus": gpus,
        "gpu_source": src_gpu or _nvml_state,
        "disks": _slow["disks"],
        "zones": _slow["zones"],
        # чесно про те, чого нема і чому
        "cpu_temp": None,
        "cpu_note":
            "Температуру процесора й материнської плати у Windows неможливо "
            "прочитати без драйвера рівня ядра — ці значення лежать у "
            "регістрах MSR і портах вводу-виводу. Монітор свого драйвера не "
            "ставить свідомо.",
        "sources": {
            "NVIDIA": _nvml_state if src_gpu != "nvidia-smi" else "nvidia-smi",
            "Диски (SMART)": (f"{len(_slow['disks'])} з температурою"
                              if _slow["disks"] else "температуру не віддають"),
            "Теплові зони ACPI": (f"{len(_slow['zones'])} шт."
                                  if _slow["zones"] else "немає"),
        },
    }
    _cache["ts"], _cache["data"] = now, out
    return out
