# -*- coding: utf-8 -*-
"""
PC Monitor — завантаження GPU по кожному процесу (Windows).

Звідки беруться цифри: з тих самих лічильників продуктивності Windows, з яких
їх бере Диспетчер задач — категорія «GPU Engine», лічильник
«Utilization Percentage». Імена екземплярів виглядають так:

    pid_12345_luid_0x00000000_0x0000C3B7_phys_0_eng_0_engtype_3D

тобто в самому імені закодований PID процесу і тип рушія (3D, VideoDecode,
Copy, Compute тощо). Ми підсумовуємо всі рушії одного процесу.

Працює без прав адміністратора і без драйверів: PDH — штатний API Windows.
Запит відкривається ОДИН раз і перевикористовується на кожному опитуванні,
тому накладні витрати мінімальні (жодних запусків сторонніх програм).

Якщо щось піде не так (немає GPU-лічильників, стара система, помилка PDH) —
модуль просто повідомляє, що недоступний, і монітор працює без колонки GPU.
"""
import logging
import re
import sys

log = logging.getLogger("pcmon.gpu")

PDH_FMT_DOUBLE = 0x00000200
PDH_FMT_NOCAP100 = 0x00008000
PDH_MORE_DATA = 0x800007D2
PDH_NO_DATA = 0x800007D5
PDH_INVALID_DATA = 0xC0000BC6
PDH_CSTATUS_VALID_DATA = 0x00000000
PDH_CSTATUS_NEW_DATA = 0x00000001

COUNTER_PATH = r"\GPU Engine(*)\Utilization Percentage"
_PID_RE = re.compile(r"pid_(\d+)_")


class GpuCounters:
    """Опитувач GPU-навантаження по PID. Не потокобезпечний — клич з одного потоку."""

    def __init__(self):
        self.ok = False
        self.status = "не ініціалізовано"
        self.query = None
        self.counter = None
        self._pdh = None
        self._structs = None
        self._primed = False
        self._fail_count = 0

    # ---------------------------------------------------------------- init --
    def start(self):
        if sys.platform != "win32":
            self.status = "недоступно: не Windows"
            return False
        try:
            import ctypes
            from ctypes import wintypes

            pdh = ctypes.WinDLL("pdh.dll")

            class PDH_FMT_COUNTERVALUE(ctypes.Structure):
                # DWORD + (padding) + union{...}; ctypes сам вирівняє double на 8
                _fields_ = [("CStatus", wintypes.DWORD),
                            ("doubleValue", ctypes.c_double)]

            class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
                _fields_ = [("szName", wintypes.LPWSTR),
                            ("FmtValue", PDH_FMT_COUNTERVALUE)]

            pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
            pdh.PdhAddEnglishCounterW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                                  ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_void_p)]
            pdh.PdhCollectQueryData.argtypes = [ctypes.c_void_p]
            pdh.PdhGetFormattedCounterArrayW.argtypes = [
                ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p]
            pdh.PdhCloseQuery.argtypes = [ctypes.c_void_p]

            query = ctypes.c_void_p()
            rc = pdh.PdhOpenQueryW(None, None, ctypes.byref(query))
            if rc != 0:
                self.status = f"PdhOpenQuery помилка 0x{rc & 0xFFFFFFFF:08X}"
                return False

            counter = ctypes.c_void_p()
            rc = pdh.PdhAddEnglishCounterW(query, COUNTER_PATH, None,
                                           ctypes.byref(counter))
            if rc != 0:
                pdh.PdhCloseQuery(query)
                self.status = ("лічильників GPU немає в системі"
                               if (rc & 0xFFFFFFFF) == 0xC0000BB8
                               else f"PdhAddCounter помилка 0x{rc & 0xFFFFFFFF:08X}")
                return False

            # Перше опитування — «затравка»: значення зʼявляться з другого разу.
            pdh.PdhCollectQueryData(query)

            self._pdh = pdh
            self._ctypes = ctypes
            self._wintypes = wintypes
            self._structs = (PDH_FMT_COUNTERVALUE, PDH_FMT_COUNTERVALUE_ITEM_W)
            self.query = query
            self.counter = counter
            self.ok = True
            self.status = "активний"
            log.info("GPU-лічильники підключено")
            return True
        except Exception as e:
            self.status = f"помилка: {e}"
            log.info("GPU-лічильники недоступні: %s", e)
            return False

    # ---------------------------------------------------------------- read --
    def sample(self):
        """
        Повертає {pid: відсоток_GPU}. Порожній словник — якщо даних нема
        (наприклад, GPU повністю простоює або лічильники ще не прогрілись).
        """
        if not self.ok:
            return {}
        ctypes = self._ctypes
        wintypes = self._wintypes
        pdh = self._pdh
        _, ITEM = self._structs
        try:
            rc = pdh.PdhCollectQueryData(self.query)
            if rc != 0:
                # PDH_NO_DATA — просто ніхто не вантажить GPU
                return {}
            if not self._primed:
                self._primed = True  # перший результат після затравки вже валідний

            size = wintypes.DWORD(0)
            count = wintypes.DWORD(0)
            rc = pdh.PdhGetFormattedCounterArrayW(
                self.counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100,
                ctypes.byref(size), ctypes.byref(count), None)
            if (rc & 0xFFFFFFFF) != PDH_MORE_DATA:
                return {}
            if size.value == 0 or count.value == 0:
                return {}
            buf = ctypes.create_string_buffer(size.value)
            rc = pdh.PdhGetFormattedCounterArrayW(
                self.counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100,
                ctypes.byref(size), ctypes.byref(count), buf)
            if rc != 0:
                return {}

            items = ctypes.cast(buf, ctypes.POINTER(ITEM))
            out = {}
            for i in range(count.value):
                it = items[i]
                name = it.szName
                if not name:
                    continue
                m = _PID_RE.search(name)
                if not m:
                    continue
                val = it.FmtValue.doubleValue
                if val <= 0:
                    continue
                pid = int(m.group(1))
                out[pid] = out.get(pid, 0.0) + val
            self._fail_count = 0
            return out
        except Exception:
            self._fail_count += 1
            if self._fail_count <= 3:
                log.exception("Помилка читання GPU-лічильників")
            if self._fail_count > 20:
                self.ok = False
                self.status = "вимкнено після повторюваних помилок"
            return {}

    def stop(self):
        try:
            if self.query is not None and self._pdh is not None:
                self._pdh.PdhCloseQuery(self.query)
        except Exception:
            pass
        self.query = None
        self.ok = False
        self.status = "зупинено"
