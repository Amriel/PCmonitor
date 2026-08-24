# -*- coding: utf-8 -*-
"""
PC Monitor — читання лічильників продуктивності Windows (PDH).

Це той самий механізм, з якого бере дані «Системний монітор» (perfmon) і
частково Диспетчер задач. Штатний API Windows, прав адміністратора не потребує,
драйверів не ставить.

Навіщо тут: щоб під час заміру затримок відрізнити ДВІ РІЗНІ причини гальм —
    • «% DPC Time» і «% Interrupt Time» — час, який процесор витрачає на
      обслуговування ДРАЙВЕРІВ. Якщо тут багато, винен драйвер, і жодне
      закриття програм не допоможе.
    • черга до процесора й перемикання контекстів — навпаки, ознака того,
      що система просто перевантажена програмами.

Запит відкривається один раз і перевикористовується, тож накладні витрати
мінімальні.
"""
import logging
import sys

log = logging.getLogger("pcmon.pdh")

PDH_FMT_DOUBLE = 0x00000200
PDH_FMT_NOCAP100 = 0x00008000
PDH_MORE_DATA = 0x800007D2


class Counters:
    """
    Набір лічильників. Приклад:
        c = Counters({"dpc": r"\\Processor Information(_Total)\\% DPC Time"})
        c.start(); ...; c.read() -> {"dpc": 1.7}
    """

    def __init__(self, paths):
        self.paths = dict(paths)
        self.ok = False
        self.status = "не запущено"
        self._q = None
        self._h = {}
        self._ct = None
        self._pdh = None
        self._primed = False

    def start(self):
        if sys.platform != "win32":
            self.status = "недоступно: не Windows"
            return False
        try:
            import ctypes
            from ctypes import wintypes

            pdh = ctypes.WinDLL("pdh.dll")
            pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
            pdh.PdhAddEnglishCounterW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                                  ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_void_p)]
            pdh.PdhCollectQueryData.argtypes = [ctypes.c_void_p]
            pdh.PdhCloseQuery.argtypes = [ctypes.c_void_p]

            class FMT(ctypes.Structure):
                _fields_ = [("CStatus", wintypes.DWORD),
                            ("doubleValue", ctypes.c_double)]

            pdh.PdhGetFormattedCounterValue.argtypes = [
                ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(FMT)]

            q = ctypes.c_void_p()
            if pdh.PdhOpenQueryW(None, None, ctypes.byref(q)) != 0:
                self.status = "не вдалося відкрити запит"
                return False

            added = {}
            for key, path in self.paths.items():
                h = ctypes.c_void_p()
                rc = pdh.PdhAddEnglishCounterW(q, path, None, ctypes.byref(h))
                if rc == 0:
                    added[key] = h
                else:
                    log.info("лічильник недоступний: %s (0x%08X)", path, rc & 0xFFFFFFFF)
            if not added:
                pdh.PdhCloseQuery(q)
                self.status = "жоден лічильник недоступний"
                return False

            pdh.PdhCollectQueryData(q)   # затравка: перше значення завжди порожнє
            self._pdh, self._ctypes, self._FMT = pdh, ctypes, FMT
            self._wintypes = wintypes
            self._q, self._h = q, added
            self.ok = True
            self.status = "активні"
            return True
        except Exception as e:
            self.status = f"помилка: {e}"
            log.info("PDH недоступний: %s", e)
            return False

    def read(self):
        """Поточні значення. Порожній словник, якщо ще нема даних."""
        if not self.ok:
            return {}
        ctypes, wintypes, pdh, FMT = self._ctypes, self._wintypes, self._pdh, self._FMT
        try:
            if pdh.PdhCollectQueryData(self._q) != 0:
                return {}
            out = {}
            for key, h in self._h.items():
                val = FMT()
                t = wintypes.DWORD(0)
                rc = pdh.PdhGetFormattedCounterValue(
                    h, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ctypes.byref(t), ctypes.byref(val))
                if rc == 0:
                    out[key] = float(val.doubleValue)
            self._primed = True
            return out
        except Exception:
            return {}

    def stop(self):
        try:
            if self._q is not None and self._pdh is not None:
                self._pdh.PdhCloseQuery(self._q)
        except Exception:
            pass
        self._q = None
        self.ok = False
        self.status = "зупинено"


# Лічильники, важливі для затримок. Імена англійські навмисне —
# PdhAddEnglishCounterW не залежить від мови системи.
LATENCY_COUNTERS = {
    # частка часу процесора на відкладені виклики драйверів
    "dpc": r"\Processor Information(_Total)\% DPC Time",
    # частка часу на апаратні переривання
    "isr": r"\Processor Information(_Total)\% Interrupt Time",
    # скільки потоків стоять у черзі й не можуть отримати процесор
    "queue": r"\System\Processor Queue Length",
    # інтенсивність перемикань контексту
    "cswitch": r"\System\Context Switches/sec",
    "interrupts": r"\Processor Information(_Total)\Interrupts/sec",
    "dpc_rate": r"\Processor Information(_Total)\DPCs Queued/sec",
}
