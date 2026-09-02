# -*- coding: utf-8 -*-
"""
PC Monitor — глобальна гаряча клавіша (показати/сховати вікно).

RegisterHotKey прив'язується до потоку, тож тримаємо окремий потік із
власним GetMessage-циклом. Це блокуючий цикл, CPU не їсть.
"""
import logging
import threading

log = logging.getLogger("pcmon.hotkey")

MODS = {"ctrl": 0x0002, "alt": 0x0001, "shift": 0x0004, "win": 0x0008}
VK = {**{chr(c): c for c in range(0x30, 0x3A)},        # 0-9
      **{chr(c): c for c in range(0x41, 0x5B)},        # A-Z
      **{f"f{i}": 0x6F + i for i in range(1, 13)},      # F1-F12
      "space": 0x20, "tab": 0x09, "esc": 0x1B, "pause": 0x13,
      "home": 0x24, "end": 0x23, "insert": 0x2D, "delete": 0x2E}


def parse(spec):
    """'ctrl+shift+m' → (mods, vk) або None."""
    parts = [p.strip().lower() for p in str(spec or "").split("+") if p.strip()]
    if not parts:
        return None
    mods, key = 0, None
    for p in parts:
        if p in MODS:
            mods |= MODS[p]
        else:
            key = VK.get(p.upper() if len(p) == 1 else p)
    if key is None or mods == 0:
        return None
    return mods | 0x4000, key      # MOD_NOREPEAT


class HotKey(threading.Thread):
    def __init__(self, spec, on_press):
        super().__init__(name="hotkey", daemon=True)
        self.spec = spec
        self.on_press = on_press
        self.ok = False
        self.error = ""

    def run(self):
        try:
            import ctypes
            from ctypes import wintypes
        except Exception as e:
            self.error = str(e)
            return
        p = parse(self.spec)
        if not p:
            self.error = f"незрозуміла комбінація: {self.spec}"
            log.warning("Гаряча клавіша: %s", self.error)
            return
        mods, vk = p
        u = ctypes.windll.user32
        if not u.RegisterHotKey(None, 1, mods, vk):
            self.error = "комбінація вже зайнята іншою програмою"
            log.warning("Гаряча клавіша %s не зареєструвалась — %s", self.spec, self.error)
            return
        self.ok = True
        log.info("Гаряча клавіша %s активна", self.spec)
        msg = wintypes.MSG()
        try:
            while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == 0x0312:          # WM_HOTKEY
                    try:
                        self.on_press()
                    except Exception:
                        log.exception("Обробник гарячої клавіші впав")
        finally:
            u.UnregisterHotKey(None, 1)
