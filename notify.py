# -*- coding: utf-8 -*-
"""
PC Monitor — центр сповіщень.

Єдина точка, через яку будь-який детектор (пам'ять, диски, порожні цикли,
підозрілість, температура, автозапуск, стеження) повідомляє людину.
Сповіщення показуються через значок у треї (стандартні сповіщення Windows).

Правила, щоб не набридати:
  - кожен тип має свій перемикач у налаштуваннях (cfg["notify"][kind]);
  - «тихі години» — нічого не показуємо, лише пишемо в журнал подій;
  - однакове повідомлення (за ключем) не повторюється частіше, ніж раз на
    cooldown (типово 6 годин), поки процес живий;
  - усе, що показано (або притлумлено), потрапляє в стрічку «Події» —
    щоб можна було подивитись і вранці.
"""
import logging
import threading
import time

log = logging.getLogger("pcmon.notify")

KINDS = {
    "new_net":   "Нова програма вперше вийшла в мережу",
    "suspicious": "Програма набрала поріг підозрілості",
    "temp":      "Температура вище порога",
    "autostart": "Новий запис у автозапуску",
    "memory":    "Оперативна пам'ять майже закінчилась",
    "disk":      "Диск скоро заповниться",
    "busy_loop": "Програма крутить порожній цикл",
    "watch":     "Активність програми зі стеження",
    "clipboard": "Буфер обміну заблоковано",
}

DEFAULTS = {
    "enabled": True,
    "new_net": True, "suspicious": True, "temp": True, "autostart": True,
    "memory": True, "disk": True, "busy_loop": True, "watch": True,
    "clipboard": True,
    "quiet_from": 23, "quiet_to": 8,      # тихі години (локальний час)
    "cooldown_h": 6,                       # не повторювати той самий ключ
    "gpu_temp_c": 85, "disk_temp_c": 60,   # пороги температури
    "ram_pct": 90,                         # поріг тиску на пам'ять
    "disk_days": 7, "disk_pct": 95,        # прогноз/поріг заповнення диска
}


class Notifier:
    def __init__(self, cfg, on_event=None):
        self.cfg = cfg
        self.icon = None            # pystray.Icon — ставить трей після старту
        self.on_event = on_event    # callback(kind, title, msg) → у стрічку подій
        self._last = {}             # key → ts останнього показу
        self._lock = threading.Lock()
        self.history = []           # останні 50 сповіщень для UI

    # --- налаштування ----------------------------------------------------
    def opts(self):
        o = dict(DEFAULTS)
        o.update(self.cfg.get("notify") or {})
        return o

    def _quiet(self, o):
        h = time.localtime().tm_hour
        a, b = int(o.get("quiet_from", 23)), int(o.get("quiet_to", 8))
        if a == b:
            return False
        return (a <= h or h < b) if a > b else (a <= h < b)

    # --- головний вхід ---------------------------------------------------
    def notify(self, kind, title, msg, key=None, force=False):
        """
        Показати сповіщення типу kind. key — для дедуплікації (типово
        kind+title). Повертає True, якщо реально показано.
        """
        o = self.opts()
        key = key or f"{kind}:{title}"
        now = time.time()
        with self._lock:
            last = self._last.get(key, 0)
            if not force and now - last < float(o.get("cooldown_h", 6)) * 3600:
                return False
            self._last[key] = now
            self.history.append({"ts": int(now), "kind": kind, "title": title,
                                 "msg": msg})
            del self.history[:-50]
        try:
            if self.on_event:
                self.on_event(kind, title, msg)
        except Exception:
            log.exception("Не вдалося записати сповіщення у події")

        if not o.get("enabled", True) or not o.get(kind, True):
            return False
        if self._quiet(o) and not force:
            log.info("Тихі години — сповіщення притлумлено: %s — %s", title, msg)
            return False
        shown = False
        if self.icon is not None:
            try:
                self.icon.notify(msg[:240], title[:60])
                shown = True
            except Exception:
                log.exception("Сповіщення через трей не вдалося")
        if not shown:
            log.info("Сповіщення: %s — %s", title, msg)
        return shown

    def test(self):
        return self.notify("watch", "PC Monitor", "Сповіщення працюють ✓",
                           key="test", force=True)
