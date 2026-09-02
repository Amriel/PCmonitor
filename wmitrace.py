# -*- coding: utf-8 -*-
"""
PC Monitor — «Хто смикає WMI».

WmiPrvSE.exe сам нічого не робить: він виконує запити ІНШИХ програм
(MSI Center, ASUS-агенти, антивірус, наш монітор). Коли він з'їдає
ядро-години, питання завжди одне — хто клієнт. Провайдер ETW
Microsoft-Windows-WMI-Activity називає клієнта кожного запиту поіменно
(ClientProcessId + текст операції).

Принцип той самий, що й у трасуванні драйверів: разово, за кліком, кілька
десятків секунд, вбудованими logman/tracerpt, без драйверів. Потрібен адмін.
"""
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

log = logging.getLogger("pcmon.wmitrace")
IS_WIN = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WIN else 0
SESSION = "PCMonWMI"
PROVIDER = "Microsoft-Windows-WMI-Activity"


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        txt = ((r.stdout or b"").decode("utf-8", "replace")
               + (r.stderr or b"").decode("utf-8", "replace")).strip()
        return r.returncode, txt
    except subprocess.TimeoutExpired:
        return -1, f"перевищено час ({timeout} с)"
    except Exception as e:
        return -1, str(e)


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class WmiTrace:
    def __init__(self, seconds=30):
        self.seconds = max(5, min(120, int(seconds)))
        self.running = False
        self.progress = 0.0
        self.stage = ""
        self.error = ""
        self.result = None
        self.diag = []
        self._cancel = False

    def _d(self, stage, detail=""):
        self.stage = stage
        self.diag.append({"stage": stage, "detail": str(detail)[:400]})
        log.info("[%s] %s", stage, str(detail)[:300])

    def start(self):
        if self.running:
            return False
        self.running = True
        threading.Thread(target=self._work, name="wmitrace", daemon=True).start()
        return True

    def cancel(self):
        self._cancel = True

    def status(self):
        return {"running": self.running, "progress": round(self.progress, 3),
                "stage": self.stage, "error": self.error, "result": self.result,
                "diag": self.diag[-20:], "seconds": self.seconds}

    def _work(self):
        tmp = tempfile.mkdtemp(prefix="pcmon_wmi_")
        etl = os.path.join(tmp, "wmi.etl")
        xml_ = os.path.join(tmp, "wmi.xml")
        try:
            if not IS_WIN:
                self.error = "лише для Windows"
                return
            if not _is_admin():
                self.error = "потрібні права адміністратора — трасування ETW доступне лише їм"
                return
            # прибрати осиротілу сесію, якщо лишилась
            _run(["logman", "stop", SESSION, "-ets"], timeout=20)
            self._d("Старт сесії", f"{PROVIDER}, {self.seconds} с")
            code, out = _run(["logman", "start", SESSION, "-p", PROVIDER,
                              "0xffffffffffffffff", "0xff", "-o", etl, "-ets"], timeout=30)
            if code != 0:
                self.error = f"logman не зміг запустити сесію: {out[:300]}"
                self._d("Помилка", out)
                return
            t0 = time.time()
            while time.time() - t0 < self.seconds and not self._cancel:
                time.sleep(0.5)
                self.progress = min(0.7, (time.time() - t0) / self.seconds * 0.7)
            self._d("Зупинка сесії")
            _run(["logman", "stop", SESSION, "-ets"], timeout=30)
            if self._cancel:
                self.error = "скасовано"
                return
            self.progress = 0.75
            self._d("Розбір траси", "tracerpt → XML")
            code, out = _run(["tracerpt", etl, "-o", xml_, "-of", "XML", "-y"], timeout=180)
            if code != 0 or not os.path.exists(xml_):
                self.error = f"tracerpt не розібрав трасу: {out[:300]}"
                self._d("Помилка", out)
                return
            self.progress = 0.9
            self.result = self._parse(xml_)
            self._d("Готово", f"клієнтів: {len(self.result['clients'])}, "
                              f"подій: {self.result['events']}")
        except Exception as e:
            self.error = str(e)
            log.exception("Трасування WMI впало")
        finally:
            self.running = False
            self.progress = 1.0
            for f in (etl, xml_):
                try:
                    os.remove(f)
                except OSError:
                    pass
            try:
                os.rmdir(tmp)
            except OSError:
                pass

    def _parse(self, path):
        """
        Витягуємо з XML події з полями ClientProcessId / Operation / User.
        Ім'я поля може відрізнятись між версіями манифесту — беремо будь-яке,
        що містить «ClientProcessId».
        """
        by_pid = {}
        events = 0
        # tracerpt-XML буває великим — читаємо потоково
        for _, el in ET.iterparse(path, events=("end",)):
            tag = el.tag.rsplit("}", 1)[-1]
            if tag != "Event":
                continue
            data = {}
            for d in el.iter():
                dt = d.tag.rsplit("}", 1)[-1]
                if dt == "Data" and d.get("Name"):
                    data[d.get("Name")] = (d.text or "").strip()
            el.clear()
            pid = None
            for k, v in data.items():
                if "clientprocessid" in k.lower():
                    try:
                        pid = int(v)
                    except ValueError:
                        pid = None
                    break
            if pid is None:
                continue
            events += 1
            op = data.get("Operation") or data.get("operation") or ""
            ns = data.get("NamespaceName") or ""
            user = data.get("User") or ""
            e = by_pid.setdefault(pid, {"pid": pid, "count": 0, "ops": {}, "ns": ns,
                                        "user": user})
            e["count"] += 1
            if op:
                # прибираємо GUID-и й хеші, щоб однакові запити злипались
                key = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<id>", op, flags=re.I)[:160]
                e["ops"][key] = e["ops"].get(key, 0) + 1
        # імена процесів
        try:
            import psutil
        except Exception:
            psutil = None
        clients = []
        for e in by_pid.values():
            name, exe = f"(pid {e['pid']})", ""
            if psutil:
                try:
                    p = psutil.Process(e["pid"])
                    name = p.name()
                    exe = p.exe()
                except Exception:
                    name += " — уже завершився"
            top_ops = sorted(e["ops"].items(), key=lambda kv: -kv[1])[:4]
            clients.append({"pid": e["pid"], "name": name, "exe": exe, "count": e["count"],
                            "per_min": round(e["count"] / (self.seconds / 60.0), 1),
                            "ops": [{"op": o, "n": n} for o, n in top_ops],
                            "ns": e["ns"], "user": e["user"]})
        clients.sort(key=lambda c: -c["count"])
        hints = []
        if clients:
            top = clients[0]
            hints.append(f"Найактивніший клієнт WMI — {top['name']} ({top['per_min']} запитів/хв). "
                         "Якщо це фонова утиліта (MSI Center, ASUS, RGB-софт) — вимкни її "
                         "автозапуск: WMI-запити не безкоштовні, кожен крутить WmiPrvSE.")
            if any(c["name"].lower().startswith("python") or "pcmonitor" in c["name"].lower()
                   for c in clients[:3]):
                hints.append("Серед топ-клієнтів — сам монітор: датчики дисків і перевірки "
                             "здоров'я йдуть через WMI. Це разові запити, не постійний потік.")
        return {"seconds": self.seconds, "events": events, "clients": clients[:25],
                "hints": hints}
