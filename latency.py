# -*- coding: utf-8 -*-
"""
PC Monitor — вимірювання затримок системи з пошуком винуватця.

ЩО ЦЕ ТАКЕ
Коли клацає звук, підвисає мишка чи гра «стрибає» при рівному FPS — винен
зазвичай не брак потужності, а те, що щось надовго захопило процесор і не
віддавало. Windows у цей момент не встигає обслужити звук чи ввід.

ЯК ШУКАЄМО ВИНУВАТЦЯ (без встановлення драйвера)
Замір іде у два потоки одночасно:

1. ВИМІРЮВАЧ. Потік із високим пріоритетом просить розбудити його рівно через
   1 мс і засікає, наскільки Windows запізнилась. Кожне запізнення понад поріг
   записується з точним часом — це «шпичка».

2. СЛІДЧИЙ. Паралельно, 5 разів на секунду, знімається зріз системи:
   скільки процесорного часу з'їв кожен процес за цей проміжок, і головне —
   штатні лічильники Windows «% DPC Time» та «% Interrupt Time», тобто частка
   часу, витрачена на обслуговування ДРАЙВЕРІВ.

Після заміру зіставляємо: у моменти шпичок навантаження було драйверне чи
програмне? І які саме процеси були активні саме тоді, а не взагалі.

Це дає відповідь на питання «хто винен» у двох площинах:
   • високий DPC/ISR під час шпичок  -> винен ДРАЙВЕР (програми закривати марно)
   • конкретний процес активний саме в моменти шпичок -> винна ПРОГРАМА

Чесне обмеження: назвати драйвер поіменно (умовно «nvlddmkm.sys») без власного
драйвера в ядрі неможливо — саме для цього LatencyMon ставить свій. Тут ми
кажемо «винні драйвери, а не програми» і підказуємо, які пристрої вимикати по
черзі, щоб знайти конкретний.
"""
import logging
import statistics
import sys
import threading
import time

log = logging.getLogger("pcmon.latency")

IS_WIN = sys.platform == "win32"

# Пороги в мікросекундах (практика роботи зі звуком):
# до ~500 мкс усе добре; понад 1000 можливі клацання; понад 2000 — точно чути.
GOOD_US = 500
WARN_US = 1000
BAD_US = 2000

SPIKE_US = 1000          # від якого запізнення вважаємо це «шпичкою»
SNAP_INTERVAL = 0.2      # як часто слідчий знімає зріз системи, с


class LatencyTest:
    def __init__(self, seconds=20):
        self.seconds = max(5, min(300, int(seconds)))
        self.running = False
        self.started_at = 0
        self.progress = 0.0
        self.result_data = None
        self.error = None
        self.spikes = []          # (час, мкс)
        self._snaps = []          # зрізи системи
        self._lock = threading.Lock()
        self._threads = []

    # ------------------------------------------------------------ запуск --
    def start(self):
        if self.running:
            return False
        self.running = True
        self.started_at = time.time()
        self.progress = 0.0
        self.spikes = []
        self._snaps = []
        t1 = threading.Thread(target=self._measure, name="lat-measure", daemon=True)
        t2 = threading.Thread(target=self._investigate, name="lat-probe", daemon=True)
        self._threads = [t1, t2]
        t1.start()
        t2.start()
        threading.Thread(target=self._finish, name="lat-finish", daemon=True).start()
        return True

    def stop(self):
        self.running = False

    def _finish(self):
        for t in self._threads:
            t.join()
        try:
            self.result_data = self._analyze()
        except Exception as e:
            self.error = str(e)
            log.exception("Помилка розбору результатів")
        self.running = False
        self.progress = 1.0

    # ------------------------------------------------- потік 1: вимірювач --
    def _measure(self):
        winmm = None
        boosted = False
        old_nice = None
        try:
            if IS_WIN:
                try:
                    import ctypes
                    winmm = ctypes.WinDLL("winmm")
                    if winmm.timeBeginPeriod(1) == 0:
                        boosted = True
                except Exception:
                    pass
            try:
                import psutil
                p = psutil.Process()
                old_nice = p.nice()
                if IS_WIN:
                    p.nice(psutil.HIGH_PRIORITY_CLASS)
            except Exception:
                pass
            if IS_WIN:
                try:
                    import ctypes
                    k32 = ctypes.windll.kernel32
                    k32.SetThreadPriority(k32.GetCurrentThread(), 15)  # TIME_CRITICAL
                except Exception:
                    pass

            perf = time.perf_counter
            t_end = time.time() + self.seconds
            interval = 0.001
            samples = []
            spikes = []
            nxt = perf() + interval

            while self.running and time.time() < t_end:
                delay = nxt - perf()
                if delay > 0.0004:
                    time.sleep(delay - 0.0003)
                while perf() < nxt:
                    pass
                after = perf()
                late_us = max(0.0, (after - nxt) * 1_000_000.0)
                samples.append(late_us)
                if late_us >= SPIKE_US:
                    spikes.append((time.time(), round(late_us, 1)))
                    if len(spikes) > 4000:
                        del spikes[:1000]
                nxt += interval
                if nxt < perf():
                    nxt = perf() + interval
                self.progress = min(0.99, 1 - (t_end - time.time()) / self.seconds)

            self._samples = samples
            with self._lock:
                self.spikes = spikes
        except Exception as e:
            self.error = str(e)
            log.exception("Помилка вимірювання")
            self._samples = []
        finally:
            self.running = False
            try:
                import psutil
                if old_nice is not None:
                    psutil.Process().nice(old_nice)
            except Exception:
                pass
            if boosted and winmm is not None:
                try:
                    winmm.timeEndPeriod(1)
                except Exception:
                    pass

    # -------------------------------------------------- потік 2: слідчий --
    def _investigate(self):
        """Зрізи системи, щоб потім зіставити їх зі шпичками."""
        counters = None
        try:
            from pdh import Counters, LATENCY_COUNTERS
            counters = Counters(LATENCY_COUNTERS)
            if not counters.start():
                counters = None
        except Exception:
            counters = None

        try:
            import psutil
        except Exception:
            return

        prev = {}
        prev_t = time.perf_counter()
        # прайм
        for p in psutil.process_iter(["pid", "name", "cpu_times"]):
            ct = p.info.get("cpu_times")
            if ct:
                prev[p.info["pid"]] = (p.info.get("name") or "?", ct.user + ct.system)

        while self.running:
            time.sleep(SNAP_INTERVAL)
            t0 = prev_t
            t1 = time.perf_counter()
            dt = max(1e-6, t1 - t0)
            prev_t = t1

            cur = {}
            procs = {}
            try:
                for p in psutil.process_iter(["pid", "name", "cpu_times"]):
                    pid = p.info["pid"]
                    ct = p.info.get("cpu_times")
                    if not ct:
                        continue
                    busy = ct.user + ct.system
                    nm = (p.info.get("name") or "?").lower()
                    cur[pid] = (nm, busy)
                    old = prev.get(pid)
                    if old and old[0] == nm:
                        d = busy - old[1]
                        if d > 0.0005:
                            procs[nm] = procs.get(nm, 0.0) + d
            except Exception:
                pass
            prev = cur

            c = counters.read() if counters else {}
            snap = {
                "t0": time.time() - dt, "t1": time.time(), "dt": dt,
                "procs": procs,
                "dpc": c.get("dpc"), "isr": c.get("isr"),
                "queue": c.get("queue"), "cswitch": c.get("cswitch"),
                "dpc_rate": c.get("dpc_rate"), "interrupts": c.get("interrupts"),
            }
            with self._lock:
                self._snaps.append(snap)

        if counters:
            counters.stop()

    # ------------------------------------------------------------- розбір --
    def _analyze(self):
        s = getattr(self, "_samples", []) or []
        if not s:
            return {"error": "не вдалося зібрати заміри"}
        s_sorted = sorted(s)
        n = len(s_sorted)

        def pct(p):
            return s_sorted[min(n - 1, int(n * p))]

        mx = s_sorted[-1]
        over = {k: sum(1 for x in s if x >= v)
                for k, v in (("500", 500), ("1000", 1000), ("2000", 2000), ("10000", 10000))}

        buckets = [0, 100, 250, 500, 1000, 2000, 5000, 10000, 10**9]
        hist = [{"from": buckets[i], "to": (buckets[i + 1] if buckets[i + 1] < 10**9 else None),
                 "n": sum(1 for x in s if buckets[i] <= x < buckets[i + 1])}
                for i in range(len(buckets) - 1)]

        with self._lock:
            spikes = list(self.spikes)
            snaps = list(self._snaps)

        attribution = self._attribute(spikes, snaps)

        level, verdict, summary = self._verdict(mx, attribution)

        return {
            "samples": n, "seconds": round(self.seconds, 1),
            "min_us": round(s_sorted[0], 1), "avg_us": round(statistics.fmean(s), 1),
            "p50_us": round(pct(0.50), 1), "p95_us": round(pct(0.95), 1),
            "p99_us": round(pct(0.99), 1), "max_us": round(mx, 1),
            "over": over, "hist": hist,
            "spike_count": len(spikes),
            "worst": sorted(spikes, key=lambda x: -x[1])[:20],
            "verdict": verdict, "level": level, "summary": summary,
            "attribution": attribution,
            "hints": _hints(level, attribution, over),
        }

    def _attribute(self, spikes, snaps):
        """Зіставити шпички зі зрізами системи й знайти винуватця."""
        out = {"available": bool(snaps), "counters": False,
               "spike_windows": 0, "calm_windows": 0,
               "processes": [], "dpc": None, "verdict_kind": None}
        if not snaps:
            return out

        out["counters"] = any(sn.get("dpc") is not None for sn in snaps)

        spike_times = [t for t, _ in spikes]
        st_i = 0
        spike_snaps, calm_snaps = [], []
        for sn in snaps:
            # чи потрапила хоч одна шпичка у вікно цього зрізу
            hit = False
            for t in spike_times:
                if sn["t0"] - 0.05 <= t <= sn["t1"] + 0.05:
                    hit = True
                    break
            (spike_snaps if hit else calm_snaps).append(sn)

        out["spike_windows"] = len(spike_snaps)
        out["calm_windows"] = len(calm_snaps)
        if not spike_snaps:
            return out

        def avg(rows, key):
            vals = [r[key] for r in rows if r.get(key) is not None]
            return round(statistics.fmean(vals), 2) if vals else None

        if out["counters"]:
            out["dpc"] = {
                "spike": {"dpc": avg(spike_snaps, "dpc"), "isr": avg(spike_snaps, "isr"),
                          "queue": avg(spike_snaps, "queue")},
                "calm": {"dpc": avg(calm_snaps, "dpc"), "isr": avg(calm_snaps, "isr"),
                         "queue": avg(calm_snaps, "queue")},
                "dpc_rate": avg(snaps, "dpc_rate"),
                "interrupts": avg(snaps, "interrupts"),
            }

        # процеси: скільки ядер вони їли під час шпичок і в спокої
        def rate(rows):
            tot = {}
            secs = sum(r["dt"] for r in rows) or 1e-6
            for r in rows:
                for nm, d in r["procs"].items():
                    tot[nm] = tot.get(nm, 0.0) + d
            return {nm: v / secs for nm, v in tot.items()}, secs

        sp_rate, sp_secs = rate(spike_snaps)
        cl_rate, _ = rate(calm_snaps) if calm_snaps else ({}, 0)

        rows = []
        for nm, r in sp_rate.items():
            c = cl_rate.get(nm, 0.0)
            rows.append({"name": nm, "spike": round(r, 3), "calm": round(c, 3),
                         "delta": round(r - c, 3)})
        rows.sort(key=lambda x: -x["delta"])
        out["processes"] = [r for r in rows if r["delta"] > 0.01][:12]

        # який вид проблеми
        d = out.get("dpc")
        if d and d["spike"]["dpc"] is not None:
            drv = (d["spike"]["dpc"] or 0) + (d["spike"]["isr"] or 0)
            calm_drv = (d["calm"]["dpc"] or 0) + (d["calm"]["isr"] or 0)
            if drv >= 5 or (drv >= 2 and drv > calm_drv * 2):
                out["verdict_kind"] = "driver"
            elif out["processes"] and out["processes"][0]["delta"] >= 0.25:
                out["verdict_kind"] = "process"
            elif (d["spike"]["queue"] or 0) >= 4:
                out["verdict_kind"] = "overload"
            else:
                out["verdict_kind"] = "unclear"
        elif out["processes"] and out["processes"][0]["delta"] >= 0.25:
            out["verdict_kind"] = "process"
        else:
            out["verdict_kind"] = "unclear"
        return out

    def _verdict(self, mx, attr):
        kind = attr.get("verdict_kind")
        top = (attr.get("processes") or [None])[0]
        if mx < GOOD_US:
            return "good", "Відмінно", ("Система відповідає вчасно. Для звуку, "
                                        "запису й ігор перешкод нема.")
        if mx < WARN_US:
            return "good", "Добре", ("Дрібні затримки є, але вони нижчі за поріг, "
                                     "на якому з'являються клацання.")
        base = ("Помірні затримки" if mx < BAD_US else "Великі затримки")
        lvl = "warn" if mx < BAD_US else "bad"
        if kind == "driver":
            d = attr["dpc"]["spike"]
            return lvl, base + " — винні драйвери", (
                f"У моменти затримок процесор витрачав {d['dpc']:.1f}% на відкладені "
                f"виклики драйверів і {d['isr']:.1f}% на переривання. Це робота "
                "ДРАЙВЕРІВ, а не програм — закривати застосунки марно.")
        if kind == "process" and top:
            return lvl, base + f" — схоже на «{top['name']}»", (
                f"Саме в моменти затримок ця програма з'їдала на {top['delta']:.2f} ядра "
                "більше, ніж у спокійні проміжки. Це найімовірніший винуватець.")
        if kind == "overload":
            return lvl, base + " — система перевантажена", (
                "У моменти затримок до процесора стояла велика черга потоків. "
                "Система просто не встигає — забагато роботи одночасно.")
        return lvl, base, ("Система інколи «завмирає» надовго. Однозначного "
                           "винуватця не видно — спробуй довший замір або "
                           "повтори в момент, коли проблема відчувається.")

    # ------------------------------------------------------------- статус --
    def status(self):
        return {
            "running": self.running,
            "progress": round(self.progress, 3),
            "seconds": self.seconds,
            "elapsed": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "error": self.error,
            "result": self.result_data,
        }


def _hints(level, attr, over):
    if level == "good":
        return []
    kind = attr.get("verdict_kind")
    h = []
    if kind == "driver":
        h += [
            "Винен драйвер. Вимикай по черзі й повторюй замір: Wi-Fi, Bluetooth, "
            "зовнішні USB-пристрої, віртуальні мережеві адаптери (VirtualBox, "
            "VMware, Hyper-V, WSL).",
            "Найчастіші винуватці: мережеві драйвери (особливо Wi-Fi та Killer), "
            "звукові карти, панелі керування відеокарт, утиліти RGB-підсвітки.",
            "Онови драйвери чипсета й мережі з сайту виробника материнської плати "
            "чи ноутбука — саме з сайту, а не через «Диспетчер пристроїв».",
        ]
    elif kind == "process":
        top = (attr.get("processes") or [{}])[0].get("name", "")
        h += [
            f"Спробуй закрити «{top}» і повторити замір — якщо затримки зникнуть, "
            "винуватця знайдено.",
            "Якщо програма потрібна, спробуй знизити їй пріоритет у Диспетчері "
            "задач або обмежити її фонову активність у налаштуваннях.",
        ]
    elif kind == "overload":
        h += ["Закрий частину програм і повтори замір — зараз система просто "
              "не встигає обслуговувати всіх."]
    else:
        h += [
            "Зроби довший замір (1–3 хвилини) — рідкісні шпички так видно краще.",
            "Найкраще міряти саме в момент, коли проблема відчувається: під час "
            "запису звуку, у грі, при копіюванні великих файлів.",
        ]
    if over.get("10000"):
        h.insert(0, "Були затримки понад 10 мс — це дуже багато. Майже завжди "
                    "це старий або конфліктний драйвер.")
    if not attr.get("counters") and sys.platform == "win32":
        h.append("Лічильники DPC/ISR не читались, тому поділ «драйвер проти "
                 "програми» неточний. Спробуй запустити монітор від адміністратора.")
    return h
