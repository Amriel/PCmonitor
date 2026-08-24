# -*- coding: utf-8 -*-
"""
PC Monitor — ETW-збирач: точні байти мережі по процесах + DNS-запити.

Використовує штатний механізм Windows — Event Tracing for Windows:
  * Microsoft-Windows-Kernel-Network  {7DD42A49-5329-4832-8DFD-43D979153A88}
      TCPv4: 10 (надіслано) / 11 (отримано); TCPv6: 26/27
      UDPv4: 42/43;  UDPv6: 58/59
      Поля: PID, size, saddr/daddr, sport/dport
  * Microsoft-Windows-DNS-Client      {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
      3008 — завершений DNS-запит (QueryName, QueryResults), PID у заголовку події

Потрібні права адміністратора. Якщо їх нема або бібліотека pywintrace
недоступна — монітор просто працює без цієї частини (fallback, не помилка).

Це пасивне читання подій, які ядро генерує і так; жодних драйверів чи
перехоплення трафіку. Колбеки максимально легкі: інкремент лічильників.
"""
import sys
import time
import logging

log = logging.getLogger("pcmon.etw")

KERNEL_NET_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
DNS_CLIENT_GUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"

SEND_IDS = {10, 26, 42, 58}   # надіслано (TCP v4/v6, UDP v4/v6)
RECV_IDS = {11, 27, 43, 59}   # отримано
DNS_DONE = 3008
ALL_IDS = sorted(SEND_IDS | RECV_IDS | {DNS_DONE})


def _to_int(v, default=-1):
    try:
        if isinstance(v, str):
            v = v.strip()
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        return int(v)
    except Exception:
        return default


class EtwNet:
    """
    on_bytes(pid:int, sent:int, recv:int)  — викликається на кожну подію (агрегуй сам)
    on_dns(pid:int, domain:str)            — на кожен завершений DNS-запит
    """

    def __init__(self, on_bytes, on_dns=None, session_name="PCMonitorETW"):
        self.on_bytes = on_bytes
        self.on_dns = on_dns
        self.session_name = session_name
        self.job = None
        self.status = "не запущено"
        self.events_seen = 0
        self.errors = 0

    # ---- внутрішнє -------------------------------------------------------
    def _callback(self, event):
        try:
            eid, data = event
            if eid == DNS_DONE:
                if not self.on_dns:
                    return
                qname = data.get("QueryName") or data.get("QueryNameString") or ""
                if not qname or qname.endswith(".local") or qname.endswith(".arpa"):
                    return
                pid = -1
                hdr = data.get("EventHeader")
                if isinstance(hdr, dict):
                    pid = _to_int(hdr.get("ProcessId"), -1)
                if pid < 0:
                    pid = _to_int(data.get("ProcessId") or data.get("PID"), -1)
                self.events_seen += 1
                self.on_dns(pid, str(qname).rstrip("."))
                return
            if eid in SEND_IDS or eid in RECV_IDS:
                pid = _to_int(data.get("PID") or data.get("pid"), -1)
                size = _to_int(data.get("size") or data.get("Size"), 0)
                if pid <= 0 or size <= 0:
                    return
                self.events_seen += 1
                if eid in SEND_IDS:
                    self.on_bytes(pid, size, 0)
                else:
                    self.on_bytes(pid, 0, size)
        except Exception:
            self.errors += 1
            if self.errors < 20:
                log.exception("Помилка в ETW-колбеку")

    # ---- публічне --------------------------------------------------------
    def start(self):
        if sys.platform != "win32":
            self.status = "недоступно: не Windows"
            return False
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.status = "вимкнено: потрібні права адміністратора"
                log.warning("ETW не запущено — немає прав адміністратора. "
                            "Мережа по процесах буде без точних байтів.")
                return False
        except Exception:
            pass
        try:
            import etw  # pywintrace
        except Exception as e:
            self.status = "вимкнено: немає pywintrace (pip install pywintrace)"
            log.warning("pywintrace недоступний: %s", e)
            return False
        try:
            providers = [
                etw.ProviderInfo("pcmon-kernel-net", etw.GUID(KERNEL_NET_GUID)),
            ]
            if self.on_dns:
                providers.append(etw.ProviderInfo("pcmon-dns", etw.GUID(DNS_CLIENT_GUID)))
            self.job = etw.ETW(
                session_name=self.session_name,
                providers=providers,
                event_callback=self._callback,
                event_id_filters=ALL_IDS,
            )
            self.job.start()
            self.status = "активний"
            log.info("ETW-сесію запущено (%s)", self.session_name)
            return True
        except Exception as e:
            # Можливо, лишилася стара сесія після аварійного завершення — спробуємо перестворити
            try:
                self._force_stop_session()
                time.sleep(0.5)
                self.job.start()
                self.status = "активний (після перезапуску сесії)"
                return True
            except Exception:
                pass
            self.status = f"помилка запуску: {e}"
            log.warning("ETW не запустився: %s", e)
            self.job = None
            return False

    def _force_stop_session(self):
        """Зупинити «осиротілу» сесію з таким самим імʼям (logman stop)."""
        import subprocess
        subprocess.run(["logman", "stop", self.session_name, "-ets"],
                       capture_output=True, timeout=10)

    def stop(self):
        if self.job is not None:
            try:
                self.job.stop()
            except Exception:
                pass
            self.job = None
        self.status = "зупинено"
