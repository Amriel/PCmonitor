# PC Monitor

*[Українська версія →](README.uk.md)*

A local Windows resource monitor. Shows what every program consumes
(CPU, RAM, disk, network), keeps a full-day history — what ran, how much
it ate, what went online and where — highlights suspicious processes, and
exports a detailed per-app log **with one click** so you can hand it to
Claude for analysis.

Everything runs **locally**. Nothing is sent anywhere. Your data lives
next to the app in `data\` as a plain SQLite database.

> Interface language: Ukrainian.

---

## Quick start (3 steps)

1. **`install.bat`** — double-click. Installs the required Python packages.
   (No Python yet? Get it from python.org and tick **"Add python.exe to
   PATH"** on the first installer screen.)

2. **`run.bat`** — starts the monitor. An app window opens and collection
   begins.
   > Want full network stats (**exact bytes per app + the domains it
   > queried**)? Right-click `run.bat` → **"Run as administrator"**.
   > It works without admin too, just without exact per-app bytes.

3. From then on: **`open.bat`** opens the window any time, **`stop.bat`**
   stops collection.

To make the monitor **start with Windows**, right-click
**`autostart_enable.bat`** → "Run as administrator". Remove it with
`autostart_disable.bat`.

---

## A real app window, not "a site in a browser"

The monitor opens in a **native Windows window**: its own taskbar entry,
its own process, a normal title bar. Inside, the UI is rendered by
**WebView2** — the system component built into Windows 10/11 (the same one
that powers Settings, Mail, Teams).

There is also a **tray icon**: click to open the window, right-click for
the menu. Closing the window does not stop collection — the monitor keeps
working in the background. Technically it is a tiny local server bound to
`127.0.0.1` only — unreachable from the network.

---

## What it shows

**Day cards on top:** average/peak CPU, peak RAM, network in/out for the
day, disk read/write, how many programs were active, new executables,
suspicious ones.

**⚡ Now (live)** — a Task-Manager-style panel: **all** running programs
with CPU · Memory · Disk · Network · GPU · Processes columns, refreshed
every 2 seconds. Click a column header to sort, click a row for details.

Memory is counted the way Task Manager counts it (unique process memory,
USS), so the numbers match. GPU comes from the same Windows performance
counters Task Manager uses ("GPU Engine") — no admin, no drivers.

**Two charts:** CPU/RAM over the day; network sent/received over the day.

**"Apps per day" table** — the core. Per app: CPU time, CPU peak, RAM
peak, disk read/write, ↑sent/↓received, distinct IPs, domains, launch
count, suspicion score. Click a row for **details**: per-minute charts,
every launch (when, how long, which process spawned it), every IP and
domain it contacted.

**⚠ Attention panel** — appears only when something scored high, with
plain-language reasons.

**Event feed** — a timeline of what started and stopped, and a **day
picker** for any past day. Per-minute detail is kept ~3 weeks, daily
summaries for a year (both configurable).

---

## How "suspicious" scoring works

The monitor adds points for traits that often (not always!) indicate
something shady, and explains **why** in plain language:

- named like a system process (`svchost.exe`) but running from a
  non-system path — classic malware masquerade;
- runs from `Temp`, `Downloads`, `ProgramData`, a drive root, or the
  Recycle Bin;
- double extension (`report.pdf.exe`);
- digital signature missing or not matching the file;
- heavy outbound traffic / uploads far more than it downloads;
- dozens of distinct IPs or unusual ports;
- active at night; restarts frequently; first seen today.

**These are hints, not verdicts.** Known-good programs can score points
too — press **"✓ Trust"** and they leave the attention list.

---

## One-click log for analysis

Every table row has a **📤** button. Press it and the monitor writes a
**complete JSON report for that app** into `exports\`: the executable
(path, size, SHA-256, signature state), per-minute behaviour, every IP,
port and domain, every launch and exit, history for previous days, and
the suspicion reasons. Drop that file into a Claude chat and ask for an
analysis.

**"👁 Watch closely"** records raw 5-second samples for one app — useful
for catching short spikes.

---

## Security

- **Everything is local.** The server listens on `127.0.0.1` only.
  No cloud, no accounts, no telemetry.
- **Your data stays yours.** The database is `data\pcmon.sqlite3`,
  reports are in `exports\`. Delete those folders to erase history.
- **No drivers, no traffic interception.** The monitor only *reads* what
  Windows already produces: the process list (psutil) and built-in kernel
  events (ETW — the same mechanism Task Manager's app history uses).
- **Open code** — plain Python, no frameworks, no build step: the core in
  `monitor.py`, suspicion heuristics in `suspicion.py`, one module per
  concern for the rest.
- **Terminal commands** (off by default) run as the **regular user** even
  when the monitor is elevated; if dropping privileges fails, the command
  is refused rather than run elevated. Dangerous operations are
  block-listed.
- Process command lines are **not** logged by default (so passwords in
  arguments never reach the database). Enable via `log_cmdline` if needed.

## Footprint

Deliberately light: process polling every 5 s costs a fraction of a
percent of CPU; database writes are batched; the monitor runs at
below-normal CPU and low I/O priority; a typical day is a few megabytes;
old per-minute data prunes itself; charts render only while the window is
open.

---

## More tools inside

- **🌡 Temperatures** — GPU (NVML), drives (SMART), ACPI thermal zones —
  as a compact strip on the "Now" tab. No kernel driver, which is also
  why there is honestly no CPU temperature (the UI explains why).
- **⌨ Terminal** on the "Now" tab (after enabling it in Settings).
- **🩺 Health** — read-only checks of disks, drivers, startup entries,
  updates, event log; system latency measurement (DPC/ISR); clipboard
  diagnostics.
- **🚀 Startup manager** — what launches with Windows, toggled through the
  same official mechanism Task Manager uses.
- **Stream Deck** — a native plugin: metrics with mini-charts right on the
  keys (Settings → "Install plugin").
- **🔔 Notifications** (1.4.0) — standard Windows toasts from the tray while
  the window is closed: a new program talking to the network, a suspicion
  threshold crossed, a *busy loop* (one core burned for 30+ minutes by a
  loop without a sleep), memory pressure with the culprit named, a disk
  that is almost full or will fill up within days at the current trend,
  GPU/drive temperature, a new startup entry. Quiet hours, per-kind
  switches, everything also lands in the Events feed. No extra polling —
  the detectors run on data the monitor already collects.
- **📅 Week / month view** with a digest: core-hours vs. the previous
  period, biggest growers, new and vanished programs; CSV export.
- **🔍 Who is hammering WMI** — a one-off 30-second ETW trace naming the
  clients behind `WmiPrvSE.exe` CPU usage (admin required).
- **Live tray icon** (CPU/RAM bars) and a global hotkey to show the window.

---

## Building the exe and installer

Optional — everything works from `run.bat` as is. For an installable
program that does not need Python:

1. Install [Inno Setup 6](https://jrsoftware.org/isinfo.php).
2. Run **`build.bat`** — it installs PyInstaller, builds
   `dist\PCMonitor\PCMonitor.exe` and `dist\PCMonitor-Setup-X.Y.Z.exe`.
   Releases are built the same way by GitHub Actions
   (`.github/workflows/release.yml`) whenever a `vX.Y.Z` tag is pushed.
3. The installer is **per-user** (no admin required), installs to
   `%LocalAppData%\Programs\PC Monitor`, and **never touches** the
   database on update or uninstall.

**Updates.** The app checks this repository's GitHub Releases every few
hours (its only network call, disabled with one switch), downloads a
newer installer into `updates\` over HTTPS, and verifies it against the
`.sha256` file attached to the release. Installing takes one click in
Settings → "About" → "Check" — or fully automatically if you enable
"Install automatically". The offline path still works too: drop an
installer into `updates\` yourself (build.bat does this for you).

---

## Configuration (`config.json`)

| Key | What it does | Default |
|---|---|---|
| `sample_interval` | process polling period, s | 5 |
| `conn_poll_interval` | connection polling period, s | 10 |
| `flush_interval` | database write period, s | 30 |
| `dashboard_port` | local UI port | 8787 |
| `retention_minutes_days` | days of per-minute detail | 21 |
| `retention_days` | days of daily summaries / events | 365 |
| `etw_enabled` | exact network bytes + DNS (needs admin) | true |
| `sig_check` | verify signatures of new executables | true |
| `hash_new_exes` | SHA-256 new executables | true |
| `log_cmdline` | log process command lines | false |
| `suspicion.*` | heuristic thresholds | see file |
| `retention_conn_days` | days of connection / process-launch history | 60 |
| `notify.*` | notification switches, quiet hours, thresholds | see Settings |
| `tray_live` | CPU/RAM bars on the tray icon | true |
| `hotkey` | global hotkey to show the window | ctrl+shift+m |

## Troubleshooting

- **Port already in use** — change `dashboard_port` in `config.json`.
- **Lots of system processes in the list** — that's normal; sort by CPU
  time, use search, and "✓ Trust" the programs you know.

## License

MIT — see [LICENSE](LICENSE). Bundled [Chart.js](https://www.chartjs.org)
is also MIT-licensed.
