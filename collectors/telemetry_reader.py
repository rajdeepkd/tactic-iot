#!/usr/bin/env python3
"""
Real device-telemetry sampler for the Objective-3 physical testbed.
Runs on each node as an always-on systemd service (never started/stopped per
attack -- Charter principle #1, anti-sessionization).

WHAT IT COLLECTS (every row tagged: device_id + config_id + session_id + boot_id +
dual clock ts_realtime_ns / ts_mono_ns for cross-device alignment):
  * Behavioural host metrics (the P5/P6 "class-dominated", transferable signal):
    CPU user/system/iowait/irq %, context switches/s, interrupts/s, forks/s,
    procs_running, procs_blocked, plus load1/5/15, mem, net/disk I/O.
  * Thermal: EVERY /sys/class/thermal zone keyed by its `type` name
    (CPU-therm, GPU-therm, AO-therm, ...), not just the hottest zone.
  * REAL power (the signal TON_IoT / CIC-YNU faked -- see P5):
      - RPi 3B+/5 : INA219 or INA260 on the I2C GPIO header, high-side on the
                    5 V input rail  (--power ina219|ina260)
      - Jetson Nano: onboard INA3221 via sysfs, tegrastats fallback (--power jetson)
      - where inline sensing is impractical: a LOCAL-API smart plug
                    (Shelly Gen2 RPC / TP-Link Kasa emeter)  (--power shelly|kasa)
    Power is sampled in a background thread at --power-hz and aggregated into each
    1 Hz row (mean/max/p95/std) so short sshd/loader blips are not averaged away.
  * Board health that CONFOUNDS the physical side-channel and must be recorded:
    RPi vcgencmd throttle/undervolt bitmask + ARM freq + core volts + fan RPM;
    Jetson nvpmodel / GPU freq.

P5 ANTI-FINGERPRINT CONTROLS (the point of this file):
  telemetry on the emulated dataset was ~93 % an architecture/VM-image fingerprint.
  To stop the physical testbed learning "device" instead of "behaviour":
   (1) run `provision_node.sh` first  -> identical governor, stripped/identical
       daemon set, UTC, I2C on, same collector version on every board;
   (2) `--emit-config` writes a per-device config MANIFEST (RAM, kernel, governor,
       freq caps, baseline process set, power method, chrony offset, ...) and a
       short `config_id` stamped into EVERY telemetry row, so architecture/config
       is a RECORDED, controlled nuisance -- never a hidden shortcut;
   (3) the same always-on reader records the per-device BENIGN BASELINE in the SAME
       campaign (orchestrator writes attack_type=benign_baseline to labels.csv over
       a continuous idle+benign-load block; the reader does not stop), so analysis
       can baseline-normalise per device and run the P5 "predict device from benign
       telemetry" confound probe.

Prefers psutil; falls back to /proc + /sys so it runs on a minimal image
(Raspberry Pi OS Lite, JetPack/L4T, Mendel). Power backends use smbus2 / urllib
(stdlib) -- no Adafruit Blinka stack required.

Usage:
  # one-off: write this session's device config manifest
  python3 telemetry_reader.py --emit-config --out /var/log/testbed/telemetry \
          --session 2026-10-01_run1 --power ina260 --shunt 0.002

  # the always-on service (reads the manifest above; stamps its config_id)
  python3 telemetry_reader.py --out /var/log/testbed/telemetry --hz 1 \
          --session 2026-10-01_run1 --power ina260 --shunt 0.002 --power-hz 10
"""
import argparse, csv, os, socket, time, glob, json, hashlib, threading, subprocess, re
from datetime import datetime, timezone

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

try:
    import smbus2
    HAVE_SMBUS = True
except Exception:
    HAVE_SMBUS = False

DEVICE_ID = socket.gethostname()
COLLECTOR_VERSION = "2.0"


def boot_id():
    # Per-boot UUID: makes CLOCK_MONOTONIC globally meaningful (mono resets to
    # ~0 each boot). (boot_id, ts_mono_ns) is unambiguous across reboots; the
    # alignment pipeline keys monotonic reasoning on this. Empty on non-Linux.
    try:
        return open("/proc/sys/kernel/random/boot_id").read().strip()
    except OSError:
        return ""


BOOT_ID = boot_id()


# --------------------------------------------------------------------------- #
#  small helpers
# --------------------------------------------------------------------------- #
def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _read_int(path):
    v = _read(path)
    try:
        return int(v)
    except Exception:
        return None


def _sh(cmd):
    """Run a short command, return stdout str or None. Never raises."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
        return out.decode("utf-8", "replace").strip()
    except Exception:
        return None


def loadavg():
    try:
        return os.getloadavg()  # (1,5,15)
    except Exception:
        return (None, None, None)


def _sanitize(name):
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()


def clocks_ns():
    """Synced wall clock + monotonic, in ns. REALTIME = cross-device common axis;
       MONOTONIC never steps -> within-device anchor + REALTIME-jump detector."""
    try:
        return (time.clock_gettime_ns(time.CLOCK_REALTIME),
                time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    except AttributeError:  # <py3.7
        return (int(time.time() * 1e9), int(time.monotonic() * 1e9))


# --------------------------------------------------------------------------- #
#  thermal: every zone by name  (Pi has 1; Jetson has AO/CPU/GPU/PMIC/...)
# --------------------------------------------------------------------------- #
def thermal_zones():
    """Return {temp_<zonetype>_c: value} for every thermal zone (+ temp_c=max)."""
    out = {}
    hottest = None
    for tpath in sorted(glob.glob("/sys/class/thermal/thermal_zone*/temp")):
        zdir = os.path.dirname(tpath)
        raw = _read_int(tpath)
        if raw is None:
            continue
        c = raw / 1000.0 if raw > 1000 else float(raw)
        ztype = _read(os.path.join(zdir, "type")) or os.path.basename(zdir)
        out["temp_%s_c" % _sanitize(ztype)] = round(c, 2)
        hottest = c if hottest is None else max(hottest, c)
    out["temp_c"] = round(hottest, 2) if hottest is not None else None  # back-compat
    return out


# --------------------------------------------------------------------------- #
#  behavioural counters from /proc/stat  (the transferable, class-dominated signal)
#  P5/P6: CPU system-time, interrupts, forks are among the FEW arch-independent,
#  behaviour-carrying features -- capture them explicitly.
# --------------------------------------------------------------------------- #
def _proc_stat():
    d = {"cpu": None, "intr": None, "ctxt": None, "processes": None,
         "procs_running": None, "procs_blocked": None}
    txt = _read("/proc/stat")
    if not txt:
        return d
    for line in txt.splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] == "cpu":
            d["cpu"] = [int(x) for x in p[1:]]  # user nice sys idle iowait irq softirq steal...
        elif p[0] in ("intr", "ctxt", "processes", "procs_running", "procs_blocked"):
            try:
                d[p[0]] = int(p[1])
            except Exception:
                pass
    return d


def cpu_breakdown(prev, cur, dt):
    row = {"cpu_user_pct": None, "cpu_sys_pct": None, "cpu_iowait_pct": None,
           "cpu_irq_pct": None, "intr_per_s": None, "ctxt_per_s": None,
           "forks_per_s": None, "procs_running": cur.get("procs_running"),
           "procs_blocked": cur.get("procs_blocked")}
    if prev and prev.get("cpu") and cur.get("cpu"):
        pc, cc = prev["cpu"], cur["cpu"]
        n = min(len(pc), len(cc))
        delta = [cc[i] - pc[i] for i in range(n)]
        tot = sum(delta) or 1
        def pct(i):
            return round(100.0 * delta[i] / tot, 2) if i < n else None
        row["cpu_user_pct"] = pct(0)
        row["cpu_sys_pct"] = pct(2)
        row["cpu_iowait_pct"] = pct(4)
        irq = (delta[5] if n > 5 else 0) + (delta[6] if n > 6 else 0)
        row["cpu_irq_pct"] = round(100.0 * irq / tot, 2)
    if prev and dt > 0:
        for k, out in (("intr", "intr_per_s"), ("ctxt", "ctxt_per_s"),
                       ("processes", "forks_per_s")):
            if prev.get(k) is not None and cur.get(k) is not None:
                row[out] = round((cur[k] - prev[k]) / dt, 1)
    return row


# --------------------------------------------------------------------------- #
#  C3 (dossier): COLLECTOR-APPARATUS LOAD as a RECORDED, controllable nuisance.
#  The measurement apparatus itself (pcap capture, auditd, journald, this reader)
#  burns CPU, and that load tracks attack intensity (capture spikes under ddos /
#  exfil). If the model learns "capture busy -> attack", part of that is an
#  extractor artifact, not victim behaviour. So we measure the apparatus' own
#  CPU/RSS each second and emit it as tel__col_* window features -> analysis can
#  control for it and show it is not the separator. The victim's IoT service
#  daemons (mosquitto/snmpd/coap_server/modbus_server/mediamtx/ffmpeg) are REAL
#  victim behaviour, not apparatus, so they are deliberately NOT counted here.
# --------------------------------------------------------------------------- #
def _clk_tck():
    try:
        return os.sysconf("SC_CLK_TCK") or 100
    except Exception:
        return 100


CLK_TCK = _clk_tck()
PAGE_KB = 4  # arm64 / x86 default page = 4 KiB (rss in /proc/stat is in pages)
SELF_PID = os.getpid()
_prev_coll_jiffies = {}


def _proc_cmdline(pid):
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _is_collector(pid, comm, cl):
    """True for measurement apparatus only. Returns (is_coll, is_capture)."""
    if pid == str(SELF_PID) or "telemetry_reader" in cl:
        return True, False
    is_cap = comm in ("tcpdump", "dumpcap") or cl.startswith("tcpdump") or " tcpdump" in cl
    if is_cap:
        return True, True
    if comm in ("auditd",) or comm.startswith("audisp") or comm in ("systemd-journal", "systemd-journald"):
        return True, False
    return False, False


def collector_load(dt):
    """Aggregate CPU%/RSS of the collector apparatus over the last dt seconds."""
    global _prev_coll_jiffies
    cur, total_j, cap_j, rss_kb, n = {}, 0, 0, 0, 0
    for d in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(d)
        comm = _read("/proc/%s/comm" % pid) or ""
        cl = _proc_cmdline(pid)
        is_coll, is_cap = _is_collector(pid, comm, cl)
        if not is_coll:
            continue
        st = _read("/proc/%s/stat" % pid)
        if not st:
            continue
        try:
            rest = st[st.rfind(")") + 1:].split()   # fields AFTER comm (field 3 onward)
            utime, stime, rss_pages = int(rest[11]), int(rest[12]), int(rest[21])
        except Exception:
            continue
        j = utime + stime
        cur[pid] = j
        n += 1
        rss_kb += rss_pages * PAGE_KB
        prev = _prev_coll_jiffies.get(pid)
        if prev is not None and dt > 0:
            dj = j - prev
            if dj >= 0:
                total_j += dj
                if is_cap:
                    cap_j += dj
    _prev_coll_jiffies = cur
    out = {"col_cpu_pct": None, "col_cap_cpu_pct": None,
           "col_rss_mb": round(rss_kb / 1024.0, 1), "col_n": n}
    if dt > 0:
        out["col_cpu_pct"] = round(100.0 * (total_j / CLK_TCK) / dt, 2)
        out["col_cap_cpu_pct"] = round(100.0 * (cap_j / CLK_TCK) / dt, 2)
    return out


# --------------------------------------------------------------------------- #
#  POWER BACKENDS  (defensive collectors only)
# --------------------------------------------------------------------------- #
class InaI2C(object):
    """INA219 / INA260 over I2C via smbus2 (no Blinka).
       INA219: bus-voltage + shunt-voltage regs, current = Vshunt / R_shunt
               (calibration-register-free; robust). Big-endian words.
       INA260: integrated 2 mOhm shunt, direct V/I/P registers."""
    def __init__(self, model, bus=1, addr=0x40, shunt_ohms=0.1):
        self.model = model
        self.addr = addr
        self.shunt = shunt_ohms
        self.bus = smbus2.SMBus(bus)

    def _rd(self, reg, signed=False):
        raw = self.bus.read_word_data(self.addr, reg)
        raw = ((raw << 8) & 0xFF00) | (raw >> 8)  # SMBus LE -> INA BE
        if signed and raw > 0x7FFF:
            raw -= 0x10000
        return raw

    def read(self):
        try:
            if self.model == "ina260":
                cur_ma = self._rd(0x01, signed=True) * 1.25   # 1.25 mA/LSB
                bus_v = self._rd(0x02) * 0.00125              # 1.25 mV/LSB
                p_mw = self._rd(0x03) * 10.0                  # 10 mW/LSB
            else:  # ina219, calibration-free path
                bus_v = (self._rd(0x02) >> 3) * 0.004         # 4 mV/LSB
                shunt_v = self._rd(0x01, signed=True) * 1e-5  # 10 uV/LSB
                cur_a = shunt_v / self.shunt if self.shunt else 0.0
                cur_ma = cur_a * 1000.0
                p_mw = bus_v * cur_a * 1000.0
            return (p_mw, bus_v, cur_ma)
        except Exception:
            return None


class JetsonPower(object):
    """Jetson Nano onboard INA3221 via sysfs (in_power0_input = POM_5V_IN, mW).
       Path varies by L4T; discovered once and recorded in the config manifest.
       tegrastats is the portable fallback (parses 'POM_5V_IN <inst>/<avg>')."""
    def __init__(self):
        self.path = None
        for pat in ("/sys/bus/i2c/drivers/ina3221x/*/iio:device*/in_power0_input",
                    "/sys/bus/i2c/drivers/ina3221/*/hwmon/*/in0_input",
                    "/sys/class/hwmon/*/power1_input"):
            hits = glob.glob(pat)
            if hits:
                self.path = hits[0]
                break
        self._teg = None

    def _from_tegrastats(self):
        if self._teg is None:
            try:
                self._teg = subprocess.Popen(
                    ["tegrastats", "--interval", "1000"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            except Exception:
                self._teg = False
        if not self._teg:
            return None
        try:
            line = self._teg.stdout.readline().decode("utf-8", "replace")
            m = re.search(r"POM_5V_IN\s+(\d+)/(\d+)", line)
            if m:
                return (float(m.group(1)), None, None)  # instantaneous mW
        except Exception:
            pass
        return None

    def read(self):
        if self.path:
            mw = _read_int(self.path)
            if mw is not None:
                return (float(mw), None, None)
        return self._from_tegrastats()


class PlugPower(object):
    """Local-API smart plug (AC-side W incl. PSU loss -- record method as metadata).
       shelly: Shelly Gen2 RPC over HTTP (pure stdlib). kasa: TP-Link via python-kasa."""
    def __init__(self, kind, host):
        self.kind = kind
        self.host = host
        self._kasa = None
        if kind == "kasa":
            try:
                import asyncio
                from kasa import SmartPlug
                self._asyncio = asyncio
                self._plug = SmartPlug(host)
            except Exception:
                self._kasa = False

    def read(self):
        try:
            if self.kind == "shelly":
                import urllib.request
                url = "http://%s/rpc/Switch.GetStatus?id=0" % self.host
                with urllib.request.urlopen(url, timeout=3) as r:
                    j = json.loads(r.read().decode())
                w = j.get("apower")
                v = j.get("voltage")
                return (w * 1000.0 if w is not None else None, v, None)
            elif self.kind == "kasa" and self._kasa is not False:
                async def _q():
                    await self._plug.update()
                    return self._plug.emeter_realtime
                e = self._asyncio.get_event_loop().run_until_complete(_q())
                return (e.get("power", 0) * 1000.0, e.get("voltage"), e.get("current"))
        except Exception:
            return None
        return None


def make_power_backend(a):
    kind = a.power
    if kind in (None, "none"):
        return None
    if kind in ("ina219", "ina260"):
        if not HAVE_SMBUS:
            print("[telemetry] WARNING: --power %s but smbus2 missing; no power." % kind)
            return None
        return InaI2C(kind, bus=a.i2c_bus, addr=int(a.i2c_addr, 0), shunt_ohms=a.shunt)
    if kind == "jetson":
        return JetsonPower()
    if kind in ("shelly", "kasa"):
        if not a.plug_host:
            print("[telemetry] WARNING: --power %s needs --plug-host; no power." % kind)
            return None
        return PlugPower(kind, a.plug_host)
    return None


class PowerSampler(threading.Thread):
    """Samples the backend at power_hz in the background; main loop drains the
       buffer once per row -> mean/max/p95/std (blip-preserving)."""
    def __init__(self, backend, hz, raw_writer=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.backend = backend
        self.period = 1.0 / hz if hz > 0 else 1.0
        self.raw_writer = raw_writer
        self.buf = []
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            t0 = time.monotonic()
            r = self.backend.read()
            if r is not None:
                with self.lock:
                    self.buf.append(r)
                if self.raw_writer:
                    self.raw_writer(*r)
            time.sleep(max(0.0, self.period - (time.monotonic() - t0)))

    def drain(self):
        with self.lock:
            b = self.buf
            self.buf = []
        # Always return the FULL key set (even empty) so the CSV header, fixed
        # from row 0, never omits power columns when row 0's buffer is empty.
        agg = {"power_mw_mean": None, "power_mw_max": None, "power_mw_p95": None,
               "power_mw_std": None, "power_n": len(b),
               "bus_v_mean": None, "current_ma_mean": None}
        if not b:
            return agg
        ps = sorted(x[0] for x in b if x[0] is not None)
        if ps:
            n = len(ps)
            mean = sum(ps) / n
            agg["power_mw_mean"] = round(mean, 1)
            agg["power_mw_max"] = round(ps[-1], 1)
            agg["power_mw_p95"] = round(ps[min(n - 1, int(0.95 * n))], 1)
            agg["power_mw_std"] = round((sum((x - mean) ** 2 for x in ps) / n) ** 0.5, 1)
        vs = [x[1] for x in b if x[1] is not None]
        cs = [x[2] for x in b if x[2] is not None]
        if vs:
            agg["bus_v_mean"] = round(sum(vs) / len(vs), 3)
        if cs:
            agg["current_ma_mean"] = round(sum(cs) / len(cs), 1)
        return agg


# --------------------------------------------------------------------------- #
#  board health that confounds the side-channel  (record it, don't hide it)
# --------------------------------------------------------------------------- #
def rpi_health():
    out = {}
    thr = _sh(["vcgencmd", "get_throttled"])           # throttled=0x...
    if thr and "=" in thr:
        out["rpi_throttled"] = thr.split("=", 1)[1]
    clk = _sh(["vcgencmd", "measure_clock", "arm"])    # frequency(48)=...
    if clk and "=" in clk:
        try:
            out["arm_freq_mhz"] = round(int(clk.split("=", 1)[1]) / 1e6, 1)
        except Exception:
            pass
    volt = _sh(["vcgencmd", "measure_volts", "core"])  # volt=1.2000V
    if volt and "=" in volt:
        out["core_volt_v"] = volt.split("=", 1)[1].rstrip("V")
    for fp in glob.glob("/sys/devices/platform/cooling_fan/hwmon/*/fan1_input") + \
              glob.glob("/sys/class/hwmon/*/fan1_input"):
        rpm = _read_int(fp)
        if rpm is not None:
            out["fan_rpm"] = rpm
            break
    return out


def jetson_health():
    out = {}
    m = _sh(["nvpmodel", "-q"])
    if m:
        mm = re.search(r"NV Power Mode:\s*(\S+)", m) or re.search(r"(\d+)\s*$", m)
        if mm:
            out["nvpmodel"] = mm.group(1)
    for fp in glob.glob("/sys/devices/*/gpu.0/devfreq/*/cur_freq") + \
              glob.glob("/sys/class/devfreq/*/cur_freq"):
        f = _read_int(fp)
        if f is not None:
            out["gpu_freq_mhz"] = round(f / 1e6, 1)
            break
    return out


# --------------------------------------------------------------------------- #
#  DEVICE CONFIG MANIFEST  (P5 controls #2/#3)
# --------------------------------------------------------------------------- #
def cpu_governors():
    govs = set()
    for fp in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"):
        g = _read(fp)
        if g:
            govs.add(g)
    return sorted(govs)


def cpu_freq_caps():
    return (_read_int("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq"),
            _read_int("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"))


def baseline_process_set():
    """Sorted unique process comm names -- the exact P5 'process set' fingerprint.
       Recorded so idle-daemon differences between boards are a KNOWN nuisance."""
    names = set()
    if HAVE_PSUTIL:
        for p in psutil.process_iter(attrs=["name"]):
            try:
                names.add(p.info["name"])
            except Exception:
                pass
    else:
        for c in glob.glob("/proc/[0-9]*/comm"):
            n = _read(c)
            if n:
                names.add(n)
    return sorted(n for n in names if n)


def chrony_offset_s():
    t = _sh(["chronyc", "tracking"])
    if t:
        m = re.search(r"Last offset\s*:\s*([-+0-9.eE]+)", t)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                pass
    return None


def os_pretty():
    txt = _read("/etc/os-release") or ""
    m = re.search(r'PRETTY_NAME="?([^"\n]+)', txt)
    return m.group(1) if m else None


def build_config(a):
    lo, hi = cpu_freq_caps()
    total_kb = None
    for line in (_read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            total_kb = int(line.split()[1]); break
    zones = {}
    for tpath in sorted(glob.glob("/sys/class/thermal/thermal_zone*/temp")):
        zdir = os.path.dirname(tpath)
        zones[_read(os.path.join(zdir, "type")) or os.path.basename(zdir)] = zdir
    procset = baseline_process_set()
    cfg = {
        "device_id": DEVICE_ID,
        "session_id": a.session,
        "boot_id": BOOT_ID,
        "collector_version": COLLECTOR_VERSION,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "arch": _sh(["uname", "-m"]),
        "kernel": _sh(["uname", "-r"]),
        "os_release": os_pretty(),
        "board_model": _read("/proc/device-tree/model"),
        "l4t": _read("/etc/nv_tegra_release"),
        "cpu_cores": os.cpu_count(),
        "cpu_governor": cpu_governors(),
        "cpu_freq_min_khz": lo,
        "cpu_freq_max_khz": hi,
        "mem_total_mb": round(total_kb / 1024.0) if total_kb else None,
        "thermal_zones": zones,
        "power_method": a.power,
        "shunt_ohms": a.shunt if a.power in ("ina219", "ina260") else None,
        "i2c_addr": a.i2c_addr if a.power in ("ina219", "ina260") else None,
        "plug_host": a.plug_host if a.power in ("shelly", "kasa") else None,
        "sample_hz": a.hz,
        "power_hz": a.power_hz,
        "chrony_last_offset_s": chrony_offset_s(),
        "nproc_baseline": len(procset),
        "baseline_process_set": procset,
    }
    if cfg["board_model"] and "raspberry" in cfg["board_model"].lower():
        cfg["rpi_health_at_snapshot"] = rpi_health()
    if cfg["l4t"]:
        cfg["jetson_health_at_snapshot"] = jetson_health()
    # config_id = short hash over STABLE fields only (not timestamp / live offset)
    stable = {k: cfg[k] for k in (
        "device_id", "arch", "kernel", "os_release", "board_model", "cpu_cores",
        "cpu_governor", "cpu_freq_min_khz", "cpu_freq_max_khz", "mem_total_mb",
        "power_method", "shunt_ohms", "sample_hz", "baseline_process_set")}
    cfg["config_id"] = hashlib.sha1(
        json.dumps(stable, sort_keys=True).encode()).hexdigest()[:12]
    return cfg


def config_path(out, session):
    return os.path.join(out, "config_%s_%s.json" % (DEVICE_ID, session or "default"))


def load_or_emit_config(a, emit):
    path = config_path(a.out, a.session)
    if emit or not os.path.exists(path):
        cfg = build_config(a)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
        print("[telemetry] config manifest -> %s (config_id=%s)" % (path, cfg["config_id"]))
        return cfg
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
#  base host sample
# --------------------------------------------------------------------------- #
def sample_base(prev_net, prev_disk):
    l1, l5, l15 = loadavg()
    row = {"load1": l1, "load5": l5, "load15": l15}
    if HAVE_PSUTIL:
        vm = psutil.virtual_memory()
        net = psutil.net_io_counters()
        dsk = psutil.disk_io_counters()
        row.update({"cpu_pct": psutil.cpu_percent(interval=None),
                    "mem_pct": vm.percent, "mem_used_mb": round(vm.used / 1e6, 1),
                    "nprocs": len(psutil.pids())})
        cur_net = (net.bytes_sent, net.bytes_recv)
        row["net_tx_bps"] = (cur_net[0] - prev_net[0]) if prev_net else 0
        row["net_rx_bps"] = (cur_net[1] - prev_net[1]) if prev_net else 0
        if dsk:
            cur_disk = (dsk.read_bytes, dsk.write_bytes)
            row["disk_r_bps"] = (cur_disk[0] - prev_disk[0]) if prev_disk else 0
            row["disk_w_bps"] = (cur_disk[1] - prev_disk[1]) if prev_disk else 0
        else:
            cur_disk = prev_disk
            row["disk_r_bps"] = row["disk_w_bps"] = None
        return row, cur_net, cur_disk
    # /proc fallback
    tx = rx = 0
    for line in (_read("/proc/net/dev") or "").splitlines()[2:]:
        try:
            _, rest = line.split(":", 1)
            f = rest.split()
            rx += int(f[0]); tx += int(f[8])
        except Exception:
            pass
    mem = {}
    for line in (_read("/proc/meminfo") or "").splitlines():
        try:
            k, v = line.split(":"); mem[k] = int(v.strip().split()[0])
        except Exception:
            pass
    mem_pct = 100.0 * (1 - mem.get("MemAvailable", 0) / mem.get("MemTotal", 1)) if mem else None
    row.update({"cpu_pct": None,
                "mem_pct": round(mem_pct, 1) if mem_pct is not None else None,
                "mem_used_mb": round((mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)) / 1000, 1) if mem else None,
                "nprocs": len(glob.glob("/proc/[0-9]*")),
                "net_tx_bps": (tx - prev_net[0]) if prev_net else 0,
                "net_rx_bps": (rx - prev_net[1]) if prev_net else 0,
                "disk_r_bps": None, "disk_w_bps": None})
    return row, (tx, rx), prev_disk


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="./telemetry")
    ap.add_argument("--hz", type=float, default=1.0, help="row rate (align to Zeek/auth windows)")
    ap.add_argument("--session", default="", help="capture-session id, stamped in every row")
    ap.add_argument("--power", default="none",
                    choices=["none", "ina219", "ina260", "jetson", "shelly", "kasa"])
    ap.add_argument("--power-hz", type=float, default=10.0, help="power sub-sample rate")
    ap.add_argument("--power-raw", action="store_true", help="also write raw high-rate power CSV")
    ap.add_argument("--shunt", type=float, default=0.1, help="INA219 shunt ohms (0.1 default; 0.002 for INA260)")
    ap.add_argument("--i2c-bus", type=int, default=1)
    ap.add_argument("--i2c-addr", default="0x40")
    ap.add_argument("--plug-host", default="", help="smart-plug IP for shelly/kasa")
    ap.add_argument("--emit-config", action="store_true", help="(re)write config manifest and exit")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    if a.emit_config:
        load_or_emit_config(a, emit=True)
        return

    cfg = load_or_emit_config(a, emit=False)
    config_id = cfg.get("config_id", "unknown")
    is_rpi = bool(cfg.get("board_model") and "raspberry" in str(cfg["board_model"]).lower())
    is_jetson = bool(cfg.get("l4t"))

    def _fresh(base):
        # never append to an existing file (its header may be from an older reader
        # version -> header/data column MISMATCH -> pandas column-shift). Always
        # start a fresh file (adding __N) so the header always matches the rows.
        if not os.path.exists(base):
            return base
        stem, ext = os.path.splitext(base)
        i = 2
        while os.path.exists("%s__%d%s" % (stem, i, ext)):
            i += 1
        return "%s__%d%s" % (stem, i, ext)
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    path = _fresh(os.path.join(a.out, "telemetry_%s_%s.csv" % (DEVICE_ID, day)))
    new = True
    fh = open(path, "w", newline="")   # fresh file, header always written
    w = None

    raw_writer = None
    if a.power_raw and a.power != "none":
        rp = os.path.join(a.out, "power_%s_%s.csv" % (DEVICE_ID, day))
        rnew = not os.path.exists(rp)
        rfh = open(rp, "a", newline="")
        rw = csv.writer(rfh)
        if rnew:
            rw.writerow(["ts_realtime_ns", "ts_mono_ns", "power_mw", "bus_v", "current_ma"])
        def raw_writer(p_mw, bus_v, cur_ma):
            r_ns, m_ns = clocks_ns()
            rw.writerow([r_ns, m_ns, p_mw, bus_v, cur_ma]); rfh.flush()

    backend = make_power_backend(a)
    sampler = None
    if backend is not None:
        sampler = PowerSampler(backend, a.power_hz, raw_writer=raw_writer)
        sampler.start()

    period = 1.0 / a.hz
    prev_net = prev_disk = None
    prev_stat = _proc_stat()
    prev_t = time.monotonic()
    if HAVE_PSUTIL:
        psutil.cpu_percent(interval=None)  # prime
    health_every = max(1, int(round(a.hz * 5)))  # vcgencmd/nvpmodel ~ every 5 s
    i = 0
    print("[telemetry] device=%s config_id=%s boot_id=%s psutil=%s power=%s -> %s"
          % (DEVICE_ID, config_id, BOOT_ID[:8], HAVE_PSUTIL, a.power, path))

    while True:
        t0 = time.monotonic()
        base, prev_net, prev_disk = sample_base(prev_net, prev_disk)
        cur_stat = _proc_stat()
        dt_loop = t0 - prev_t
        cpu = cpu_breakdown(prev_stat, cur_stat, dt_loop)
        coll = collector_load(dt_loop)   # C3: apparatus load as recorded nuisance
        prev_stat, prev_t = cur_stat, t0
        real_ns, mono_ns = clocks_ns()

        # rotate the output file at UTC midnight (always-on service must not append
        # to one endless file; keeps telemetry_<dev>_<day>.csv device+day resolvable)
        _g = time.gmtime(real_ns / 1e9)
        cur_day = "%04d%02d%02d" % (_g.tm_year, _g.tm_mon, _g.tm_mday)
        if cur_day != day:
            day = cur_day
            fh.close()
            path = _fresh(os.path.join(a.out, "telemetry_%s_%s.csv" % (DEVICE_ID, day)))
            new = True
            fh = open(path, "w", newline="")   # fresh file, header always matches rows
            w = None

        # identity + dual clock first (cross-device alignment axis), then signals
        row = {"device_id": DEVICE_ID, "config_id": config_id, "session_id": a.session,
               "boot_id": BOOT_ID, "ts_realtime_ns": real_ns, "ts_mono_ns": mono_ns,
               "ts_iso": datetime.now(timezone.utc).isoformat(),
               "ts_mono": round(time.monotonic(), 3)}
        row.update(base)
        row.update(cpu)
        row.update(coll)
        row.update(thermal_zones())
        if sampler is not None:
            row.update(sampler.drain())
        if (i % health_every) == 0:
            if is_rpi:
                row.update(rpi_health())
            if is_jetson:
                row.update(jetson_health())
        i += 1

        if w is None:
            w = csv.DictWriter(fh, fieldnames=list(row.keys()), extrasaction="ignore")
            if new:
                w.writeheader()
        w.writerow(row); fh.flush()
        time.sleep(max(0, period - (time.monotonic() - t0)))


if __name__ == "__main__":
    main()
