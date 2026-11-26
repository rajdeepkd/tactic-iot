#!/usr/bin/env python3
"""
service_traffic.py -- legitimate IoT service traffic generator (benign).

Provides the continuous, periodic device chatter that a low-and-slow C2/exfil
beacon must hide inside. Without it, "any small periodic flow == malicious" would
separate the exfil scenario trivially (a network-only shortcut). With it, benign
MQTT/HTTP/RTSP/CoAP/Modbus flows share the beacon's periodicity, small-packet
ratio and inter-arrival distribution, so the beacon is resolvable only by
correlating stages/sources.

Each --proto is a long-lived loop (benignd supervises/restarts it). All endpoints
are the operator's own lab services. Every client degrades gracefully if its
library is missing, so a partial software install still yields a running campaign.

Protocols:
  mqtt    paho-mqtt: publish sensor-like JSON to iot/<dev>/telemetry every N s,
          subscribe to iot/<dev>/cmd. (mosquitto broker on rpi3b-1.)
  http    urllib: GET a REST /health + POST a small reading every N s.
  rtsp    ffprobe/openRTSP: pull a few seconds of the camera stream every N s.
  coap    aiocoap: GET coap://host/sensor every N s.
  modbus  pymodbus: read holding registers every N s (industrial-style poll).

Usage:
  python3 service_traffic.py --proto mqtt   --broker 10.0.0.11 --interval 15
  python3 service_traffic.py --proto http   --url http://10.0.0.11:8080/health --interval 20
  python3 service_traffic.py --proto rtsp   --url rtsp://10.0.0.30:554/stream1 --interval 30
  python3 service_traffic.py --proto modbus --host 10.0.0.12 --interval 10
"""
import argparse, json, os, random, socket, subprocess, sys, time
from datetime import datetime, timezone

DEV = socket.gethostname()


def jittered(interval, frac=0.25):
    return max(0.5, interval * random.uniform(1 - frac, 1 + frac))


def _real_temp_c():
    """The board's actual CPU temperature if readable, else None. Makes the
    benign payload real device telemetry rather than synthetic noise."""
    try:
        import glob as _glob
        for p in _glob.glob("/sys/class/thermal/thermal_zone*/temp"):
            with open(p) as fh:
                v = int(fh.read().strip())
            return round(v / 1000.0, 2) if v > 1000 else round(float(v), 2)
    except Exception:
        return None
    return None


def reading():
    """A plausible sensor payload (small, JSON) -- shape of real IoT telemetry.
    Uses the board's real CPU temperature when available."""
    t = _real_temp_c()
    return json.dumps({
        "dev": DEV, "ts": datetime.now(timezone.utc).isoformat(),
        "temp_c": t if t is not None else round(random.uniform(20, 55), 2),
        "hum": round(random.uniform(30, 80), 1),
        "seq": random.randint(0, 10 ** 6),
    })


def _make_mqtt_client(mqtt, client_id):
    """paho-mqtt 2.x requires the callback-API-version argument; 1.x does not.
    Debian trixie ships 2.x, so the bare 1.x constructor raises -- try 2.x first."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id)


def run_mqtt(broker, port, interval, name=None, control_every=0, username=None, password=None):
    name = name or DEV
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("[svc] paho-mqtt missing (pip install paho-mqtt)", file=sys.stderr); return
    c = _make_mqtt_client(mqtt, f"{DEV}-benign-{name}")
    # authenticated benign client: a real deployment's legitimate clients present
    # valid credentials, so the broker logs an auth SUCCESS for benign and an auth
    # FAILURE for the credential-guessing brute. This makes the applog brute signal
    # realistic (failed auth cadence) rather than mere credential-presence.
    if username:
        c.username_pw_set(username, password)
    c.on_message = lambda *_: None
    # realistic device lifecycle: a last-will + a retained online status, so the
    # benign profile has CONNECT/PUBLISH-retain/SUBSCRIBE shape, not just publishes.
    status = f"iot/{name}/status"
    c.will_set(status, payload="offline", qos=1, retain=True)
    try:
        c.connect(broker, int(port), keepalive=max(15, int(interval * 2)))
    except Exception as e:
        print(f"[svc] mqtt connect failed: {e}", file=sys.stderr); return
    c.publish(status, "online", qos=1, retain=True)
    c.subscribe(f"iot/{name}/cmd")
    c.loop_start()
    topic = f"iot/{name}/telemetry"
    print(f"[svc] mqtt pub -> {broker}:{port} {topic} every ~{interval}s"
          + (f", legit cmd every {control_every}" if control_every else ""))
    try:
        n = 0
        while True:
            # mix QoS 0 and 1 like a real device (periodic telemetry + occasional
            # acknowledged reading).
            n += 1
            c.publish(topic, reading(), qos=(1 if n % 5 == 0 else 0))
            # LEGITIMATE operator command on the SAME iot/<dev>/cmd topic the attack
            # uses, at a low rate. This gives benign windows a cmd-handler host
            # footprint too, so control_mqtt_cmdinject is not separable by the mere
            # presence of a command -- only the attack's burst rate + label are.
            if control_every and n % control_every == 0:
                c.publish(f"iot/{name}/cmd", "run", qos=0)
            time.sleep(jittered(interval))
    finally:
        c.loop_stop(); c.disconnect()


def run_http(url, interval):
    import urllib.request
    base = url.rsplit("/", 1)[0]
    post_url = base + "/reading"
    print(f"[svc] http poll {url} + post {post_url} every ~{interval}s")
    while True:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                r.read(2048)
        except Exception:
            pass
        try:
            req = urllib.request.Request(post_url, data=reading().encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read(512)
        except Exception:
            pass
        time.sleep(jittered(interval))


def run_rtsp(url, interval, secs=4):
    tool = None
    for t in ("ffprobe", "ffmpeg", "openRTSP"):
        if subprocess.call(["bash", "-lc", f"command -v {t} >/dev/null 2>&1"]) == 0:
            tool = t; break
    if not tool:
        print("[svc] no rtsp tool (apt install ffmpeg / livemedia-utils)", file=sys.stderr); return
    print(f"[svc] rtsp pull {url} via {tool} every ~{interval}s")
    while True:
        try:
            if tool == "ffprobe":
                subprocess.call(["ffprobe", "-v", "quiet", "-rtsp_transport", "tcp",
                                 "-timeout", "5000000", url],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            elif tool == "ffmpeg":
                subprocess.call(["ffmpeg", "-y", "-rtsp_transport", "tcp", "-i", url,
                                 "-t", str(secs), "-f", "null", "-"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            else:
                subprocess.call(["openRTSP", "-d", str(secs), url],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except Exception:
            pass
        time.sleep(jittered(interval))


def run_coap(host, interval, name=None, control_every=0):
    print(f"[svc] coap GET coap://{host}/sensor every ~{interval}s"
          + (f", legit PUT /actuator every {control_every}" if control_every else ""))
    try:
        import asyncio, aiocoap
    except ImportError:
        print("[svc] aiocoap missing (pip install aiocoap)", file=sys.stderr); return

    async def poll():
        ctx = await aiocoap.Context.create_client_context()
        n = 0
        while True:
            n += 1
            try:
                req = aiocoap.Message(code=aiocoap.GET, uri=f"coap://{host}/sensor")
                await ctx.request(req).response
            except Exception:
                pass
            # occasional legitimate actuation (PUT /actuator) so a benign CoAP write
            # exists alongside the recon/flood traffic.
            if control_every and n % control_every == 0:
                try:
                    put = aiocoap.Message(code=aiocoap.PUT, uri=f"coap://{host}/actuator",
                                          payload=b"ok")
                    await ctx.request(put).response
                except Exception:
                    pass
            await asyncio.sleep(jittered(interval))
    asyncio.run(poll())


def run_modbus(host, port, interval, name=None, control_every=0):
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        try:
            from pymodbus.client.sync import ModbusTcpClient   # older pymodbus
        except ImportError:
            print("[svc] pymodbus missing (pip install pymodbus)", file=sys.stderr); return
    print(f"[svc] modbus poll {host}:{port} every ~{interval}s"
          + (f", legit write every {control_every}" if control_every else ""))
    n = 0
    while True:
        n += 1
        try:
            c = ModbusTcpClient(host, port=int(port), timeout=3)
            if c.connect():
                try: c.read_holding_registers(0, count=10)
                except TypeError: c.read_holding_registers(0, 10)  # arg-name drift
                # occasional legitimate control write to a scratch holding register,
                # so a benign modbus WRITE exists (same function code the attack uses);
                # only the attack's burst rate + host/label separate them.
                if control_every and n % control_every == 0:
                    try: c.write_register(120, 1)
                    except TypeError: c.write_register(120, value=1)
            c.close()
        except Exception:
            pass
        time.sleep(jittered(interval))


def run_snmp(host, interval, name=None, control_every=0):
    """SNMP monitoring client: periodic GET of a few scalars (benign polling) and,
    occasionally, a legitimate SET of the writable vendor config OID -- the same OID
    control_snmp_set attacks, so a benign SNMP SET exists and the attack is not
    separable by SET-presence alone. Uses the net-snmp CLI (snmpget/snmpset)."""
    gets = ["1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"]  # uptime/name/location
    set_oid = ".1.3.6.1.4.1.8072.9999.1.0"
    print(f"[svc] snmp GET {host} every ~{interval}s"
          + (f", legit SET every {control_every}" if control_every else ""))
    n = 0
    while True:
        n += 1
        for oid in gets:
            try:
                subprocess.call(["snmpget", "-v2c", "-c", "public", "-t", "2", host, oid],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
            except Exception:
                pass
        if control_every and n % control_every == 0:
            try:
                subprocess.call(["snmpset", "-v2c", "-c", "tactic_rw", "-t", "2", host,
                                 set_oid, "s", "tactic-lab rack"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
            except Exception:
                pass
        time.sleep(jittered(interval))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", required=True, choices=["mqtt", "http", "rtsp", "coap", "modbus", "snmp"])
    ap.add_argument("--broker"); ap.add_argument("--url"); ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--interval", type=float, default=15)
    ap.add_argument("--devname", default=None,
                    help="device/topic name for the TARGET victim (e.g. rpi3b1); "
                         "defaults to this host. Used for iot/<dev>/... topics.")
    ap.add_argument("--control-every", type=int, default=0,
                    help="every Nth poll, perform ONE legitimate control op (benign "
                         "command/write/set). 0 disables. Keep N large so benign "
                         "control is light vs the attack burst.")
    ap.add_argument("--username", default=None, help="MQTT username (valid benign account)")
    ap.add_argument("--password", default=None, help="MQTT password (synthetic lab credential)")
    a = ap.parse_args()
    ce = a.control_every
    if a.proto == "mqtt":
        run_mqtt(a.broker or a.host, a.port or 1883, a.interval, a.devname, ce,
                 a.username, a.password)
    elif a.proto == "http":
        run_http(a.url, a.interval)
    elif a.proto == "rtsp":
        run_rtsp(a.url, a.interval)
    elif a.proto == "coap":
        run_coap(a.host, a.interval, a.devname, ce)
    elif a.proto == "modbus":
        run_modbus(a.host, a.port or 502, a.interval, a.devname, ce)
    elif a.proto == "snmp":
        run_snmp(a.host, a.interval, a.devname, ce)


if __name__ == "__main__":
    main()
