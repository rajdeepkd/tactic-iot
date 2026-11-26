#!/usr/bin/env python3
"""
discovery.py -- legitimate fleet service DISCOVERY / health monitor (benign).

Fixes the P7 "benign never scans" confound: in CIC-YNU every malware family
scanned (Telnet/SYN fan-out) and no benign program did, so SYN-count / TCP-share
/ Telnet-share alone separated the classes. Here a normal operations monitor
produces the SAME connect()/SYN fan-out and mDNS chatter as benign traffic, so
those network features are no longer diagnostic and recon must be distinguished
by behaviour + other modalities.

This is a MONITOR, not a scanner. It touches ONLY the configured, known service
inventory (host + specific service port), exactly like Nagios `check_tcp`,
Prometheus blackbox-exporter, or a Consul health check. It never sweeps unknown
hosts or port ranges. Two modes:

  --inventory FILE  TCP connect() liveness of each (host, port) in the inventory,
                    plus an app-level probe where cheap (HTTP GET /health, MQTT
                    CONNECT+DISCONNECT). Reports up/down; does not exploit.
  --mdns            passive DNS-SD / mDNS browse of the local segment via
                    `avahi-browse -at` (service advertisement discovery).

Inventory YAML (discovery_inventory.yaml):
  services:
    - {host: 10.0.0.11, port: 22,   name: ssh}
    - {host: 10.0.0.11, port: 1883, name: mqtt}
    - {host: 10.0.0.11, port: 8080, name: http}
    - {host: 10.0.0.20, port: 554,  name: rtsp}

Usage:
  python3 discovery.py --inventory discovery_inventory.yaml --interval 45
  python3 discovery.py --mdns --interval 60
Runs long-lived (loops every --interval) until killed by benignd/systemd.
"""
import argparse, os, socket, subprocess, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def tcp_check(host, port, timeout=2.0):
    """Standard liveness probe: open a TCP connection to a KNOWN service port."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, round((time.monotonic() - t0) * 1000, 1)
    except Exception:
        return False, round((time.monotonic() - t0) * 1000, 1)


def http_health(host, port, path="/health", timeout=3.0):
    try:
        import urllib.request
        url = f"http://{host}:{port}{path}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 500
    except Exception:
        return False


def mqtt_ping(host, port, timeout=3.0):
    """CONNECT then DISCONNECT -- a broker-liveness check, no publish/subscribe."""
    try:
        import paho.mqtt.client as mqtt
        c = mqtt.Client()
        c.connect(host, int(port), keepalive=int(timeout))
        c.disconnect()
        return True
    except Exception:
        return False


def run_inventory(inv_path, interval):
    inv = load_yaml(inv_path)
    services = inv.get("services", [])
    print(f"[discovery] health-monitor over {len(services)} known services, every {interval}s")
    while True:
        for s in services:
            host, port, name = s["host"], s["port"], s.get("name", "")
            up, rtt = tcp_check(host, port)
            if up and name == "http":
                up = http_health(host, port, s.get("path", "/health"))
            elif up and name == "mqtt":
                up = mqtt_ping(host, port)
            ts = datetime.now(timezone.utc).isoformat()
            print(f"  {ts} {host}:{port}/{name} up={up} rtt_ms={rtt}")
            time.sleep(0.3)                    # spaced probes (monitor cadence)
        time.sleep(interval)


def run_mdns(interval):
    print(f"[discovery] mDNS/DNS-SD browse every {interval}s (avahi-browse -at)")
    while True:
        try:
            subprocess.call(["avahi-browse", "-atrp", "-T"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except FileNotFoundError:
            print("[discovery] avahi-browse not installed (apt install avahi-utils)", file=sys.stderr)
            return
        except Exception:
            pass
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory")
    ap.add_argument("--mdns", action="store_true")
    ap.add_argument("--interval", type=int, default=45)
    a = ap.parse_args()
    if a.mdns:
        run_mdns(a.interval)
    elif a.inventory:
        run_inventory(a.inventory, a.interval)
    else:
        ap.error("give --inventory FILE or --mdns")


if __name__ == "__main__":
    main()
