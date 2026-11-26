#!/usr/bin/env python3
"""
tactic-cmd-handler.py -- the victim's MQTT command subscriber (always-on
tb-cmd-handler.service).

WHY IT EXISTS: control_mqtt_cmdinject publishes a command to iot/<dev>/cmd. For
that attack to be LABELLABLE and DETECTABLE from the host silo (the whole point
of the unauthorized_control class), the device must ACT on the command and leave
a host footprint. On every message this handler runs a benign, reversible local
action: it writes a syslog line and touches a scratch file, which produces an
auditd execve event inside the attack window. The network sees only a valid
PUBLISH; the host sees the effect. That asymmetry is the multimodal-necessity
evidence.

Benign command traffic (the operator's own occasional iot/<dev>/cmd message)
exercises the same path, so "any command == malicious" is not a shortcut: the
label comes from run_action.sh, not from the presence of a command.

Scope: the action is logger + a touch of /tmp/tactic_cmd.<n>, both reversible,
never destructive, never a shell of attacker-controlled text. The payload is
NOT executed; only a fixed local action runs. Requires paho-mqtt.
"""
import os
import socket
import subprocess
import sys

DEV = socket.gethostname()
BROKER = os.environ.get("TB_BROKER", "127.0.0.1")
PORT = int(os.environ.get("TB_BROKER_PORT", "1883"))

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("[cmd] paho-mqtt missing (sudo apt install python3-paho-mqtt)", file=sys.stderr)
    sys.exit(1)


def make_client():
    """paho 2.x needs the callback-API-version argument; 1.x does not."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{DEV}-cmd")
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=f"{DEV}-cmd")


def on_connect(client, userdata, *args, **kwargs):
    # Subscribe on EVERY (re)connect. paho's loop_forever auto-reconnects after a
    # broker restart but does NOT replay subscriptions, so subscribing once in
    # main() leaves a connected-but-unsubscribed zombie the moment mosquitto is
    # restarted (which silently kills control_mqtt_cmdinject). Subscribing here
    # fixes that. The *args/**kwargs signature tolerates both the paho 1.x
    # (client,userdata,flags,rc) and 2.x (…,reason_code,properties) callbacks.
    client.subscribe(f"iot/{DEV}/cmd")
    print(f"[cmd] (re)subscribed iot/{DEV}/cmd on {BROKER}:{PORT}", flush=True)


def on_message(client, userdata, msg):
    # FIXED local action, independent of payload content. Reversible host effect.
    n = userdata["n"] = userdata.get("n", 0) + 1
    scratch = f"/tmp/tactic_cmd.{n % 8}"
    try:
        subprocess.run(["logger", "-t", "tactic-cmd", f"cmd received on {DEV}"],
                       timeout=5, check=False)
        with open(scratch, "w") as f:
            f.write("ack\n")
        os.remove(scratch)
    except Exception:
        pass


def main():
    c = make_client()
    c.user_data_set({})
    c.on_connect = on_connect
    c.on_message = on_message
    # Reconnect forever with backoff. connect_async + loop_forever tolerates the
    # broker being down at startup (no hard exit, no crash-loop) and reconnects
    # automatically; on_connect then resubscribes each time.
    c.reconnect_delay_set(min_delay=1, max_delay=30)
    c.connect_async(BROKER, PORT, keepalive=30)
    print(f"[cmd] starting, will connect+subscribe to iot/{DEV}/cmd on {BROKER}:{PORT}", flush=True)
    c.loop_forever()


if __name__ == "__main__":
    main()
