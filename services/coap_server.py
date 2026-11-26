#!/usr/bin/env python3
"""
coap_server.py -- benign CoAP device server for the TACTIC-IoT v2 testbed.

Runs ON a victim board (always-on systemd unit tb-coap.service). Exposes the
resources a real constrained IoT device would, so that:
  * benign CoAP traffic (GET /sensor, Observe) is present on the victim capture,
  * recon_coap_discovery (GET /.well-known/core) has something to enumerate,
  * ddos_coap_conflood has a confirmable-message target (the victim's OWN server,
    never a reflected third party),
  * an unauthorized PUT to /actuator is a protocol-specific write the network
    sees as valid and the host/device state reveals.

Anti-identity: no payload is logged here. Ground truth is caused by run_action.sh
on the hub, not inferred from this server. Resource values are scratch only and
reset on restart. Requires python3-aiocoap. Degrades to a clear message if absent.

Listens on 0.0.0.0:5683 (udp). W=the air-gapped LAN; no auth is standard for CoAP.
"""
import asyncio
import os
import random
import socket
import sys
import time
from datetime import datetime, timezone

# Persistent application-log: one line per request event (TYPE ONLY, never payload),
# so CoAP recon/control classes get an app-log feature. Epoch-prefixed like the broker
# log, harvested by time-slice. journald is avoided (volatile under flood volume).
_APPLOG = os.environ.get("COAP_APPLOG", "/var/log/testbed/coap_tactic.log")


def _applog(ev):
    try:
        with open(_APPLOG, "a") as f:
            f.write(f"{int(time.time())}: coap {ev}\n")
    except Exception:
        pass

try:
    import aiocoap
    import aiocoap.resource as resource
except ImportError:
    print("[coap] aiocoap missing (sudo apt install python3-aiocoap)", file=sys.stderr)
    sys.exit(1)

DEV = socket.gethostname()


class SensorResource(resource.ObservableResource):
    """GET /sensor -> a small sensor reading. Observable, so benign clients can
    subscribe (realistic constrained-device telemetry)."""

    def __init__(self):
        super().__init__()
        self.handle = None
        self.reading = self._sample()

    def _sample(self):
        return (f'{{"dev":"{DEV}","ts":"{datetime.now(timezone.utc).isoformat()}",'
                f'"temp_c":{round(random.uniform(20, 55), 2)},'
                f'"hum":{round(random.uniform(30, 80), 1)}}}').encode()

    def notify(self):
        self.reading = self._sample()
        self.updated_state()
        self.reschedule()

    def reschedule(self):
        self.handle = asyncio.get_event_loop().call_later(10, self.notify)

    def update_observation_count(self, count):
        if count and self.handle is None:
            self.reschedule()
        elif count == 0 and self.handle is not None:
            self.handle.cancel()
            self.handle = None

    async def render_get(self, request):
        _applog("get sensor")
        return aiocoap.Message(payload=self.reading)


class ActuatorResource(resource.Resource):
    """GET/PUT /actuator -> a scratch writable resource. A PUT is a device-control
    write. For the benign profile the legitimate client never writes here; the
    unauthorized-control attack does. The value is scratch and reset on restart."""

    def __init__(self):
        super().__init__()
        self.state = b"off"

    async def render_get(self, request):
        _applog("get actuator")
        return aiocoap.Message(payload=self.state)

    async def render_put(self, request):
        # accept and store; a real device would act. Value kept reversible; we log the
        # WRITE EVENT (not the value) so control_coap writes get an app-log trace.
        _applog("put actuator")
        self.state = request.payload[:16] or b"off"
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.state)


class LoggingWKC(resource.WKCResource):
    """/.well-known/core with an app-log line per discovery request (recon_coap_discovery)."""
    async def render_get(self, request):
        _applog("discovery")
        return await super().render_get(request)


async def main():
    root = resource.Site()
    # /.well-known/core is auto-served by aiocoap for discovery (recon target).
    root.add_resource(['.well-known', 'core'],
                      LoggingWKC(root.get_resources_as_linkheader))
    root.add_resource(['sensor'], SensorResource())
    root.add_resource(['actuator'], ActuatorResource())
    await aiocoap.Context.create_server_context(root, bind=("0.0.0.0", 5683))
    print(f"[coap] serving /sensor /actuator /.well-known/core on {DEV}:5683")
    await asyncio.get_event_loop().create_future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
