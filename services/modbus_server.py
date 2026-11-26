#!/usr/bin/env python3
"""
modbus_server.py -- benign Modbus/TCP device server for TACTIC-IoT v2.

Runs ON a victim board (always-on tb-modbus.service). Presents a small
industrial-style register map so that:
  * benign Modbus reads (hub poll of holding registers) are on the capture,
  * recon_modbus_scan has a device + function set to enumerate,
  * control_modbus_write has scratch coils/holding registers to write (function
    codes 5,6,15,16). A write is VALID Modbus and looks benign on the wire; the
    server-side state change is the host/device evidence. Scratch only, reset on
    restart, so the write is reversible and harms nothing.

Anti-identity: nothing here is ground truth. labels.csv (caused by run_action.sh
on the hub) is. Requires python3-pymodbus. Supports both the 3.x and the older
import paths, matching service_traffic.py's degradation style.

Listens on 0.0.0.0:502 (tcp). No auth: standard for Modbus, and the point of the
unauthorized-write class.
"""
import os
import socket
import subprocess
import sys
import time

DEV = socket.gethostname()
# Persistent application-log of write events (epoch-prefixed, like the broker/CoAP
# logs). journald is volatile under flood volume, so the file is the reliable harvest
# source for the Modbus write-rate app-log feature. Fixed text, never the values.
_APPLOG = os.environ.get("MODBUS_APPLOG", "/var/log/testbed/modbus_tactic.log")


def _log_write():
    """Host + application footprint for a Modbus write (func 5/6/15/16). Fires on
    every write (benign control op AND attack), so it is a write-RATE signal, not a
    label marker. Writes a persistent app-log line and a journald/auditd execve trace."""
    try:
        with open(_APPLOG, "a") as f:
            f.write(f"{int(time.time())}: modbus write\n")
    except Exception:
        pass
    try:
        subprocess.run(["logger", "-t", "tactic-modbus", f"modbus write on {DEV}"],
                       timeout=5, check=False)
    except Exception:
        pass

try:
    # pymodbus 3.x
    from pymodbus.datastore import (ModbusSequentialDataBlock,
                                    ModbusServerContext, ModbusSlaveContext)
    from pymodbus.server import StartTcpServer
    NEW = True
except ImportError:
    try:
        from pymodbus.datastore import (ModbusSequentialDataBlock,
                                        ModbusServerContext, ModbusSlaveContext)
        from pymodbus.server.sync import StartTcpServer  # older pymodbus
        NEW = False
    except ImportError:
        print("[modbus] pymodbus missing (sudo apt install python3-pymodbus)", file=sys.stderr)
        sys.exit(1)


class LoggingBlock(ModbusSequentialDataBlock):
    """A data block that leaves a host-log trace on every WRITE (setValues) and
    nothing on reads (getValues), so control_modbus_write is visible in the host
    silo. Used for the writable coil/holding blocks only."""
    def setValues(self, address, values, *args, **kwargs):
        _log_write()
        return super().setValues(address, values, *args, **kwargs)


def build_context():
    # scratch blocks: 200 coils, 200 discrete inputs, 200 holding + 200 input regs.
    # addresses 0..99 = "live" device registers (read by benign polls),
    # addresses 100..199 = scratch write targets for control_modbus_write.
    block = lambda n: ModbusSequentialDataBlock(0, [0] * n)
    wblock = lambda n: LoggingBlock(0, [0] * n)  # coils + holding regs are writable
    # pymodbus >=3.8 removed the zero_mode kwarg from ModbusSlaveContext; the
    # datastore is zero-based by construction (block starts at address 0), so the
    # scratch range 100..199 is addressed directly either way. Keep it kwarg-free
    # for forward compatibility and fall back for older pymodbus that still wants it.
    # co (coils) and hr (holding regs) are write targets -> LoggingBlock; di and
    # ir are read-only input blocks -> plain block.
    try:
        slave = ModbusSlaveContext(di=block(200), co=wblock(200),
                                   hr=wblock(200), ir=block(200))
    except TypeError:
        slave = ModbusSlaveContext(di=block(200), co=wblock(200),
                                   hr=wblock(200), ir=block(200), zero_mode=True)
    return ModbusServerContext(slaves=slave, single=True)


def main():
    ctx = build_context()
    print(f"[modbus] serving unit 1 on {DEV}:502 (hr/ir/co/di x200, scratch 100..199)")
    StartTcpServer(context=ctx, address=("0.0.0.0", 502))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[modbus] port 502 needs CAP_NET_BIND_SERVICE or root "
              "(the systemd unit grants it)", file=sys.stderr)
        sys.exit(1)
