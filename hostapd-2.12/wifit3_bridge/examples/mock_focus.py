"""Hardware-free AP startup smoke-test. NEVER emits radio signals.

Run from extracted source tree after compiling hostapd:
    python -m wifit3_bridge.examples.mock_focus
A local hostapd process is launched with an ephemeral token and IPC port.
"""
from __future__ import annotations

from pathlib import Path
import os
import secrets
import subprocess
import tempfile
import threading
from wifit3_bridge.bridge import (
    Wifit3Bridge, RadioConfig, CAP_BEACON, CAP_TX_MGMT,
    CAP_RX_MGMT, CAP_SET_FREQ,
)


class NullFocusRadio:
    """Accepts AP initialization for logic tests, transmits nothing."""
    def set_frequency(self, mhz: int) -> bool:
        print(f"[mock] set_frequency: {mhz} MHz")
        return mhz == 2412

    def set_beacon(self, head: bytes, tail: bytes, interval_tu: int, dtim: int) -> bool:
        print(f"[mock] beacon template: head={len(head)} tail={len(tail)}, interval={interval_tu} TU")
        return True

    def tx_mgmt(self, frame: bytes, freq_mhz: int, noack: bool, no_encrypt: bool,
                wait_ms: int) -> bool:
        print(f"[mock] discarded TX management frame ({len(frame)} bytes)")
        return True

    def tx_eapol(self, *args) -> bool:
        return False

    def install_key(self, *args) -> bool:
        return False

    def station_add(self, *args) -> bool:
        return False

    def station_flags(self, *args) -> bool:
        return False

    def station_remove(self, *args) -> bool:
        return False


def main() -> int:
    exe_name = "hostapd.exe" if os.name == "nt" else "hostapd"
    exe = Path(__file__).resolve().parents[2] / "hostapd" / exe_name
    if not exe.exists():
        raise SystemExit(f"Build hostapd before running mock: {exe}")
    secret = secrets.token_hex(32)
    cfg = RadioConfig(b"\x02\x00\x00\x00\x00\x01", (2412,),
                      CAP_BEACON | CAP_TX_MGMT | CAP_RX_MGMT | CAP_SET_FREQ)
    bridge = Wifit3Bridge(NullFocusRadio(), cfg, secret, port=0)
    port = bridge.start_listener()
    thread = threading.Thread(target=bridge.serve_once, daemon=True)
    thread.start()
    with tempfile.TemporaryDirectory() as directory:
        conf = Path(directory) / "mock.conf"
        conf.write_text("interface=wifit3mock0\ndriver=wifit3\nssid=wifit3-portability-smoketest\n"
                        "hw_mode=g\nchannel=1\nwpa=0\n", encoding="utf-8")
        env = dict(os.environ, WIFIT3_BRIDGE_TOKEN=secret,
                   WIFIT3_BRIDGE_PORT=str(port))
        print("Starting hostapd 2.12 on a simulated (no-RF) radio. Ctrl+C to stop.")
        try:
            return subprocess.call([str(exe), "-d", str(conf)], env=env)
        finally:
            bridge.close()
            thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
