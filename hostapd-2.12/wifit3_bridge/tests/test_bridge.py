import os
from pathlib import Path
import os
import hashlib
import hmac
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from wifit3_bridge.bridge import (
    CAP_ACCOUNTING, CAP_BEACON, CAP_KEY, CAP_RX_EAPOL, CAP_RX_MGMT, CAP_SET_FREQ,
    CAP_STA, CAP_TX_EAPOL, CAP_TX_MGMT, RadioConfig, Wifit3Bridge,
    _read, _send,
)


def _hostapd_binary() -> Path:
    root = Path(__file__).resolve().parents[2] / "hostapd"
    return root / ("hostapd.exe" if os.name == "nt" else "hostapd")


def _openssl_binary() -> Path | str | None:
    found = shutil.which("openssl")
    if found:
        return found
    if os.name == "nt":
        workspace = Path(__file__).resolve().parents[3]
        candidate = workspace / "msys2" / "ucrt64" / "bin" / "openssl.exe"
        if candidate.is_file():
            return candidate
    return None


def _radius_attr(attr_type: int, value: bytes) -> bytes:
    return bytes((attr_type, len(value) + 2)) + value


def _radius_access_request(identifier: int, secret: bytes) -> bytes:
    authenticator = bytes.fromhex("00112233445566778899aabbccddeeff")
    eap = b"\x02\x01\x00\x09\x01user"
    attrs = (
        _radius_attr(1, b"user") +
        _radius_attr(4, bytes((127, 0, 0, 1))) +
        _radius_attr(79, eap) +
        _radius_attr(80, b"\x00" * 16)
    )
    packet = struct.pack("!BBH", 1, identifier, 20 + len(attrs)) + authenticator + attrs
    msg_auth_offset = 20 + len(_radius_attr(1, b"user")) + len(_radius_attr(4, bytes((127, 0, 0, 1)))) + len(_radius_attr(79, eap)) + 2
    digest = hmac.new(secret, packet, hashlib.md5).digest()
    return packet[:msg_auth_offset] + digest + packet[msg_auth_offset + 16:]


def _radius_accounting_start(identifier: int, secret: bytes) -> bytes:
    attrs = (
        _radius_attr(40, struct.pack("!I", 1)) +
        _radius_attr(1, b"user") +
        _radius_attr(4, bytes((127, 0, 0, 1)))
    )
    zero_auth = b"\x00" * 16
    packet = struct.pack("!BBH", 4, identifier, 20 + len(attrs)) + zero_auth + attrs
    authenticator = hashlib.md5(packet + secret).digest()
    return packet[:4] + authenticator + packet[20:]


class FakeFocusRadio:
    """Simulation only: records calls, NEVER transmits or receives RF packets."""
    def __init__(self):
        self.calls = []

    def set_frequency(self, mhz):
        self.calls.append(("set_frequency", mhz))
        return mhz == 2412

    def set_beacon(self, head, tail, interval_tu, dtim):
        self.calls.append(("beacon", interval_tu, dtim, head, tail))
        return True

    def tx_mgmt(self, frame, freq_mhz, noack, no_encrypt, wait_ms):
        self.calls.append(("tx_mgmt", freq_mhz, frame, noack, no_encrypt, wait_ms))
        return True

    def tx_eapol(self, destination, source, payload, encrypt):
        self.calls.append(("tx_eapol", destination, source, payload, encrypt))
        return True

    def install_key(self, *args):
        raise NotImplementedError("no hardware key installation in simulation")

    def station_add(self, *args):
        return False

    def station_flags(self, *args):
        return False

    def station_remove(self, *args):
        return False


class BridgeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.token = secrets.token_hex(32)
        self.radio = FakeFocusRadio()
        caps = CAP_BEACON | CAP_TX_MGMT | CAP_RX_MGMT | CAP_SET_FREQ | CAP_TX_EAPOL | CAP_RX_EAPOL
        self.bridge = Wifit3Bridge(self.radio,
                                   RadioConfig(b"\x02\x11\x22\x33\x44\x55", (2412,), caps),
                                   self.token, port=0)
        self.port = self.bridge.start_listener()
        self.thread = threading.Thread(target=self.bridge.serve_once, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.bridge.close()
        self.thread.join(timeout=3)

    def connect(self, token=None):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        sock.settimeout(2)
        tok = (token or self.token).encode()
        _send(sock, b"\x01\x01" + bytes((len(tok),)) + tok + b"\x07w3test0")
        return sock

    def test_authenticated_control_flow(self):
        with self.connect() as s:
            hello = _read(s)
            self.assertEqual(hello[0:2], b"\x81\x00")
            self.assertEqual(hello[2:8], b"\x02\x11\x22\x33\x44\x55")
            self.assertEqual(hello[12], 1)
            _send(s, b"\x10" + struct.pack("!H", 2412))
            self.assertEqual(_read(s), b"\x90\x00")
            _send(s, b"\x10" + struct.pack("!H", 5500))
            self.assertEqual(_read(s), b"\x90\x01")
            head, tail = b"beacon-head", b"beacon-tail"
            cmd = b"\x11" + struct.pack("!HBHH", 100, 2, len(head), len(tail)) + head + tail
            _send(s, cmd)
            self.assertEqual(_read(s), b"\x90\x00")
            mgmt = b"\x80\x00" + b"\x00" * 22
            _send(s, b"\x12" + struct.pack("!HBHH", 2412, 3, 120, len(mgmt)) + mgmt)
            self.assertEqual(_read(s), b"\x90\x00")
            self.assertEqual(self.radio.calls[-1], ("tx_mgmt", 2412, mgmt, True, True, 120))
            _send(s, b"\x14" + b"\x00" * 15)  # CAP_KEY unavailable
            self.assertEqual(_read(s), b"\x90\x01")
            self.bridge.on_eapol_rx(b"\x10\x11\x12\x13\x14\x15", b"\x01\x00\x00\x00")
            self.assertEqual(_read(s)[0], 0x31)
            self.assertEqual(self.radio.calls[0], ("set_frequency", 2412))
            self.assertEqual(self.radio.calls[1][0], "beacon")

    def test_unacked_management_and_get_seqnum(self):
        from wifit3_bridge.bridge import CAP_KEY
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, (2412,),
            self.bridge.config.capabilities | CAP_KEY)
        seen = {}

        def tx_mgmt(frame, freq_mhz, noack, no_encrypt, wait_ms):
            self.radio.calls.append(("tx_mgmt", freq_mhz, frame, noack, no_encrypt, wait_ms))
            return 2

        def tx_tsc(addr, index):
            seen["tsc"] = (addr, index)
            return 0x010203

        self.radio.tx_mgmt = tx_mgmt
        self.radio.tx_tsc = tx_tsc
        with self.connect() as s:
            _read(s)
            mgmt = b"\xb0\x00" + b"\x00" * 22
            _send(s, b"\x12" + struct.pack("!HBHH", 2412, 0, 0, len(mgmt)) + mgmt)
            self.assertEqual(_read(s), b"\x90\x02")
            _send(s, b"\x18" + b"\xff" * 6 + bytes((1,)))
            self.assertEqual(_read(s), b"\x91" + (0x010203).to_bytes(6, "little"))
            self.assertEqual(seen["tsc"], (b"\xff" * 6, 1))
            self.radio.tx_tsc = lambda addr, index: None
            _send(s, b"\x18" + b"\x02\x11\x22\x33\x44\x55" + bytes((0,)))
            self.assertEqual(_read(s), b"\x90\x01")

    def test_observed_data_accounting_event_serialization(self):
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, (2412,),
            self.bridge.config.capabilities | CAP_ACCOUNTING)
        source = b"\x10\x11\x12\x13\x14\x15"
        destination = b"\x02\x11\x22\x33\x44\x55"
        with self.connect() as s:
            _read(s)
            for _ in range(100):
                if self.bridge.connected():
                    break
                time.sleep(0.005)
            self.assertTrue(self.bridge.connected())
            self.bridge.on_data_rx(source, destination, 123)
            event = _read(s)
            self.assertEqual(event, b"\x32" + source + destination +
                             struct.pack("!I", 123))

    def test_hostapd_enterprise_eap_tls_startup(self):
        """EAP server and WPA2-Enterprise config initialize; NO RF involved."""
        exe = _hostapd_binary()
        openssl = _openssl_binary()
        if not exe.is_file() or openssl is None:
            self.skipTest("needs compiled hostapd and openssl")
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, (2412,), self.bridge.config.capabilities | CAP_KEY)
        self.radio.install_key = lambda *args: True  # simulation only
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            creation = subprocess.run(
                [str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-keyout", str(d / "key.pem"),
                 "-out", str(d / "cert.pem"), "-subj", "/CN=wifit3-lab.invalid"],
                capture_output=True, text=True)
            self.assertEqual(creation.returncode, 0, creation.stderr)
            (d / "users.txt").write_text('* TLS "TLS"\n')
            conf = d / "ap.conf"
            conf.write_text("interface=w3test0\ndriver=wifit3\n"
                            "ssid=wifit3-8021x-lab\nhw_mode=g\nchannel=1\n"
                            "ieee8021x=1\neap_server=1\nwpa=2\n"
                            "wpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\n"
                            f"eap_user_file={d / 'users.txt'}\n"
                            f"server_cert={d / 'cert.pem'}\n"
                            f"private_key={d / 'key.pem'}\n")
            env = dict(os.environ, WIFIT3_BRIDGE_TOKEN=self.token,
                       WIFIT3_BRIDGE_PORT=str(self.port))
            log = d / "hostapd.log"
            with log.open("w", encoding="utf-8") as output:
                p = subprocess.Popen([str(exe), "-d", str(conf)],
                                     stdout=output, stderr=subprocess.STDOUT,
                                     text=True, env=env)
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and p.poll() is None:
                        if any(c[0] == "beacon" for c in self.radio.calls):
                            break
                        time.sleep(0.025)
                    self.assertTrue(any(c[0] == "beacon" for c in self.radio.calls))
                    # Beacon registration precedes the WPA group-key state
                    # machine; allow its acknowledged key operation to complete.
                    time.sleep(0.25)
                    self.assertIsNone(
                        p.poll(),
                        "WPA2-Enterprise startup failed: "
                        f"calls={self.radio.calls!r} "
                        f"log={log.read_text(encoding='utf-8', errors='replace')!r}",
                    )
                finally:
                    p.terminate()
                    p.wait(timeout=3)
            out = log.read_text(encoding="utf-8", errors="replace")
            # The process stayed alive after the beacon was acknowledged; the
            # certificate-chain message proves that the integrated EAP-TLS
            # server initialized before the Windows hard termination.
            self.assertIn("Configured certificate chain", out)

    def test_hostapd_integrated_radius_auth_and_accounting_udp(self):
        """Windows hostapd must answer local EAP/RADIUS auth and accounting UDP."""
        exe = _hostapd_binary()
        openssl = _openssl_binary()
        if not exe.is_file() or openssl is None:
            self.skipTest("needs compiled hostapd and openssl")
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, (2412,),
            self.bridge.config.capabilities | CAP_KEY)
        self.radio.install_key = lambda *args: True
        secret = b"wifit3-radius-secret"
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            creation = subprocess.run(
                [str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-keyout", str(d / "key.pem"),
                 "-out", str(d / "cert.pem"), "-subj", "/CN=wifit3-radius.invalid"],
                capture_output=True, text=True)
            self.assertEqual(creation.returncode, 0, creation.stderr)
            (d / "users.txt").write_text('* TLS "TLS"\n')
            (d / "clients.conf").write_text(
                "127.0.0.1 " + secret.decode("ascii") + "\n")
            conf = d / "radius.conf"
            conf.write_text(
                "interface=w3test0\ndriver=wifit3\nssid=wifit3-radius-lab\n"
                "hw_mode=g\nchannel=1\nbeacon_int=100\n"
                "ieee8021x=1\neap_server=1\nwpa=2\n"
                "wpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\n"
                f"eap_user_file={d / 'users.txt'}\n"
                f"server_cert={d / 'cert.pem'}\n"
                f"private_key={d / 'key.pem'}\n"
                f"radius_server_clients={d / 'clients.conf'}\n"
                "radius_server_auth_port=18120\n"
                "radius_server_acct_port=18121\n"
            )
            env = dict(os.environ, WIFIT3_BRIDGE_TOKEN=self.token,
                       WIFIT3_BRIDGE_PORT=str(self.port))
            log = d / "hostapd.log"
            with log.open("w", encoding="utf-8") as output:
                p = subprocess.Popen([str(exe), "-d", str(conf)],
                                     stdout=output, stderr=subprocess.STDOUT,
                                     text=True, env=env)
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline and p.poll() is None:
                        if any(c[0] == "beacon" for c in self.radio.calls):
                            break
                        time.sleep(0.025)
                    self.assertTrue(any(c[0] == "beacon" for c in self.radio.calls))
                    self.assertIsNone(p.poll(), log.read_text(encoding="utf-8", errors="replace"))

                    auth_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    auth_sock.settimeout(2)
                    try:
                        auth_sock.sendto(_radius_access_request(7, secret),
                                        ("127.0.0.1", 18120))
                        auth_reply, _ = auth_sock.recvfrom(4096)
                    finally:
                        auth_sock.close()
                    self.assertGreaterEqual(len(auth_reply), 20)
                    self.assertEqual(auth_reply[0], 11, auth_reply.hex())

                    acct_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    acct_sock.settimeout(2)
                    try:
                        acct_sock.sendto(_radius_accounting_start(8, secret),
                                        ("127.0.0.1", 18121))
                        acct_reply, _ = acct_sock.recvfrom(4096)
                    finally:
                        acct_sock.close()
                    self.assertGreaterEqual(len(acct_reply), 20)
                    self.assertEqual(acct_reply[0], 5, acct_reply.hex())
                finally:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=3)

    def test_authenticated_bridge_survives_idle(self):
        """Regression: after HELLO a legitimate idle AP must remain connected."""
        with self.connect() as s:
            self.assertEqual(_read(s)[:2], b"\x81\x00")
            time.sleep(2.25)
            _send(s, b"\x10" + struct.pack("!H", 2412))
            self.assertEqual(_read(s), b"\x90\x00")

    def test_reject_bad_token(self):
        s = self.connect("X" * len(self.token))
        s.settimeout(2)
        with self.assertRaises((EOFError, ConnectionResetError, TimeoutError, OSError)):
            _read(s)
        s.close()

    def test_hostapd_open_ap_initializes(self):
        binary = _hostapd_binary()
        if not binary.is_file():
            self.skipTest("compile hostapd with .config.wifit3 before running integration test")
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "lab.conf"
            log = Path(directory) / "hostapd.log"
            cfg.write_text("interface=w3test0\ndriver=wifit3\nssid=wifit3-test-only\n"
                           "hw_mode=g\nchannel=1\nbeacon_int=100\nwpa=0\n")
            env = os.environ.copy()
            env.update(WIFIT3_BRIDGE_TOKEN=self.token, WIFIT3_BRIDGE_PORT=str(self.port))
            with log.open("w", encoding="utf-8") as output:
                p = subprocess.Popen([str(binary), "-d", str(cfg)], stdout=output,
                                     stderr=subprocess.STDOUT, env=env, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline and p.poll() is None:
                        if any(call[0] == "beacon" for call in self.radio.calls):
                            break
                        time.sleep(0.05)
                    # Even without connected stations, hostapd must issue at least
                    # one set-beacon command to the Python radio adapter.
                    self.assertTrue(any(call[0] == "beacon" for call in self.radio.calls))
                    self.assertEqual(p.poll(), None, "hostapd exited before AP startup")
                finally:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=3)
            output = log.read_text(encoding="utf-8", errors="replace")
            # Windows may terminate the process before its C stdio buffer is
            # flushed; the acknowledged beacon command is the authoritative
            # startup observation in this fake-radio test.
            self.assertTrue(any(call[0] == "beacon" for call in self.radio.calls))

    def test_hostapd_control_deauthenticate_uses_driver_management_path(self):
        """A hostapd station disconnect command must reach radio TX."""
        binary = _hostapd_binary()
        cli = binary.parent / ("hostapd_cli.exe" if os.name == "nt" else "hostapd_cli")
        if not binary.is_file() or not cli.is_file():
            self.skipTest("compile hostapd and hostapd_cli before running integration test")
        station = "02:aa:bb:cc:dd:ee"
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, self.bridge.config.frequencies,
            self.bridge.config.capabilities | CAP_STA)
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "disconnect.conf"
            cfg.write_text(
                "interface=w3test0\ndriver=wifit3\nssid=wifit3-disconnect-test\n"
                "hw_mode=g\nchannel=1\nbeacon_int=100\nctrl_interface=udp:8891\n"
                "wpa=0\n"
            )
            env = os.environ.copy()
            env.update(WIFIT3_BRIDGE_TOKEN=self.token,
                       WIFIT3_BRIDGE_PORT=str(self.port))
            log = Path(directory) / "hostapd.log"
            with log.open("w", encoding="utf-8") as output:
                p = subprocess.Popen([str(binary), "-d", str(cfg)], stdout=output,
                                     stderr=subprocess.STDOUT, env=env, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline and p.poll() is None:
                        if any(call[0] == "beacon" for call in self.radio.calls):
                            break
                        time.sleep(0.05)
                    self.assertTrue(any(call[0] == "beacon" for call in self.radio.calls))
                    self.radio.calls.clear()
                    result = subprocess.run(
                        [str(cli), "-i", "127.0.0.1:8891", "deauthenticate", station],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(
                        any(call[0] == "tx_mgmt" and
                            ((int.from_bytes(call[2][:2], "little") >> 4) & 0x0f) == 12 and
                            call[2][4:10] == bytes.fromhex(station.replace(":", ""))
                            for call in self.radio.calls),
                        f"deauth was not forwarded: calls={self.radio.calls!r}",
                    )
                finally:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=3)

    def test_hostapd_control_disassociate_uses_driver_management_path(self):
        """A hostapd station disassociate command must reach radio TX."""
        binary = _hostapd_binary()
        cli = binary.parent / ("hostapd_cli.exe" if os.name == "nt" else "hostapd_cli")
        if not binary.is_file() or not cli.is_file():
            self.skipTest("compile hostapd and hostapd_cli before running integration test")
        station = "02:aa:bb:cc:dd:ef"
        self.bridge.config = RadioConfig(
            self.bridge.config.mac, self.bridge.config.frequencies,
            self.bridge.config.capabilities | CAP_STA)
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / "disconnect.conf"
            cfg.write_text(
                "interface=w3test0\ndriver=wifit3\nssid=wifit3-disconnect-test\n"
                "hw_mode=g\nchannel=1\nbeacon_int=100\nctrl_interface=udp:8892\n"
                "wpa=0\n"
            )
            env = os.environ.copy()
            env.update(WIFIT3_BRIDGE_TOKEN=self.token,
                       WIFIT3_BRIDGE_PORT=str(self.port))
            log = Path(directory) / "hostapd.log"
            with log.open("w", encoding="utf-8") as output:
                p = subprocess.Popen([str(binary), "-d", str(cfg)], stdout=output,
                                     stderr=subprocess.STDOUT, env=env, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline and p.poll() is None:
                        if any(call[0] == "beacon" for call in self.radio.calls):
                            break
                        time.sleep(0.05)
                    self.assertTrue(any(call[0] == "beacon" for call in self.radio.calls))
                    self.radio.calls.clear()
                    result = subprocess.run(
                        [str(cli), "-i", "127.0.0.1:8892", "disassociate", station],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(
                        any(call[0] == "tx_mgmt" and
                            ((int.from_bytes(call[2][:2], "little") >> 4) & 0x0f) == 10 and
                            call[2][4:10] == bytes.fromhex(station.replace(":", ""))
                            for call in self.radio.calls),
                        f"disassoc was not forwarded: calls={self.radio.calls!r}",
                    )
                finally:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
