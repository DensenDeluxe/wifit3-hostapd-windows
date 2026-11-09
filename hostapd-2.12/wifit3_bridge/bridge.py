"""wifit3 / hostapd-2.12 portable AP driver bridge (standard library only).

This module intentionally does not reach directly into chip mini-driver private
APIs. Call it from a wifit3 Focus-owned radio session through RadioCallbacks;
the radio/session owner remains responsible for USB transactions, channel lease,
beacon timing, key slots and 802.11 TX/RX delivery.

Protocol: 4-byte network byte-order length, 1-byte opcode, payload.
Authentication: 256-bit random shared secret, loopback-only. One connection.
No credential harvesting or debug-logging of EAP payload/key material.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import socket
import struct
import threading
from typing import Callable, Protocol

CAP_TX_MGMT = 1
CAP_TX_EAPOL = 2
CAP_BEACON = 4
CAP_KEY = 8
CAP_STA = 16
CAP_RX_MGMT = 32
CAP_RX_EAPOL = 64
CAP_SET_FREQ = 128
CAP_BIP = 256
CAP_SAE = 512
CAP_ACCOUNTING = 1024
CAP_GCMP = 2048
CAP_GCMP_256 = 4096
CAP_CCMP_256 = 8192
CAP_TKIP = 16384
REQUIRED_AP = CAP_TX_MGMT | CAP_RX_MGMT | CAP_BEACON | CAP_SET_FREQ
MAX_PACKET = 16384
MAX_FREQ = 64
VERSION = 1


class ProtocolError(Exception):
    """Malformed, unauthorized or unsupported bridge command."""


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    parts = bytearray()
    while len(parts) < length:
        block = sock.recv(length - len(parts))
        if not block:
            raise EOFError("bridge disconnected")
        parts.extend(block)
    return bytes(parts)


def _read(sock: socket.socket) -> bytes:
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    if not 1 <= length <= MAX_PACKET:
        raise ProtocolError("invalid packet size")
    return _recv_exact(sock, length)


def _send(sock: socket.socket, payload: bytes) -> None:
    if not 1 <= len(payload) <= MAX_PACKET:
        raise ProtocolError("invalid outbound packet size")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


class RadioPort(Protocol):
    """Implement these using an exclusively leased wifit3 USB mini-driver.

    A successful response means completion by the hardware/firmware, not just
    queue submission. In particular, install_key must reject unsupported cipher
    and key slot types. Protect AP beacon timing and ownership in wifit3.
    """

    def set_frequency(self, mhz: int) -> bool: ...
    def set_beacon(self, head: bytes, tail: bytes, interval_tu: int, dtim: int) -> bool: ...
    def tx_mgmt(self, frame: bytes, freq_mhz: int, noack: bool,
                no_encrypt: bool, wait_ms: int) -> bool | int: ...
    def tx_eapol(self, destination: bytes, source: bytes, payload: bytes, encrypt: bool) -> bool: ...
    def install_key(self, alg: int, index: int, peer: bytes, flags: int,
                    sequence: bytes, key: bytes) -> bool: ...
    def station_add(self, addr: bytes, aid: int, capability: int, update: bool) -> bool: ...
    def station_flags(self, addr: bytes, total: int, enable: int, mask: int) -> bool: ...
    def station_remove(self, addr: bytes) -> bool: ...


@dataclass(frozen=True)
class RadioConfig:
    mac: bytes
    frequencies: tuple[int, ...]
    capabilities: int

    def __post_init__(self) -> None:
        if len(self.mac) != 6 or not 1 <= len(self.frequencies) <= MAX_FREQ:
            raise ValueError("radio must supply 6-byte MAC and 1..64 frequencies")
        if len(set(self.frequencies)) != len(self.frequencies):
            raise ValueError("duplicate radio frequency")
        if any(not ((2412 <= freq <= 2472 and (freq - 2412) % 5 == 0) or
                    freq == 2484 or (5000 <= freq <= 5895 and freq % 5 == 0))
               for freq in self.frequencies):
            raise ValueError("unsupported frequency; v1 models only legacy 2.4/5 GHz")
        if self.capabilities & REQUIRED_AP != REQUIRED_AP:
            raise ValueError("required AP/MLME capabilities missing")


class Wifit3Bridge:
    """Session-oriented loopback listener; run serve_once on a dedicated thread.

    RX injection can be called from a wifit3 receive callback in another thread;
    send is locked so event frames never interleave with command ACK frames.
    The caller should route only frames from the Focus-owned AP radio.
    """

    def __init__(self, radio: RadioPort, config: RadioConfig,
                 token: str, host: str = "127.0.0.1", port: int = 6791):
        if host != "127.0.0.1":
            raise ValueError("only literal IPv4 loopback binding is permitted")
        if not 32 <= len(token) <= 128 or not token.isascii():
            raise ValueError("token must be 32..128 ASCII chars, use secrets.token_hex(32)")
        self.radio = radio
        self.config = config
        self.token = token.encode("ascii")
        self.host = host
        self.port = port
        self._client: socket.socket | None = None
        self._writer_lock = threading.Lock()
        self._connected = threading.Event()
        self._listener: socket.socket | None = None
        self._stop = threading.Event()

    def start_listener(self) -> int:
        """Bind before launching hostapd. Port 0 obtains an ephemeral test port."""
        if self._listener:
            raise RuntimeError("listener already started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        sock.settimeout(0.5)
        self._listener = sock
        self.port = sock.getsockname()[1]
        return self.port

    def close(self) -> None:
        self._stop.set()
        with self._writer_lock:
            if self._client:
                try:
                    self._client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._client.close()
                self._client = None
        if self._listener:
            self._listener.close()
            self._listener = None
        self._connected.clear()

    def connected(self) -> bool:
        return self._connected.is_set()

    def _send_connected(self, payload: bytes) -> None:
        with self._writer_lock:
            if not self._connected.is_set() or self._client is None:
                raise RuntimeError("no authenticated hostapd connection")
            _send(self._client, payload)

    def on_mgmt_rx(self, frame: bytes, freq_mhz: int, signal_dbm: int = -50) -> None:
        if not self.config.capabilities & CAP_RX_MGMT:
            raise RuntimeError("management RX unavailable")
        if not 24 <= len(frame) <= MAX_PACKET - 6:
            raise ValueError("invalid 802.11 management frame length")
        if not -128 <= signal_dbm <= 127:
            raise ValueError("invalid signal")
        packet = struct.pack("!B Hb H", 0x30, freq_mhz, signal_dbm, len(frame)) + frame
        self._send_connected(packet)

    def on_eapol_rx(self, source: bytes, payload: bytes) -> None:
        if not self.config.capabilities & CAP_RX_EAPOL:
            raise RuntimeError("EAPOL RX unavailable")
        if len(source) != 6 or not 4 <= len(payload) <= MAX_PACKET - 9:
            raise ValueError("invalid EAPOL data")
        self._send_connected(b"\x31" + source + struct.pack("!H", len(payload)) + payload)

    def on_data_rx(self, source: bytes, destination: bytes, frame_len: int) -> None:
        """Relay observed raw data-frame metadata for station accounting.

        The bridge deliberately carries metadata only: the hostapd driver does
        not receive or inspect user payloads through this event. Counters are
        therefore explicitly limited to frames observed by the wifit3 RX hook.
        """
        if not self.config.capabilities & CAP_ACCOUNTING:
            raise RuntimeError("station accounting unavailable")
        if (len(source) != 6 or len(destination) != 6 or
                not 24 <= frame_len <= MAX_PACKET):
            raise ValueError("invalid data accounting metadata")
        self._send_connected(b"\x32" + source + destination +
                             struct.pack("!I", frame_len))

    def _hello(self, sock: socket.socket) -> bool:
        hello = _read(sock)
        if len(hello) < 4 or hello[0] != 1 or hello[1] != VERSION:
            return False
        tlen = hello[2]
        if not 32 <= tlen <= 128 or len(hello) < tlen + 4:
            return False
        if not hmac.compare_digest(hello[3:3+tlen], self.token):
            return False
        nlen = hello[3+tlen]
        if not 1 <= nlen <= 128 or len(hello) != 4+tlen+nlen:
            return False
        # No shell, file or dynamic import based on interface name.
        ack = (b"\x81\x00" + self.config.mac +
               struct.pack("!IB", self.config.capabilities, len(self.config.frequencies)) +
               b"".join(struct.pack("!H", f) for f in self.config.frequencies))
        _send(sock, ack)
        return True

    def _command(self, payload: bytes) -> bytes:
        """Return the command reply: ``0x90`` plus status, or ``0x91`` plus PN.

        Status 0 is success. Status 2 is a submitted management frame that an
        armed link-ACK wait did not acknowledge. Status 1 is a hard failure.
        Opcode 0x18 answers with the 6-octet little-endian last-used PN.
        """
        fail = b"\x90\x01"
        if not payload:
            return fail
        op = payload[0]
        caps = self.config.capabilities
        d = payload
        try:
            if op == 0x10 and len(d) == 3 and (caps & CAP_SET_FREQ):
                (freq,) = struct.unpack("!H", d[1:3])
                ok = freq in self.config.frequencies and bool(self.radio.set_frequency(freq))
                return b"\x90\x00" if ok else fail
            if op == 0x11 and len(d) >= 8 and (caps & CAP_BEACON):
                interval, dtim, hlen, tlen = struct.unpack("!HBHH", d[1:8])
                if len(d) != 8 + hlen + tlen:
                    return fail
                ok = bool(self.radio.set_beacon(d[8:8+hlen], d[8+hlen:], interval, dtim))
                return b"\x90\x00" if ok else fail
            if op == 0x12 and len(d) >= 8 and (caps & CAP_TX_MGMT):
                freq, flags, wait, flen = struct.unpack("!HBHH", d[1:8])
                if len(d) != flen+8 or flen < 24 or flags & ~3:
                    return fail
                result = self.radio.tx_mgmt(d[8:], freq, bool(flags & 1),
                                             bool(flags & 2), wait)
                if result == 2:
                    return b"\x90\x02"
                return b"\x90\x00" if result else fail
            if op == 0x13 and len(d) >= 16 and (caps & CAP_TX_EAPOL):
                flen = struct.unpack("!H", d[14:16])[0]
                if len(d) != flen+16 or flen < 4:
                    return fail
                ok = bool(self.radio.tx_eapol(d[1:7], d[7:13], d[16:], bool(d[13])))
                return b"\x90\x00" if ok else fail
            if op == 0x14 and len(d) >= 16 and (caps & CAP_KEY):
                seq_len, key_len, flags = struct.unpack("!BHI", d[3:10])
                if len(d) != 16 + seq_len + key_len or key_len > 256 or seq_len > 16:
                    return fail
                ok = bool(self.radio.install_key(d[1], d[2], d[10:16], flags,
                                                 d[16:16+seq_len], d[16+seq_len:]))
                return b"\x90\x00" if ok else fail
            if op == 0x15 and len(d) == 12 and (caps & CAP_STA):
                aid, capability = struct.unpack("!HH", d[7:11])
                ok = bool(self.radio.station_add(d[1:7], aid, capability, bool(d[11])))
                return b"\x90\x00" if ok else fail
            if op == 0x16 and len(d) == 19 and (caps & CAP_STA):
                total, on, mask = struct.unpack("!III", d[7:19])
                ok = bool(self.radio.station_flags(d[1:7], total, on, mask))
                return b"\x90\x00" if ok else fail
            if op == 0x17 and len(d) == 7 and (caps & CAP_STA):
                ok = bool(self.radio.station_remove(d[1:7]))
                return b"\x90\x00" if ok else fail
            if op == 0x18 and len(d) == 8 and (caps & CAP_KEY):
                getter = getattr(self.radio, "tx_tsc", None)
                if not callable(getter):
                    return fail
                value = getter(d[1:7], d[7])
                if not isinstance(value, int) or isinstance(value, bool):
                    return fail
                if not 0 <= value < (1 << 48):
                    return fail
                return bytes((0x91,)) + value.to_bytes(6, "little")
        except (ValueError, NotImplementedError, OSError, RuntimeError, TimeoutError):
            return fail
        return fail

    def serve_once(self) -> None:
        if not self._listener:
            raise RuntimeError("call start_listener before serve_once")
        while not self._stop.is_set():
            try:
                sock, _address = self._listener.accept()
                break
            except socket.timeout:
                continue
            except OSError:
                return
        else:
            return
        with sock:
            sock.settimeout(2.0)
            try:
                if not self._hello(sock):
                    return
                # 2s timeout applies only to handshake/authentication. A hostapd
                # AP may be legitimately idle for hours; the IPC connection
                # must not time out between commands.
                sock.settimeout(None)
                with self._writer_lock:
                    self._client = sock
                    self._connected.set()
                while not self._stop.is_set():
                    command = _read(sock)
                    self._send_connected(self._command(command))
            except (EOFError, OSError, ProtocolError, RuntimeError):
                pass
            finally:
                with self._writer_lock:
                    self._connected.clear()
                    self._client = None


class Wifit3RadioCallbacks:
    """Explicit integration seam, called inside a wifit3 Focus radio lease.

    Supply operations using the existing mini-driver, not an independent USB
    reader. Missing operations fail closed. Do NOT advertise unsupported caps.
    """
    def __init__(self, *, set_frequency: Callable | None = None,
                 set_beacon: Callable | None = None, tx_mgmt: Callable | None = None,
                 tx_eapol: Callable | None = None, install_key: Callable | None = None,
                 station_add: Callable | None = None, station_flags: Callable | None = None,
                 station_remove: Callable | None = None):
        self._callbacks = {k: v for k, v in locals().items()
                           if k not in ("self",) and v is not None}

    def __getattr__(self, name: str):
        callback = self._callbacks.get(name)
        if callback is None:
            raise NotImplementedError(f"wifit3 radio operation not implemented: {name}")
        return callback
