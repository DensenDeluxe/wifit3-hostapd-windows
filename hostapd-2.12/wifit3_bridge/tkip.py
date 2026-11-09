"""Software TKIP data protection for the explicit wifit3 lab path.

The implementation is deliberately self-contained: TKIP phase-1/phase-2
mixing, Michael MIC, RC4, ICV and per-key replay state are all handled here.
It is not a replacement for a chipset TKIP engine or a Windows Ethernet path.
"""
from __future__ import annotations

import hmac
import threading
import zlib

from .ccmp import (
    CCMP_BROADCAST,
    CCMP_KEY_FLAG_GROUP,
    CCMP_KEY_FLAG_NEXT,
    CCMP_KEY_FLAG_PAIRWISE,
    CcmpError,
    _SBOX,
    _xtime,
    _header_length,
    initial_packet_number,
)


WPA_ALG_NONE = 0
WPA_ALG_TKIP = 2
TKIP_KEY_FLAG_MODIFY = 1 << 0
TKIP_KEY_FLAG_RX = 1 << 2
TKIP_KEY_FLAG_TX = 1 << 3
TKIP_KEY_FLAG_GROUP = CCMP_KEY_FLAG_GROUP
TKIP_KEY_FLAG_PAIRWISE = CCMP_KEY_FLAG_PAIRWISE
TKIP_KEY_FLAG_NEXT = CCMP_KEY_FLAG_NEXT

_MAX_TSC = 1 << 48


class TkipError(CcmpError):
    """Malformed, unauthenticated or replayed TKIP frame."""


def _u16(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _sbox16(value: int) -> int:
    """802.11i TKIP S-box from the AES S-box, without a 128 KiB table."""
    lo = _SBOX[value & 0xff]
    hi = _SBOX[(value >> 8) & 0xff]
    lo_entry = (_xtime(lo) << 8) | (lo ^ _xtime(lo))
    hi_entry = (_xtime(hi) << 8) | (hi ^ _xtime(hi))
    return (lo_entry ^ ((hi_entry << 8) | (hi_entry >> 8))) & 0xffff


def tkip_phase1(tk: bytes, transmitter: bytes, iv32: int) -> tuple[int, ...]:
    """Return the five-word TKIP TTAK phase-1 result."""
    if not isinstance(tk, bytes) or len(tk) != 16:
        raise TkipError("TKIP temporal key must be 16 octets")
    if not isinstance(transmitter, bytes) or len(transmitter) != 6:
        raise TkipError("TKIP transmitter address must be six octets")
    if not 0 <= iv32 < (1 << 32):
        raise TkipError("TKIP IV32 out of range")
    ttak = [
        iv32 & 0xffff,
        (iv32 >> 16) & 0xffff,
        _u16(transmitter[0:2]),
        _u16(transmitter[2:4]),
        _u16(transmitter[4:6]),
    ]
    for i in range(8):
        j = 2 * (i & 1)
        ttak[0] = (ttak[0] + _sbox16(ttak[4] ^ _u16(tk[j:j + 2]))) & 0xffff
        ttak[1] = (ttak[1] + _sbox16(ttak[0] ^ _u16(tk[4 + j:6 + j]))) & 0xffff
        ttak[2] = (ttak[2] + _sbox16(ttak[1] ^ _u16(tk[8 + j:10 + j]))) & 0xffff
        ttak[3] = (ttak[3] + _sbox16(ttak[2] ^ _u16(tk[12 + j:14 + j]))) & 0xffff
        ttak[4] = (ttak[4] + _sbox16(ttak[3] ^ _u16(tk[j:j + 2])) + i) & 0xffff
    return tuple(ttak)


def _ror16(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (16 - bits))) & 0xffff


def tkip_phase2(tk: bytes, ttak: tuple[int, ...], iv16: int) -> bytes:
    """Return the 16-octet WEP seed/RC4 key for one TKIP TSC."""
    if not isinstance(tk, bytes) or len(tk) != 16:
        raise TkipError("TKIP temporal key must be 16 octets")
    if len(ttak) != 5 or not 0 <= iv16 < (1 << 16):
        raise TkipError("invalid TKIP phase-2 inputs")
    ppk = [int(x) & 0xffff for x in ttak]
    ppk.append((ppk[4] + iv16) & 0xffff)
    for i in range(6):
        ppk[i] = (ppk[i] + _sbox16(
            ppk[(i - 1) % 6] ^ _u16(tk[2 * i:2 * i + 2]))) & 0xffff
    ppk[0] = (ppk[0] + _ror16(ppk[5] ^ _u16(tk[12:14]), 1)) & 0xffff
    ppk[1] = (ppk[1] + _ror16(ppk[0] ^ _u16(tk[14:16]), 1)) & 0xffff
    for i in range(2, 6):
        ppk[i] = (ppk[i] + _ror16(ppk[i - 1], 1)) & 0xffff
    seed = bytearray((iv16 >> 8, ((iv16 >> 8) | 0x20) & 0x7f, iv16 & 0xff))
    seed.append(((ppk[5] ^ _u16(tk[:2])) >> 1) & 0xff)
    for word in ppk:
        seed.extend(word.to_bytes(2, "little"))
    return bytes(seed)


def _rc4(key: bytes, data: bytes) -> bytes:
    if not key or not isinstance(data, bytes):
        raise TkipError("invalid RC4 input")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xff
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xff
        j = (j + state[i]) & 0xff
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 0xff])
    return bytes(out)


def _michael_block(left: int, right: int) -> tuple[int, int]:
    left &= 0xffffffff
    right &= 0xffffffff
    right ^= ((left << 17) | (left >> 15)) & 0xffffffff
    left = (left + right) & 0xffffffff
    right ^= ((left & 0x00ff00ff) << 8) | ((left & 0xff00ff00) >> 8)
    right &= 0xffffffff
    left = (left + right) & 0xffffffff
    right ^= ((left << 3) | (left >> 29)) & 0xffffffff
    left = (left + right) & 0xffffffff
    right ^= ((left >> 2) | (left << 30)) & 0xffffffff
    right &= 0xffffffff
    left = (left + right) & 0xffffffff
    return left, right


def michael_mic_core(key: bytes, message: bytes) -> bytes:
    """Compute the Annex-H Michael primitive over an arbitrary byte string."""
    if not isinstance(key, bytes) or len(key) != 8:
        raise TkipError("Michael key must be eight octets")
    if not isinstance(message, bytes):
        raise TkipError("Michael message must be bytes")
    left = int.from_bytes(key[:4], "little")
    right = int.from_bytes(key[4:], "little")
    offset = 0
    while offset + 4 <= len(message):
        left ^= int.from_bytes(message[offset:offset + 4], "little")
        left, right = _michael_block(left, right)
        offset += 4
    remainder = message[offset:]
    padded = remainder + b"\x5a" + bytes(3 - len(remainder))
    left ^= int.from_bytes(padded, "little")
    left, right = _michael_block(left, right)
    left, right = _michael_block(left, right)
    return left.to_bytes(4, "little") + right.to_bytes(4, "little")


def _michael_header(frame: bytes) -> bytes:
    try:
        header_len = _header_length(frame)
    except CcmpError as error:
        raise TkipError(str(error)) from error
    fc = int.from_bytes(frame[:2], "little")
    ds = fc & 0x0300
    if ds == 0x0100:  # ToDS
        destination, source = frame[16:22], frame[10:16]
    elif ds == 0x0200:  # FromDS
        destination, source = frame[4:10], frame[16:22]
    elif ds == 0x0300:  # WDS
        if len(frame) < 30:
            raise TkipError("truncated WDS frame")
        destination, source = frame[16:22], frame[24:30]
    else:
        destination, source = frame[4:10], frame[10:16]
    priority = frame[header_len - 2] & 0x0f if fc & 0x0080 else 0
    return bytes(destination) + bytes(source) + bytes((priority, 0, 0, 0))


def michael_mic(key: bytes, frame: bytes, payload: bytes | None = None) -> bytes:
    """Compute Michael over the 802.11 DA/SA/priority pseudo-header."""
    try:
        header_len = _header_length(frame)
    except CcmpError as error:
        raise TkipError(str(error)) from error
    if payload is None:
        payload = frame[header_len:]
    if not isinstance(payload, bytes):
        raise TkipError("Michael payload must be bytes")
    return michael_mic_core(key, _michael_header(frame) + payload)


def _key_parts(key: bytes) -> tuple[bytes, bytes, bytes]:
    if not isinstance(key, bytes) or len(key) != 32:
        raise TkipError("TKIP key must contain 32 octets")
    return key[:16], key[16:24], key[24:32]


def _mic_key(key: bytes, frame: bytes) -> bytes:
    _tk, tx_mic, rx_mic = _key_parts(key)
    fc = int.from_bytes(frame[:2], "little")
    return tx_mic if fc & 0x0200 else rx_mic


def _validate_data_frame(frame: bytes, *, protected: bool) -> int:
    if not isinstance(frame, bytes):
        raise TkipError("frame must be bytes")
    try:
        header_len = _header_length(frame)
    except CcmpError as error:
        raise TkipError(str(error)) from error
    fc = int.from_bytes(frame[:2], "little")
    if bool(fc & 0x4000) != protected:
        raise TkipError("unexpected TKIP Protected flag")
    return header_len


def tkip_encrypt_mpdu(frame: bytes, key: bytes, tsc: int,
                      key_id: int = 0) -> bytes:
    """Encrypt one unfragmented 802.11 data MPDU with TKIP."""
    header_len = _validate_data_frame(frame, protected=False)
    tk, tx_mic, rx_mic = _key_parts(key)
    if not 0 < tsc < (1 << 48) or not 0 <= key_id <= 3:
        raise TkipError("invalid TKIP TSC or key index")
    iv16, iv32 = tsc & 0xffff, tsc >> 16
    seed = tkip_phase2(tk, tkip_phase1(tk, frame[10:16], iv32), iv16)
    mic_key = tx_mic if int.from_bytes(frame[:2], "little") & 0x0200 else rx_mic
    plaintext = frame[header_len:] + michael_mic(mic_key, frame)
    plaintext += (zlib.crc32(plaintext) & 0xffffffff).to_bytes(4, "little")
    iv = seed[:3] + bytes(((key_id << 6) | 0x20,)) + iv32.to_bytes(4, "little")
    header = bytearray(frame[:header_len])
    header[1] |= 0x40
    return bytes(header) + iv + _rc4(seed, plaintext)


def tkip_decrypt_mpdu(frame: bytes, key: bytes, *, source: bytes | None = None,
                      minimum_tsc: int = -1) -> tuple[int, bytes]:
    """Verify and decrypt one TKIP MPDU."""
    header_len = _validate_data_frame(frame, protected=True)
    _key_parts(key)
    if source is not None and (not isinstance(source, bytes) or len(source) != 6):
        raise TkipError("invalid TKIP source")
    if source is not None and frame[10:16] != source:
        raise TkipError("TKIP source address mismatch")
    body = frame[header_len:]
    if len(body) < 8 + 8 + 4:
        raise TkipError("TKIP frame is too short")
    key_id = body[3]
    if not key_id & 0x20:
        raise TkipError("TKIP Extended IV is missing")
    iv16 = (body[0] << 8) | body[2]
    iv32 = int.from_bytes(body[4:8], "little")
    tsc = (iv32 << 16) | iv16
    if tsc <= minimum_tsc:
        raise TkipError("TKIP replay detected")
    tk, _tx_mic, _rx_mic = _key_parts(key)
    seed = tkip_phase2(tk, tkip_phase1(tk, frame[10:16], iv32), iv16)
    plain_with_mic_icv = _rc4(seed, body[8:])
    if len(plain_with_mic_icv) < 12:
        raise TkipError("TKIP payload is too short")
    data_and_mic = plain_with_mic_icv[:-4]
    received_icv = plain_with_mic_icv[-4:]
    expected_icv = (zlib.crc32(data_and_mic) & 0xffffffff).to_bytes(4, "little")
    if not hmac.compare_digest(received_icv, expected_icv):
        raise TkipError("TKIP ICV verification failed")
    payload = data_and_mic[:-8]
    received_mic = data_and_mic[-8:]
    plain_header = bytearray(frame[:header_len])
    plain_header[1] &= ~0x40
    plain = bytes(plain_header) + payload
    if not hmac.compare_digest(received_mic, michael_mic(_mic_key(key, frame), plain)):
        raise TkipError("TKIP Michael MIC verification failed")
    return tsc, plain


class TkipKeyStore:
    """Thread-safe TKIP key slots with TX/RX TSC replay state."""

    def __init__(self):
        self._keys: dict[tuple[bytes, int], dict[str, object]] = {}
        self._next_keys: dict[tuple[bytes, int], dict[str, object]] = {}
        self._lock = threading.RLock()
        self._group_index = 0

    def install(self, alg: int, index: int, peer: bytes, flags: int,
                sequence: bytes, key: bytes) -> bool:
        if not isinstance(peer, bytes) or len(peer) != 6:
            return False
        if not isinstance(sequence, bytes) or len(sequence) not in (0, 6):
            return False
        if not isinstance(key, bytes) or not 0 <= index <= 3:
            return False
        slot = (peer, index)
        with self._lock:
            if alg == WPA_ALG_NONE:
                if key or sequence:
                    return False
                self._keys.pop(slot, None)
                self._next_keys.pop(slot, None)
                return True
            if alg != WPA_ALG_TKIP or len(key) != 32:
                return False
            initial = initial_packet_number(sequence)
            if not 0 <= initial < (1 << 48):
                return False
            candidate = {
                "key": bytes(key),
                "flags": int(flags),
                "alg": WPA_ALG_TKIP,
                "tx_tsc": max(1, initial),
                "rx_tsc": initial - 1,
            }
            if (flags & TKIP_KEY_FLAG_NEXT and
                    flags & TKIP_KEY_FLAG_PAIRWISE and
                    peer != CCMP_BROADCAST):
                self._next_keys[slot] = candidate
            elif (flags & TKIP_KEY_FLAG_PAIRWISE and
                  peer != CCMP_BROADCAST):
                previous = self._next_keys.pop(slot, None)
                if previous is not None and previous["key"] == bytes(key):
                    previous["flags"] = int(flags)
                    self._keys[slot] = previous
                else:
                    self._keys[slot] = candidate
            else:
                self._keys[slot] = candidate
            if peer == CCMP_BROADCAST or flags & TKIP_KEY_FLAG_GROUP:
                self._group_index = index
            return True

    def _slot_for(self, peer: bytes, index: int, *, group_ok: bool = True):
        slot = self._keys.get((peer, index))
        if slot is None and group_ok:
            slot = self._keys.get((CCMP_BROADCAST, index))
        return slot

    @staticmethod
    def _is_group(peer: bytes) -> bool:
        return bool(peer[0] & 1)

    def last_tx_tsc(self, peer: bytes, index: int) -> int | None:
        """Latest used TX TSC. An unused key reports 0."""
        if not isinstance(peer, bytes) or len(peer) != 6 or not 0 <= index <= 3:
            return None
        with self._lock:
            slot = self._keys.get((peer, index))
            if slot is None and not self._is_group(peer):
                slot = self._next_keys.get((peer, index))
            if slot is None:
                return None
            return max(0, int(slot["tx_tsc"]) - 1)

    def encrypt(self, frame: bytes, destination: bytes) -> bytes:
        if not isinstance(destination, bytes) or len(destination) != 6:
            raise TkipError("invalid TKIP destination")
        with self._lock:
            index = self._group_index if self._is_group(destination) else 0
            slot = self._slot_for(destination, index,
                                  group_ok=self._is_group(destination))
            if slot is None and not self._is_group(destination):
                slot = self._next_keys.get((destination, index))
            if slot is None:
                raise TkipError("no TKIP TX key for destination")
            tsc = int(slot["tx_tsc"])
            if tsc >= (1 << 48):
                raise TkipError("TKIP TX TSC exhausted")
            protected = tkip_encrypt_mpdu(frame, bytes(slot["key"]), tsc, index)
            slot["tx_tsc"] = tsc + 1
            return protected

    def decrypt(self, frame: bytes, source: bytes) -> tuple[int, bytes]:
        if not isinstance(source, bytes) or len(source) != 6:
            raise TkipError("invalid TKIP source")
        header_len = _validate_data_frame(frame, protected=True)
        if len(frame) < header_len + 4:
            raise TkipError("truncated TKIP frame")
        index = (frame[header_len + 3] >> 6) & 3
        destination = frame[4:10]
        with self._lock:
            slot = self._slot_for(source, index, group_ok=False)
            next_slot = self._next_keys.get((source, index))
            if slot is None and next_slot is not None:
                slot = next_slot
            if slot is None and self._is_group(destination):
                slot = self._slot_for(CCMP_BROADCAST, index, group_ok=True)
            if slot is None:
                raise TkipError("no TKIP RX key for source")
            try:
                tsc, plain = tkip_decrypt_mpdu(
                    frame, bytes(slot["key"]), source=source,
                    minimum_tsc=int(slot["rx_tsc"]))
            except TkipError:
                if next_slot is None or slot is next_slot:
                    raise
                tsc, plain = tkip_decrypt_mpdu(
                    frame, bytes(next_slot["key"]), source=source,
                    minimum_tsc=int(next_slot["rx_tsc"]))
                slot = next_slot
            slot["rx_tsc"] = tsc
            return tsc, plain

    def snapshot(self) -> dict[str, dict[str, int | bool]]:
        with self._lock:
            snapshot = {
                f"{peer.hex(':')}/{index}": {
                    "alg": int(slot["alg"]),
                    "flags": int(slot["flags"]),
                    "tx_tsc": int(slot["tx_tsc"]),
                    "rx_tsc": int(slot["rx_tsc"]),
                }
                for (peer, index), slot in self._keys.items()
            }
            for (peer, index), slot in self._next_keys.items():
                snapshot[f"{peer.hex(':')}/{index}/next"] = {
                    "alg": int(slot["alg"]),
                    "flags": int(slot["flags"]),
                    "tx_tsc": int(slot["tx_tsc"]),
                    "rx_tsc": int(slot["rx_tsc"]),
                }
            return snapshot

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()
            self._next_keys.clear()
