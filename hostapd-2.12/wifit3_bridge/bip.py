"""Software BIP integrity protection for the explicit wifit3 PMF lab path.

The radio API exposes raw management frames and key installation, but no
firmware BIP offload. This module implements IEEE 802.11w BIP-CMAC-128/256
and BIP-GMAC-128/256, with strict MMIE validation and per-key IPN replay state.
"""
from __future__ import annotations

import hmac
import threading

from .ccmp import (
    CCMP_BROADCAST,
    _aes_encrypt,
    _expand_key,
    aes_gcm_encrypt,
    initial_packet_number,
)


class BipError(ValueError):
    """Malformed, unauthenticated, unsupported, or replayed BIP frame."""


WPA_ALG_BIP_CMAC_128 = 4
WPA_ALG_BIP_GMAC_128 = 10
WPA_ALG_BIP_GMAC_256 = 11
WPA_ALG_BIP_CMAC_256 = 12
BIP_KEY_FLAG_GROUP = 1 << 4
_MAX_IPN = 1 << 48
_MMIE_EID = 0x4C
_CMAC_128_MIC_LEN = 8
_MIC_256_LEN = 16
_MMIE_BASE_LEN = 8  # Key ID (2) + IPN (6), excluding EID/length and MIC.
_PROTECTED = 0x4000


def _validate_key(key: bytes, key_length: int | None = None) -> None:
    if not isinstance(key, bytes) or len(key) not in (16, 32):
        raise BipError("BIP requires a 16- or 32-octet AES key")
    if key_length is not None and len(key) != key_length:
        raise BipError(f"BIP requires a {key_length}-octet AES key")


def _left_shift(block: bytes) -> bytes:
    value = int.from_bytes(block, "big") << 1
    return (value & ((1 << 128) - 1)).to_bytes(16, "big")


def _cmac_subkeys(key: bytes) -> tuple[bytes, bytes]:
    _validate_key(key)
    expanded = _expand_key(key)
    l_value = _aes_encrypt(expanded, bytes(16))
    k1 = _left_shift(l_value)
    if l_value[0] & 0x80:
        k1 = bytes(k1[:-1]) + bytes((k1[-1] ^ 0x87,))
    k2 = _left_shift(k1)
    if k1[0] & 0x80:
        k2 = bytes(k2[:-1]) + bytes((k2[-1] ^ 0x87,))
    return k1, k2


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """Return the 128-bit AES-CMAC of *message* (RFC 4493/4494)."""
    _validate_key(key)
    if not isinstance(message, bytes):
        raise BipError("CMAC message must be bytes")
    k1, k2 = _cmac_subkeys(key)
    if message and len(message) % 16 == 0:
        blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
        last = bytes(a ^ b for a, b in zip(blocks.pop(), k1))
    else:
        blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
        tail = blocks.pop() if blocks else b""
        padded = tail + b"\x80" + bytes(15 - len(tail))
        last = bytes(a ^ b for a, b in zip(padded, k2))
    expanded = _expand_key(key)
    state = bytes(16)
    for block in blocks:
        state = _aes_encrypt(expanded, bytes(a ^ b for a, b in zip(state, block)))
    return _aes_encrypt(expanded, bytes(a ^ b for a, b in zip(state, last)))


def _mgmt_aad(frame: bytes) -> bytes:
    if len(frame) < 24:
        raise BipError("management frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if (fc >> 2) & 0x03 != 0:
        raise BipError("BIP requires an 802.11 management frame")
    if fc & 0x8000:
        raise BipError("HTC/order management frames are unsupported")
    # BIP AAD is FC (mask Retry, Power Management and More Data) followed by
    # the three MAC addresses. Sequence Control is intentionally excluded.
    masked_fc = (fc & 0xC7FF).to_bytes(2, "little")
    return masked_fc + frame[4:22]


def _mmie(key_id: int, ipn: int, mic: bytes = bytes(8)) -> bytes:
    if not 0 <= key_id <= 0xFFFF:
        raise BipError("invalid BIP key ID")
    if not 0 <= ipn < _MAX_IPN:
        raise BipError("BIP IPN exhausted")
    if len(mic) not in (_CMAC_128_MIC_LEN, _MIC_256_LEN):
        raise BipError("BIP MIC must be eight or sixteen octets")
    mmie_len = _MMIE_BASE_LEN + len(mic)
    return (bytes((_MMIE_EID, mmie_len)) + key_id.to_bytes(2, "little") +
            ipn.to_bytes(6, "little") + mic)


def _bip_cmac_protect(frame: bytes, key: bytes, *, key_id: int, ipn: int,
                      mic_len: int) -> bytes:
    _validate_key(key, 16 if mic_len == _CMAC_128_MIC_LEN else 32)
    if not isinstance(frame, bytes) or len(frame) < 24:
        raise BipError("management frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if (fc >> 2) & 0x03 != 0 or fc & _PROTECTED:
        raise BipError("frame must be an unprotected management MPDU")
    base = bytearray(frame)
    base[:2] = (fc | _PROTECTED).to_bytes(2, "little")
    zero_mmie = _mmie(key_id, ipn, bytes(mic_len))
    mic = aes_cmac(key, _mgmt_aad(bytes(base)) + bytes(base[24:]) + zero_mmie)[:8]
    if mic_len == _MIC_256_LEN:
        mic = aes_cmac(key, _mgmt_aad(bytes(base)) + bytes(base[24:]) + zero_mmie)
    return bytes(base) + _mmie(key_id, ipn, mic[:mic_len])


def bip_cmac_protect(frame: bytes, key: bytes, *, key_id: int, ipn: int) -> bytes:
    """Append an IEEE 802.11 BIP-CMAC-128 MMIE."""
    return _bip_cmac_protect(frame, key, key_id=key_id, ipn=ipn,
                             mic_len=_CMAC_128_MIC_LEN)


def bip_cmac256_protect(frame: bytes, key: bytes, *, key_id: int,
                        ipn: int) -> bytes:
    """Append an IEEE 802.11 BIP-CMAC-256 MMIE."""
    return _bip_cmac_protect(frame, key, key_id=key_id, ipn=ipn,
                             mic_len=_MIC_256_LEN)


def _bip_cmac_verify(frame: bytes, key: bytes, *, minimum_ipn: int | None,
                     expected_key_id: int | None, mic_len: int) -> int:
    _validate_key(key, 16 if mic_len == _CMAC_128_MIC_LEN else 32)
    mmie_total = 2 + _MMIE_BASE_LEN + mic_len
    if not isinstance(frame, bytes) or len(frame) < 24 + mmie_total:
        raise BipError("protected management frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if (fc >> 2) & 0x03 != 0 or not (fc & _PROTECTED):
        raise BipError("frame is not BIP-protected management")
    mmie = frame[-mmie_total:]
    if mmie[:2] != bytes((_MMIE_EID, _MMIE_BASE_LEN + mic_len)):
        raise BipError("BIP MMIE is missing or malformed")
    key_id = int.from_bytes(mmie[2:4], "little")
    ipn = int.from_bytes(mmie[4:10], "little")
    if expected_key_id is not None and key_id != expected_key_id:
        raise BipError("unexpected BIP key ID")
    if minimum_ipn is not None and ipn <= minimum_ipn:
        raise BipError("BIP replay detected")
    zero_mmie = _mmie(key_id, ipn, bytes(mic_len))
    expected = aes_cmac(key, _mgmt_aad(frame) + frame[24:-mmie_total] + zero_mmie)[:mic_len]
    if not hmac.compare_digest(mmie[10:], expected):
        raise BipError("BIP MIC verification failed")
    return ipn


def bip_cmac_verify(frame: bytes, key: bytes, *, minimum_ipn: int | None = None,
                    expected_key_id: int | None = None) -> int:
    """Verify a BIP-CMAC-128 MMIE and return its IPN."""
    return _bip_cmac_verify(frame, key, minimum_ipn=minimum_ipn,
                            expected_key_id=expected_key_id,
                            mic_len=_CMAC_128_MIC_LEN)


def bip_cmac256_verify(frame: bytes, key: bytes, *, minimum_ipn: int | None = None,
                       expected_key_id: int | None = None) -> int:
    """Verify a BIP-CMAC-256 MMIE and return its IPN."""
    return _bip_cmac_verify(frame, key, minimum_ipn=minimum_ipn,
                            expected_key_id=expected_key_id,
                            mic_len=_MIC_256_LEN)


def _bip_gmac_material(frame: bytes, key_id: int, ipn: int) -> tuple[bytes, bytes, bytes]:
    if not isinstance(frame, bytes) or len(frame) < 24:
        raise BipError("management frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if (fc >> 2) & 0x03 != 0 or fc & _PROTECTED:
        raise BipError("frame must be an unprotected management MPDU")
    base = bytearray(frame)
    base[:2] = (fc | _PROTECTED).to_bytes(2, "little")
    zero_mmie = _mmie(key_id, ipn, bytes(_MIC_256_LEN))
    aad = _mgmt_aad(bytes(base))
    nonce = bytes(base[10:16]) + ipn.to_bytes(6, "big")
    material = aad + bytes(base[24:]) + zero_mmie
    return bytes(base), nonce, material


def bip_gmac_protect(frame: bytes, key: bytes, *, key_id: int, ipn: int) -> bytes:
    """Append an IEEE 802.11 BIP-GMAC-128/256 MMIE."""
    _validate_key(key)
    base, nonce, material = _bip_gmac_material(frame, key_id, ipn)
    _ciphertext, mic = aes_gcm_encrypt(key, nonce, material, b"")
    return base + _mmie(key_id, ipn, mic)


def bip_gmac_verify(frame: bytes, key: bytes, *, minimum_ipn: int | None = None,
                    expected_key_id: int | None = None) -> int:
    """Verify a BIP-GMAC-128/256 MMIE and return its IPN."""
    _validate_key(key)
    mmie_total = 2 + _MMIE_BASE_LEN + _MIC_256_LEN
    if not isinstance(frame, bytes) or len(frame) < 24 + mmie_total:
        raise BipError("protected management frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if (fc >> 2) & 0x03 != 0 or not (fc & _PROTECTED):
        raise BipError("frame is not BIP-protected management")
    mmie = frame[-mmie_total:]
    if mmie[:2] != bytes((_MMIE_EID, _MMIE_BASE_LEN + _MIC_256_LEN)):
        raise BipError("BIP MMIE is missing or malformed")
    key_id = int.from_bytes(mmie[2:4], "little")
    ipn = int.from_bytes(mmie[4:10], "little")
    if expected_key_id is not None and key_id != expected_key_id:
        raise BipError("unexpected BIP key ID")
    if minimum_ipn is not None and ipn <= minimum_ipn:
        raise BipError("BIP replay detected")
    aad = _mgmt_aad(frame)
    nonce = frame[10:16] + ipn.to_bytes(6, "big")
    zero_mmie = _mmie(key_id, ipn, bytes(_MIC_256_LEN))
    material = aad + frame[24:-mmie_total] + zero_mmie
    _ciphertext, expected = aes_gcm_encrypt(key, nonce, material, b"")
    if not hmac.compare_digest(mmie[10:], expected):
        raise BipError("BIP MIC verification failed")
    return ipn


class BipKeyStore:
    """Thread-safe IGTK slots with independent TX and RX IPN state."""

    def __init__(self):
        self._keys: dict[int, dict[str, object]] = {}
        self._lock = threading.RLock()
        self._tx_index = 4

    def install(self, alg: int, index: int, peer: bytes, flags: int,
                sequence: bytes, key: bytes) -> bool:
        if not isinstance(peer, bytes) or len(peer) != 6:
            return False
        if not isinstance(sequence, bytes) or len(sequence) not in (0, 6):
            return False
        if alg == 0:
            if key or sequence:
                return False
            with self._lock:
                self._keys.pop(index, None)
            return True
        if (peer != CCMP_BROADCAST or index not in (4, 5) or
                not isinstance(key, bytes)):
            return False
        valid = {
            WPA_ALG_BIP_CMAC_128: 16,
            WPA_ALG_BIP_GMAC_128: 16,
            WPA_ALG_BIP_GMAC_256: 32,
            WPA_ALG_BIP_CMAC_256: 32,
        }
        if alg not in valid or len(key) != valid[alg]:
            return False
        ipn = initial_packet_number(sequence)
        if ipn >= _MAX_IPN:
            return False
        with self._lock:
            self._keys[index] = {
                "key": bytes(key), "alg": int(alg), "flags": int(flags),
                "tx_ipn": ipn, "rx_ipn": ipn - 1,
            }
            self._tx_index = index
        return True

    def last_tx_tsc(self, index: int) -> int | None:
        """Latest used IPN for IGTK index 4 or 5. An unused key reports 0."""
        if index not in (4, 5):
            return None
        with self._lock:
            slot = self._keys.get(index)
            if slot is None:
                return None
            return max(0, int(slot["tx_ipn"]) - 1)

    def protect(self, frame: bytes) -> bytes:
        with self._lock:
            slot = self._keys.get(self._tx_index)
            if slot is None:
                raise BipError("no BIP TX key")
            ipn = int(slot["tx_ipn"])
            key = bytes(slot["key"])
            alg = int(slot["alg"])
            if alg == WPA_ALG_BIP_CMAC_128:
                protected = bip_cmac_protect(
                    frame, key, key_id=self._tx_index, ipn=ipn)
            elif alg == WPA_ALG_BIP_CMAC_256:
                protected = bip_cmac256_protect(
                    frame, key, key_id=self._tx_index, ipn=ipn)
            else:
                protected = bip_gmac_protect(
                    frame, key, key_id=self._tx_index, ipn=ipn)
            slot["tx_ipn"] = ipn + 1
            return protected

    def verify(self, frame: bytes) -> int:
        # BIP-CMAC-128 uses an 18-byte MMIE; BIP-GMAC and the 256-bit CMAC
        # paths use a 26-byte MMIE. Parse the trailing element before looking
        # up the key so RX verification works for every enabled algorithm.
        candidates = []
        for total, mmie_len in ((18, 16), (26, 24)):
            if (len(frame) >= 24 + total and
                    frame[-total] == _MMIE_EID and
                    frame[-total + 1] == mmie_len):
                candidates.append((total, mmie_len))
        if not candidates:
            raise BipError("protected management frame is too short or MMIE is malformed")
        with self._lock:
            slot = None
            key_id = None
            total = None
            for candidate_total, _mmie_len in candidates:
                candidate_id = int.from_bytes(
                    frame[-candidate_total + 2:-candidate_total + 4], "little")
                candidate_slot = self._keys.get(candidate_id)
                if candidate_slot is not None:
                    slot = candidate_slot
                    key_id = candidate_id
                    total = candidate_total
                    break
            if slot is None or key_id is None or total is None:
                raise BipError("no BIP RX key")
            key = bytes(slot["key"])
            alg = int(slot["alg"])
            expected_total = 18 if alg == WPA_ALG_BIP_CMAC_128 else 26
            if total != expected_total:
                raise BipError("BIP MMIE length does not match key algorithm")
            if alg == WPA_ALG_BIP_CMAC_128:
                ipn = bip_cmac_verify(
                    frame, key, minimum_ipn=int(slot["rx_ipn"]),
                    expected_key_id=key_id)
            elif alg == WPA_ALG_BIP_CMAC_256:
                ipn = bip_cmac256_verify(
                    frame, key, minimum_ipn=int(slot["rx_ipn"]),
                    expected_key_id=key_id)
            else:
                ipn = bip_gmac_verify(
                    frame, key, minimum_ipn=int(slot["rx_ipn"]),
                    expected_key_id=key_id)
            slot["rx_ipn"] = ipn
            return ipn

    def has_key(self) -> bool:
        with self._lock:
            return bool(self._keys)

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {
                str(index): {
                    "alg": int(slot["alg"]),
                    "flags": int(slot["flags"]),
                    "tx_ipn": int(slot["tx_ipn"]),
                    "rx_ipn": int(slot["rx_ipn"]),
                }
                for index, slot in self._keys.items()
            }

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()
