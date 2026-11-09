"""Small, dependency-free IEEE 802.11 CCMP/GCMP implementation.

The hostapd bridge implements AES-128-CCM with an eight-octet MIC for WPA2/
CCMP, AES-256-CCM with a sixteen-octet MIC for CCMP-256, and AES-GCM for
GCMP-128/256. Callers must provide their own key lifecycle and replay state;
the packet helpers reject malformed frames and invalid packet numbers.
"""
from __future__ import annotations

import hmac
import threading


class CcmpError(ValueError):
    """Malformed, unauthenticated, or replayed CCMP frame."""


class GcmpError(CcmpError):
    """Malformed, unauthenticated, or replayed GCMP frame."""


WPA_ALG_NONE = 0
WPA_ALG_CCMP = 3
WPA_ALG_CCMP_256 = 9
CCMP_KEY_FLAG_MODIFY = 1 << 0
CCMP_KEY_FLAG_RX = 1 << 2
CCMP_KEY_FLAG_TX = 1 << 3
CCMP_KEY_FLAG_GROUP = 1 << 4
CCMP_KEY_FLAG_PAIRWISE = 1 << 5
CCMP_KEY_FLAG_NEXT = 1 << 7
CCMP_KEY_FLAG_PAIRWISE_NEXT = CCMP_KEY_FLAG_PAIRWISE | CCMP_KEY_FLAG_RX | CCMP_KEY_FLAG_NEXT
CCMP_KEY_FLAG_PAIRWISE_RX_TX = CCMP_KEY_FLAG_PAIRWISE | CCMP_KEY_FLAG_RX | CCMP_KEY_FLAG_TX
CCMP_BROADCAST = b"\xff" * 6
_MAX_PN = 1 << 48


_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = (1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154)
_MASK_128 = (1 << 128) - 1
_GHASH_R = 0xE1000000000000000000000000000000


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _ror32(value: int) -> int:
    return ((value >> 8) | (value << 24)) & 0xFFFFFFFF


_T0 = [(_xtime(s) << 24) | (s << 16) | (s << 8) | (_xtime(s) ^ s)
       for s in _SBOX]
_T1 = [_ror32(v) for v in _T0]
_T2 = [_ror32(v) for v in _T1]
_T3 = [_ror32(v) for v in _T2]


def _expand_key(key: bytes) -> list[int]:
    if not isinstance(key, bytes) or len(key) not in (16, 32):
        raise CcmpError("AES requires a 16- or 32-octet key")
    nk = len(key) // 4
    rounds = nk + 6
    words = [int.from_bytes(key[i:i + 4], "big")
             for i in range(0, len(key), 4)]
    target = 4 * (rounds + 1)
    index = nk
    while len(words) < target:
        t = words[-1]
        if index % nk == 0:
            t = ((_SBOX[(t >> 16) & 0xFF] << 24) |
                 (_SBOX[(t >> 8) & 0xFF] << 16) |
                 (_SBOX[t & 0xFF] << 8) | _SBOX[t >> 24]) ^ \
                (_RCON[index // nk - 1] << 24)
        elif nk > 6 and index % nk == 4:
            t = ((_SBOX[t >> 24] << 24) |
                 (_SBOX[(t >> 16) & 0xFF] << 16) |
                 (_SBOX[(t >> 8) & 0xFF] << 8) | _SBOX[t & 0xFF])
        words.append(words[-nk] ^ t)
        index += 1
    return words


def _aes_encrypt(expanded: list[int], block: bytes) -> bytes:
    if len(block) != 16:
        raise CcmpError("AES block must be 16 octets")
    if len(expanded) not in (44, 60):
        raise CcmpError("invalid AES expanded key")
    rounds = len(expanded) // 4 - 1
    value = int.from_bytes(block, "big")
    s0 = (value >> 96) ^ expanded[0]
    s1 = ((value >> 64) & 0xFFFFFFFF) ^ expanded[1]
    s2 = ((value >> 32) & 0xFFFFFFFF) ^ expanded[2]
    s3 = (value & 0xFFFFFFFF) ^ expanded[3]
    for r in range(1, rounds):
        key_offset = r * 4
        s0, s1, s2, s3 = (
            _T0[s0 >> 24] ^ _T1[(s1 >> 16) & 0xFF] ^
            _T2[(s2 >> 8) & 0xFF] ^ _T3[s3 & 0xFF] ^ expanded[key_offset],
            _T0[s1 >> 24] ^ _T1[(s2 >> 16) & 0xFF] ^
            _T2[(s3 >> 8) & 0xFF] ^ _T3[s0 & 0xFF] ^ expanded[key_offset + 1],
            _T0[s2 >> 24] ^ _T1[(s3 >> 16) & 0xFF] ^
            _T2[(s0 >> 8) & 0xFF] ^ _T3[s1 & 0xFF] ^ expanded[key_offset + 2],
            _T0[s3 >> 24] ^ _T1[(s0 >> 16) & 0xFF] ^
            _T2[(s1 >> 8) & 0xFF] ^ _T3[s2 & 0xFF] ^ expanded[key_offset + 3],
        )
    out = 0
    for a, b, c, d, k in (
        (s0, s1, s2, s3, expanded[rounds * 4]),
        (s1, s2, s3, s0, expanded[rounds * 4 + 1]),
        (s2, s3, s0, s1, expanded[rounds * 4 + 2]),
        (s3, s0, s1, s2, expanded[rounds * 4 + 3]),
    ):
        word = ((_SBOX[a >> 24] << 24) |
                (_SBOX[(b >> 16) & 0xFF] << 16) |
                (_SBOX[(c >> 8) & 0xFF] << 8) | _SBOX[d & 0xFF]) ^ k
        out = (out << 32) | word
    return out.to_bytes(16, "big")


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def initial_packet_number(sequence: bytes) -> int:
    """Next PN/TSC/IPN from a hostapd key-install sequence.

    An empty sequence starts at 1. A present sequence is little-endian, the
    same order hostapd and nl80211 use for the TSC/packet number.
    """
    if not sequence:
        return 1
    return int.from_bytes(sequence, "little")


def _header_length(frame: bytes) -> int:
    if len(frame) < 24:
        raise CcmpError("802.11 data frame is too short")
    fc = int.from_bytes(frame[:2], "little")
    if ((fc >> 2) & 0x03) != 2:
        raise CcmpError("CCMP requires an 802.11 data frame")
    if int.from_bytes(frame[22:24], "little") & 0x000F:
        raise CcmpError("fragmented data frame is not supported")
    header_len = 24
    if (fc & 0x0300) == 0x0300:
        header_len += 6
    qos = bool((fc & 0x0080) and ((fc >> 2) & 0x03) == 2)
    if qos:
        header_len += 2
    if fc & 0x8000:
        raise CcmpError("HTC/order data frames are not supported")
    if len(frame) < header_len:
        raise CcmpError("truncated 802.11 header")
    return header_len


def _aad(frame: bytes, header_len: int) -> bytes:
    """Build the CCMP/GCMP additional authentication data for a data MPDU.

    IEEE 802.11 clears subtype bits 4-6, Retry, PwrMgt and MoreData, and
    forces Protected to 1. QoS data also clears Order, which carries +HTC
    rather than an authenticated header bit. Only the fragment number is
    authenticated, and the QoS Control field contributes the TID.
    """
    fc = int.from_bytes(frame[:2], "little")
    masked = fc & ~0x0070
    if fc & 0x0080:
        masked &= ~0x8000
    masked &= ~(0x0800 | 0x1000 | 0x2000)
    masked |= 0x4000
    result = bytearray(masked.to_bytes(2, "little"))
    result.extend(frame[4:22])
    seq = int.from_bytes(frame[22:24], "little") & 0x000F
    result.extend(seq.to_bytes(2, "little"))
    if (fc & 0x0300) == 0x0300:
        result.extend(frame[24:30])
    if fc & 0x0080:
        qos_offset = header_len - 2
        qos = int.from_bytes(frame[qos_offset:qos_offset + 2], "little") & 0x000F
        result.extend(qos.to_bytes(2, "little"))
    return bytes(result)


def _nonce(frame: bytes, pn: int, header_len: int) -> bytes:
    fc = int.from_bytes(frame[:2], "little")
    priority = 0
    if fc & 0x0080:
        priority = frame[header_len - 2] & 0x0F
    # CCMP nonce is priority || transmitter address || PN5..PN0.
    return bytes((priority,)) + frame[10:16] + pn.to_bytes(6, "big")


def _cbc_mac(expanded: list[int], b0: bytes, aad: bytes, plaintext: bytes,
             mic_len: int = 8) -> bytes:
    x = _aes_encrypt(expanded, b0)
    encoded_aad = len(aad).to_bytes(2, "big") + aad
    if len(encoded_aad) % 16:
        encoded_aad += bytes(16 - len(encoded_aad) % 16)
    for offset in range(0, len(encoded_aad), 16):
        x = _aes_encrypt(expanded, _xor(x, encoded_aad[offset:offset + 16]))
    padded = plaintext
    if len(padded) % 16:
        padded += bytes(16 - len(padded) % 16)
    for offset in range(0, len(padded), 16):
        x = _aes_encrypt(expanded, _xor(x, padded[offset:offset + 16]))
    return x[:mic_len]


def _ctr(expanded: list[int], nonce: bytes, counter: int) -> bytes:
    return _aes_encrypt(expanded, b"\x01" + nonce + counter.to_bytes(2, "big"))


def _validate_key(key: bytes, key_length: int = 16) -> None:
    if not isinstance(key, bytes) or len(key) != key_length:
        raise CcmpError(f"CCMP requires a {key_length}-octet AES key")


def _validate_gcm_inputs(key: bytes, nonce: bytes, aad: bytes,
                         payload: bytes) -> None:
    if not isinstance(key, bytes) or len(key) not in (16, 32):
        raise GcmpError("GCMP requires a 16- or 32-octet AES key")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise GcmpError("GCM requires a 12-octet nonce")
    if not isinstance(aad, bytes) or not isinstance(payload, bytes):
        raise GcmpError("GCM inputs must be bytes")
    if len(aad) >= (1 << 61) or len(payload) >= (1 << 39):
        raise GcmpError("GCM input is too long")


def _ghash_multiply(left: int, right: int) -> int:
    result = 0
    value = right
    for bit in range(128):
        if left & (1 << (127 - bit)):
            result ^= value
        if value & 1:
            value = (value >> 1) ^ _GHASH_R
        else:
            value >>= 1
    return result


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_value = int.from_bytes(h, "big")
    state = 0
    encoded = bytearray(aad)
    if len(encoded) % 16:
        encoded.extend(bytes(16 - len(encoded) % 16))
    encoded.extend(ciphertext)
    if len(ciphertext) % 16:
        encoded.extend(bytes(16 - len(ciphertext) % 16))
    encoded.extend((len(aad) * 8).to_bytes(8, "big"))
    encoded.extend((len(ciphertext) * 8).to_bytes(8, "big"))
    for offset in range(0, len(encoded), 16):
        state = _ghash_multiply(
            state ^ int.from_bytes(encoded[offset:offset + 16], "big"),
            h_value)
    return state.to_bytes(16, "big")


def _gcm_crypt(expanded: list[int], nonce: bytes, payload: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(payload), 16):
        block = payload[offset:offset + 16]
        counter = 2 + offset // 16
        ctr = nonce + counter.to_bytes(4, "big")
        out.extend(_xor(block, _aes_encrypt(expanded, ctr)))
    return bytes(out)


def aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes,
                    plaintext: bytes) -> tuple[bytes, bytes]:
    """Return AES-GCM ciphertext and 16-octet authentication tag."""
    _validate_gcm_inputs(key, nonce, aad, plaintext)
    expanded = _expand_key(key)
    h = _aes_encrypt(expanded, bytes(16))
    ciphertext = _gcm_crypt(expanded, nonce, plaintext)
    j0 = nonce + b"\x00\x00\x00\x01"
    tag = _xor(_aes_encrypt(expanded, j0), _ghash(h, aad, ciphertext))
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                    ciphertext: bytes, tag: bytes) -> bytes:
    """Authenticate and decrypt AES-GCM ciphertext."""
    _validate_gcm_inputs(key, nonce, aad, ciphertext)
    if not isinstance(tag, bytes) or len(tag) != 16:
        raise GcmpError("GCM requires a 16-octet authentication tag")
    expanded = _expand_key(key)
    h = _aes_encrypt(expanded, bytes(16))
    j0 = nonce + b"\x00\x00\x00\x01"
    expected = _xor(_aes_encrypt(expanded, j0), _ghash(h, aad, ciphertext))
    if not hmac.compare_digest(expected, tag):
        raise GcmpError("GCMP MIC verification failed")
    return _gcm_crypt(expanded, nonce, ciphertext)


def _gcmp_nonce(frame: bytes, pn: int) -> bytes:
    if len(frame) < 16:
        raise GcmpError("GCMP frame is too short")
    return frame[10:16] + pn.to_bytes(6, "big")


def gcmp_encrypt_mpdu(frame: bytes, key: bytes, pn: int,
                      key_id: int = 0) -> bytes:
    """Encrypt an unprotected 802.11 data MPDU with GCMP-128."""
    if not isinstance(frame, bytes):
        raise GcmpError("frame must be bytes")
    if not 0 <= pn < (1 << 48):
        raise GcmpError("GCMP packet number exhausted")
    if not 0 <= key_id <= 3:
        raise GcmpError("invalid GCMP key index")
    header_len = _header_length(frame)
    fc = int.from_bytes(frame[:2], "little")
    if fc & 0x4000:
        raise GcmpError("frame is already protected")
    header = bytearray(frame[:header_len])
    header[:2] = (fc | 0x4000).to_bytes(2, "little")
    plaintext = frame[header_len:]
    ciphertext, tag = aes_gcm_encrypt(
        key, _gcmp_nonce(frame, pn), _aad(frame, header_len), plaintext)
    gcmp_header = bytes((pn & 0xFF, (pn >> 8) & 0xFF, (key_id & 3) << 6,
                         (pn >> 16) & 0xFF, (pn >> 24) & 0xFF,
                         (pn >> 32) & 0xFF, (pn >> 40) & 0xFF, 0))
    return bytes(header) + gcmp_header + ciphertext + tag


def gcmp_decrypt_mpdu(frame: bytes, key: bytes, minimum_pn: int | None = None,
                      *, expected_key_id: int | None = None) -> tuple[int, bytes]:
    """Authenticate/decrypt one GCMP-128 MPDU; return ``(PN, MPDU)``."""
    if not isinstance(frame, bytes):
        raise GcmpError("frame must be bytes")
    header_len = _header_length(frame)
    fc = int.from_bytes(frame[:2], "little")
    if not fc & 0x4000 or len(frame) < header_len + 8 + 16:
        raise GcmpError("missing or truncated GCMP payload")
    gcmp = frame[header_len:header_len + 8]
    key_id = (gcmp[2] >> 6) & 3
    if expected_key_id is not None and key_id != expected_key_id:
        raise GcmpError("unexpected GCMP key index")
    pn = (gcmp[0] | (gcmp[1] << 8) | (gcmp[3] << 16) |
          (gcmp[4] << 24) | (gcmp[5] << 32) | (gcmp[6] << 40))
    if minimum_pn is not None and pn <= minimum_pn:
        raise GcmpError("GCMP replay detected")
    ciphertext = frame[header_len + 8:-16]
    tag = frame[-16:]
    plaintext = aes_gcm_decrypt(
        key, _gcmp_nonce(frame, pn), _aad(frame, header_len), ciphertext, tag)
    header = bytearray(frame[:header_len])
    header[:2] = (fc & ~0x4000).to_bytes(2, "little")
    return pn, bytes(header) + plaintext


def _ccmp_encrypt_mpdu(frame: bytes, key: bytes, pn: int, key_id: int,
                       *, key_length: int, mic_len: int) -> bytes:
    _validate_key(key, key_length)
    if not isinstance(frame, bytes):
        raise CcmpError("frame must be bytes")
    if not 0 <= pn < (1 << 48):
        raise CcmpError("CCMP packet number exhausted")
    if not 0 <= key_id <= 3:
        raise CcmpError("invalid CCMP key index")
    header_len = _header_length(frame)
    fc = int.from_bytes(frame[:2], "little")
    if fc & 0x4000:
        raise CcmpError("frame is already protected")
    header = bytearray(frame[:header_len])
    header[:2] = (fc | 0x4000).to_bytes(2, "little")
    plaintext = frame[header_len:]
    nonce = _nonce(frame, pn, header_len)
    expanded = _expand_key(key)
    flags = 0x59 if mic_len == 8 else 0x79
    b0 = bytes((flags,)) + nonce + len(plaintext).to_bytes(2, "big")
    mic = _cbc_mac(expanded, b0, _aad(frame, header_len), plaintext, mic_len)
    encrypted = bytearray()
    for offset in range(0, len(plaintext), 16):
        block = plaintext[offset:offset + 16]
        encrypted.extend(_xor(block, _ctr(expanded, nonce, offset // 16 + 1)))
    encrypted.extend(_xor(mic, _ctr(expanded, nonce, 0)[:mic_len]))
    ccmp_header = bytes((pn & 0xFF, (pn >> 8) & 0xFF, (key_id & 3) << 6,
                         (pn >> 16) & 0xFF, (pn >> 24) & 0xFF,
                         (pn >> 32) & 0xFF, (pn >> 40) & 0xFF, 0))
    return bytes(header) + ccmp_header + bytes(encrypted)


def _ccmp_decrypt_mpdu(frame: bytes, key: bytes, minimum_pn: int | None,
                       expected_key_id: int | None, *, key_length: int,
                       mic_len: int) -> tuple[int, bytes]:
    _validate_key(key, key_length)
    if not isinstance(frame, bytes):
        raise CcmpError("frame must be bytes")
    header_len = _header_length(frame)
    fc = int.from_bytes(frame[:2], "little")
    if not fc & 0x4000 or len(frame) < header_len + 8 + mic_len:
        raise CcmpError("missing or truncated CCMP payload")
    ccmp = frame[header_len:header_len + 8]
    key_id = (ccmp[2] >> 6) & 3
    if expected_key_id is not None and key_id != expected_key_id:
        raise CcmpError("unexpected CCMP key index")
    pn = (ccmp[0] | (ccmp[1] << 8) | (ccmp[3] << 16) |
          (ccmp[4] << 24) | (ccmp[5] << 32) | (ccmp[6] << 40))
    if minimum_pn is not None and pn <= minimum_pn:
        raise CcmpError("CCMP replay detected")
    ciphertext = frame[header_len + 8:-mic_len]
    encrypted_mic = frame[-mic_len:]
    nonce = _nonce(frame, pn, header_len)
    expanded = _expand_key(key)
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        plaintext.extend(_xor(block, _ctr(expanded, nonce, offset // 16 + 1)))
    flags = 0x59 if mic_len == 8 else 0x79
    b0 = bytes((flags,)) + nonce + len(plaintext).to_bytes(2, "big")
    mic = _cbc_mac(expanded, b0, _aad(frame, header_len), bytes(plaintext), mic_len)
    received_mic = _xor(encrypted_mic, _ctr(expanded, nonce, 0)[:mic_len])
    if not hmac.compare_digest(mic, received_mic):
        raise CcmpError("CCMP MIC verification failed")
    header = bytearray(frame[:header_len])
    header[:2] = (fc & ~0x4000).to_bytes(2, "little")
    return pn, bytes(header) + bytes(plaintext)


def ccmp_encrypt_mpdu(frame: bytes, key: bytes, pn: int, key_id: int = 0) -> bytes:
    """Encrypt one unprotected 802.11 data MPDU with CCMP-128."""
    return _ccmp_encrypt_mpdu(frame, key, pn, key_id,
                              key_length=16, mic_len=8)


def ccmp_decrypt_mpdu(frame: bytes, key: bytes, minimum_pn: int | None = None,
                      *, expected_key_id: int | None = None) -> tuple[int, bytes]:
    """Authenticate/decrypt CCMP-128; return ``(PN, unprotected MPDU)``."""
    return _ccmp_decrypt_mpdu(frame, key, minimum_pn, expected_key_id,
                              key_length=16, mic_len=8)


def ccmp256_encrypt_mpdu(frame: bytes, key: bytes, pn: int,
                         key_id: int = 0) -> bytes:
    """Encrypt one unprotected 802.11 data MPDU with CCMP-256."""
    return _ccmp_encrypt_mpdu(frame, key, pn, key_id,
                              key_length=32, mic_len=16)


def ccmp256_decrypt_mpdu(frame: bytes, key: bytes, minimum_pn: int | None = None,
                         *, expected_key_id: int | None = None) -> tuple[int, bytes]:
    """Authenticate/decrypt CCMP-256; return ``(PN, unprotected MPDU)``."""
    return _ccmp_decrypt_mpdu(frame, key, minimum_pn, expected_key_id,
                              key_length=32, mic_len=16)


class CcmpKeyStore:
    """Thread-safe CCMP key slots with independent TX and RX replay state."""

    def __init__(self, *, algorithm: int = WPA_ALG_CCMP,
                 key_length: int = 16):
        if algorithm not in (WPA_ALG_CCMP, WPA_ALG_CCMP_256):
            raise ValueError("unsupported CCMP algorithm")
        if key_length not in (16, 32):
            raise ValueError("CCMP key length must be 16 or 32 octets")
        self.algorithm = algorithm
        self.key_length = key_length
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
        if not isinstance(key, bytes):
            return False
        if not 0 <= index <= 3:
            return False
        slot = (peer, index)
        with self._lock:
            if alg == WPA_ALG_NONE:
                if key or sequence:
                    return False
                self._keys.pop(slot, None)
                self._next_keys.pop(slot, None)
                if peer == CCMP_BROADCAST and index == self._group_index:
                    self._group_index = 0
                return True
            if alg != self.algorithm or len(key) != self.key_length:
                return False
            initial = initial_packet_number(sequence)
            if initial >= _MAX_PN:
                return False
            candidate = {
                "key": bytes(key),
                "flags": int(flags),
                "tx_pn": initial,
                "rx_pn": initial - 1,
            }
            if (flags & CCMP_KEY_FLAG_NEXT and
                    flags & CCMP_KEY_FLAG_PAIRWISE and
                    peer != CCMP_BROADCAST):
                # hostapd uses this before M3/rekey as an RX-only candidate.
                # It must not reset the currently active pairwise replay state.
                self._next_keys[slot] = candidate
            elif (flags & CCMP_KEY_FLAG_PAIRWISE and
                  peer != CCMP_BROADCAST):
                # Promote a candidate without resetting its PN counters.
                previous = self._next_keys.pop(slot, None)
                if previous is not None and previous["key"] == bytes(key):
                    previous["flags"] = int(flags)
                    self._keys[slot] = previous
                else:
                    self._keys[slot] = candidate
            else:
                self._keys[slot] = candidate
            if peer == CCMP_BROADCAST or flags & CCMP_KEY_FLAG_GROUP:
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
        """Return the latest PN already used for TX, or None when no key exists.

        hostapd copies this value into the EAPOL-Key RSC. It is one less than
        the next PN, so a peer accepts that next frame. A key that has not
        transmitted yet reports 0.
        """
        if not isinstance(peer, bytes) or len(peer) != 6 or not 0 <= index <= 3:
            return None
        with self._lock:
            slot = self._keys.get((peer, index))
            if slot is None and not self._is_group(peer):
                slot = self._next_keys.get((peer, index))
            if slot is None:
                return None
            return max(0, int(slot["tx_pn"]) - 1)

    def encrypt(self, frame: bytes, destination: bytes) -> bytes:
        if not isinstance(destination, bytes) or len(destination) != 6:
            raise CcmpError("invalid CCMP destination")
        with self._lock:
            index = self._group_index if self._is_group(destination) else 0
            slot = self._slot_for(destination, index, group_ok=self._is_group(destination))
            if slot is None and not self._is_group(destination):
                # The first encrypted WPA2 M3 can be emitted while hostapd has
                # only installed KEY_FLAG_PAIRWISE_NEXT. Use that candidate
                # for the transition frame; final promotion remains RX/TX.
                slot = self._next_keys.get((destination, index))
            if slot is None:
                raise CcmpError("no CCMP TX key for destination")
            pn = int(slot["tx_pn"])
            if pn >= _MAX_PN:
                raise CcmpError("CCMP TX packet number exhausted")
            encryptor = (ccmp256_encrypt_mpdu if self.algorithm == WPA_ALG_CCMP_256
                         else ccmp_encrypt_mpdu)
            protected = encryptor(frame, bytes(slot["key"]), pn, index)
            slot["tx_pn"] = pn + 1
            return protected

    def decrypt(self, frame: bytes, source: bytes) -> tuple[int, bytes]:
        if not isinstance(source, bytes) or len(source) != 6:
            raise CcmpError("invalid CCMP source")
        header_len = _header_length(frame)
        if len(frame) < header_len + 3:
            raise CcmpError("truncated CCMP header")
        index = (frame[header_len + 2] >> 6) & 3
        destination = frame[4:10]
        with self._lock:
            slot = self._slot_for(source, index, group_ok=False)
            next_slot = self._next_keys.get((source, index))
            if slot is None and next_slot is not None:
                slot = next_slot
            if slot is None and self._is_group(destination):
                slot = self._slot_for(CCMP_BROADCAST, index, group_ok=True)
            if slot is None:
                raise CcmpError("no CCMP RX key for source")
            try:
                decryptor = (ccmp256_decrypt_mpdu if self.algorithm == WPA_ALG_CCMP_256
                             else ccmp_decrypt_mpdu)
                pn, plain = decryptor(
                    frame, bytes(slot["key"]), int(slot["rx_pn"]),
                    expected_key_id=index,
                )
            except CcmpError:
                if next_slot is None or slot is next_slot:
                    raise
                pn, plain = decryptor(
                    frame, bytes(next_slot["key"]), int(next_slot["rx_pn"]),
                    expected_key_id=index,
                )
                slot = next_slot
            slot["rx_pn"] = pn
            return pn, plain

    def snapshot(self) -> dict[str, dict[str, int | bool]]:
        """Diagnostics without exposing key bytes."""
        with self._lock:
            snapshot = {
                f"{peer.hex(':')}/{index}": {
                    "flags": int(slot["flags"]),
                    "tx_pn": int(slot["tx_pn"]),
                    "rx_pn": int(slot["rx_pn"]),
                }
                for (peer, index), slot in self._keys.items()
            }
            for (peer, index), slot in self._next_keys.items():
                snapshot[f"{peer.hex(':')}/{index}/next"] = {
                    "flags": int(slot["flags"]),
                    "tx_pn": int(slot["tx_pn"]),
                    "rx_pn": int(slot["rx_pn"]),
                }
            return snapshot

    def clear(self) -> None:
        with self._lock:
            self._keys.clear()
            self._next_keys.clear()


class Ccmp256KeyStore(CcmpKeyStore):
    """CCMP-256 slots using AES-256-CCM and a sixteen-octet MIC."""

    def __init__(self):
        super().__init__(algorithm=WPA_ALG_CCMP_256, key_length=32)
