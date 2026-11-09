"""Software GCMP key lifecycle for the explicit wifit3 lab path."""
from __future__ import annotations

import threading

from .ccmp import (
    CCMP_BROADCAST,
    CCMP_KEY_FLAG_GROUP,
    CCMP_KEY_FLAG_NEXT,
    CCMP_KEY_FLAG_PAIRWISE,
    CcmpError,
    _MAX_PN,
    _header_length,
    initial_packet_number,
    gcmp_decrypt_mpdu,
    gcmp_encrypt_mpdu,
)


WPA_ALG_GCMP = 5
WPA_ALG_GCMP_256 = 8


class GcmpKeyStore:
    """Thread-safe GCMP slots with independent TX/RX replay state."""

    def __init__(self, *, algorithm: int = WPA_ALG_GCMP,
                 key_length: int = 16):
        if algorithm not in (WPA_ALG_GCMP, WPA_ALG_GCMP_256):
            raise ValueError("unsupported GCMP algorithm")
        if key_length not in (16, 32):
            raise ValueError("GCMP key length must be 16 or 32 octets")
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
        if not isinstance(key, bytes) or not 0 <= index <= 3:
            return False
        slot = (peer, index)
        with self._lock:
            if alg == 0:
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
                self._next_keys[slot] = candidate
            elif (flags & CCMP_KEY_FLAG_PAIRWISE and
                  peer != CCMP_BROADCAST):
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
        """Latest used TX PN. See ``CcmpKeyStore.last_tx_tsc``."""
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
            raise CcmpError("invalid GCMP destination")
        with self._lock:
            index = self._group_index if self._is_group(destination) else 0
            slot = self._slot_for(destination, index,
                                  group_ok=self._is_group(destination))
            if slot is None and not self._is_group(destination):
                slot = self._next_keys.get((destination, index))
            if slot is None:
                raise CcmpError("no GCMP TX key for destination")
            pn = int(slot["tx_pn"])
            if pn >= _MAX_PN:
                raise CcmpError("GCMP TX packet number exhausted")
            protected = gcmp_encrypt_mpdu(
                frame, bytes(slot["key"]), pn, index)
            slot["tx_pn"] = pn + 1
            return protected

    def decrypt(self, frame: bytes, source: bytes) -> tuple[int, bytes]:
        if not isinstance(source, bytes) or len(source) != 6:
            raise CcmpError("invalid GCMP source")
        header_len = _header_length(frame)
        if len(frame) < header_len + 3:
            raise CcmpError("truncated GCMP header")
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
                raise CcmpError("no GCMP RX key for source")
            try:
                pn, plain = gcmp_decrypt_mpdu(
                    frame, bytes(slot["key"]), int(slot["rx_pn"]),
                    expected_key_id=index)
            except CcmpError:
                if next_slot is None or slot is next_slot:
                    raise
                pn, plain = gcmp_decrypt_mpdu(
                    frame, bytes(next_slot["key"]), int(next_slot["rx_pn"]),
                    expected_key_id=index)
                slot = next_slot
            slot["rx_pn"] = pn
            return pn, plain

    def snapshot(self) -> dict[str, dict[str, int | bool]]:
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


class Gcmp256KeyStore(GcmpKeyStore):
    """GCMP-256 slots using AES-256-GCM and a sixteen-octet MIC."""

    def __init__(self):
        super().__init__(algorithm=WPA_ALG_GCMP_256, key_length=32)
