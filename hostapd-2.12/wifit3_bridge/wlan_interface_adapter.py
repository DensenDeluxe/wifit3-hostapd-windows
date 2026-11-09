"""Experimental wifit3 WlanInterface adapter for hostapd 2.12 (BSD-3-Clause).

Uses public methods reviewed against derv82/wifit3's WlanInterface source on
2026-11-08: set_channel, send_no_wait, register_rx_callback,
unregister_rx_callback, mac_address, supported_channels.

This is a real USB TX/RX integration *seam*, not a production AP implementation.
Software beacons include a TIM and a monotonic timestamp. They are not a
hardware TBTT/TSF and are unsuitable for production.  The optional
station, observed-accounting, WPA2/CCMP/GCMP/TKIP, and WPA3-SAE capability paths
are software paths for the raw-monitor lab mode; the optional PMF path implements
BIP in software. Chipset hardware key offload remains unsupported. SAE
OTA/client completion is a separate
verification item.
No automatic USB ownership is acquired. The Focus lease MUST be exclusive.
"""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time
from typing import Callable

from .bridge import (
    CAP_ACCOUNTING, CAP_BEACON, CAP_BIP, CAP_CCMP_256, CAP_GCMP, CAP_GCMP_256, CAP_KEY, CAP_RX_EAPOL, CAP_RX_MGMT, CAP_SAE,
    CAP_SET_FREQ, CAP_STA, CAP_TKIP, CAP_TX_MGMT, CAP_TX_EAPOL, RadioConfig, Wifit3Bridge,
)
from .bip import (
    BipError,
    BipKeyStore,
    WPA_ALG_BIP_CMAC_128,
    WPA_ALG_BIP_CMAC_256,
    WPA_ALG_BIP_GMAC_128,
    WPA_ALG_BIP_GMAC_256,
)
from .ccmp import (
    Ccmp256KeyStore,
    CcmpError,
    CcmpKeyStore,
    WPA_ALG_CCMP_256,
    WPA_ALG_NONE,
)
from .gcmp import Gcmp256KeyStore, GcmpKeyStore, WPA_ALG_GCMP, WPA_ALG_GCMP_256
from .tkip import TkipError, TkipKeyStore, WPA_ALG_TKIP

_LOG = logging.getLogger(__name__)
_LLC_EAPOL = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'
_WPA_STA_MFP = 1 << 3


def hardware_ack_supported(iface) -> bool:
    driver = getattr(iface, 'driver', None)
    support = getattr(getattr(driver, 'FAKE_MAC', None), 'value', None)
    return (support in ('spoofable', 'fixed_mac') and
            all(callable(getattr(iface, name, None))
                for name in ('set_fake_mac', 'enable_rx_acks', 'send_until_ack')))


def mhz_to_channel(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472 and (freq - 2412) % 5 == 0:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5895 and freq % 5 == 0:
        return (freq - 5000) // 5
    raise ValueError(f'unsupported frequency: {freq}')


def channel_to_mhz(channel: int) -> int:
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + 5 * channel
    if 34 <= channel <= 177:
        return 5000 + 5 * channel
    raise ValueError(f'unsupported channel: {channel}')


def extract_eapol_from_mpdu(frame: bytes) -> tuple[bytes, bytes] | None:
    """Find unencrypted 802.11 data+LLC/SNAP EAPOL without interpreting keys.

    Protected / A-MSDU frames are deliberately NOT classified. Management
    frames or fragmented frames are rejected. Address 2 is STA for ToDS only.
    """
    if len(frame) < 24:
        return None
    fc = int.from_bytes(frame[:2], 'little')
    if (fc & 0x000c) != 0x0008 or fc & 0x4000 or fc & 0x0400:
        return None
    if fc & 0x0300 != 0x0100:  # from client to AP
        return None
    hdrlen = 24
    if (fc & 0x0080):  # QoS subtype
        hdrlen += 2
        if fc & 0x8000:
            hdrlen += 4
    eapol_offset = frame[hdrlen:hdrlen + 16].find(_LLC_EAPOL)
    if eapol_offset < 0:
        return None
    payload = frame[hdrlen + eapol_offset + len(_LLC_EAPOL):]
    if len(payload) < 4:
        return None
    return frame[10:16], payload


def extract_protected_eapol_from_mpdu(frame: bytes,
                                      keys: CcmpKeyStore) -> tuple[bytes, bytes] | None:
    """Authenticate/decrypt a protected client-to-AP EAPOL data MPDU."""
    if len(frame) < 32:
        return None
    fc = int.from_bytes(frame[:2], 'little')
    if (fc & 0x000c) != 0x0008 or not (fc & 0x4000):
        return None
    if fc & 0x0300 != 0x0100:
        return None
    source = frame[10:16]
    try:
        _pn, plain = keys.decrypt(frame, source)
    except CcmpError:
        return None
    return extract_eapol_from_mpdu(plain)


class Wifit3InterfaceRadio:
    """Bound to *existing*, exclusively leased WlanInterface and app loop.

    The bridge runs in a background thread, while this adapter schedules
    coroutines on the app's asyncio loop using run_coroutine_threadsafe.
    Only APIs confirmed in WlanInterface are called.
    """
    def __init__(self, iface, event_loop: asyncio.AbstractEventLoop,
                 *, lease_guard: Callable[[], bool],
                 software_beacons: bool = False, allow_eapol_tx: bool = False,
                 software_stations: bool = False, software_ccmp: bool = False,
                 software_ccmp256: bool = False,
                 software_bip: bool = False, software_sae: bool = False,
                 software_accounting: bool = False, software_gcmp: bool = False,
                 software_gcmp256: bool = False,
                 software_tkip: bool = False,
                 hardware_ack: bool = False,
                 timeout_s: float = 3.0):
        if not callable(lease_guard) or not lease_guard():
            raise RuntimeError('Focus must own an exclusive radio lease')
        if event_loop.is_closed() or not event_loop.is_running():
            raise ValueError('wifit3 app event loop must be running')
        self.iface = iface
        self.loop = event_loop
        self.lease_guard = lease_guard
        self.software_beacons = bool(software_beacons)
        self.allow_eapol_tx = bool(allow_eapol_tx)
        self.software_stations = bool(software_stations)
        self.software_ccmp = bool(software_ccmp)
        self.software_ccmp256 = bool(software_ccmp256)
        self.software_bip = bool(software_bip)
        self.software_sae = bool(software_sae)
        self.software_accounting = bool(software_accounting)
        self.software_gcmp = bool(software_gcmp)
        self.software_gcmp256 = bool(software_gcmp256)
        self.software_tkip = bool(software_tkip)
        self.hardware_ack = bool(hardware_ack)
        self.timeout_s = timeout_s
        self._beacon_task: asyncio.Task | None = None
        self._seq_lock = threading.Lock()
        self._ap_seq = 0
        self._beacon_head = b""
        self._beacon_tail = b""
        self._dtim_period = 1
        self._dtim_count = 0
        self._rx_attached = False
        self._rx_queue: queue.Queue = queue.Queue(maxsize=256)
        self._rx_stop = threading.Event()
        self._rx_thread = threading.Thread(
            target=self._rx_writer, name="wifit3-rx", daemon=True)
        self._rx_thread.start()
        self._bridge: Wifit3Bridge | None = None
        self._current_freq = None
        self._hardware_ack_armed = False
        self._hardware_ack_tx_count = 0
        self._stations: dict[bytes, dict[str, int | bool]] = {}
        self._stations_lock = threading.RLock()
        self._ccmp = CcmpKeyStore() if self.software_ccmp else None
        self._ccmp256 = Ccmp256KeyStore() if self.software_ccmp256 else None
        self._gcmp = GcmpKeyStore() if self.software_gcmp else None
        self._gcmp256 = Gcmp256KeyStore() if self.software_gcmp256 else None
        self._tkip = TkipKeyStore() if self.software_tkip else None
        self._bip = BipKeyStore() if self.software_bip else None

    def _assert_lease(self) -> None:
        if not self.lease_guard():
            raise RuntimeError('Focus radio lease lost: AP operation rejected')

    async def arm_hardware_ack(self) -> bool:
        """Opt into public wifit3 active-monitor/link-ACK support.

        The radio must explicitly expose both active-monitor MAC programming
        and ACK tallying.  If either operation is absent or fails, leave the
        adapter unarmed so hostapd never receives an untruthful OTA-ACK result.
        """
        if not self.hardware_ack or not self.lease_guard():
            return False
        set_fake_mac = getattr(self.iface, 'set_fake_mac', None)
        enable_rx_acks = getattr(self.iface, 'enable_rx_acks', None)
        if not callable(set_fake_mac) or not callable(enable_rx_acks):
            return False
        rx_enabled = False
        try:
            await enable_rx_acks()
            rx_enabled = True
            mac = getattr(self.iface, 'mac_address', None)
            if not isinstance(mac, str):
                raise RuntimeError('wifit3 MAC unavailable for active monitor')
            armed = await set_fake_mac(mac=mac, bssid=mac)
            if not armed:
                raise RuntimeError('wifit3 active monitor refused the AP MAC')
            self._hardware_ack_armed = True
            return True
        except (OSError, RuntimeError, TypeError, ValueError):
            clear_fake_mac = getattr(self.iface, 'clear_fake_mac', None)
            if callable(clear_fake_mac):
                try:
                    await clear_fake_mac()
                except Exception:
                    _LOG.debug('active-monitor cleanup failed', exc_info=True)
            if rx_enabled:
                disable_rx_acks = getattr(self.iface, 'disable_rx_acks', None)
                if callable(disable_rx_acks):
                    try:
                        await disable_rx_acks()
                    except Exception:
                        _LOG.debug('ACK-tally cleanup failed', exc_info=True)
            return False

    def _run(self, awaitable) -> bool:
        return bool(self._run_value(awaitable))

    def _run_value(self, awaitable):
        """Wait for one radio coroutine and return its result unchanged.

        ``False`` covers a lost lease, a timeout, and any radio exception.
        A value of ``2`` is preserved so a missing link ACK is not reported
        as a successful acknowledgement.
        """
        if not self.lease_guard():
            awaitable.close()
            return False
        future = asyncio.run_coroutine_threadsafe(awaitable, self.loop)
        try:
            return future.result(timeout=self.timeout_s)
        except Exception:
            future.cancel()
            _LOG.exception('wifit3 radio operation failed')
            return False

    def _next_seq_ctrl(self, fragment: int) -> bytes:
        """Allocate the next 12-bit sequence for this AP and keep the fragment."""
        with self._seq_lock:
            seq = self._ap_seq
            self._ap_seq = (seq + 1) & 0x0fff
        return ((seq << 4) | (fragment & 0x000f)).to_bytes(2, "little")

    def _tim_element(self) -> bytes:
        """TIM inserted between hostapd's beacon head and tail.

        hostapd ends the head after the DS Parameter Set and starts the tail
        at the next element, leaving the TIM gap for the driver. There is no
        power-save queue here, so every bitmap bit stays clear. The bitmap is
        still long enough to cover the highest associated AID. The DTIM count
        advances once per composed beacon. The TSF is filled separately and
        remains a software clock.
        """
        with self._stations_lock:
            count = self._dtim_count
            period = self._dtim_period
            if period <= 1 or count <= 0:
                self._dtim_count = 0 if period <= 1 else period - 1
            else:
                self._dtim_count = count - 1
            max_aid = 0
            for state in self._stations.values():
                aid = int(state.get("aid", 0))
                if 1 <= aid <= 2007 and aid > max_aid:
                    max_aid = aid
        bitmap_len = 1 if max_aid == 0 else min(251, (max_aid // 8) + 1)
        return bytes((5, 3 + bitmap_len, count & 0xFF, period & 0xFF, 0)) + bytes(bitmap_len)

    def _compose_beacon(self) -> bytes | None:
        tim = self._tim_element()
        head = self._beacon_head
        tail = self._beacon_tail
        if len(head) + len(tim) + len(tail) > 4096:
            tim = bytes((5, 4, tim[2], tim[3], 0, 0))
            if len(head) + len(tim) + len(tail) > 4096:
                return None
        frame = bytearray(head)
        frame.extend(tim)
        frame.extend(tail)
        frame[24:32] = (time.monotonic_ns() // 1000 & ((1 << 64) - 1)).to_bytes(8, "little")
        fragment = int.from_bytes(frame[22:24], "little") & 0x000f
        frame[22:24] = self._next_seq_ctrl(fragment)
        return bytes(frame)

    def set_frequency(self, mhz: int) -> bool:
        try:
            channel = mhz_to_channel(mhz)
        except ValueError:
            return False
        if channel not in self.iface.supported_channels:
            return False
        ok = self._run(self.iface.set_channel(channel, scan=False))
        if ok:
            self._current_freq = mhz
        return ok

    def tx_mgmt(self, frame: bytes, freq_mhz: int, noack: bool,
                no_encrypt: bool, wait_ms: int) -> bool | int:
        """Transmit one management frame.

        Returns True when the frame was sent and either link-acked or no ACK
        was required. Returns 2 when an armed link-ACK wait completed without
        an ACK. Returns False when the frame was not submitted. A missing ACK
        tally still returns True on successful submission: hostapd drops the
        association if the completion is reported as unacked, and there is no
        tally that could justify that result.
        """
        if len(frame) < 24 or (int.from_bytes(frame[:2], 'little') & 0x000c) != 0:
            return False
        if not self.lease_guard():
            return False
        if self._current_freq != freq_mhz and freq_mhz != 0:
            return False
        # Group frames and hostapd's noack flag (broadcast wildcard probes)
        # must not wait for a link ACK. Waiting makes the probe response fail
        # whenever the station does not ACK it.
        wants_ack = not noack and not (frame[4] & 1)
        if self.hardware_ack and not self._hardware_ack_armed and wants_ack:
            # Unicast management TX must not silently downgrade to a
            # submission-only result when ACK mode was explicitly requested.
            return False
        mpdu = bytearray(frame)
        fragment = int.from_bytes(mpdu[22:24], "little") & 0x000f
        mpdu[22:24] = self._next_seq_ctrl(fragment)
        frame = bytes(mpdu)
        if frame[1] & 0x40:
            # Never transmit an opaque protected frame without an explicit
            # software BIP lifecycle.
            if self._bip is None:
                return False
        elif self._bip is not None and self._management_needs_bip(frame):
            try:
                frame = self._bip.protect(frame)
            except BipError:
                return False
        # The public wifit3 bulk-TX path can report a recoverable USB failure
        # even though the radio remains usable.  Retry only after the first
        # future has completed; never overlap USB transfers on one interface.
        # A completed link-ACK miss is not retried here: send_until_ack already
        # waited, and another submission would look like a second sequence.
        saw_unacked = False
        for attempt in range(2):
            result = self._run_value(self._send_mgmt_once(frame, not wants_ack))
            if result is True:
                return True
            if result == 2:
                saw_unacked = True
                break
            if attempt == 0:
                time.sleep(0.05)
        if saw_unacked:
            return 2
        return False

    async def _send_mgmt_once(self, frame: bytes, noack: bool) -> bool | int:
        """Use a real public link-ACK wait only when one was requested."""
        if not noack and self._hardware_ack_armed and not (frame[4] & 1):
            send_until_ack = getattr(self.iface, 'send_until_ack', None)
            if not callable(send_until_ack):
                return False
            self._hardware_ack_tx_count += 1
            acked = await send_until_ack(frame, max_retries=1)
            return True if acked else 2
        return bool(await self.iface.send_no_wait(frame))

    @property
    def hardware_ack_tx_count(self) -> int:
        """Number of unicast management submissions routed through link-ACK TX."""
        return self._hardware_ack_tx_count

    def _management_needs_bip(self, frame: bytes) -> bool:
        """Return whether hostapd's MFP station state requires BIP on TX."""
        if len(frame) < 24:
            return False
        fc = int.from_bytes(frame[:2], 'little')
        if (fc >> 2) & 0x03 != 0:
            return False
        # Robust management subtypes: disassociation, deauthentication, action.
        if ((fc >> 4) & 0x0f) not in (10, 12, 13):
            return False
        destination = frame[4:10]
        if destination[0] & 1:
            return True
        with self._stations_lock:
            state = self._stations.get(bytes(destination))
            return bool(state and int(state.get('flags', 0)) & _WPA_STA_MFP)

    async def _send_beacon_with_retry(self, frame: bytes) -> bool:
        """Send one beacon, tolerating one completed transient USB failure.

        A beacon is periodic and must not overlap USB transfers.  The public
        wifit3 bulk-TX path can return a recoverable false result while the
        interface remains usable; stopping the beacon task on that first result
        would make an otherwise healthy lab AP disappear.
        """
        for attempt in range(2):
            if not self.lease_guard():
                return False
            if await self.iface.send_no_wait(frame):
                return True
            if attempt == 0:
                await asyncio.sleep(0.05)
        return False

    def set_beacon(self, head: bytes, tail: bytes, interval_tu: int, dtim: int) -> bool:
        if not self.software_beacons or not (25 <= interval_tu <= 1000) or not (1 <= dtim <= 255):
            return False
        # Reserve the minimum 6-octet TIM that is inserted between head and tail.
        if len(head) < 36 or len(head) + len(tail) + 6 > 4096:
            return False
        if (int.from_bytes(head[:2], 'little') & 0x00fc) != 0x0080:
            return False  # beacon subtype only

        async def replace_beacon() -> bool:
            self._assert_lease()
            if self._beacon_task is not None:
                self._beacon_task.cancel()
                try:
                    await self._beacon_task
                except asyncio.CancelledError:
                    pass
            self._beacon_head = bytes(head)
            self._beacon_tail = bytes(tail)
            self._dtim_period = dtim
            self._dtim_count = 0
            # TX itself, not just task scheduling, must succeed at least once.
            first = self._compose_beacon()
            if first is None or not await self._send_beacon_with_retry(first):
                return False
            self._beacon_task = self.loop.create_task(self._beacon_loop(interval_tu))
            return True
        return self._run(replace_beacon())

    async def _beacon_loop(self, interval_tu: int) -> None:
        # Best-effort userspace scheduling. The TIM and DTIM count are real;
        # the TSF is a monotonic microsecond clock, not a hardware TSF, and
        # the beacon is not anchored to a hardware TBTT.
        interval = interval_tu * 1024 / 1_000_000
        next_deadline = self.loop.time() + interval
        while self.lease_guard():
            await asyncio.sleep(max(0, next_deadline - self.loop.time()))
            frame = self._compose_beacon()
            if frame is None or not await self._send_beacon_with_retry(frame):
                _LOG.warning('software beacon transmission failed; stopping')
                return
            next_deadline += interval
            if self.loop.time() - next_deadline > interval:
                next_deadline = self.loop.time() + interval

    def _defer_rx(self) -> bool:
        """Queue socket writes that would otherwise stall the radio loop.

        Test collectors and direct bridge callers stay synchronous. Only a
        real ``Wifit3Bridge`` invoked on the radio asyncio thread is queued,
        because that thread also runs USB TX and beacon transmission.
        """
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            return False
        return running is self.loop and isinstance(self._bridge, Wifit3Bridge)

    def _emit_rx(self, kind: str, args: tuple) -> None:
        bridge = self._bridge
        if bridge is None:
            return
        if kind == "mgmt":
            bridge.on_mgmt_rx(*args)
        elif kind == "eapol":
            bridge.on_eapol_rx(*args)
        elif kind == "data":
            bridge.on_data_rx(*args)

    def _relay_rx(self, kind: str, args: tuple, *, defer: bool) -> None:
        if not defer:
            self._emit_rx(kind, args)
            return
        try:
            self._rx_queue.put_nowait((kind, args))
        except queue.Full:
            _LOG.warning("wifit3 RX dropped: hostapd is not reading the bridge")

    def _rx_writer(self) -> None:
        while not self._rx_stop.is_set():
            try:
                kind, args = self._rx_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._emit_rx(kind, args)
            except (RuntimeError, ValueError, OSError):
                _LOG.debug("wifit3 RX bridge is disconnected or cannot relay frame")

    def on_packet(self, pkt) -> None:
        if not self.lease_guard() or self._bridge is None or not self._bridge.connected():
            return
        raw = getattr(pkt, 'raw', b'')
        if not isinstance(raw, bytes) or len(raw) < 24:
            return
        defer = self._defer_rx()
        try:
            if getattr(pkt, 'type_id', None) == 0:
                # A protected management MPDU is only meaningful when the
                # software BIP key lifecycle is active. Verify the MMIE and
                # IPN before handing it to hostapd; otherwise an unverified
                # robust-management frame would bypass PMF in the raw path.
                if raw[1] & 0x40:
                    if self._bip is None:
                        return
                    self._bip.verify(raw)
                self._relay_rx("mgmt", (raw, self._current_freq or 2412,
                                        max(-128, min(127, int(pkt.rssi)))),
                               defer=defer)
            else:
                if self.software_accounting:
                    addresses = self._data_addresses(raw)
                    if addresses is not None:
                        self._relay_rx("data", (addresses[0], addresses[1], len(raw)),
                                       defer=defer)
                found = extract_eapol_from_mpdu(raw)
                if found is None and self._ccmp is not None:
                    found = extract_protected_eapol_from_mpdu(raw, self._ccmp)
                if found is None and self._ccmp256 is not None:
                    found = extract_protected_eapol_from_mpdu(raw, self._ccmp256)
                if found is None and self._gcmp is not None:
                    found = extract_protected_eapol_from_mpdu(raw, self._gcmp)
                if found is None and self._gcmp256 is not None:
                    found = extract_protected_eapol_from_mpdu(raw, self._gcmp256)
                if found is None and self._tkip is not None:
                    found = extract_protected_eapol_from_mpdu(raw, self._tkip)
                if found:
                    self._relay_rx("eapol", found, defer=defer)
        except (RuntimeError, ValueError, OSError):
            _LOG.debug('wifit3 RX bridge is disconnected or cannot relay frame')

    @staticmethod
    def _data_addresses(frame: bytes) -> tuple[bytes, bytes] | None:
        """Return (source, destination) for a raw 802.11 data MPDU."""
        if len(frame) < 24:
            return None
        fc = int.from_bytes(frame[:2], 'little')
        if (fc & 0x000c) != 0x0008 or fc & 0x4000:
            return None
        to_ds = bool(fc & 0x0100)
        from_ds = bool(fc & 0x0200)
        if to_ds and from_ds:  # WDS: addr4 is source, addr3 is destination.
            if len(frame) < 30:
                return None
            return frame[24:30], frame[16:22]
        if to_ds:             # client -> AP
            return frame[10:16], frame[16:22]
        if from_ds:           # AP -> client
            return frame[16:22], frame[4:10]
        # Non-DS data (e.g. IBSS): transmitter/source is addr2.
        return frame[10:16], frame[4:10]

    def attach(self, bridge: Wifit3Bridge) -> None:
        self._assert_lease()
        if self._rx_attached:
            raise RuntimeError('RX callback is already attached')
        self._bridge = bridge
        self.iface.register_rx_callback(self.on_packet)
        self._rx_attached = True

    async def close(self) -> None:
        self._rx_stop.set()
        self._rx_thread.join(timeout=1)
        if self._hardware_ack_armed:
            clear_fake_mac = getattr(self.iface, 'clear_fake_mac', None)
            if callable(clear_fake_mac):
                try:
                    await clear_fake_mac()
                except Exception:
                    _LOG.debug('active-monitor cleanup failed', exc_info=True)
            disable_rx_acks = getattr(self.iface, 'disable_rx_acks', None)
            if callable(disable_rx_acks):
                try:
                    await disable_rx_acks()
                except Exception:
                    _LOG.debug('ACK-tally cleanup failed', exc_info=True)
            self._hardware_ack_armed = False
        if self._rx_attached:
            self.iface.unregister_rx_callback(self.on_packet)
        self._rx_attached = False
        self._bridge = None
        if self._beacon_task:
            self._beacon_task.cancel()
            try:
                await self._beacon_task
            except asyncio.CancelledError:
                pass
            self._beacon_task = None
        if self._ccmp is not None:
            self._ccmp.clear()
        if self._ccmp256 is not None:
            self._ccmp256.clear()
        if self._gcmp is not None:
            self._gcmp.clear()
        if self._gcmp256 is not None:
            self._gcmp256.clear()
        if self._tkip is not None:
            self._tkip.clear()
        if self._bip is not None:
            self._bip.clear()

    def station_add(self, addr: bytes, aid: int, capability: int,
                    update: bool) -> bool:
        """Maintain AP station state for the explicit raw-monitor lab path.

        This is intentionally not presented as a chipset hardware admission table:
        WlanInterface has no public station-programming API. It gives hostapd a
        truthful software station registry while the radio remains in monitor mode.
        """
        if not self.software_stations or len(addr) != 6 or addr == b'\xff' * 6:
            return False
        if not 0 <= aid <= 0xffff or not 0 <= capability <= 0xffff:
            return False
        with self._stations_lock:
            if addr in self._stations and not update:
                return False
            old = self._stations.get(addr, {})
            self._stations[bytes(addr)] = {
                'aid': aid,
                'capability': capability,
                'flags': int(old.get('flags', 0)),
                'authorized': bool(old.get('authorized', False)),
            }
        return True

    def station_flags(self, addr: bytes, total: int, enable: int,
                      mask: int) -> bool:
        if not self.software_stations or len(addr) != 6:
            return False
        if not 0 <= total <= 0xffffffff or not 0 <= enable <= 0xffffffff:
            return False
        if not 0 <= mask <= 0xffffffff:
            return False
        with self._stations_lock:
            state = self._stations.get(bytes(addr))
            if state is None:
                return False
            # hostapd supplies the complete bitmap plus the traditional
            # flags_or/flags_and update masks. Preserve that ABI rather than
            # treating the first argument as an unconditional assignment.
            effective = (int(total) & int(mask)) | int(enable)
            state['flags'] = effective
            state['authorized'] = bool(effective & 0x01)
        return True

    def station_remove(self, addr: bytes) -> bool:
        if not self.software_stations or len(addr) != 6:
            return False
        with self._stations_lock:
            # hostapd may repeat cleanup after a failed association; removal
            # is therefore an idempotent successful operation.
            self._stations.pop(bytes(addr), None)
            return True

    def station_snapshot(self) -> dict[str, dict[str, int | bool]]:
        """Return a copy suitable for diagnostics and tests; no key material included."""
        with self._stations_lock:
            return {
                addr.hex(':'): dict(state)
                for addr, state in self._stations.items()
            }

    # EAPOL data TX is opt-in: not every mini-driver reliably transmits data.
    def tx_eapol(self, destination: bytes, source: bytes,
                 payload: bytes, encrypt: bool) -> bool:
        if not self.allow_eapol_tx or self._current_freq is None:
            return False
        if len(destination) != 6 or len(source) != 6 or not 4 <= len(payload) <= 2300:
            return False
        if (encrypt and self._ccmp is None and self._ccmp256 is None and
                self._gcmp is None and self._gcmp256 is None and
                self._tkip is None):
            return False
        seq_ctrl = self._next_seq_ctrl(0)
        # Build an ordinary FromDS frame first; ccmp_encrypt_mpdu sets the
        # Protected bit and inserts the CCMP header after authenticating it.
        # Beacon, management and EAPOL share one per-TA sequence counter.
        fc = 0x0208
        mpdu = (fc.to_bytes(2, 'little') + b"\x00\x00" + destination + source + source +
                seq_ctrl + _LLC_EAPOL + payload)
        if encrypt:
            encrypted = None
            for store in (self._ccmp, self._ccmp256, self._gcmp, self._gcmp256,
                          self._tkip):
                if store is None:
                    continue
                try:
                    encrypted = store.encrypt(mpdu, bytes(destination))
                    break
                except (CcmpError, TkipError):
                    continue
            if encrypted is None:
                return False
            mpdu = encrypted
        return self._run(self.iface.send_no_wait(mpdu))

    def install_key(self, *args) -> bool:
        """Install or remove an explicitly-supported software cipher key."""
        if len(args) != 6:
            return False
        try:
            if args[0] == WPA_ALG_NONE:
                stores = (self._ccmp, self._ccmp256, self._gcmp,
                          self._gcmp256, self._tkip, self._bip)
                return any(store is not None and store.install(*args)
                           for store in stores)
            if args[0] in (WPA_ALG_BIP_CMAC_128, WPA_ALG_BIP_GMAC_128,
                           WPA_ALG_BIP_GMAC_256, WPA_ALG_BIP_CMAC_256):
                return bool(self._bip and self._bip.install(*args))
            if args[0] == WPA_ALG_GCMP:
                return bool(self._gcmp and self._gcmp.install(*args))
            if args[0] == WPA_ALG_GCMP_256:
                return bool(self._gcmp256 and self._gcmp256.install(*args))
            if args[0] == WPA_ALG_CCMP_256:
                return bool(self._ccmp256 and self._ccmp256.install(*args))
            if args[0] == WPA_ALG_TKIP:
                return bool(self._tkip and self._tkip.install(*args))
            return bool(self._ccmp and self._ccmp.install(*args))
        except (TypeError, ValueError, CcmpError, BipError):
            return False

    def tx_tsc(self, addr: bytes, index: int) -> int | None:
        """Latest used PN/TSC/IPN for hostapd's get_seqnum request.

        Indices 4 and 5 are IGTK slots. Other indices are pairwise or group
        cipher slots. A missing key returns None so the bridge reports failure
        instead of an invented packet number.
        """
        if not isinstance(addr, bytes) or len(addr) != 6:
            return None
        if not isinstance(index, int) or not 0 <= index <= 255:
            return None
        if index in (4, 5):
            if self._bip is None:
                return None
            return self._bip.last_tx_tsc(index)
        for store in (self._ccmp, self._ccmp256, self._gcmp, self._gcmp256, self._tkip):
            if store is None:
                continue
            value = store.last_tx_tsc(addr, index)
            if value is not None:
                return value
        return None

    def key_snapshot(self) -> dict[str, dict[str, int | bool]]:
        snapshot = self._ccmp.snapshot() if self._ccmp is not None else {}
        if self._ccmp256 is not None:
            snapshot.update({f'ccmp256/{key}': state
                             for key, state in self._ccmp256.snapshot().items()})
        if self._bip is not None:
            snapshot.update({f'bip/{index}': state
                             for index, state in self._bip.snapshot().items()})
        if self._gcmp is not None:
            snapshot.update({f'gcmp/{key}': state
                             for key, state in self._gcmp.snapshot().items()})
        if self._gcmp256 is not None:
            snapshot.update({f'gcmp256/{key}': state
                             for key, state in self._gcmp256.snapshot().items()})
        if self._tkip is not None:
            snapshot.update({f'tkip/{key}': state
                             for key, state in self._tkip.snapshot().items()})
        return snapshot


def bridge_config_for_interface(iface, *, channels: tuple[int, ...],
                                software_beacons: bool = False,
                                allow_eapol_tx: bool = False,
                                software_stations: bool = False,
                                software_ccmp: bool = False,
                                software_ccmp256: bool = False,
                                software_bip: bool = False,
                                software_sae: bool = False,
                                software_accounting: bool = False,
                                software_gcmp: bool = False,
                                software_gcmp256: bool = False,
                                software_tkip: bool = False) -> RadioConfig:
    """Generate handshake with only available capabilities, no invented key support.

    Caller supplies a restrictive non-DFS channel list allowed by local law.
    Set software_beacons=True only for laboratory-only open AP tests.
    """
    if not channels or any(c not in iface.supported_channels for c in channels):
        raise ValueError('channels must be present in real WlanInterface SUPPORTED_CHANNELS')
    if not software_beacons:
        raise ValueError('CAP_BEACON unavailable: enable lab-only software beacon mode explicitly')
    mac = getattr(iface, 'mac_address', None)
    if not isinstance(mac, str):
        raise ValueError('MAC unavailable: ensure iface.connect() completed')
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    capabilities = (CAP_TX_MGMT | CAP_RX_MGMT | CAP_SET_FREQ | CAP_BEACON |
                    CAP_RX_EAPOL |
                    (CAP_TX_EAPOL if allow_eapol_tx else 0) |
                    (CAP_STA if software_stations else 0) |
                    (CAP_KEY if (((software_ccmp or software_ccmp256 or software_gcmp or software_gcmp256 or software_tkip) and allow_eapol_tx) or
                                 software_bip) else 0) |
                    (CAP_CCMP_256 if software_ccmp256 else 0) |
                    (CAP_TKIP if software_tkip else 0) |
                    (CAP_BIP if software_bip else 0) |
                    (CAP_SAE if (software_sae and software_stations and
                                 software_ccmp and allow_eapol_tx) else 0) |
                    (CAP_ACCOUNTING if software_accounting else 0) |
                    (CAP_GCMP if software_gcmp else 0) |
                    (CAP_GCMP_256 if software_gcmp256 else 0))
    return RadioConfig(mac=mac_bytes,
                       frequencies=tuple(channel_to_mhz(c) for c in channels),
                       capabilities=capabilities)
