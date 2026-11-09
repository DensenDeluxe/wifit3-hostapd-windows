"""Source-API integration tests with a fake WlanInterface (no RF transmissions)."""
import asyncio
from dataclasses import dataclass
import secrets
import threading
import time
from types import SimpleNamespace
import unittest

import wifit3_bridge.wlan_interface_adapter as adapter
from wifit3.chips.driver import FakeMacSupport
from wifit3_bridge.bridge import Wifit3Bridge
from wifit3_bridge.ccmp import ccmp_decrypt_mpdu, ccmp_encrypt_mpdu
from wifit3_bridge.wlan_interface_adapter import (
    Wifit3InterfaceRadio, bridge_config_for_interface,
    extract_eapol_from_mpdu, channel_to_mhz, mhz_to_channel,
)

class FakeInterface:
    """Mock of the public WlanInterface API, not of a USB mini-driver."""
    mac_address = '02:11:22:33:44:55'
    supported_channels = [1, 6, 11]
    def __init__(self):
        self.channel = 1
        self.frames = []
        self.ack_frames = []
        self.callbacks = []
        self.send_results = []
        self.active_monitor_mac = None
        self.rx_acks_enabled = False
    async def set_channel(self, channel, scan=False):
        if channel not in self.supported_channels:
            return False
        self.channel = channel
        return True
    async def send_no_wait(self, frame):
        self.frames.append(bytes(frame))
        return self.send_results.pop(0) if self.send_results else True
    async def send_until_ack(self, frame, max_retries=0):
        self.ack_frames.append((bytes(frame), max_retries))
        return self.send_results.pop(0) if self.send_results else True
    async def enable_rx_acks(self):
        self.rx_acks_enabled = True
    async def disable_rx_acks(self):
        self.rx_acks_enabled = False
    async def set_fake_mac(self, mac=None, bssid=None):
        self.active_monitor_mac = mac
        return mac
    async def clear_fake_mac(self):
        self.active_monitor_mac = None
    def register_rx_callback(self, cb):
        self.callbacks.append(cb)
    def unregister_rx_callback(self, cb):
        self.callbacks.remove(cb)

@dataclass
class FakePacket:
    raw: bytes
    type_id: int
    rssi: int = -45

class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.lease = True
        self.iface = FakeInterface()
        self.radio = Wifit3InterfaceRadio(self.iface, self.loop,
                                          lease_guard=lambda: self.lease,
                                          software_beacons=True)
        self.cfg = bridge_config_for_interface(self.iface, channels=(1,6),
                                                software_beacons=True)
    def tearDown(self):
        self.lease = False
        task = asyncio.run_coroutine_threadsafe(self.radio.close(), self.loop)
        task.result(timeout=2)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=2)
        self.loop.close()

    def test_channel_frequency(self):
        self.assertEqual(mhz_to_channel(2412), 1)
        self.assertEqual(mhz_to_channel(2484), 14)
        self.assertEqual(channel_to_mhz(36), 5180)
        self.assertTrue(self.radio.set_frequency(2437))
        self.assertEqual(self.iface.channel, 6)
        self.assertFalse(self.radio.set_frequency(5500))
        self.assertFalse(self.radio.tx_mgmt(b'', 2437, True, True, 0))

    def test_management_tx_retries_a_completed_transient_usb_failure(self):
        self.assertTrue(self.radio.set_frequency(2412))
        self.iface.send_results = [False, True]
        frame = b'\x40\x00' + b'\x00' * 22

        self.assertTrue(self.radio.tx_mgmt(frame, 2412, True, True, 0))
        self.assertEqual(len(self.iface.frames), 2)

    def test_optional_hardware_ack_uses_public_ack_api_for_unicast_management(self):
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, hardware_ack=True)
        armed = asyncio.run_coroutine_threadsafe(
            radio.arm_hardware_ack(), self.loop).result(timeout=2)
        self.assertTrue(armed)
        self.assertTrue(self.iface.rx_acks_enabled)
        self.assertEqual(self.iface.active_monitor_mac, self.iface.mac_address)
        self.assertTrue(radio.set_frequency(2412))
        destination = bytes.fromhex('0a1122334455')
        source = bytes.fromhex('021122334455')
        frame = (b'\xb0\x00' + b'\x00\x00' + destination + source + source +
                 b'\x00\x00')
        self.assertTrue(radio.tx_mgmt(frame, 2412, False, True, 0))
        self.assertEqual(len(self.iface.ack_frames), 1)
        self.assertEqual(radio.hardware_ack_tx_count, 1)
        self.assertEqual(len(self.iface.frames), 0)
        asyncio.run_coroutine_threadsafe(radio.close(), self.loop).result(timeout=2)
        self.assertFalse(self.iface.rx_acks_enabled)
        self.assertIsNone(self.iface.active_monitor_mac)

    def test_hardware_ack_support_detection_requires_complete_public_api(self):
        self.iface.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE)
        self.assertTrue(adapter.hardware_ack_supported(self.iface))

        class PartialInterface:
            driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE)
            async def set_fake_mac(self, mac=None, bssid=None):
                return True
            async def enable_rx_acks(self):
                return None

        self.assertFalse(adapter.hardware_ack_supported(PartialInterface()))
        self.iface.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.NONE)
        self.assertFalse(adapter.hardware_ack_supported(self.iface))
        self.assertFalse(adapter.hardware_ack_supported(object()))

    def test_beacon_software_tx_and_lease_loss(self):
        self.assertTrue(self.radio.set_frequency(2412))
        head = b'\x80\x00' + b'\x00'*34
        self.assertTrue(self.radio.set_beacon(head, b'\x00\x03lab', 100, 1))
        self.assertGreaterEqual(len(self.iface.frames), 1)
        first = self.iface.frames[0]
        self.assertEqual(first[:22], head[:22])
        self.assertNotEqual(first[24:32], b'\x00' * 8)
        # hostapd leaves a TIM gap between head and tail. The adapter fills it.
        self.assertEqual(first[36:42], b'\x05\x04\x00\x01\x00\x00')
        self.assertEqual(first[42:], b'\x00\x03lab')
        self.lease = False
        self.assertFalse(self.radio.tx_mgmt(head, 2412, True, True, 0))

    def test_beacon_tim_covers_station_aid_and_dtim_count_advances(self):
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_stations=True)
        self.assertTrue(radio.set_frequency(2412))
        self.assertTrue(radio.station_add(bytes.fromhex('0a1122334455'), 9, 0, False))
        head = b'\x80\x00' + b'\x00' * 34
        self.assertTrue(radio.set_beacon(head, b'\x00\x03lab', 1000, 2))
        first = self.iface.frames[-1]
        # AID 9 needs two bitmap octets. No power-save queue, so the bits stay clear.
        self.assertEqual(first[36:43], b'\x05\x05\x00\x02\x00\x00\x00')
        self.assertEqual(first[43:], b'\x00\x03lab')
        if radio._beacon_task is not None:
            radio._beacon_task.cancel()
        second = radio._compose_beacon()
        self.assertEqual(second[38], 1)  # next DTIM count
        self.assertEqual(second[39], 2)
        asyncio.run_coroutine_threadsafe(radio.close(), self.loop).result(timeout=2)

    def test_management_and_beacon_share_one_sequence_counter(self):
        self.assertTrue(self.radio.set_frequency(2412))
        head = b'\x80\x00' + b'\x00' * 34
        self.assertTrue(self.radio.set_beacon(head, b'\x00\x03lab', 1000, 1))
        if self.radio._beacon_task is not None:
            self.radio._beacon_task.cancel()
        beacon_seq = int.from_bytes(self.iface.frames[-1][22:24], 'little') >> 4
        self.assertEqual(beacon_seq, 0)
        frame = bytearray(b'\x40\x00' + b'\x00' * 22)
        frame[22] = 0x03
        self.assertTrue(self.radio.tx_mgmt(bytes(frame), 2412, True, True, 0))
        sent = self.iface.frames[-1]
        self.assertEqual(sent[22] & 0x0f, 0x03)
        self.assertEqual(int.from_bytes(sent[22:24], 'little') >> 4, 1)
        self.assertTrue(self.radio.tx_mgmt(bytes(frame), 2412, True, True, 0))
        sent = self.iface.frames[-1]
        self.assertEqual(int.from_bytes(sent[22:24], 'little') >> 4, 2)

    def test_noack_does_not_wait_for_link_ack(self):
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, hardware_ack=True)
        armed = asyncio.run_coroutine_threadsafe(
            radio.arm_hardware_ack(), self.loop).result(timeout=2)
        self.assertTrue(armed)
        self.assertTrue(radio.set_frequency(2412))
        destination = bytes.fromhex('0a1122334455')
        source = bytes.fromhex('021122334455')
        frame = (b'\x50\x00' + b'\x00\x00' + destination + source + source +
                 b'\x00\x00')
        self.assertTrue(radio.tx_mgmt(frame, 2412, True, True, 0))
        self.assertEqual(radio.hardware_ack_tx_count, 0)
        self.assertEqual(len(self.iface.ack_frames), 0)
        self.assertEqual(len(self.iface.frames), 1)
        self.iface.send_results = [False, False]
        missed = radio.tx_mgmt(frame, 2412, False, True, 0)
        self.assertEqual(missed, 2)
        self.assertEqual(radio.hardware_ack_tx_count, 1)
        asyncio.run_coroutine_threadsafe(radio.close(), self.loop).result(timeout=2)

    def test_beacon_retries_a_completed_transient_usb_failure(self):
        self.assertTrue(self.radio.set_frequency(2412))
        self.iface.send_results = [False, True]
        head = b'\x80\x00' + b'\x00' * 34

        self.assertTrue(self.radio.set_beacon(head, b'\x00\x03lab', 100, 1))
        self.assertEqual(len(self.iface.frames), 2)

    def test_source_api_rx_dispatch_to_bridge(self):
        token = secrets.token_hex(32)
        bridge = Wifit3Bridge(self.radio, self.cfg, token, port=0)
        self.radio.attach(bridge)
        self.assertEqual(len(self.iface.callbacks), 1)
        class Collector:
            def __init__(self): self.frames = []
            def on_mgmt_rx(self, frame, mhz, signal):
                self.frames.append((frame,mhz,signal))
            def on_eapol_rx(self, source, payload):
                self.frames.append((source,payload))
        collector = Collector()
        self.radio._bridge = collector
        collector.connected = lambda: True
        self.radio._current_freq = 2412
        self.iface.callbacks[0](FakePacket(b'\x40\x00' + b'\x00'*22, 0))
        self.assertEqual(collector.frames[0][1], 2412)
        source = b'\x02\x01\x02\x03\x04\x05'
        raw = (b'\x08\x01' + b'\x00\x00' + b'\x02\x11\x22\x33\x44\x55' +
               source + b'\x00'*8 + b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' +
               b'\x01\x00\x00\x00')
        self.iface.callbacks[0](FakePacket(raw, 2))
        self.assertEqual(collector.frames[1], (source,b'\x01\x00\x00\x00'))
        bridge.close()

    def test_optional_unprotected_eapol_tx(self):
        from wifit3_bridge.bridge import CAP_TX_EAPOL
        radio = Wifit3InterfaceRadio(self.iface, self.loop,
                                     lease_guard=lambda: self.lease,
                                     software_beacons=True, allow_eapol_tx=True)
        config = bridge_config_for_interface(self.iface, channels=(1,),
                                             software_beacons=True, allow_eapol_tx=True)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = b'\x02\x11\x22\x33\x44\x55'
        src = b'\x02\x01\x02\x03\x04\x05'
        data = b'\x01\x00\x00\x00'
        self.assertTrue(radio.tx_eapol(dest, src, data, encrypt=False))
        self.assertTrue(self.iface.frames[-1].endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + data))
        self.assertFalse(radio.tx_eapol(dest, src, data, encrypt=True))

    def test_optional_wpa2_ccmp_key_and_protected_eapol_path(self):
        from wifit3_bridge.bridge import CAP_KEY, CAP_TX_EAPOL
        from wifit3_bridge.ccmp import WPA_ALG_CCMP
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, allow_eapol_tx=True,
            software_stations=True, software_ccmp=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            allow_eapol_tx=True, software_stations=True, software_ccmp=True,
        )
        self.assertTrue(config.capabilities & CAP_KEY)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = bytes.fromhex('0a1122334455')
        src = bytes.fromhex('021122334455')
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        payload = b'\x02\x03\x00\x05hello'
        self.assertTrue(radio.install_key(WPA_ALG_CCMP, 0, dest, 0, b'', key))
        self.assertTrue(radio.tx_eapol(dest, src, payload, encrypt=True))
        pn, decoded = ccmp_decrypt_mpdu(self.iface.frames[-1], key)
        self.assertEqual(pn, 1)
        self.assertTrue(decoded.endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload))

        class Collector:
            def __init__(self): self.frames = []
            def on_eapol_rx(self, source, payload): self.frames.append((source, payload))

        collector = Collector()
        collector.connected = lambda: True
        radio._bridge = collector
        uplink = (b'\x08\x01\x00\x00' + src + dest + src + b'\x00\x00' +
                  b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload)
        # The STA's pairwise key is keyed by its source address on AP RX.
        self.assertTrue(radio.install_key(WPA_ALG_CCMP, 0, dest, 0, b'', key))
        protected = ccmp_encrypt_mpdu(uplink, key, 2)
        radio.on_packet(FakePacket(protected, 2))
        self.assertEqual(collector.frames, [(dest, payload)])

    def test_optional_wpa3_gcmp128_key_and_protected_eapol_path(self):
        from wifit3_bridge.bridge import CAP_GCMP, CAP_KEY, CAP_TX_EAPOL
        from wifit3_bridge.gcmp import WPA_ALG_GCMP, gcmp_decrypt_mpdu
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, allow_eapol_tx=True,
            software_stations=True, software_gcmp=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            allow_eapol_tx=True, software_stations=True, software_gcmp=True,
        )
        self.assertTrue(config.capabilities & CAP_GCMP)
        self.assertTrue(config.capabilities & CAP_KEY)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = bytes.fromhex('0a1122334455')
        src = bytes.fromhex('021122334455')
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        payload = b'\x02\x03\x00\x05hello'
        self.assertTrue(radio.install_key(WPA_ALG_GCMP, 0, dest, 0, b'', key))
        self.assertTrue(radio.tx_eapol(dest, src, payload, encrypt=True))
        pn, decoded = gcmp_decrypt_mpdu(self.iface.frames[-1], key)
        self.assertEqual(pn, 1)
        self.assertTrue(decoded.endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload))

    def test_optional_gcmp256_key_and_protected_eapol_path(self):
        from wifit3_bridge.bridge import CAP_GCMP_256, CAP_KEY, CAP_TX_EAPOL
        from wifit3_bridge.gcmp import (
            WPA_ALG_GCMP_256, gcmp_decrypt_mpdu,
        )
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, allow_eapol_tx=True,
            software_stations=True, software_gcmp256=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            allow_eapol_tx=True, software_stations=True,
            software_gcmp256=True,
        )
        self.assertTrue(config.capabilities & CAP_GCMP_256)
        self.assertTrue(config.capabilities & CAP_KEY)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = bytes.fromhex('0a1122334455')
        src = bytes.fromhex('021122334455')
        key = bytes.fromhex(
            '00112233445566778899aabbccddeeff'
            '102132435465768798a9bacbdcedfe0f')
        payload = b'\x02\x03\x00\x05hello'
        self.assertTrue(radio.install_key(WPA_ALG_GCMP_256, 0, dest, 0, b'', key))
        self.assertTrue(radio.tx_eapol(dest, src, payload, encrypt=True))
        pn, decoded = gcmp_decrypt_mpdu(self.iface.frames[-1], key)
        self.assertEqual(pn, 1)
        self.assertTrue(decoded.endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload))

    def test_optional_ccmp256_key_and_protected_eapol_path(self):
        from wifit3_bridge.bridge import CAP_CCMP_256, CAP_KEY, CAP_TX_EAPOL
        from wifit3_bridge.ccmp import (
            WPA_ALG_CCMP_256, ccmp256_decrypt_mpdu,
        )
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, allow_eapol_tx=True,
            software_stations=True, software_ccmp256=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            allow_eapol_tx=True, software_stations=True,
            software_ccmp256=True,
        )
        self.assertTrue(config.capabilities & CAP_CCMP_256)
        self.assertTrue(config.capabilities & CAP_KEY)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = bytes.fromhex('0a1122334455')
        src = bytes.fromhex('021122334455')
        key = bytes.fromhex(
            '00112233445566778899aabbccddeeff'
            '102132435465768798a9bacbdcedfe0f')
        payload = b'\x02\x03\x00\x05hello'
        self.assertTrue(radio.install_key(WPA_ALG_CCMP_256, 0, dest, 0, b'', key))
        self.assertTrue(radio.tx_eapol(dest, src, payload, encrypt=True))
        pn, decoded = ccmp256_decrypt_mpdu(self.iface.frames[-1], key)
        self.assertEqual(pn, 1)
        self.assertTrue(decoded.endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload))

    def test_optional_tkip_key_and_protected_eapol_path(self):
        from wifit3_bridge.bridge import CAP_KEY, CAP_TKIP, CAP_TX_EAPOL
        from wifit3_bridge.tkip import WPA_ALG_TKIP, tkip_decrypt_mpdu
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, allow_eapol_tx=True,
            software_stations=True, software_tkip=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            allow_eapol_tx=True, software_stations=True,
            software_tkip=True,
        )
        self.assertTrue(config.capabilities & CAP_TKIP)
        self.assertTrue(config.capabilities & CAP_KEY)
        self.assertTrue(config.capabilities & CAP_TX_EAPOL)
        self.assertTrue(radio.set_frequency(2412))
        dest = bytes.fromhex('0a1122334455')
        src = bytes.fromhex('021122334455')
        key = bytes.fromhex(
            '00112233445566778899aabbccddeeff'
            '102132435465768798a9bacbdcedfe0f')
        payload = b'\x02\x03\x00\x05hello'
        self.assertTrue(radio.install_key(WPA_ALG_TKIP, 0, dest, 0, b'', key))
        self.assertTrue(radio.tx_eapol(dest, src, payload, encrypt=True))
        tsc, decoded = tkip_decrypt_mpdu(
            self.iface.frames[-1], key, source=src)
        self.assertEqual(tsc, 1)
        self.assertTrue(decoded.endswith(b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + payload))

    def test_tkip_key_removal_uses_software_store(self):
        from wifit3_bridge.ccmp import WPA_ALG_NONE
        from wifit3_bridge.tkip import WPA_ALG_TKIP
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_tkip=True,
        )
        peer = bytes.fromhex('0a1122334455')
        key = bytes(range(32))
        self.assertTrue(radio.install_key(WPA_ALG_TKIP, 0, peer, 0, b'', key))
        self.assertIn(f'tkip/{peer.hex(":")}/0', radio.key_snapshot())
        self.assertTrue(radio.install_key(WPA_ALG_NONE, 0, peer, 0, b'', b''))
        self.assertNotIn(f'tkip/{peer.hex(":")}/0', radio.key_snapshot())

    def test_optional_software_sae_capability_is_explicit(self):
        # CAP_SAE is intentionally the next extension bit after the current
        # public bridge capabilities.  The driver must only advertise SAE
        # when the caller opts into the software SAE/AP path.
        cap_sae = 1 << 9
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_stations=True,
            allow_eapol_tx=True, software_ccmp=True, software_sae=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            software_stations=True, allow_eapol_tx=True,
            software_ccmp=True, software_sae=True,
        )
        self.assertTrue(config.capabilities & cap_sae)
        self.assertTrue(radio.software_sae)

    def test_optional_software_accounting_forwards_raw_data_metadata(self):
        from wifit3_bridge.bridge import CAP_ACCOUNTING
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_accounting=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            software_accounting=True,
        )
        self.assertTrue(config.capabilities & CAP_ACCOUNTING)
        self.assertTrue(radio.software_accounting)

        class Collector:
            def __init__(self): self.frames = []
            def connected(self): return True
            def on_data_rx(self, source, destination, frame_len):
                self.frames.append((source, destination, frame_len))

        collector = Collector()
        radio._bridge = collector
        sta = bytes.fromhex('0a1122334455')
        ap = bytes.fromhex('021122334455')
        raw = (b'\x08\x01\x00\x00' + ap + sta + ap + b'\x00\x00' +
               b'accounting-payload')
        radio.on_packet(FakePacket(raw, 2))
        self.assertEqual(collector.frames, [(sta, ap, len(raw))])

    def test_capabilities_never_invent_key_tx(self):
        from wifit3_bridge.bridge import CAP_KEY, CAP_STA, CAP_TX_EAPOL
        self.assertEqual(self.cfg.capabilities & (CAP_KEY|CAP_STA|CAP_TX_EAPOL), 0)
        self.assertFalse(self.radio.install_key(None))

    def test_optional_software_station_state_is_explicit_and_lifecycle_safe(self):
        from wifit3_bridge.bridge import CAP_STA
        addr = bytes.fromhex('021122334455')
        radio = Wifit3InterfaceRadio(self.iface, self.loop,
                                     lease_guard=lambda: self.lease,
                                     software_beacons=True,
                                     software_stations=True)
        config = bridge_config_for_interface(self.iface, channels=(1,),
                                             software_beacons=True,
                                             software_stations=True)
        self.assertTrue(config.capabilities & CAP_STA)
        self.assertTrue(radio.station_add(addr, 7, 0x1234, False))
        self.assertEqual(radio.station_snapshot()[addr.hex(':')], {
            'aid': 7, 'capability': 0x1234, 'flags': 0, 'authorized': False,
        })
        self.assertTrue(radio.station_flags(addr, 0x41, 0x41, 0xFFFFFFFF))
        self.assertEqual(radio.station_snapshot()[addr.hex(':')]['flags'], 0x41)
        self.assertTrue(radio.station_snapshot()[addr.hex(':')]['authorized'])
        self.assertTrue(radio.station_remove(addr))
        self.assertNotIn(addr.hex(':'), radio.station_snapshot())
        self.assertTrue(radio.station_remove(addr))

    def test_station_flags_honors_hostapd_or_and_mask_semantics(self):
        addr = bytes.fromhex('021122334455')
        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_stations=True,
        )
        self.assertTrue(radio.station_add(addr, 7, 0x1234, False))
        self.assertTrue(radio.station_flags(addr, 0x41, 0x01, 0xFFFFFFFF))
        self.assertEqual(radio.station_snapshot()[addr.hex(':')]['flags'], 0x41)
        self.assertTrue(radio.station_flags(addr, 0x40, 0x00, 0xFFFFFFFF))
        self.assertEqual(radio.station_snapshot()[addr.hex(':')]['flags'], 0x40)
        self.assertFalse(radio.station_snapshot()[addr.hex(':')]['authorized'])

    def test_eapol_parser_rejects_protected(self):
        raw = (b'\x08\x41' + b'\x00'*22 + b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' +
               b'\x01\x00\x00\x00')
        self.assertIsNone(extract_eapol_from_mpdu(raw))

    def test_eapol_parser_accepts_dma_padding_before_llc(self):
        sta = bytes.fromhex('0a1122334455')
        ap = bytes.fromhex('021122334455')
        payload = b'\x02\x03\x00\x00'
        raw = (b'\x88\x01\x00\x00' + ap + sta + ap + b'\x00\x00' +
               b'\x00\x00\x00\x00' + b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' +
               payload)
        self.assertEqual(extract_eapol_from_mpdu(raw), (sta, payload))

    def test_optional_software_bip_protects_robust_management_for_mfp_station(self):
        from wifit3_bridge.bip import WPA_ALG_BIP_CMAC_128, bip_cmac_verify
        from wifit3_bridge.bridge import CAP_BIP
        from wifit3_bridge.ccmp import CCMP_BROADCAST

        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_stations=True, software_bip=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            software_stations=True, software_bip=True,
        )
        self.assertTrue(config.capabilities & CAP_BIP)
        self.assertTrue(radio.set_frequency(2412))
        sta = bytes.fromhex('0a1122334455')
        ap = bytes.fromhex(self.iface.mac_address.replace(':', ''))
        self.assertTrue(radio.station_add(sta, 1, 0, False))
        self.assertTrue(radio.station_flags(sta, 0x08, 0x08, 0xFFFFFFFF))
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        self.assertTrue(radio.install_key(
            WPA_ALG_BIP_CMAC_128, 4, CCMP_BROADCAST, 0x10, b'', key))
        action = b'\xd0\x00\x00\x00' + sta + ap + ap + b'\x10\x00\x08\x01test'

        self.assertTrue(radio.tx_mgmt(action, 2412, False, False, 0))
        protected = self.iface.frames[-1]
        self.assertTrue(protected[1] & 0x40)
        self.assertEqual(bip_cmac_verify(protected, key, minimum_ipn=0,
                                         expected_key_id=4), 1)

    def test_optional_software_bip_gmac256_protects_robust_management(self):
        from wifit3_bridge.bip import (
            WPA_ALG_BIP_GMAC_256, bip_gmac_verify,
        )
        from wifit3_bridge.bridge import CAP_BIP
        from wifit3_bridge.ccmp import CCMP_BROADCAST

        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_stations=True, software_bip=True,
        )
        config = bridge_config_for_interface(
            self.iface, channels=(1,), software_beacons=True,
            software_stations=True, software_bip=True,
        )
        self.assertTrue(config.capabilities & CAP_BIP)
        self.assertTrue(radio.set_frequency(2412))
        sta = bytes.fromhex('0a1122334455')
        ap = bytes.fromhex(self.iface.mac_address.replace(':', ''))
        self.assertTrue(radio.station_add(sta, 1, 0, False))
        self.assertTrue(radio.station_flags(sta, 0x08, 0x08, 0xFFFFFFFF))
        key = bytes.fromhex(
            '00112233445566778899aabbccddeeff'
            '102132435465768798a9bacbdcedfe0f')
        self.assertTrue(radio.install_key(
            WPA_ALG_BIP_GMAC_256, 4, CCMP_BROADCAST, 0x10, b'', key))
        action = b'\xd0\x00\x00\x00' + sta + ap + ap + b'\x10\x00\x08\x01test'

        self.assertTrue(radio.tx_mgmt(action, 2412, False, False, 0))
        protected = self.iface.frames[-1]
        self.assertTrue(protected[1] & 0x40)
        self.assertEqual(bip_gmac_verify(protected, key, minimum_ipn=0,
                                         expected_key_id=4), 1)

    def test_optional_software_bip_verifies_protected_management_on_rx(self):
        from wifit3_bridge.bip import WPA_ALG_BIP_CMAC_128
        from wifit3_bridge.ccmp import CCMP_BROADCAST

        radio = Wifit3InterfaceRadio(
            self.iface, self.loop, lease_guard=lambda: self.lease,
            software_beacons=True, software_bip=True,
        )
        ap = bytes.fromhex(self.iface.mac_address.replace(':', ''))
        sta = bytes.fromhex('0a1122334455')
        key = bytes.fromhex('00112233445566778899aabbccddeeff')
        self.assertTrue(radio.install_key(
            WPA_ALG_BIP_CMAC_128, 4, CCMP_BROADCAST, 0x10, b'', key))

        class Collector:
            def __init__(self):
                self.frames = []
            def connected(self):
                return True
            def on_mgmt_rx(self, frame, freq, signal):
                self.frames.append((frame, freq, signal))

        collector = Collector()
        radio._bridge = collector
        action = b'\xd0\x00\x00\x00' + ap + sta + ap + b'\x10\x00\x08\x01test'
        protected = radio._bip.protect(action)
        radio.on_packet(FakePacket(protected, 0))
        self.assertEqual(collector.frames, [(protected, 2412, -45)])

        radio.on_packet(FakePacket(protected, 0))
        self.assertEqual(len(collector.frames), 1)

if __name__ == '__main__':
    unittest.main()
