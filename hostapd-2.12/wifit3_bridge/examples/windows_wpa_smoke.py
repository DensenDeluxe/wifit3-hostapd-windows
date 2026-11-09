"""Native Windows WPA2/CCMP hostapd startup smoke test on one wifit3 card.

This exercises the real USB adapter, bridge IPC, hostapd capability negotiation,
GTK installation and AP startup.  It does not claim that a Windows client has
completed the four-way handshake; use a separate OTA test for that.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

from wifit3.device.manager import wlan_ifaces
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3_bridge.bridge import Wifit3Bridge
from wifit3_bridge.eap_tls_client import EapTlsClient, ENTERPRISE_RSN_IE
from wifit3_bridge.eap_fast_client import EapFastClient
from wifit3_bridge.eap_teap_client import EapTeapClient
from wifit3_bridge.eap_eke_client import EapEkeClient
from wifit3_bridge.eap_ikev2_client import EapIkev2Client
from wifit3_bridge.eap_aka_client import EapAkaClient
from wifit3_bridge.eap_aka_prime_client import EapAkaPrimeClient
from wifit3_bridge.eap_mschapv2_client import EapMschapv2Client
from wifit3_bridge.eap_peap_client import EapPeapMschapv2Client
from wifit3_bridge.eap_pax_client import EapPaxClient
from wifit3_bridge.eap_psk_client import EapPskClient
from wifit3_bridge.eap_pwd_client import EapPwdClient
from wifit3_bridge.eap_sake_client import EapSakeClient
from wifit3_bridge.eap_gpsk_client import EAP_GPSK_CIPHER_SHA256, EapGpskClient
from wifit3_bridge.eap_sim_client import EapSimClient
from wifit3_bridge.eap_ttls_client import EapTtlsMschapv2Client
from wifit3_bridge.ft_client import (
    FT_DEFAULT_MGMT_GROUP_CIPHER,
    FT_SAE_RSN_IE,
    FT_SAE_EXT_KEY_RSN_IE,
    build_ft_auth_ies,
    build_ft_auth_request,
    build_ft_reassoc_ies_for_addresses,
    build_ft_reassoc_request,
    build_mdie,
    derive_ft_ptk,
    derive_pmk_r0,
    derive_pmk_r1,
    parse_ft_ies,
    rsn_capabilities,
)
from wifit3_bridge.wlan_interface_adapter import (
    Wifit3InterfaceRadio,
    bridge_config_for_interface,
    hardware_ack_supported,
)

PMF_RSN_IE = GENERIC_RSN_IE[:-2] + b"\xc0\x00"
GCMP_RSN_IE = bytes.fromhex("30140100000fac080100000fac080100000fac020000")
GCMP256_RSN_IE = bytes.fromhex("30140100000fac090100000fac090100000fac020000")
CCMP256_RSN_IE = bytes.fromhex("30140100000fac0a0100000fac0a0100000fac020000")
TKIP_RSN_IE = bytes.fromhex("30140100000fac020100000fac020100000fac020000")
SAE_RSN_IE = (
    # hostapd's WPA3-SAE test configuration advertises this exact 22-byte
    # RSNE; the optional group-management-cipher tail is not present here.
    b"\x30\x14"
    b"\x01\x00"
    b"\x00\x0f\xac\x04"
    b"\x01\x00\x00\x0f\xac\x04"
    b"\x01\x00\x00\x0f\xac\x08"
    b"\xc0\x00"
)
SAE_EXT_KEY_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac18c000")


def _pmf_assoc_rsn_ie(rsn_ie: bytes, pmf_cipher: str) -> bytes:
    """Add the management-group suite required in a non-default PMF RSNE."""
    suite = {
        "BIP-GMAC-128": bytes.fromhex("000fac0b"),
        "BIP-GMAC-256": bytes.fromhex("000fac0c"),
        "BIP-CMAC-256": bytes.fromhex("000fac0d"),
    }.get(pmf_cipher.upper())
    if len(rsn_ie) < 2 or rsn_ie[0] != 0x30:
        raise ValueError("PMF association RSN IE is malformed")
    body_len = rsn_ie[1]
    body = rsn_ie[2:2 + body_len]
    if len(body) != body_len:
        raise ValueError("PMF association RSN IE is truncated")
    if len(body) < 2:
        raise ValueError("PMF association RSN IE has no RSN capabilities")
    # MFPC is required for a PMF association. Preserve any existing MFPR bit;
    # enterprise RSNEs otherwise advertise 0x0000.
    body = bytearray(body)
    capabilities = int.from_bytes(body[-2:], "little") | 0x0080
    body[-2:] = capabilities.to_bytes(2, "little")
    if suite is None:
        return bytes((0x30, body_len)) + bytes(body)
    # The PMKID count precedes the management-group suite, even when zero.
    return bytes((0x30, body_len + 6)) + bytes(body) + b"\x00\x00" + suite


def _openssl_binary() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    candidate = Path(__file__).resolve().parents[3] / "msys2" / "ucrt64" / "bin" / "openssl.exe"
    return str(candidate) if candidate.is_file() else None


def _radius_attr(attr_type: int, value: bytes) -> bytes:
    return bytes((attr_type, len(value) + 2)) + value


def _radius_access_request(identifier: int, secret: bytes) -> bytes:
    authenticator = bytes.fromhex("00112233445566778899aabbccddeeff")
    eap = b"\x02\x01\x00\x09\x01user"
    attrs = (_radius_attr(1, b"user") +
             _radius_attr(4, bytes((127, 0, 0, 1))) +
             _radius_attr(79, eap) +
             _radius_attr(80, b"\x00" * 16))
    packet = struct.pack("!BBH", 1, identifier, 20 + len(attrs)) + authenticator + attrs
    offset = (20 + len(_radius_attr(1, b"user")) +
              len(_radius_attr(4, bytes((127, 0, 0, 1)))) +
              len(_radius_attr(79, eap)) + 2)
    digest = hmac.new(secret, packet, hashlib.md5).digest()
    return packet[:offset] + digest + packet[offset + 16:]


def _radius_accounting_start(identifier: int, secret: bytes) -> bytes:
    attrs = (_radius_attr(40, struct.pack("!I", 1)) +
             _radius_attr(1, b"user") +
             _radius_attr(4, bytes((127, 0, 0, 1))))
    packet = struct.pack("!BBH", 4, identifier, 20 + len(attrs)) + b"\x00" * 16 + attrs
    authenticator = hashlib.md5(packet + secret).digest()
    return packet[:4] + authenticator + packet[20:]


def _radius_roundtrip(port: int, packet: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(packet, ("127.0.0.1", port))
        reply, _ = sock.recvfrom(4096)
        return reply
    finally:
        sock.close()


def _sim_triplets() -> list[tuple[bytes, bytes, bytes]]:
    return [
        (bytes(range(16)), bytes.fromhex("a0a1a2a3a4a5a6a7"),
         bytes.fromhex("d0d1d2d3")),
        (bytes(range(16, 32)), bytes.fromhex("b0b1b2b3b4b5b6b7"),
         bytes.fromhex("e0e1e2e3")),
    ]


def _aka_auth_data() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    return (bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)),
            bytes(range(48, 64)), bytes(range(64, 72)))


def _aka_prime_auth_data() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    autn = bytearray(range(16, 32))
    autn[6] |= 0x80
    return (bytes(range(16)), bytes(autn), bytes(range(32, 48)),
            bytes(range(48, 64)), bytes(range(64, 72)))


class _EapSimDbServer:
    def __init__(self, path: Path | None, triplets: list[tuple[bytes, bytes, bytes]],
                 aka_prime: bool = False):
        self.triplets = triplets
        self.aka_prime = aka_prime
        self.socket: socket.socket | None = None
        self.port: int | None = None
        self.endpoint: str | None = None
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.endpoint = f"udp:127.0.0.1:{self.port}"
        self.socket.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        if self.socket is None:
            return
        while not self.stop_event.is_set():
            try:
                request, address = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            fields = request.decode("ascii", errors="replace").split()
            self.requests.append(bytes(request))
            if fields[0] not in ("SIM-REQ-AUTH", "AKA-REQ-AUTH") or len(fields) < 2:
                continue
            if fields[0] == "SIM-REQ-AUTH":
                if len(fields) != 3:
                    continue
                try:
                    maximum = max(2, min(3, int(fields[2])))
                except ValueError:
                    continue
                response = "SIM-RESP-AUTH " + fields[1]
                for rand, kc, sres in self.triplets[:maximum]:
                    response += " " + kc.hex() + ":" + sres.hex() + ":" + rand.hex()
            else:
                auth_data = (_aka_prime_auth_data() if self.aka_prime
                             else _aka_auth_data())
                rand, autn, ik, ck, res = auth_data
                response = ("AKA-RESP-AUTH " + fields[1] + " " + rand.hex() +
                            " " + autn.hex() + " " + ik.hex() + " " + ck.hex() +
                            " " + res.hex())
            try:
                payload = response.encode("ascii")
                self.socket.sendto(payload, address)
                self.responses.append(payload)
            except OSError:
                return

    def close(self) -> None:
        self.stop_event.set()
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.thread is not None:
            self.thread.join(timeout=1)
            self.thread = None


def _wlan_interfaces() -> str:
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True, text=True, encoding="oem", errors="replace",
    )
    return result.stdout


def _connected_ssid(text: str) -> str | None:
    status = re.search(r"^\s*Status\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if not status or not ssid:
        return None
    if not re.search(r"verbunden|connected", status.group(1), re.IGNORECASE):
        return None
    return ssid.group(1).strip()


def _profile_xml(ssid: str, passphrase: str, open_network: bool = False) -> str:
    security = (
        "    <authEncryption><authentication>open</authentication>"
        "<encryption>none</encryption><useOneX>false</useOneX></authEncryption>"
        if open_network else
        "    <authEncryption><authentication>WPA2PSK</authentication>"
        "<encryption>AES</encryption><useOneX>false</useOneX></authEncryption>"
        "\n    <sharedKey><keyType>passPhrase</keyType><protected>false</protected>"
        f"<keyMaterial>{passphrase}</keyMaterial></sharedKey>"
    )
    return f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security>
{security}
  </security></MSM>
</WLANProfile>'''


def _run_ota_client(ssid: str, passphrase: str, interface: str,
                    wait_s: float, open_network: bool = False) -> bool:
    original = _connected_ssid(_wlan_interfaces())
    with tempfile.TemporaryDirectory(prefix="wifit3-wlan-") as directory:
        profile = Path(directory) / "profile.xml"
        profile.write_text(_profile_xml(ssid, passphrase, open_network), encoding="utf-8")
        added = subprocess.run(
            ["netsh", "wlan", "add", "profile", f"filename={profile}", "user=current"],
            capture_output=True, text=True, encoding="oem", errors="replace",
        ).returncode == 0
        if not added:
            print("ota_profile_added=False")
            return False
        try:
            # Force an active scan instead of relying on the currently
            # connected 5-GHz profile's cache.
            subprocess.run(
                ["netsh", "wlan", "disconnect", f"interface={interface}"],
                capture_output=True, text=True, encoding="oem", errors="replace",
            )
            subprocess.run(
                ["netsh", "wlan", "scan", f"interface={interface}"],
                capture_output=True, text=True, encoding="oem", errors="replace",
            )
            scan_seen = False
            scan_deadline = time.monotonic() + min(max(wait_s, 10.0), 20.0)
            scan_request = 0.0
            while time.monotonic() < scan_deadline:
                now = time.monotonic()
                if now >= scan_request:
                    subprocess.run(
                        ["netsh", "wlan", "scan", f"interface={interface}"],
                        capture_output=True, text=True, encoding="oem", errors="replace",
                    )
                    scan_request = now + 3.0
                    time.sleep(3.0)
                scan = subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid",
                     f"interface={interface}"],
                    capture_output=True, text=True, encoding="oem", errors="replace",
                )
                scan_seen = ssid in scan.stdout
                if scan_seen:
                    break
                time.sleep(1.0)
            print(f"ota_scan_seen={scan_seen}")
            deadline = time.monotonic() + wait_s
            connected = False
            connect_ok = False
            connect_message = ""
            connect_request = 0.0
            while time.monotonic() < deadline:
                now = time.monotonic()
                if now >= connect_request:
                    connect = subprocess.run(
                        ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}",
                         f"interface={interface}"],
                        capture_output=True, text=True, encoding="oem", errors="replace",
                    )
                    connect_ok = connect_ok or connect.returncode == 0
                    if connect.stdout.strip():
                        connect_message = connect.stdout.strip().splitlines()[-1]
                    elif connect.stderr.strip():
                        connect_message = connect.stderr.strip().splitlines()[-1]
                    connect_request = now + 10.0
                connected = _connected_ssid(_wlan_interfaces()) == ssid
                if connected:
                    break
                time.sleep(0.25)
            print(f"ota_connect_command_ok={connect_ok}")
            if connect_message:
                print("ota_connect_message=" + connect_message)
            print(f"ota_profile_added=True")
            print(f"ota_client_connected={connected}")
            return connected
        finally:
            subprocess.run(
                ["netsh", "wlan", "delete", "profile", f"name={ssid}",
                 f"interface={interface}"],
                capture_output=True, text=True, encoding="oem", errors="replace",
            )
            if original:
                subprocess.run(
                    ["netsh", "wlan", "connect", f"name={original}",
                     f"interface={interface}"],
                    capture_output=True, text=True, encoding="oem", errors="replace",
                )


async def run(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[3]
    hostapd = root / "hostapd-2.12" / "hostapd" / "hostapd.exe"
    if not hostapd.is_file():
        raise SystemExit(f"hostapd.exe fehlt: {hostapd}")

    ifaces = wlan_ifaces()
    if not ifaces:
        raise SystemExit("Kein wifit3-kompatibler USB-Dongle gefunden")
    # H2E is an AP configuration variant of the existing explicit SAE
    # software capability. Keep the CLI ergonomic while preserving all SAE
    # validation and capability gating below.
    if args.sae_h2e:
        args.sae = True
    if args.sae_ext_key:
        if args.sae_pk:
            raise SystemExit("--sae-ext-key ist nicht mit --sae-pk kombinierbar")
        args.sae = True
        args.sae_h2e = True
    if args.ft_sae_ext_key:
        if args.sae_ext_key or args.sae_pk or args.sae_password_id:
            raise SystemExit("--ft-sae-ext-key ist nicht mit SAE-PK, SAE-EXT-KEY oder einer Passwort-ID kombinierbar")
        args.ft_sae = True
        args.sae = True
        args.sae_h2e = True
    if args.ft_ota:
        args.ft_sae = True
        args.raw_assoc = True
        args.wpa_client = True
    if args.ft_sae:
        if args.sae_ext_key or args.sae_pk or args.sae_password_id:
            raise SystemExit("--ft-sae ist nur mit dem normalen FT-SAE-Pfad kombinierbar")
        args.sae = True
        args.sae_h2e = True
    if args.sae_group != 19:
        args.sae = True
    if args.sae_pk:
        if not args.sae_pk_credential:
            raise SystemExit("--sae-pk benötigt --sae-pk-credential")
        if args.sae_password_id:
            raise SystemExit("--sae-pk ist nicht mit --sae-password-id kombinierbar")
        args.sae = True
        args.sae_h2e = True
    if args.sae_password_id:
        args.sae = True
        args.sae_h2e = True
    if args.index < 0 or args.index >= len(ifaces):
        raise SystemExit(f"--index muss zwischen 0 und {len(ifaces) - 1} liegen")
    eap_psk_key = None
    if args.psk_client:
        try:
            eap_psk_key = bytes.fromhex(args.psk_key)
        except ValueError as error:
            raise SystemExit("--psk-key muss aus Hexadezimalzeichen bestehen") from error
        if len(eap_psk_key) != 16:
            raise SystemExit("--psk-key muss genau 16 Byte bzw. 32 Hexzeichen enthalten")
    eap_sake_key = None
    if args.sake_client:
        try:
            eap_sake_key = bytes.fromhex(args.sake_key)
        except ValueError as error:
            raise SystemExit("--sake-key muss aus Hexadezimalzeichen bestehen") from error
        if len(eap_sake_key) != 32:
            raise SystemExit("--sake-key muss genau 32 Byte bzw. 64 Hexzeichen enthalten")
    eap_pax_key = None
    if args.pax_client:
        try:
            eap_pax_key = bytes.fromhex(args.pax_key)
        except ValueError as error:
            raise SystemExit("--pax-key muss aus Hexadezimalzeichen bestehen") from error
        if len(eap_pax_key) != 16:
            raise SystemExit("--pax-key muss genau 16 Byte bzw. 32 Hexzeichen enthalten")
    eap_gpsk_key = None
    if args.gpsk_client:
        try:
            eap_gpsk_key = bytes.fromhex(args.gpsk_key)
        except ValueError as error:
            raise SystemExit("--gpsk-key muss aus Hexadezimalzeichen bestehen") from error
        if len(eap_gpsk_key) != 16:
            raise SystemExit("--gpsk-key muss genau 16 Byte bzw. 32 Hexzeichen enthalten")
    eap_gpsk_sha256_key = None
    if args.gpsk_sha256_client:
        try:
            eap_gpsk_sha256_key = bytes.fromhex(args.gpsk_sha256_key)
        except ValueError as error:
            raise SystemExit("--gpsk-sha256-key muss aus Hexadezimalzeichen bestehen") from error
        if len(eap_gpsk_sha256_key) != 32:
            raise SystemExit("--gpsk-sha256-key muss genau 32 Byte bzw. 64 Hexzeichen enthalten")
    if args.sim_client and not re.fullmatch(r"[0-9]{14,16}", args.sim_imsi):
        raise SystemExit("--sim-imsi muss aus 14 bis 16 Dezimalzeichen bestehen")
    if args.aka_client and not re.fullmatch(r"[0-9]{14,16}", args.aka_imsi):
        raise SystemExit("--aka-imsi muss aus 14 bis 16 Dezimalzeichen bestehen")
    if args.aka_prime_client and not re.fullmatch(r"[0-9]{14,16}", args.aka_prime_imsi):
        raise SystemExit("--aka-prime-imsi muss aus 14 bis 16 Dezimalzeichen bestehen")
    if args.wpa_client and (args.open or not args.raw_assoc or
                            args.observer_index is None):
        raise SystemExit("--wpa-client benötigt WPA2, --raw-assoc und --observer-index")
    if args.ft_ota and args.observer_index is None:
        raise SystemExit("--ft-ota benötigt --observer-index")
    if (args.enterprise_client or args.mschapv2_client or
            args.peap_mschapv2_client or args.ttls_mschapv2_client or
            args.pwd_client or args.psk_client or args.sake_client or
            args.pax_client or args.gpsk_client or args.gpsk_sha256_client or
            args.sim_client or args.aka_client or args.aka_prime_client or args.fast_client or args.teap_client or args.eke_client or args.ikev2_client) and (not args.control_smoke or args.open or args.sae or
                                   args.ota or not args.raw_assoc or
                                   args.observer_index is None):
        raise SystemExit("Enterprise-Client benötigt Control-Smoke, Raw-Association und einen Enterprise-AP")
    if args.gcmp and args.gcmp256:
        raise SystemExit("--gcmp und --gcmp256 sind gegenseitig ausgeschlossen")
    if args.ccmp256 and (args.gcmp or args.gcmp256):
        raise SystemExit("--ccmp256 ist mit --gcmp/--gcmp256 gegenseitig ausgeschlossen")
    if args.tkip and (args.ccmp256 or args.gcmp or args.gcmp256 or args.pmf or args.sae):
        raise SystemExit("--tkip ist mit 256-bit/GCMP/PMF/SAE nicht kombinierbar")
    if args.sae and (args.open or args.ota):
        raise SystemExit("--sae ist nicht mit Open- oder Windows-WLAN-OTA kombinierbar")
    if (args.ccmp256 or args.gcmp or args.gcmp256) and (args.open or args.sae or args.radius_smoke):
        raise SystemExit("256-bit/GCMP ist mit Open-, SAE- und RADIUS-Smoke nicht kombinierbar")
    if args.radius_smoke and (not args.control_smoke or args.open or args.sae or
                              args.ota or args.raw_assoc or args.wpa_client or
                              args.enterprise_client or args.mschapv2_client or
                              args.peap_mschapv2_client or
                              args.ttls_mschapv2_client or args.pwd_client or
                              args.psk_client or args.sake_client or args.pax_client or
                              args.gpsk_client or args.gpsk_sha256_client or
                              args.sim_client or args.aka_client or args.aka_prime_client or args.fast_client or args.teap_client or args.eke_client or args.ikev2_client):
        raise SystemExit("--radius-smoke benötigt Control-Smoke und einen Enterprise-AP")
    if args.accounting_smoke and (not args.control_smoke or not args.raw_assoc or
                                  args.open or args.sae or args.observer_index is None):
        raise SystemExit("--accounting-smoke benötigt --control-smoke, --raw-assoc und einen WPA2-AP")
    if args.pmf_cipher != "AES-128-CMAC" and not (args.pmf or args.sae):
        raise SystemExit("--pmf-cipher benötigt --pmf oder --sae")

    iface = ifaces[args.index]
    pmf_enabled = bool(args.pmf or args.sae)
    observer = None
    wpa_client = None
    enterprise_client = None
    eap_label = ("eap_teap" if args.teap_client else
                 ("eap_fast" if args.fast_client else
                 ("eap_eke" if args.eke_client else
                 ("eap_ikev2" if args.ikev2_client else
                 ("eap_aka_prime" if args.aka_prime_client else
                 ("eap_aka" if args.aka_client else
                 ("eap_gpsk_sha256" if args.gpsk_sha256_client else
                 ("eap_gpsk" if args.gpsk_client else
                 ("eap_pax" if args.pax_client else
                 ("eap_sake" if args.sake_client else
                 ("eap_sim" if args.sim_client else
                 ("eap_psk" if args.psk_client else
                 ("eap_pwd" if args.pwd_client else
                 ("eap_ttls_mschapv2" if args.ttls_mschapv2_client else
                 ("eap_peap_mschapv2" if args.peap_mschapv2_client else
                 ("eap_mschapv2" if args.mschapv2_client else "eap_tls"))))))))))))))))
    wpa_client_tx = 0
    wpa_client_tx_ok = 0
    wpa_client_tx_fail = 0
    wpa_client_tx_headers: list[str] = []
    wpa_client_tx_msgs: list[int | None] = []
    wpa_client_rx_headers: list[str] = []
    wpa_client_rx_msgs: list[int | None] = []
    wpa_client_rx_eap: list[tuple[int, int, int, int | None, int | None, int]] = []
    ap_tx_eap: list[tuple[int, int, int, int | None, int | None, int]] = []
    observer_counts = {"beacon": 0, "probe_req": 0, "auth": 0,
                       "assoc_req": 0, "assoc_resp": 0, "eapol": 0}
    observer_probe_ssids: list[str | None] = []
    observer_beacons: list[tuple[str | None, str, str, bool, int | None]] = []
    observer_beacon_hex: str | None = None
    ap_rx_eapol_msgs: list[int | None] = []
    ap_rx_ccmp: list[str] = []
    ap_rx_gcmp: list[str] = []
    ap_rx_tkip: list[str] = []
    ap_rx_bip: list[str] = []
    ap_rx_data_frames = 0
    ap_tx_counts = {"beacon": 0, "probe_resp": 0, "auth": 0,
                    "assoc_resp": 0, "deauth": 0, "disassoc": 0, "data": 0}
    station_smoke = None
    radius_smoke = None
    accounting_smoke = None
    ft_ota_result = None
    sae_result = None
    pmf_action_result = None
    pmf_action_pass = False
    radius_secret = b"wifit3-radius-secret"
    radius_auth_port = 18120 + (args.index * 2)
    radius_acct_port = radius_auth_port + 1
    loop = asyncio.get_running_loop()
    if not await iface.connect():
        raise SystemExit(f"USB-Dongle konnte nicht geöffnet werden: {iface.description}")
    ap_mac = bytes.fromhex(iface.mac_address.replace(':', ''))
    sta_mac = None
    ft_rx_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=16)
    mgmt_send_results = {"deauth": [], "disassoc": []}
    if args.station_smoke:
        original_send_no_wait = iface.send_no_wait

        async def traced_send_no_wait(frame: bytes) -> bool:
            kind = None
            if len(frame) >= 2:
                fc = int.from_bytes(frame[:2], "little")
                if ((fc >> 2) & 3) == 0:
                    kind = {10: "disassoc", 12: "deauth"}.get((fc >> 4) & 0x0f)
            try:
                result = bool(await original_send_no_wait(frame))
            except BaseException:
                if kind is not None:
                    mgmt_send_results[kind].append(False)
                raise
            if kind is not None:
                mgmt_send_results[kind].append(result)
            return result

        iface.send_no_wait = traced_send_no_wait
    sim_db_server = None
    sim_db_requests: list[bytes] = []
    sim_db_responses: list[bytes] = []
    if args.sim_client or args.aka_client or args.aka_prime_client:
        sim_db_server = _EapSimDbServer(
            Path(tempfile.gettempdir()) /
            f"wifit3-eap-sim-{os.getpid()}-{args.index}.sock",
            _sim_triplets(), args.aka_prime_client)
    if (args.ota or args.raw_assoc) and args.observer_index is not None:
        if args.observer_index == args.index or args.observer_index < 0 or args.observer_index >= len(ifaces):
            raise SystemExit("--observer-index muss auf einen anderen vorhandenen Dongle zeigen")
        observer = ifaces[args.observer_index]
        if not await observer.connect():
            raise SystemExit(f"OTA-Beobachter konnte nicht geöffnet werden: {observer.description}")
        if not await observer.set_channel(args.channel):
            raise SystemExit("OTA-Beobachter konnte nicht auf den AP-Kanal eingestellt werden")

        async def send_client_response(frame: bytes, use_ack: bool) -> bool:
            # The AP's EAPOL/CCMP verification is the OTA oracle. Enabling the
            # adapter-specific ACK filter before association changes RX/TX
            # behavior on some wifit3 drivers, so keep this path fire-and-forget.
            if use_ack:
                await asyncio.sleep(0.05)
            return await observer.send_no_wait(frame)

        def enqueue_ft_frame(frame: bytes) -> None:
            try:
                ft_rx_queue.put_nowait(bytes(frame))
            except asyncio.QueueFull:
                try:
                    ft_rx_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                ft_rx_queue.put_nowait(bytes(frame))

        def observe(pkt) -> None:
            nonlocal observer_beacon_hex, wpa_client_tx, wpa_client_tx_ok, wpa_client_tx_fail
            raw = bytes(getattr(pkt, "raw", b""))
            if getattr(pkt, "type_id", None) != 0:
                if getattr(pkt, "type_id", None) == 2:
                    is_eapol = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in raw
                    if is_eapol:
                        observer_counts["eapol"] += 1
                    station_client = enterprise_client or wpa_client
                    if station_client is not None:
                        key_client = (enterprise_client.wpa_client
                                      if enterprise_client is not None else
                                      station_client)
                        eapol_mic_len = getattr(key_client, "_mic_len", 16)
                        observer_sta_mac = bytes.fromhex(
                            observer.mac_address.replace(':', ''))
                        observer_ap_mac = bytes.fromhex(
                            iface.mac_address.replace(':', ''))
                        if (len(raw) < 16 or raw[4:10] != observer_sta_mac or
                                raw[10:16] != observer_ap_mac):
                            return
                        if len(wpa_client_rx_headers) < 8:
                            wpa_client_rx_headers.append(bytes(pkt.raw[:32]).hex())
                        if is_eapol and len(wpa_client_rx_eap) < 32:
                            marker = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
                            eapol = raw.find(marker, 24, min(len(raw), 48)) + len(marker)
                            if eapol >= len(marker) and len(raw) >= eapol + 4:
                                eapol_type = raw[eapol + 1]
                                eapol_len = int.from_bytes(raw[eapol + 2:eapol + 4], "big")
                                eap = raw[eapol + 4:eapol + 4 + eapol_len]
                                wpa_client_rx_eap.append(
                                    (eapol_type,
                                     eap[0] if len(eap) >= 1 else -1,
                                     eap[1] if len(eap) >= 2 else -1,
                                     eap[4] if len(eap) >= 5 and eap[0] == 1 else None,
                                     eap[5] if len(eap) >= 6 and eap[0] == 1 and eap[4] == 13 else None,
                                     len(eap)))
                        if len(wpa_client_rx_msgs) < 32:
                            parsed = WlanFrameParser.parse_80211_frame(
                                bytes(pkt.raw), -30, eapol_mic_len=eapol_mic_len)
                            wpa_client_rx_msgs.append(
                                getattr(parsed, "msg_num", None) if parsed else None)
                        for response in station_client.handle_frame(bytes(pkt.raw)):
                            parsed_response = WlanFrameParser.parse_80211_frame(
                                response, -30, eapol_mic_len=eapol_mic_len)
                            use_ack = getattr(parsed_response, "msg_num", None) == 4
                            future = asyncio.run_coroutine_threadsafe(
                                send_client_response(response, use_ack), loop)

                            def tx_done(done) -> None:
                                nonlocal wpa_client_tx_ok, wpa_client_tx_fail
                                try:
                                    if done.result():
                                        wpa_client_tx_ok += 1
                                    else:
                                        wpa_client_tx_fail += 1
                                except Exception:
                                    wpa_client_tx_fail += 1

                            future.add_done_callback(tx_done)
                            if len(wpa_client_tx_headers) < 8:
                                wpa_client_tx_headers.append(bytes(response[:32]).hex())
                            if len(wpa_client_tx_msgs) < 32:
                                parsed = WlanFrameParser.parse_80211_frame(
                                    response, -30, eapol_mic_len=eapol_mic_len)
                                wpa_client_tx_msgs.append(
                                    getattr(parsed, "msg_num", None) if parsed else None)
                            wpa_client_tx += 1
                return
            if (args.ft_ota and sta_mac is not None and len(raw) >= 30 and
                    raw[4:10] == sta_mac and raw[10:16] == ap_mac):
                subtype = (int.from_bytes(raw[:2], "little") >> 4) & 0x0f
                if subtype == 11:
                    algorithm, sequence, _status = struct.unpack_from(
                        "<HHH", raw, 24)
                    if algorithm == 2 and sequence == 2:
                        loop.call_soon_threadsafe(enqueue_ft_frame, raw)
                elif subtype == 3:
                    loop.call_soon_threadsafe(enqueue_ft_frame, raw)
            subtype = getattr(pkt, "subtype_id", None)
            if subtype == 8 and getattr(pkt, "ssid", None) == args.ssid:
                observer_counts["beacon"] += 1
                if observer_beacon_hex is None:
                    observer_beacon_hex = getattr(pkt, "raw", b"").hex()
                if len(observer_beacons) < 2:
                    observer_beacons.append((getattr(pkt, "ssid", None),
                                             getattr(pkt, "bssid", ""),
                                             getattr(pkt, "encryption", ""),
                                             bool(getattr(pkt, "rsn_valid", False)),
                                             getattr(pkt, "channel", None)))
            elif subtype == 4:
                observer_counts["probe_req"] += 1
                if len(observer_probe_ssids) < 8:
                    observer_probe_ssids.append(getattr(pkt, "ssid", None))
            elif subtype == 11:
                observer_counts["auth"] += 1
            elif subtype == 0:
                observer_counts["assoc_req"] += 1
            elif subtype == 1:
                observer_counts["assoc_resp"] += 1

        observer.register_rx_callback(observe)

    lease = True
    radio = Wifit3InterfaceRadio(
        iface,
        loop,
        lease_guard=lambda: lease,
        software_beacons=True,
        software_stations=True,
        allow_eapol_tx=True,
        software_ccmp=not (args.ccmp256 or args.gcmp or args.gcmp256 or args.tkip),
        software_ccmp256=args.ccmp256,
        software_bip=pmf_enabled,
        software_sae=args.sae,
        software_accounting=args.accounting_smoke,
        software_gcmp=args.gcmp,
        software_gcmp256=args.gcmp256,
        software_tkip=args.tkip,
        hardware_ack=args.hardware_ack or hardware_ack_supported(iface),
    )

    def record_ap_tx(frame: bytes) -> None:
        if len(frame) < 2:
            return
        fc = int.from_bytes(frame[:2], "little")
        if ((fc >> 2) & 3) == 0:
            ap_tx_counts[{8: "beacon", 5: "probe_resp", 11: "auth",
                          1: "assoc_resp", 10: "disassoc", 12: "deauth"}
                         .get((fc >> 4) & 0x0f, "data")] += 1
        elif ((fc >> 2) & 3) == 2:
            ap_tx_counts["data"] += 1
            marker = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
            eapol = frame.find(marker, 24, min(len(frame), 48)) + len(marker)
            if eapol >= len(marker) and len(frame) >= eapol + 4 and len(ap_tx_eap) < 32:
                eapol_type = frame[eapol + 1]
                eapol_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
                eap = frame[eapol + 4:eapol + 4 + eapol_len]
                ap_tx_eap.append(
                    (eapol_type,
                     eap[0] if len(eap) >= 1 else -1,
                     eap[1] if len(eap) >= 2 else -1,
                     eap[4] if len(eap) >= 5 and eap[0] == 1 else None,
                     eap[5] if len(eap) >= 6 and eap[0] == 1 and eap[4] == 13 else None,
                     len(eap)))

    iface.on_tx = record_ap_tx
    def current_eapol_mic_len() -> int:
        key_client = (enterprise_client.wpa_client
                      if enterprise_client is not None else wpa_client)
        return getattr(key_client, "_mic_len", 16)

    if radio._ccmp is not None:
        original_ccmp_decrypt = radio._ccmp.decrypt
        traced_sta_mac = (bytes.fromhex(observer.mac_address.replace(':', ''))
                          if observer is not None and observer.mac_address else None)

        def traced_ccmp_decrypt(frame, source):
            relevant = traced_sta_mac is not None and source == traced_sta_mac
            try:
                result = original_ccmp_decrypt(frame, source)
                if relevant and len(ap_rx_ccmp) < 32:
                    _pn, plain = result
                    if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in plain:
                        parsed = WlanFrameParser.parse_80211_frame(
                            plain, -30, eapol_mic_len=current_eapol_mic_len())
                        ap_rx_ccmp.append(
                            "eapol-m" + str(getattr(parsed, "msg_num", None))
                        )
                return result
            except Exception as error:
                if relevant and len(ap_rx_ccmp) < 32:
                    ap_rx_ccmp.append(type(error).__name__ + ":" + str(error))
                raise

        radio._ccmp.decrypt = traced_ccmp_decrypt

    if radio._ccmp256 is not None:
        original_ccmp256_decrypt = radio._ccmp256.decrypt

        def traced_ccmp256_decrypt(frame, source):
            try:
                result = original_ccmp256_decrypt(frame, source)
                if len(ap_rx_ccmp) < 32:
                    _pn, plain = result
                    if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in plain:
                        parsed = WlanFrameParser.parse_80211_frame(
                            plain, -30, eapol_mic_len=current_eapol_mic_len())
                        ap_rx_ccmp.append(
                            "eapol-m" + str(getattr(parsed, "msg_num", None)))
                return result
            except Exception as error:
                if len(ap_rx_ccmp) < 32:
                    ap_rx_ccmp.append(type(error).__name__ + ":" + str(error))
                raise

        radio._ccmp256.decrypt = traced_ccmp256_decrypt

    if radio._gcmp is not None:
        original_gcmp_decrypt = radio._gcmp.decrypt

        def traced_gcmp_decrypt(frame, source):
            try:
                result = original_gcmp_decrypt(frame, source)
                if len(ap_rx_gcmp) < 32:
                    _pn, plain = result
                    if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in plain:
                        parsed = WlanFrameParser.parse_80211_frame(
                            plain, -30, eapol_mic_len=current_eapol_mic_len())
                        ap_rx_gcmp.append(
                            "eapol-m" + str(getattr(parsed, "msg_num", None)))
                return result
            except Exception as error:
                if len(ap_rx_gcmp) < 32:
                    ap_rx_gcmp.append(type(error).__name__ + ":" + str(error))
                raise

        radio._gcmp.decrypt = traced_gcmp_decrypt

    if radio._gcmp256 is not None:
        original_gcmp256_decrypt = radio._gcmp256.decrypt

        def traced_gcmp256_decrypt(frame, source):
            try:
                result = original_gcmp256_decrypt(frame, source)
                if len(ap_rx_gcmp) < 32:
                    _pn, plain = result
                    if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in plain:
                        parsed = WlanFrameParser.parse_80211_frame(
                            plain, -30, eapol_mic_len=current_eapol_mic_len())
                        ap_rx_gcmp.append(
                            "eapol-m" + str(getattr(parsed, "msg_num", None)))
                return result
            except Exception as error:
                if len(ap_rx_gcmp) < 32:
                    ap_rx_gcmp.append(type(error).__name__ + ":" + str(error))
                raise

        radio._gcmp256.decrypt = traced_gcmp256_decrypt

    if radio._tkip is not None:
        original_tkip_decrypt = radio._tkip.decrypt

        def traced_tkip_decrypt(frame, source):
            try:
                result = original_tkip_decrypt(frame, source)
                if len(ap_rx_tkip) < 32:
                    _tsc, plain = result
                    if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in plain:
                        parsed = WlanFrameParser.parse_80211_frame(
                            plain, -30, eapol_mic_len=current_eapol_mic_len())
                        ap_rx_tkip.append(
                            "eapol-m" + str(getattr(parsed, "msg_num", None)))
                return result
            except Exception as error:
                if len(ap_rx_tkip) < 32:
                    ap_rx_tkip.append(type(error).__name__ + ":" + str(error))
                raise

        radio._tkip.decrypt = traced_tkip_decrypt

    if radio._bip is not None:
        original_bip_verify = radio._bip.verify

        def traced_bip_verify(frame):
            try:
                result = original_bip_verify(frame)
                if len(ap_rx_bip) < 32:
                    ap_rx_bip.append("verified")
                return result
            except Exception as error:
                if len(ap_rx_bip) < 32:
                    ap_rx_bip.append(type(error).__name__ + ":" + str(error))
                raise

        radio._bip.verify = traced_bip_verify

    def ap_rx_debug(pkt) -> None:
        nonlocal ap_rx_data_frames
        raw = bytes(getattr(pkt, "raw", b""))
        if (observer is None or getattr(pkt, "type_id", None) != 2 or
                len(raw) < 24 or raw[10:16] != bytes.fromhex(
                    observer.mac_address.replace(':', ''))):
            return
        if args.accounting_smoke:
            ap_rx_data_frames += 1
        if raw[1] & 0x40 and radio._ccmp is not None:
            if len(ap_rx_ccmp) < 32:
                ap_rx_ccmp.append("protected")
            return
        if raw[1] & 0x40 and radio._ccmp256 is not None:
            if len(ap_rx_ccmp) < 32:
                ap_rx_ccmp.append("protected")
            return
        if raw[1] & 0x40 and radio._gcmp is not None:
            if len(ap_rx_gcmp) < 32:
                ap_rx_gcmp.append("protected")
            return
        if raw[1] & 0x40 and radio._gcmp256 is not None:
            if len(ap_rx_gcmp) < 32:
                ap_rx_gcmp.append("protected")
            return
        if raw[1] & 0x40 and radio._tkip is not None:
            if len(ap_rx_tkip) < 32:
                ap_rx_tkip.append("protected")
            return
        if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" not in raw:
            return
        parsed = WlanFrameParser.parse_80211_frame(
            raw, -30, eapol_mic_len=current_eapol_mic_len())
        if len(ap_rx_eapol_msgs) < 32:
            ap_rx_eapol_msgs.append(
                getattr(parsed, "msg_num", None) if parsed else None)

    iface.register_rx_callback(ap_rx_debug)
    config = bridge_config_for_interface(
        iface,
        channels=(args.channel,),
        software_beacons=True,
        software_stations=True,
        allow_eapol_tx=True,
        software_ccmp=not (args.ccmp256 or args.gcmp or args.gcmp256 or args.tkip),
        software_ccmp256=args.ccmp256,
        software_bip=pmf_enabled,
        software_sae=args.sae,
        software_accounting=args.accounting_smoke,
        software_gcmp=args.gcmp,
        software_gcmp256=args.gcmp256,
        software_tkip=args.tkip,
    )
    token = secrets.token_hex(32)
    bridge = Wifit3Bridge(radio, config, token, port=0)
    radio.attach(bridge)
    port = bridge.start_listener()
    worker = threading.Thread(target=bridge.serve_once, daemon=True)
    worker.start()
    process = None

    def stop_hostapd() -> None:
        nonlocal process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    try:
        if radio.hardware_ack:
            if not await radio.arm_hardware_ack():
                print("hardware_ack_armed=False")
                if args.hardware_ack:
                    return 1
                radio.hardware_ack = False
            else:
                print("hardware_ack_armed=True")
        with tempfile.TemporaryDirectory(prefix="wifit3-hostapd-") as directory:
            directory = Path(directory)
            if sim_db_server is not None:
                sim_db_server.start()
                sim_db_requests = sim_db_server.requests
                sim_db_responses = sim_db_server.responses
            conf = directory / "wpa.conf"
            log = directory / "hostapd.log"
            enterprise_security = ""
            if (args.radius_smoke or args.enterprise_client or
                    args.mschapv2_client or args.peap_mschapv2_client or
                    args.ttls_mschapv2_client or args.pwd_client or
                    args.psk_client or args.sake_client or args.pax_client or
                    args.gpsk_client or args.gpsk_sha256_client or
                    args.sim_client or args.aka_client or args.aka_prime_client or
                    args.fast_client or args.teap_client or args.eke_client or args.ikev2_client):
                openssl = _openssl_binary()
                if openssl is None and not (args.mschapv2_client or args.pwd_client or
                                            args.psk_client or args.sake_client or
                                            args.pax_client or args.gpsk_client or
                                            args.gpsk_sha256_client or args.sim_client or
                                            args.aka_client or args.aka_prime_client or
                                            args.eke_client or args.ikev2_client):
                    raise SystemExit("openssl.exe fehlt für den Enterprise-Test")
                if (args.enterprise_client or args.peap_mschapv2_client or
                        args.ttls_mschapv2_client or args.fast_client or
                        args.teap_client):
                    ca_key = directory / "ca.key"
                    ca_cert = directory / "ca.pem"
                    server_csr = directory / "server.csr"
                    client_csr = directory / "client.csr"
                    commands = [
                        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-days", "1", "-keyout", str(ca_key), "-out", str(ca_cert),
                         "-subj", "/CN=wifit3-eap-ca"],
                        [openssl, "req", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", str(directory / "key.pem"), "-out", str(server_csr),
                         "-subj", "/CN=wifit3-eap.invalid"],
                        [openssl, "x509", "-req", "-in", str(server_csr),
                         "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                         "-days", "1", "-out", str(directory / "cert.pem")],
                        [openssl, "req", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", str(directory / "client.key"), "-out", str(client_csr),
                         "-subj", "/CN=wifit3-client"],
                        [openssl, "x509", "-req", "-in", str(client_csr),
                         "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                         "-days", "1", "-out", str(directory / "client.pem")],
                    ]
                elif (args.mschapv2_client or args.pwd_client or args.psk_client or
                      args.sake_client or args.pax_client or args.gpsk_client or
                      args.gpsk_sha256_client or args.sim_client or args.aka_client or
                      args.aka_prime_client or args.ikev2_client):
                    commands = []
                else:
                    commands = [[
                        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-keyout", str(directory / "key.pem"),
                        "-out", str(directory / "cert.pem"),
                        "-subj", "/CN=wifit3-radius.invalid",
                    ]]
                for command in commands:
                    creation = subprocess.run(command, capture_output=True, text=True)
                    if creation.returncode != 0:
                        raise SystemExit("temporäre EAP-TLS-Zertifikate konnten nicht erzeugt werden")
                if args.ttls_mschapv2_client:
                    user_line = ("* TTLS\n"
                                 f'"wifit3-mschap" TTLS-MSCHAPV2 "{args.passphrase}" [2]\n')
                elif args.peap_mschapv2_client:
                    user_line = (f'"wifit3-peap" PEAP [ver=1]\n'
                                 f'"wifit3-mschap" MSCHAPV2 "{args.passphrase}" [2]\n')
                elif args.mschapv2_client:
                    user_line = (f'"wifit3-mschap" MSCHAPV2 "{args.passphrase}"\n')
                elif args.pwd_client:
                    user_line = (f'"wifit3-pwd" PWD "{args.passphrase}"\n')
                elif args.psk_client:
                    user_line = f'"wifit3-psk" PSK {args.psk_key.lower()}\n'
                elif args.sake_client:
                    user_line = f'"wifit3-sake" SAKE {args.sake_key.lower()}\n'
                elif args.pax_client:
                    user_line = f'"wifit3-pax" PAX {args.pax_key.lower()}\n'
                elif args.gpsk_client:
                    user_line = f'"wifit3-gpsk" GPSK {args.gpsk_key.lower()}\n'
                elif args.gpsk_sha256_client:
                    user_line = f'"wifit3-gpsk-sha256" GPSK {args.gpsk_sha256_key.lower()}\n'
                elif args.sim_client:
                    user_line = f'"1{args.sim_imsi}" SIM\n'
                elif args.aka_prime_client:
                    user_line = f'"6{args.aka_prime_imsi}" AKA\'\n'
                elif args.aka_client:
                    user_line = f'"0{args.aka_imsi}" AKA\n'
                elif args.fast_client:
                    user_line = (f'"anonymous" FAST\n'
                                 f'"wifit3-mschap" MSCHAPV2 "{args.passphrase}" [2]\n')
                elif args.teap_client:
                    user_line = (f'"anonymous" TEAP\n'
                                 f'"wifit3-mschap" MSCHAPV2 "{args.passphrase}" [2]\n')
                elif args.eke_client:
                    user_line = f'"wifit3-eke" EKE "{args.passphrase}"\n'
                elif args.ikev2_client:
                    user_line = f'"wifit3-ikev2" IKEV2 "{args.passphrase}"\n'
                elif args.enterprise_client:
                    user_line = '* TLS "TLS"\n'
                else:
                    user_line = '* TLS "TLS"\n'
                (directory / "users.txt").write_text(user_line, encoding="utf-8")
                (directory / "clients.conf").write_text(
                    "127.0.0.1 " + radius_secret.decode("ascii") + "\n",
                    encoding="utf-8")
                enterprise_security = (
                    "ieee8021x=1\neap_server=1\nwpa=2\n"
                    "wpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\n"
                    + (f"pwd_group={args.pwd_group}\n" if args.pwd_client else "")
                    + f"eap_user_file={directory / 'users.txt'}\n"
                    + (f"eap_sim_db={sim_db_server.endpoint}\neap_sim_id=0\n"
                       if (args.sim_client or args.aka_client or args.aka_prime_client) and sim_db_server is not None else "")
                    + (f"ca_cert={directory / 'ca.pem'}\n"
                       if args.enterprise_client or args.peap_mschapv2_client or
                       args.ttls_mschapv2_client or args.fast_client or args.teap_client else "")
                    + ("fragment_size=200\n"
                       if args.enterprise_client or args.peap_mschapv2_client or
                       args.ttls_mschapv2_client or args.fast_client or
                       args.teap_client else "")
                    + (f"server_cert={directory / 'cert.pem'}\n"
                       f"private_key={directory / 'key.pem'}\n"
                       if args.enterprise_client or args.peap_mschapv2_client or
                       args.ttls_mschapv2_client or args.fast_client or args.teap_client or
                       args.radius_smoke else "")
                    + ("pac_opaque_encr_key=00112233445566778899aabbccddeeff\n"
                       "eap_fast_a_id=101112131415161718191a1b1c1d1e1f\n"
                       "eap_fast_a_id_info=wifit3-lab\n"
                       "eap_fast_prov=0\n"
                       if args.fast_client or args.teap_client else "")
                    + f"radius_server_clients={directory / 'clients.conf'}\n"
                    f"radius_server_auth_port={radius_auth_port}\n"
                    f"radius_server_acct_port={radius_acct_port}\n"
                )
            if (args.radius_smoke or args.enterprise_client or
                    args.mschapv2_client or args.peap_mschapv2_client or
                    args.ttls_mschapv2_client or args.pwd_client or
                    args.psk_client or args.sake_client or args.pax_client or
                    args.gpsk_client or args.gpsk_sha256_client or
                    args.sim_client or args.aka_client or args.aka_prime_client or
                    args.fast_client or args.teap_client or args.eke_client or args.ikev2_client):
                security = enterprise_security
            elif args.open:
                security = "wpa=0\n"
            elif args.ft_sae:
                sae_client_password = args.passphrase
                r1_key_holder = iface.mac_address.replace(":", "")
                security = (
                    "wpa=2\n"
                    + ("wpa_key_mgmt=FT-SAE-EXT-KEY\n"
                       if args.ft_sae_ext_key else "wpa_key_mgmt=FT-SAE\n")
                    + f"sae_password={args.passphrase}\n"
                    + f"wpa_passphrase={args.passphrase}\n"
                    + "rsn_pairwise=CCMP\n"
                    + f"sae_groups={args.sae_group}\n"
                    + "sae_pwe=1\n"
                    + "mobility_domain=a1b2\n"
                    + "nas_identifier=wifit3-ft-r0\n"
                    + f"r1_key_holder={r1_key_holder}\n"
                    + "ft_over_ds=0\n"
                )
            elif args.sae:
                sae_client_password = args.passphrase
                sae_password = (args.sae_pk_credential if args.sae_pk
                                else args.passphrase)
                if args.sae_pk:
                    sae_client_password = sae_password.split("|", 1)[0]
                if args.sae_password_id:
                    sae_password += "|id=" + args.sae_password_id
                security = ("wpa=2\nwpa_key_mgmt="
                            + ("SAE-EXT-KEY\n" if args.sae_ext_key else "SAE\n")
                            + f"sae_password={sae_password}\n"
                            f"wpa_passphrase={sae_client_password}\nrsn_pairwise=CCMP\n" +
                            f"sae_groups={args.sae_group}\n" +
                            ("sae_pwe=1\n" if args.sae_h2e else ""))
            elif args.ccmp256:
                security = ("wpa=2\nwpa_key_mgmt=WPA-PSK\n"
                            f"wpa_passphrase={args.passphrase}\nrsn_pairwise=CCMP-256\n")
            elif args.tkip:
                security = ("wpa=2\nwpa_key_mgmt=WPA-PSK\n"
                            f"wpa_passphrase={args.passphrase}\nrsn_pairwise=TKIP\n")
            elif args.gcmp or args.gcmp256:
                security = ("wpa=2\nwpa_key_mgmt=WPA-PSK\n"
                            f"wpa_passphrase={args.passphrase}\nrsn_pairwise="
                            + ("GCMP-256\n" if args.gcmp256 else "GCMP\n"))
            else:
                security = ("wpa=2\nwpa_key_mgmt=WPA-PSK\n"
                            f"wpa_passphrase={args.passphrase}\nrsn_pairwise=CCMP\n")
            configuration = (
                "interface=wifit3-wpa-smoke\n"
                "driver=wifit3\n"
                f"ssid={args.ssid}\n"
                "hw_mode=g\n"
                f"channel={args.channel}\n"
                "beacon_int=100\n"
                + ("ctrl_interface=udp:8877\n" if args.control_smoke else "")
                + security
                + ("ieee80211w=2\n" if pmf_enabled else "ieee80211w=0\n")
                + (f"group_mgmt_cipher={args.pmf_cipher}\n" if pmf_enabled else "")
            )
            conf.write_text(
                configuration,
                encoding="utf-8",
            )
            with log.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
            [str(hostapd), "-dd", str(conf)],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    env=dict(os.environ, WIFIT3_BRIDGE_TOKEN=token,
                              WIFIT3_BRIDGE_PORT=str(port)),
                )
                deadline = time.monotonic() + args.wait
                while process.poll() is None and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
                process_state = process.poll()
                text = log.read_text(encoding="utf-8", errors="replace")
                enabled = "AP-ENABLED" in text
                fatal = "FATAL_FAILURE" in text
                control_ping = None
                control_status = None
                control_sta = None
                control_all_sta = None
                control_cli_result = None
                control_raw = None
                control_raw_status = None
                if not fatal and args.control_smoke and (
                        enabled or process_state is None):
                    control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    control_socket.settimeout(1.0)
                    try:
                        control_socket.sendto(b"GET_COOKIE", ("127.0.0.1", 8877))
                        cookie, _ = control_socket.recvfrom(256)
                        control_socket.sendto(cookie + b" PING", ("127.0.0.1", 8877))
                        control_raw = control_socket.recvfrom(256)[0].decode(
                            "ascii", errors="replace").strip()
                        control_socket.sendto(cookie + b" STATUS", ("127.0.0.1", 8877))
                        control_raw_status = control_socket.recvfrom(4096)[0].decode(
                            "ascii", errors="replace").strip()
                    except OSError as error:
                        control_raw = f"error:{error}"
                    finally:
                        control_socket.close()
                    if control_raw_status and "state=ENABLED" in control_raw_status:
                        enabled = True
                    cli = hostapd.parent / "hostapd_cli.exe"
                    ping = subprocess.run(
                        [str(cli), "-i", "127.0.0.1:8877", "ping"],
                        capture_output=True, text=True, encoding="oem", errors="replace",
                    )
                    status = subprocess.run(
                        [str(cli), "-i", "127.0.0.1:8877", "status"],
                        capture_output=True, text=True, encoding="oem", errors="replace",
                    )
                    control_ping = ping.stdout.strip()
                    control_status = status.stdout.strip()
                    control_cli_result = {
                        "ping_returncode": ping.returncode,
                        "ping_stderr": ping.stderr.strip(),
                        "status_returncode": status.returncode,
                        "status_stderr": status.stderr.strip(),
                    }
                    if "state=ENABLED" in control_status:
                        enabled = True
                    if args.radius_smoke:
                        try:
                            auth_reply = _radius_roundtrip(
                                radius_auth_port,
                                _radius_access_request(7, radius_secret))
                            acct_reply = _radius_roundtrip(
                                radius_acct_port,
                                _radius_accounting_start(8, radius_secret))
                            radius_smoke = {
                                "auth_port": radius_auth_port,
                                "acct_port": radius_acct_port,
                                "auth_code": auth_reply[0] if auth_reply else None,
                                "acct_code": acct_reply[0] if acct_reply else None,
                                "auth_access_challenge": bool(auth_reply and auth_reply[0] == 11),
                                "acct_response": bool(acct_reply and acct_reply[0] == 5),
                            }
                        except OSError as error:
                            radius_smoke = {"error": repr(error)}
                    if args.station_smoke:
                        station = ("ff:ff:ff:ff:ff:ff" if args.station_broadcast else
                                   f"02:aa:bb:cc:dd:{args.index:02x}")
                        before_deauth = ap_tx_counts["deauth"]
                        before_disassoc = ap_tx_counts["disassoc"]
                        before_deauth_results = len(mgmt_send_results["deauth"])
                        before_disassoc_results = len(mgmt_send_results["disassoc"])
                        deauth = subprocess.run(
                            [str(cli), "-i", "127.0.0.1:8877",
                             "deauthenticate", station],
                            capture_output=True, text=True, encoding="oem",
                            errors="replace",
                        )
                        disassoc = subprocess.run(
                            [str(cli), "-i", "127.0.0.1:8877",
                             "disassociate", station],
                            capture_output=True, text=True, encoding="oem",
                            errors="replace",
                        )
                        await asyncio.sleep(0.25)
                        deauth_results = mgmt_send_results["deauth"][before_deauth_results:]
                        disassoc_results = mgmt_send_results["disassoc"][before_disassoc_results:]
                        station_smoke = {
                            "station": station,
                            "deauth_returncode": deauth.returncode,
                            "disassoc_returncode": disassoc.returncode,
                            "deauth_before": before_deauth,
                            "deauth_after": ap_tx_counts["deauth"],
                            "disassoc_before": before_disassoc,
                            "disassoc_after": ap_tx_counts["disassoc"],
                            "deauth_send_results": deauth_results,
                            "disassoc_send_results": disassoc_results,
                            "deauth_tx": bool(deauth_results) and any(deauth_results),
                            "disassoc_tx": bool(disassoc_results) and any(disassoc_results),
                            "deauth_output": deauth.stdout.strip() or deauth.stderr.strip(),
                            "disassoc_output": disassoc.stdout.strip() or disassoc.stderr.strip(),
                        }
                ota_connected = False
                raw_assoc = False
                if enabled and not fatal and args.ota:
                    ota_connected = _run_ota_client(
                        args.ssid, args.passphrase, args.interface, args.client_wait,
                        args.open)
                if enabled and not fatal and args.raw_assoc:
                    from wifit3.dot11.ie import GENERIC_RSN_IE
                    if observer is None or not observer.mac_address:
                        raise RuntimeError("raw association requires a connected observer")
                    assoc_rsn_ie = (ENTERPRISE_RSN_IE if (
                        args.enterprise_client or args.mschapv2_client or
                        args.peap_mschapv2_client or
                        args.ttls_mschapv2_client or args.pwd_client or
                        args.psk_client or args.sake_client or args.pax_client or
                        args.gpsk_client or args.gpsk_sha256_client or
                        args.sim_client or args.aka_client or args.aka_prime_client or
                        args.fast_client or args.teap_client or args.eke_client or args.ikev2_client) else
                                    ((FT_SAE_EXT_KEY_RSN_IE if args.ft_sae_ext_key else
                                      FT_SAE_RSN_IE) if args.ft_sae else
                                    (SAE_EXT_KEY_RSN_IE if args.sae_ext_key else
                                     (SAE_RSN_IE if args.sae else
                                    (PMF_RSN_IE if args.pmf else
                                     (TKIP_RSN_IE if args.tkip else
                                      (CCMP256_RSN_IE if args.ccmp256 else
                                       (GCMP256_RSN_IE if args.gcmp256 else
                                        (GCMP_RSN_IE if args.gcmp else GENERIC_RSN_IE)))))))))
                    if args.pmf or args.sae:
                        assoc_rsn_ie = _pmf_assoc_rsn_ie(
                            assoc_rsn_ie, args.pmf_cipher)
                    sta_mac = bytes.fromhex(observer.mac_address.replace(':', ''))
                    if args.sae:
                        from wifit3_bridge.sae_client import (
                            SAE_H2E_RSNX_IE, SAE_PK_RSNX_IE, sae_associate)

                        def sae_confirmed(sae_client) -> None:
                            nonlocal wpa_client
                            # FT-SAE needs the MDIE/FTIE emitted in the
                            # Association Response.  That frame is only
                            # available after sae_associate() returns, so the
                            # client is instantiated below for this path.
                            if args.ft_sae:
                                return
                            if not args.wpa_client or sae_client.pmk is None:
                                return
                            from wifit3_bridge.wpa2_client import Wpa2PskClient
                            wpa_client = Wpa2PskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid, sae_client_password,
                                # SAE H2E RSNXE is negotiated in the
                                # association and must also be echoed in
                                # EAPOL-Key message 2/4.
                                rsn_ie=(assoc_rsn_ie +
                                        (SAE_PK_RSNX_IE if args.sae_pk else
                                         SAE_H2E_RSNX_IE)
                                        if args.sae_h2e else assoc_rsn_ie),
                                cipher="CCMP",
                                akm=(("FT-SAE-EXT-KEY" if args.ft_sae_ext_key else "FT-SAE")
                                     if args.ft_sae else
                                     ("SAE-EXT-KEY" if args.sae_ext_key else "SAE")),
                                ft_mobility_domain=(bytes.fromhex("a1b2")
                                                    if args.ft_sae else None),
                                ft_r0kh_id=(b"wifit3-ft-r0"
                                            if args.ft_sae else None),
                                ft_r1kh_id=(bytes.fromhex(
                                    iface.mac_address.replace(":", ""))
                                            if args.ft_sae else None),
                                pmk=sae_client.pmk)

                        sae_result = await sae_associate(
                            observer,
                            bytes.fromhex(iface.mac_address.replace(':', '')),
                            sta_mac,
                            args.ssid,
                            sae_client_password,
                            args.channel,
                            ((FT_SAE_EXT_KEY_RSN_IE if args.ft_sae_ext_key else
                              FT_SAE_RSN_IE) if args.ft_sae else
                             (SAE_EXT_KEY_RSN_IE if args.sae_ext_key else SAE_RSN_IE)),
                            group=args.sae_group,
                            h2e=args.sae_h2e,
                            password_identifier=args.sae_password_id,
                            sae_pk=args.sae_pk,
                            sae_ext_key=(args.ft_sae_ext_key or args.sae_ext_key),
                            assoc_extra_ies=(build_mdie(bytes.fromhex("a1b2"))
                                             if args.ft_sae else b""),
                            on_confirmed=sae_confirmed,
                        )
                        raw_assoc = sae_result.associated
                        print(f"raw_ota_association={raw_assoc}")
                        print(f"raw_auth_status={sae_result.auth_status}")
                        print(f"raw_assoc_status={sae_result.assoc_status}")
                        print("raw_assoc_fail_reason=" + repr(sae_result.fail_reason))
                        if (raw_assoc and args.wpa_client and args.ft_sae and
                                sae_result.client.pmk is not None):
                            from wifit3_bridge.ft_client import parse_ft_ies
                            from wifit3_bridge.wpa2_client import Wpa2PskClient
                            assoc_frame = sae_result.assoc_response
                            if assoc_frame is None or len(assoc_frame) < 30:
                                raise RuntimeError(
                                    "FT-SAE association response was not captured")
                            ft_mic_len = (len(sae_result.client.pmk) // 2
                                          if args.ft_sae_ext_key else 16)
                            assoc_ies = parse_ft_ies(
                                assoc_frame[30:], mic_len=ft_mic_len)
                            wpa_client = Wpa2PskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid, sae_client_password,
                                rsn_ie=(assoc_rsn_ie + SAE_H2E_RSNX_IE),
                                cipher="CCMP",
                                akm=("FT-SAE-EXT-KEY" if args.ft_sae_ext_key
                                     else "FT-SAE"),
                                ft_mobility_domain=bytes.fromhex("a1b2"),
                                ft_r0kh_id=b"wifit3-ft-r0",
                                ft_r1kh_id=bytes.fromhex(
                                    iface.mac_address.replace(":", "")),
                                ft_assoc_mdie=assoc_ies.mdie,
                                ft_assoc_ftie=assoc_ies.ftie,
                                pmk=sae_result.client.pmk,
                            )
                    else:
                        from wifit3.wlan.station import Association
                        association = Association(
                            observer,
                            iface.mac_address,
                            args.ssid,
                            args.channel,
                            our_mac=sta_mac,
                            assoc_trailer_ies=assoc_rsn_ie,
                            privacy=not args.open,
                            assoc_timeout=2.0,
                            auth_timeout=1.5,
                        )
                        association.start()
                        try:
                            raw_assoc = await association.associate(attempts=2)
                        finally:
                            association.stop()
                        print(f"raw_ota_association={raw_assoc}")
                        print(f"raw_auth_status={association.auth_status}")
                        print(f"raw_assoc_status={association.assoc_status}")
                        print("raw_assoc_fail_reason=" + repr(association.fail_reason))
                    if raw_assoc and (args.enterprise_client or
                                      args.mschapv2_client or
                                      args.peap_mschapv2_client or
                                      args.ttls_mschapv2_client or
                                      args.pwd_client or args.psk_client or
                                      args.sake_client or args.pax_client or
                                      args.gpsk_client or args.gpsk_sha256_client or
                                      args.sim_client or args.aka_client or args.aka_prime_client or
                                      args.fast_client or args.teap_client or args.eke_client or args.ikev2_client):
                        if args.teap_client:
                            enterprise_client = EapTeapClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                outer_identity="anonymous",
                                inner_identity="wifit3-mschap",
                                password=args.passphrase,
                                keylog_file=directory / "teap.keylog",
                                fragment_size=200,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.eke_client:
                            enterprise_client = EapEkeClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-eke",
                                password=args.passphrase,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.ikev2_client:
                            enterprise_client = EapIkev2Client(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-ikev2",
                                password=args.passphrase,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.fast_client:
                            enterprise_client = EapFastClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                outer_identity="anonymous",
                                inner_identity="wifit3-mschap",
                                password=args.passphrase,
                                keylog_file=directory / "fast.keylog",
                                fragment_size=200,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.aka_prime_client:
                            aka_rand, aka_autn, aka_ik, aka_ck, aka_res = _aka_prime_auth_data()
                            enterprise_client = EapAkaPrimeClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="6" + args.aka_prime_imsi,
                                rand=aka_rand,
                                autn=aka_autn,
                                ik=aka_ik,
                                ck=aka_ck,
                                res=aka_res,
                                network_name=b"WLAN",
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.aka_client:
                            aka_rand, aka_autn, aka_ik, aka_ck, aka_res = _aka_auth_data()
                            enterprise_client = EapAkaClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="0" + args.aka_imsi,
                                rand=aka_rand,
                                autn=aka_autn,
                                ik=aka_ik,
                                ck=aka_ck,
                                res=aka_res,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.sim_client:
                            enterprise_client = EapSimClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="1" + args.sim_imsi,
                                triplets=_sim_triplets(),
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.gpsk_sha256_client:
                            enterprise_client = EapGpskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-gpsk-sha256",
                                password=eap_gpsk_sha256_key,
                                cipher_specifier=EAP_GPSK_CIPHER_SHA256,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.gpsk_client:
                            enterprise_client = EapGpskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-gpsk",
                                password=eap_gpsk_key,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.pax_client:
                            enterprise_client = EapPaxClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-pax",
                                password=eap_pax_key,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.sake_client:
                            enterprise_client = EapSakeClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-sake",
                                password=eap_sake_key,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.psk_client:
                            enterprise_client = EapPskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-psk",
                                password=eap_psk_key,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.ttls_mschapv2_client:
                            enterprise_client = EapTtlsMschapv2Client(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-mschap",
                                outer_identity="wifit3-ttls",
                                password=args.passphrase,
                                keylog_file=directory / "ttls.keylog",
                                fragment_size=200,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.peap_mschapv2_client:
                            enterprise_client = EapPeapMschapv2Client(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                outer_identity="wifit3-peap",
                                inner_identity="wifit3-mschap",
                                password=args.passphrase,
                                keylog_file=directory / "peap.keylog",
                                fragment_size=200,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.mschapv2_client:
                            enterprise_client = EapMschapv2Client(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-mschap",
                                password=args.passphrase,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        elif args.pwd_client:
                            enterprise_client = EapPwdClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-pwd",
                                password=args.passphrase,
                                group=args.pwd_group,
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                        else:
                            enterprise_client = EapTlsClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid,
                                identity="wifit3-client",
                                client_cert=directory / "client.pem",
                                client_key=directory / "client.key",
                                keylog_file=directory / "client.keylog",
                                rsn_ie=assoc_rsn_ie,
                                pmf_cipher=args.pmf_cipher,
                            )
                    if raw_assoc and args.wpa_client:
                        if wpa_client is None:
                            from wifit3_bridge.wpa2_client import Wpa2PskClient
                            cipher_name = ("TKIP" if args.tkip else
                                           ("CCMP-256" if args.ccmp256 else
                                            ("GCMP-256" if args.gcmp256 else
                                             ("GCMP" if args.gcmp else "CCMP"))))
                            wpa_client = Wpa2PskClient(
                                bytes.fromhex(iface.mac_address.replace(':', '')),
                                sta_mac, args.ssid, args.passphrase,
                                rsn_ie=assoc_rsn_ie,
                                cipher=cipher_name,
                                pmf_cipher=args.pmf_cipher,
                            )
                    if args.control_smoke:
                        cli = hostapd.parent / "hostapd_cli.exe"
                        sta = subprocess.run(
                            [str(cli), "-i", "127.0.0.1:8877", "sta",
                             observer.mac_address],
                            capture_output=True, text=True, encoding="oem", errors="replace",
                        )
                        all_sta = subprocess.run(
                            [str(cli), "-i", "127.0.0.1:8877", "all_sta"],
                            capture_output=True, text=True, encoding="oem", errors="replace",
                        )
                        control_sta = sta.stdout.strip() or sta.stderr.strip()
                        control_all_sta = all_sta.stdout.strip() or all_sta.stderr.strip()
                    if args.accounting_smoke and raw_assoc and observer is not None:
                        ap_mac = bytes.fromhex(iface.mac_address.replace(':', ''))
                        sta_mac = bytes.fromhex(observer.mac_address.replace(':', ''))
                        data_frame = (b'\x08\x01\x00\x00' + ap_mac + sta_mac +
                                      ap_mac + b'\x00\x00' + b'wifit3-accounting')
                        tx_results = []
                        for _ in range(3):
                            try:
                                tx_results.append(bool(await observer.send_no_wait(data_frame)))
                            except Exception as error:
                                tx_results.append(False)
                                print("accounting_tx_error=" + repr(error))
                            await asyncio.sleep(0.15)
                        # Give Windows' hostapd eloop time to drain the
                        # asynchronous accounting events before querying STA.
                        await asyncio.sleep(0.75)
                        sta_text = ""
                        rx_packets = None
                        rx_bytes = None
                        for _ in range(10):
                            sta_accounting = subprocess.run(
                                [str(cli), "-i", "127.0.0.1:8877", "sta",
                                 observer.mac_address],
                                capture_output=True, text=True, encoding="oem",
                                errors="replace",
                            )
                            sta_text = (sta_accounting.stdout.strip() or
                                        sta_accounting.stderr.strip())
                            rx_packets = re.search(r"(?:^|\n)rx_packets=(\d+)", sta_text)
                            rx_bytes = re.search(r"(?:^|\n)rx_bytes=(\d+)", sta_text)
                            if rx_packets and int(rx_packets.group(1)) > 0:
                                break
                            await asyncio.sleep(0.2)
                        accounting_smoke = {
                            "tx_results": tx_results,
                            "sta_output": sta_text,
                            "rx_packets": int(rx_packets.group(1)) if rx_packets else None,
                            "rx_bytes": int(rx_bytes.group(1)) if rx_bytes else None,
                            "pass": any(tx_results) and bool(rx_packets and int(rx_packets.group(1)) > 0),
                        }
                active_client = enterprise_client or wpa_client
                if active_client is not None:
                    deadline = loop.time() + args.client_wait
                    while not active_client.authorized and loop.time() < deadline:
                        await asyncio.sleep(0.05)
                    ota_wpa_complete = (
                        active_client.authorized and
                        (4 in ap_rx_eapol_msgs or "eapol-m4" in ap_rx_ccmp or
                         "eapol-m4" in ap_rx_gcmp or
                         "eapol-m4" in ap_rx_tkip)
                    )
                    if (args.ft_ota and ota_wpa_complete and observer is not None
                            and sae_result is not None and sae_result.client.pmk is not None):
                        try:
                            ft_mdid = bytes.fromhex("a1b2")
                            ft_r0kh = b"wifit3-ft-r0"
                            ft_caps = rsn_capabilities(assoc_rsn_ie)
                            ft_ext_key = args.ft_sae_ext_key
                            ft_akm = 25 if ft_ext_key else 9
                            ft_kck_len = len(sae_result.client.pmk) // 2 if ft_ext_key else 16
                            ft_mgmt = {
                                "AES-128-CMAC": FT_DEFAULT_MGMT_GROUP_CIPHER,
                                "BIP-GMAC-128": bytes.fromhex("000fac0b"),
                                "BIP-GMAC-256": bytes.fromhex("000fac0c"),
                                "BIP-CMAC-256": bytes.fromhex("000fac0d"),
                            }[args.pmf_cipher.upper()]
                            pmk_r0, pmk_r0_name = derive_pmk_r0(
                                sae_result.client.pmk, args.ssid.encode(),
                                ft_mdid, ft_r0kh, sta_mac)
                            ft_snonce = os.urandom(32)
                            while not ft_rx_queue.empty():
                                ft_rx_queue.get_nowait()
                            auth_ies = build_ft_auth_ies(
                                pmk_r0_name, ft_mdid, ft_r0kh, ft_snonce,
                                akm=ft_akm,
                                capabilities=ft_caps,
                                ft_mic_len=ft_kck_len,
                                mgmt_group_cipher=ft_mgmt)
                            auth_request = build_ft_auth_request(
                                ap_mac, sta_mac, auth_ies)
                            auth_tx = bool(await observer.send_no_wait(auth_request))
                            auth_response = await asyncio.wait_for(
                                ft_rx_queue.get(), timeout=3.0)
                            if len(auth_response) < 30:
                                raise RuntimeError("FT auth response is too short")
                            auth_algorithm, auth_sequence, auth_status = struct.unpack_from(
                                "<HHH", auth_response, 24)
                            if (auth_algorithm, auth_sequence, auth_status) != (2, 2, 0):
                                raise RuntimeError(
                                    "FT auth rejected: "
                                    f"algorithm={auth_algorithm} sequence={auth_sequence} "
                                    f"status={auth_status}")
                            auth_ies_response = parse_ft_ies(
                                auth_response[30:], mic_len=ft_kck_len)
                            ft_r1kh = auth_ies_response.r1kh_id or ap_mac
                            ft_response_r0kh = auth_ies_response.r0kh_id or ft_r0kh
                            pmk_r1, pmk_r1_name = derive_pmk_r1(
                                pmk_r0, pmk_r0_name, ft_r1kh, sta_mac)
                            ft_ptk = derive_ft_ptk(
                                pmk_r1, pmk_r1_name, ft_snonce,
                                auth_ies_response.anonce, sta_mac, ap_mac,
                                ext_key=ft_ext_key)
                            reassoc_ies = build_ft_reassoc_ies_for_addresses(
                                pmk_r1_name, ft_mdid, ft_response_r0kh, ft_r1kh,
                                ft_snonce, auth_ies_response.anonce,
                                ft_ptk[:ft_kck_len], sta_mac, ap_mac,
                                capabilities=ft_caps,
                                mgmt_group_cipher=ft_mgmt,
                                rsnxe=SAE_H2E_RSNX_IE,
                                akm=ft_akm)
                            while not ft_rx_queue.empty():
                                ft_rx_queue.get_nowait()
                            reassoc_request = build_ft_reassoc_request(
                                ap_mac, sta_mac, args.ssid, args.channel,
                                reassoc_ies)
                            reassoc_tx = bool(await observer.send_no_wait(
                                reassoc_request))
                            reassoc_response = await asyncio.wait_for(
                                ft_rx_queue.get(), timeout=3.0)
                            if len(reassoc_response) < 30:
                                raise RuntimeError(
                                    "FT reassociation response is too short")
                            reassoc_status = int.from_bytes(
                                reassoc_response[26:28], "little")
                            ft_ota_result = {
                                "auth_tx": auth_tx,
                                "auth_status": auth_status,
                                "reassoc_tx": reassoc_tx,
                                "reassoc_status": reassoc_status,
                                "pass": auth_tx and reassoc_tx and reassoc_status == 0,
                            }
                        except Exception as error:
                            ft_ota_result = {"pass": False, "error": repr(error)}
                    if (args.pmf or args.sae) and observer is not None and active_client.authorized:
                        try:
                            ap_mac = bytes.fromhex(iface.mac_address.replace(':', ''))
                            sta_mac = bytes.fromhex(observer.mac_address.replace(':', ''))
                            sa_query = (b'\xd0\x00\x00\x00' + ap_mac + sta_mac +
                                        ap_mac + b'\x10\x00\x08\x00\x01\x00')
                            protected_action = active_client.protect_management(sa_query)
                            pmf_action_result = bool(
                                await observer.send_no_wait(protected_action))
                            await asyncio.sleep(0.5)
                            pmf_action_pass = (pmf_action_result and
                                               "verified" in ap_rx_bip)
                        except Exception as error:
                            pmf_action_result = repr(error)
                            pmf_action_pass = False
                        print(f"pmf_client_action={pmf_action_result}")
                        print(f"pmf_client_action_pass={pmf_action_pass}")
                    key_client = (enterprise_client.wpa_client
                                  if enterprise_client is not None else wpa_client)
                    print(f"wpa_client_state={active_client.state}")
                    print(f"ota_wpa_complete={ota_wpa_complete}")
                    if args.ft_ota:
                        print("ft_ota_result=" + repr(ft_ota_result))
                    if enterprise_client is not None:
                        print(f"{eap_label}_state={enterprise_client.state}")
                        print(f"{eap_label}_success={enterprise_client.eap_success}")
                        print(f"{eap_label}_error=" + repr(enterprise_client.last_error))
                        print(f"{eap_label}_last_code={enterprise_client.last_eap_code}")
                        print(f"{eap_label}_last_type={enterprise_client.last_eap_type}")
                        print(f"{eap_label}_last_flags={getattr(enterprise_client, 'last_tls_flags', None)}")
                        print(f"{eap_label}_rx_len={getattr(enterprise_client, 'last_tls_rx_len', 0)}")
                        print(f"{eap_label}_tx_len={getattr(enterprise_client, 'last_tls_tx_len', 0)}")
                        print(f"{eap_label}_inner_success={getattr(enterprise_client, 'inner_success', False)}")
                        print(f"{eap_label}_inner_trace={getattr(enterprise_client, 'inner_trace', [])}")
                        print(f"{eap_label}_trace={getattr(enterprise_client, 'eap_trace', getattr(enterprise_client, 'eap_tls_trace', []))}")
                    print(f"wpa_client_tx={wpa_client_tx}")
                    print(f"wpa_client_tx_ok={wpa_client_tx_ok}")
                    print(f"wpa_client_tx_fail={wpa_client_tx_fail}")
                    print(f"wpa_client_tx_headers={wpa_client_tx_headers}")
                    print(f"wpa_client_tx_msgs={wpa_client_tx_msgs}")
                    print(f"wpa_client_key_data_tags={key_client.last_key_data_tags if key_client else []}")
                    print("wpa_client_error=" + repr(key_client.last_error if key_client else active_client.last_error))
                    print("wpa_client_rx_headers=" + repr(wpa_client_rx_headers))
                    print(f"ap_rx_eapol_msgs={ap_rx_eapol_msgs}")
                    print(f"ap_rx_ccmp={ap_rx_ccmp}")
                    print(f"ap_rx_gcmp={ap_rx_gcmp}")
                await asyncio.sleep(0.2)
                # Flush hostapd's redirected stdout before the temporary
                # directory is removed; Windows keeps inherited file handles
                # open until the child exits.
                stop_hostapd()
            if sim_db_server is not None:
                sim_db_server.close()
                sim_db_server = None
            if args.sim_client or args.aka_client or args.aka_prime_client:
                print(f"sim_db_requests={sim_db_requests}")
                print(f"sim_db_responses={sim_db_responses}")
            if enterprise_client is not None:
                enterprise_client.close()
            text = log.read_text(encoding="utf-8", errors="replace")
            enabled = ("AP-ENABLED" in text or
                       (control_raw_status is not None and
                        "state=ENABLED" in control_raw_status) or
                       (control_status is not None and
                        "state=ENABLED" in control_status))
            fatal = "FATAL_FAILURE" in text
            print(f"adapter={iface.description}")
            print(f"mac={iface.mac_address}")
            print(f"capabilities=0x{config.capabilities:02x}")
            print(f"ap_enabled={enabled}")
            print(f"fatal_failure={fatal}")
            if args.sae_h2e:
                print("sae_h2e=True")
            if args.sae_password_id:
                print("sae_password_id=True")
            if args.sae_pk:
                print("sae_pk=True")
            if args.sae_ext_key:
                print("sae_ext_key=True")
            if radio.hardware_ack:
                print(f"hardware_ack_armed={radio._hardware_ack_armed}")
                print(f"hardware_ack_tx_count={radio.hardware_ack_tx_count}")
            if args.ota:
                print(f"ota_client_connected={ota_connected}")
            if args.raw_assoc:
                print(f"raw_ota_association={raw_assoc}")
            if args.ft_ota:
                print("ft_ota_result=" + repr(ft_ota_result))
            active_client = enterprise_client or wpa_client
            if active_client is not None:
                key_client = (enterprise_client.wpa_client
                              if enterprise_client is not None else wpa_client)
                print(f"wpa_client_state={active_client.state}")
                print(f"ota_wpa_complete={active_client.authorized and (4 in ap_rx_eapol_msgs or 'eapol-m4' in ap_rx_ccmp or 'eapol-m4' in ap_rx_gcmp or 'eapol-m4' in ap_rx_tkip)}")
                if enterprise_client is not None:
                    print(f"{eap_label}_state={enterprise_client.state}")
                    print(f"{eap_label}_success={enterprise_client.eap_success}")
                    print(f"{eap_label}_error=" + repr(enterprise_client.last_error))
                    print(f"{eap_label}_last_code={enterprise_client.last_eap_code}")
                    print(f"{eap_label}_last_type={enterprise_client.last_eap_type}")
                    print(f"{eap_label}_last_flags={getattr(enterprise_client, 'last_tls_flags', None)}")
                    print(f"{eap_label}_rx_len={getattr(enterprise_client, 'last_tls_rx_len', 0)}")
                    print(f"{eap_label}_tx_len={getattr(enterprise_client, 'last_tls_tx_len', 0)}")
                    print(f"{eap_label}_cipher={getattr(enterprise_client, 'tls_cipher', None)}")
                    print(f"{eap_label}_inner_success={getattr(enterprise_client, 'inner_success', False)}")
                    print(f"{eap_label}_inner_trace={getattr(enterprise_client, 'inner_trace', [])}")
                    print(f"{eap_label}_trace={getattr(enterprise_client, 'eap_trace', getattr(enterprise_client, 'eap_tls_trace', []))}")
                print(f"wpa_client_tx={wpa_client_tx}")
                print(f"wpa_client_tx_ok={wpa_client_tx_ok}")
                print(f"wpa_client_tx_fail={wpa_client_tx_fail}")
                print(f"wpa_client_tx_headers={wpa_client_tx_headers}")
                print(f"wpa_client_tx_msgs={wpa_client_tx_msgs}")
                print(f"wpa_client_key_data_tags={key_client.last_key_data_tags if key_client else []}")
                print("wpa_client_error=" + repr(key_client.last_error if key_client else active_client.last_error))
                print("wpa_client_rx_headers=" + repr(wpa_client_rx_headers))
                print(f"wpa_client_rx_msgs={wpa_client_rx_msgs}")
                print(f"wpa_client_rx_eap={wpa_client_rx_eap}")
                print(f"ap_tx_eap={ap_tx_eap}")
                print(f"ap_rx_eapol_msgs={ap_rx_eapol_msgs}")
                print(f"ap_rx_ccmp={ap_rx_ccmp}")
                print(f"ap_rx_gcmp={ap_rx_gcmp}")
                print(f"ap_rx_tkip={ap_rx_tkip}")
                print(f"ap_rx_bip={ap_rx_bip}")
            if args.control_smoke:
                print(f"control_ping={control_ping}")
                print("control_status=" + repr(control_status))
                if control_sta is not None:
                    print("control_sta=" + repr(control_sta))
                if control_all_sta is not None:
                    print("control_all_sta=" + repr(control_all_sta))
                print("control_cli_result=" + repr(control_cli_result))
                print(f"control_raw={control_raw}")
                print("control_raw_status=" + repr(control_raw_status))
            if args.ota or args.raw_assoc or args.station_smoke:
                print("ota_observer=" + str(observer_counts))
                print("ota_probe_ssids=" + str(observer_probe_ssids))
                print("ota_beacons=" + str(observer_beacons))
                print("ota_beacon_hex=" + str(observer_beacon_hex))
                print("ap_tx=" + str(ap_tx_counts))
            if station_smoke is not None:
                print("station_smoke=" + repr(station_smoke))
            if radius_smoke is not None:
                print("radius_smoke=" + repr(radius_smoke))
            if accounting_smoke is not None:
                print("accounting_smoke=" + repr(accounting_smoke))
                print(f"ap_rx_data_frames={ap_rx_data_frames}")
            print("key_slots=" + str(len(radio.key_snapshot())))
            print("key_snapshot=" + str(radio.key_snapshot()))
            print("relevant_log:")
            for line in text.splitlines():
                if any(marker in line for marker in
                       ("wifit3:", "GTK_INIT", "SETKEYSDONE", "FATAL_FAILURE",
                        "AP-ENABLED", "Interface initialization failed",
                        "authentication", "association", "AP-STA", "WPA: RX",
                        "associated", "WPA:", "EAPOL", "eapol", "STA=", "STA ",
                        "start authentication", "sending 1/4", "4-Way", "PTK",
                        "invalid MIC", "invalid state", "key_info=", "WPA: Send",
                        "SAE:", "PMK", "RSN:",
                        "ctrl_iface", "bind", "failed", "Failed",
                         "EAP-PEAP", "EAP-TTLS", "EAP-MSCHAP", "EAP-TLS",
                        "EAP-FAST", "Compound MAC", "keyblock size",
                        "EAP-TEAP", "EAP-EKE", "EAP-IKEV2", "IKEV2", "EAP:",
                        "Unknown", "Could not")):
                    print(line)
            if args.control_smoke and not enabled:
                print(f"control_process_returncode={process_state}")
                print("control_debug_log=" + repr(text[-4000:]))
            return 0 if (enabled and not fatal and
                         (not args.ota or ota_connected) and
                         (not args.raw_assoc or raw_assoc) and
                         (active_client is None or
                          (active_client.authorized and
                            (4 in ap_rx_eapol_msgs or "eapol-m4" in ap_rx_ccmp or
                             "eapol-m4" in ap_rx_gcmp or "eapol-m4" in ap_rx_tkip) and
                           (not (args.pmf or args.sae) or pmf_action_pass))) and
                         (not args.control_smoke or
                         (control_ping == "PONG" or control_raw == "PONG") and
                         ((control_status is not None and
                           "state=ENABLED" in control_status) or
                          (control_raw_status is not None and
                           "state=ENABLED" in control_raw_status))) and
                         (not args.station_smoke or
                          (station_smoke is not None and
                           station_smoke["deauth_returncode"] == 0 and
                           station_smoke["disassoc_returncode"] == 0 and
                           station_smoke["deauth_tx"] and
                           station_smoke["disassoc_tx"])) and
                         (not args.radius_smoke or
                          (radius_smoke is not None and
                           radius_smoke.get("auth_access_challenge") and
                           radius_smoke.get("acct_response"))) and
                         (not args.accounting_smoke or
                          (accounting_smoke is not None and
                           accounting_smoke.get("pass"))) and
                         (not args.ft_ota or
                          (ft_ota_result is not None and
                           ft_ota_result.get("pass")))) else 1
    finally:
        if sim_db_server is not None:
            sim_db_server.close()
        stop_hostapd()
        lease = False
        bridge.close()
        await radio.close()
        iface.unregister_rx_callback(ap_rx_debug)
        await iface.close()
        if observer is not None:
            await observer.close()
        worker.join(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--channel", type=int, default=1)
    parser.add_argument("--ssid", default="wifit3-wpa2-smoke")
    parser.add_argument("--passphrase", default="wifit3-lab-passphrase")
    parser.add_argument("--wait", type=float, default=5.0)
    parser.add_argument("--ota", action="store_true",
                        help="Windows-WPA2-Clienttest durchführen und WLAN-Profil restaurieren")
    parser.add_argument("--raw-assoc", action="store_true",
                        help="rohen OTA-Auth/Association-Test mit dem Beobachterdongle durchführen")
    parser.add_argument("--wpa-client", action="store_true",
                        help="experimentellen WPA2-PSK-Client auf dem Beobachterdongle ausführen")
    parser.add_argument("--pmf", action="store_true",
                        help="WPA2-PMF/BIP-CMAC-128-Startup mit Software-IGTK testen")
    parser.add_argument("--pmf-cipher", default="AES-128-CMAC",
                        choices=("AES-128-CMAC", "BIP-GMAC-128",
                                 "BIP-GMAC-256", "BIP-CMAC-256"),
                        help="PMF-Gruppenmanagement-Cipher für den Startup-Test")
    parser.add_argument("--sae", action="store_true",
                        help="WPA3-SAE-AP-Startup/Control-Smoke mit Software-Capability testen")
    parser.add_argument("--sae-h2e", action="store_true",
                        help="WPA3-SAE-H2E-AP-Startup/Control-Smoke mit sae_pwe=1 testen")
    parser.add_argument("--sae-password-id",
                        help="SAE-H2E-Passwort-Identifier im Commit testen")
    parser.add_argument("--sae-pk", action="store_true",
                        help="WPA3-SAE-PK-AP und SAE-PK-KeyAuth OTA testen")
    parser.add_argument("--sae-pk-credential",
                        help="hostapd sae_password=...|pk=... Credential für SAE-PK")
    parser.add_argument("--sae-ext-key", action="store_true",
                        help="WPA3-SAE-EXT-KEY/H2E-AKM-24 OTA testen")
    parser.add_argument("--ft-sae", action="store_true",
                        help="IEEE-802.11r FT-SAE-Initial-Association über OTA testen")
    parser.add_argument("--ft-sae-ext-key", action="store_true",
                        help="IEEE-802.11r FT-SAE-EXT-KEY-Initial-Association über OTA testen")
    parser.add_argument("--ft-ota", action="store_true",
                        help="FT-SAE-OTA-Roam mit FT-Authentication und Reassociation testen")
    parser.add_argument("--sae-group", type=int, choices=(19, 20, 21), default=19,
                        help="SAE-ECC-Gruppe für den Authentifizierungs- und OTA-Test")
    parser.add_argument("--gcmp", action="store_true",
                        help="WPA2-GCMP-128-AP-Startup/Control-Smoke mit Software-Capability testen")
    parser.add_argument("--gcmp256", action="store_true",
                        help="WPA2-GCMP-256-AP-Startup/Control-Smoke mit Software-Capability testen")
    parser.add_argument("--ccmp256", action="store_true",
                        help="WPA2-CCMP-256-AP-Startup/Control-Smoke mit Software-Capability testen")
    parser.add_argument("--tkip", action="store_true",
                        help="WPA2-TKIP-AP-Startup/Control-Smoke mit Software-Capability testen")
    parser.add_argument("--hardware-ack", action="store_true",
                        help="require active-monitor link acknowledgements; supported adapters enable them automatically")
    parser.add_argument("--control-smoke", action="store_true",
                        help="UDP-Control-Interface mit hostapd_cli testen")
    parser.add_argument("--station-smoke", action="store_true",
                        help="Deauth/Disassoc über hostapd_cli und echten Management-TX testen")
    parser.add_argument("--station-broadcast", action="store_true",
                        help="Station-Smoke mit Broadcast-Ziel statt unicast ohne Peer ausführen")
    parser.add_argument("--radius-smoke", action="store_true",
                        help="integrierten EAP-/RADIUS-Auth- und Accounting-UDP-Pfad testen")
    parser.add_argument("--enterprise-client", action="store_true",
                        help="experimentellen EAP-TLS-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--mschapv2-client", action="store_true",
                        help="experimentellen EAP-MSCHAPv2-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--peap-mschapv2-client", action="store_true",
                        help="experimentellen PEAPv1/MSCHAPv2-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--ttls-mschapv2-client", action="store_true",
                        help="experimentellen EAP-TTLS/MSCHAPv2-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--fast-client", action="store_true",
                        help="experimentellen EAP-FAST/MSCHAPv2-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--teap-client", action="store_true",
                        help="test the experimental EAP-TEAP/MSCHAPv2 enterprise client over real OTA frames")
    parser.add_argument("--eke-client", action="store_true",
                        help="test the experimental EAP-EKE enterprise client over real OTA frames")
    parser.add_argument("--ikev2-client", action="store_true",
                        help="test the EAP-IKEv2 enterprise client over real OTA frames")
    parser.add_argument("--psk-client", action="store_true",
                        help="experimentellen EAP-PSK-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--psk-key", default="00112233445566778899aabbccddeeff",
                        help="16-Byte-EAP-PSK als 32 Hexzeichen")
    parser.add_argument("--sake-client", action="store_true",
                        help="experimentellen EAP-SAKE-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--sake-key",
                        default="00112233445566778899aabbccddeeff"
                                "102132435465768798a9bacbdcedfe0f",
                        help="32-Byte-EAP-SAKE-Schlüssel als 64 Hexzeichen")
    parser.add_argument("--pax-client", action="store_true",
                        help="experimentellen EAP-PAX-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--pax-key", default="00112233445566778899aabbccddeeff",
                        help="16-Byte-EAP-PAX-Schlüssel als 32 Hexzeichen")
    parser.add_argument("--gpsk-client", action="store_true",
                        help="experimentellen EAP-GPSK-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--gpsk-key", default="00112233445566778899aabbccddeeff",
                        help="16-Byte-EAP-GPSK-Schlüssel als 32 Hexzeichen")
    parser.add_argument("--gpsk-sha256-client", action="store_true",
                        help="experimentellen EAP-GPSK-SHA256-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--gpsk-sha256-key",
                        default="00112233445566778899aabbccddeeff"
                                "00112233445566778899aabbccddeeff",
                        help="32-Byte-EAP-GPSK-SHA256-Schlüssel als 64 Hexzeichen")
    parser.add_argument("--sim-client", action="store_true",
                        help="experimentellen EAP-SIM-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--sim-imsi", default="123456789012345",
                        help="14- bis 16-stellige Labor-IMSI für den EAP-SIM-Test")
    parser.add_argument("--aka-client", action="store_true",
                        help="experimentellen EAP-AKA-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--aka-imsi", default="123456789012345",
                        help="14- bis 16-stellige Labor-IMSI für den EAP-AKA-Test")
    parser.add_argument("--aka-prime-client", action="store_true",
                        help="experimentellen EAP-AKA'-Enterprise-Client über echte OTA-Frames testen")
    parser.add_argument("--aka-prime-imsi", default="123456789012345",
                        help="14- bis 16-stellige Labor-IMSI für den EAP-AKA'-Test")
    parser.add_argument("--pwd-client", action="store_true")
    parser.add_argument("--pwd-group", type=int, choices=(19, 20, 21), default=19)
    parser.add_argument("--accounting-smoke", action="store_true",
                        help="OTA-Rohdaten und hostapd-Station counters/inactivity testen")
    parser.add_argument("--open", action="store_true",
                        help="offenen AP statt WPA2 für einen Managementpfad-Diagnosetest verwenden")
    parser.add_argument("--interface", default="WLAN")
    parser.add_argument("--client-wait", type=float, default=15.0)
    parser.add_argument("--observer-index", type=int, default=1)
    parser.add_argument("--no-observer", action="store_const",
                        dest="observer_index", const=None)
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
