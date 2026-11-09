"""Minimal WPA2-Personal/CCMP/GCMP/TKIP station for the real OTA lab harness.

This module implements the RSN-PSK four-way exchange needed to verify the
hostapd/wifit3 data path for CCMP, GCMP-128/256 and TKIP. It also contains the
explicit WPA3-SAE group-19/20/21 EAPOL continuation used by the OTA lab
harness: SHA-256 PTK derivation for ordinary SAE, AKM-defined descriptor
version 0, and AES-CMAC MICs. SAE-EXT-KEY selects the SHA-256/384/512 PTK and
variable HMAC-SHA256/384/512 MIC from the SAE PMK length.
It is not a general Windows supplicant. The scoped EAP-TLS client reuses this
module after deriving the Enterprise MSK/PMK. It can consume an encrypted IGTK
KDE from a PMF-capable M3 and generate a BIP-CMAC-128 protected management
frame for the explicit PMF OTA laboratory test.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

from wifit3.dot11.ap import eapol_m1
from wifit3.dot11.eapol import (
    HMAC_MD5_RC4,
    HMAC_SHA1_AES,
    LLC_SNAP_EAPOL,
    data_header,
    eapol_key,
    set_mic,
)
from wifit3.dot11.ie import GENERIC_RSN_IE, iter_information_elements
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.wpa import (
    build_eapol_m2,
    derive_pmk,
    derive_ptk,
    derive_ptk_sha256,
    eapol_mic,
    eapol_mic_aes_cmac,
    eapol_mic_hmac_md5,
    eapol_mic_hmac_sha256,
)

from .ccmp import (
    CcmpError,
    ccmp256_decrypt_mpdu,
    ccmp256_encrypt_mpdu,
    ccmp_decrypt_mpdu,
    ccmp_encrypt_mpdu,
)
from .bip import (
    BipError,
    bip_cmac_protect,
    bip_cmac256_protect,
    bip_gmac_protect,
)
from .gcmp import gcmp_decrypt_mpdu, gcmp_encrypt_mpdu
from .tkip import TkipError, tkip_decrypt_mpdu, tkip_encrypt_mpdu
from .ft_client import derive_ft_ptk, derive_pmk_r0, derive_pmk_r1

_MIC_OFFSET_IN_EAPOL = 81
_EAPOL_KEY_DATA_OFFSET = 99
_IGTK_KDE = b"\x00\x0f\xac\x09"
GCMP_RSN_IE = bytes.fromhex("30140100000fac080100000fac080100000fac020000")
GCMP256_RSN_IE = bytes.fromhex("30140100000fac090100000fac090100000fac020000")
TKIP_RSN_IE = bytes.fromhex("30140100000fac020100000fac020100000fac020000")


class Wpa2ClientError(ValueError):
    """Malformed or unauthenticated WPA2 four-way frame."""


def _derive_sae_ext_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
                        anonce: bytes, snonce: bytes, nbytes: int) -> bytes:
    """Derive SAE-EXT-KEY PTK with the hash selected by the PMK length."""
    digestmod = {32: hashlib.sha256, 48: hashlib.sha384,
                 64: hashlib.sha512}.get(len(pmk))
    if digestmod is None:
        raise Wpa2ClientError("SAE-EXT-KEY PMK must be 32, 48, or 64 octets")
    context = (min(ap_mac, sta_mac) + max(ap_mac, sta_mac) +
               min(anonce, snonce) + max(anonce, snonce))
    length_bits = nbytes * 8
    output = bytearray()
    counter = 1
    while len(output) < nbytes:
        output.extend(hmac.new(
            pmk,
            counter.to_bytes(2, "little") + b"Pairwise key expansion" +
            context + length_bits.to_bytes(2, "little"),
            digestmod,
        ).digest())
        counter += 1
    return bytes(output[:nbytes])


def _build_variable_mic_eapol_key(*, key_info: int, key_len: int,
                                  replay: int, nonce: bytes,
                                  key_data: bytes, mic_len: int) -> bytes:
    if len(nonce) != 32:
        raise ValueError("nonce must be 32 octets")
    body = (
        b"\x02" + struct.pack(">H", key_info) + struct.pack(">H", key_len) +
        struct.pack(">Q", replay) + nonce + bytes(16) + bytes(8) + bytes(8) +
        bytes(mic_len) + struct.pack(">H", len(key_data)) + key_data)
    return b"\x02\x03" + struct.pack(">H", len(body)) + body


def _set_variable_mic(payload: bytes, mic: bytes) -> bytes:
    if len(payload) < 81 + len(mic) + 2:
        raise ValueError("EAPOL-Key payload is too short")
    return payload[:81] + mic + payload[81 + len(mic):]


class Wpa2PskClient:
    """A small WPA2-PSK/CCMP four-way station state machine.

    ``handle_frame`` accepts raw AP-to-station 802.11 frames and returns raw
    station-to-AP frames that the caller can transmit through its wifit3
    interface. The PMK is derived from the passphrase; key bytes are never
    included in the diagnostic state.
    """

    llc_eapol = LLC_SNAP_EAPOL

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 passphrase: str, *, rsn_ie: bytes = GENERIC_RSN_IE,
                 cipher: str = "CCMP",
                 snonce: bytes | None = None,
                 pmk: bytes | None = None,
                 akm: str = "WPA-PSK",
                 pmf_cipher: str = "AES-128-CMAC",
                 ft_mobility_domain: bytes | None = None,
                 ft_r0kh_id: bytes | None = None,
                 ft_r1kh_id: bytes | None = None,
                 ft_assoc_mdie: bytes | None = None,
                 ft_assoc_ftie: bytes | None = None):
        if len(ap_mac) != 6 or len(sta_mac) != 6:
            raise ValueError("AP and station MACs must be six octets")
        if ap_mac == sta_mac:
            raise ValueError("AP and station MAC must differ")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not isinstance(ssid, bytes) or not ssid:
            raise ValueError("SSID must be non-empty bytes")
        if not isinstance(passphrase, str) or not 8 <= len(passphrase.encode()) <= 63:
            raise ValueError("WPA2 passphrase must encode to 8..63 bytes")
        if not isinstance(rsn_ie, bytes) or not rsn_ie:
            raise ValueError("RSN IE is required")
        cipher = cipher.upper()
        if cipher not in ("CCMP", "CCMP-256", "GCMP", "GCMP-256", "TKIP"):
            raise ValueError("cipher must be CCMP, CCMP-256, GCMP, GCMP-256, or TKIP")
        akm = akm.upper()
        if akm not in ("WPA-PSK", "WPA-EAP", "SAE", "SAE-EXT-KEY",
                       "FT-SAE", "FT-SAE-EXT-KEY"):
            raise ValueError("unsupported WPA key management")
        pmf_cipher = pmf_cipher.upper()
        if pmf_cipher not in (
                "AES-128-CMAC", "BIP-GMAC-128", "BIP-GMAC-256",
                "BIP-CMAC-256"):
            raise ValueError("unsupported PMF group-management cipher")
        if snonce is not None and len(snonce) != 32:
            raise ValueError("SNonce must be 32 octets")
        if pmk is not None and akm not in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY") and len(pmk) != 32:
            raise ValueError("external PMK must be 32 octets")
        if (pmk is not None and akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY") and
                len(pmk) not in (32, 48, 64)):
            raise ValueError("SAE-EXT-KEY PMK must be 32, 48, or 64 octets")
        if akm == "FT-SAE-EXT-KEY" and (pmk is None or len(pmk) not in (32, 48, 64)):
            raise ValueError("FT-SAE-EXT-KEY requires a 32/48/64-byte PMK")
        if akm == "FT-SAE" and pmk is not None and len(pmk) != 32:
            raise ValueError("FT-SAE PMK must be 32 octets")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.passphrase = passphrase
        self.rsn_ie = bytes(rsn_ie)
        self.cipher = cipher
        self.akm = akm
        self.pmf_cipher = pmf_cipher
        self._tk_len = 32 if cipher.endswith("-256") or cipher == "TKIP" else 16
        self._pmk_len = len(pmk) if pmk is not None else 32
        # hostapd uses PMK/2 for SAE-EXT-KEY KCK and selects the PTK PRF from
        # the PMK length: SHA-256/384/512 for 32/48/64-byte SAE PMKs.
        self._ft = akm in ("FT-SAE", "FT-SAE-EXT-KEY")
        self._kck_len = (self._pmk_len // 2
                         if akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY") else 16)
        self._mic_len = self._kck_len if akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY") else 16
        self._kek_offset = self._kck_len
        self._kek_len = (16 if self._pmk_len <= 32 else 32
                         if akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY") else 16)
        self._tk_offset = self._kck_len + self._kek_len
        self._fixed_snonce = bytes(snonce) if snonce is not None else None
        self._external_pmk = bytes(pmk) if pmk is not None else None
        self._ft_mobility_domain = (bytes(ft_mobility_domain)
                                    if ft_mobility_domain is not None else None)
        self._ft_r0kh_id = bytes(ft_r0kh_id) if ft_r0kh_id is not None else None
        self._ft_r1kh_id = bytes(ft_r1kh_id) if ft_r1kh_id is not None else None
        self._ft_assoc_mdie = (bytes(ft_assoc_mdie)
                               if ft_assoc_mdie is not None else None)
        self._ft_assoc_ftie = (bytes(ft_assoc_ftie)
                               if ft_assoc_ftie is not None else None)
        if self._ft and (self._ft_mobility_domain is None or
                         self._ft_r0kh_id is None or self._ft_r1kh_id is None):
            raise ValueError("FT-SAE requires mobility-domain, R0KH-ID, and R1KH-ID")
        if ((self._ft_assoc_mdie is None) != (self._ft_assoc_ftie is None)):
            raise ValueError("FT-SAE MDIE and FTIE must be supplied together")
        self.state = "UNAUTHENTICATED"
        self.anonce: bytes | None = None
        self.snonce: bytes | None = None
        self.ptk: bytes | None = None
        self.replay_counter: bytes | None = None
        self._tx_pn = 1
        self._rx_pn = 0
        self.igtk: bytes | None = None
        self.igtk_id: int | None = None
        self.last_key_data_tags: list[int] = []
        self._bip_tx_ipn = 1
        self.last_error: str | None = None

    @property
    def authorized(self) -> bool:
        return self.state == "AUTHORIZED"

    def _new_snonce(self) -> bytes:
        return self._fixed_snonce if self._fixed_snonce is not None else os.urandom(32)

    def _rsn_with_pmkid(self, pmkid: bytes) -> bytes:
        """Return the negotiated RSNE with one FT PMKID inserted/replaced."""
        if len(pmkid) != 16 or len(self.rsn_ie) < 2 or self.rsn_ie[0] != 0x30:
            raise Wpa2ClientError("invalid FT RSN IE or PMKID")
        body_len = self.rsn_ie[1]
        body = self.rsn_ie[2:2 + body_len]
        if len(body) != body_len or len(body) < 2 + 4 + 2 + 4 + 2 + 4 + 2:
            raise Wpa2ClientError("truncated FT RSN IE")
        pos = 2 + 4
        pairwise_count = int.from_bytes(body[pos:pos + 2], "little")
        pos += 2 + 4 * pairwise_count
        if pos + 2 > len(body):
            raise Wpa2ClientError("truncated FT pairwise suite list")
        akm_count = int.from_bytes(body[pos:pos + 2], "little")
        pos += 2 + 4 * akm_count
        if pos + 2 > len(body):
            raise Wpa2ClientError("truncated FT AKM suite list")
        pos += 2
        if pos + 2 > len(body):
            if pos == len(body):
                return (bytes((0x30, len(body) + 18)) + body +
                        b"\x01\x00" + pmkid +
                        self.rsn_ie[2 + body_len:])
            raise Wpa2ClientError("FT RSN capabilities are missing")
        pmkid_count = int.from_bytes(body[pos:pos + 2], "little")
        pmkid_pos = pos + 2
        existing_end = pmkid_pos + 16 * pmkid_count
        if existing_end > len(body):
            raise Wpa2ClientError("truncated FT PMKID list")
        if pmkid_count:
            body = body[:pmkid_pos] + pmkid + body[existing_end:]
        else:
            body = body[:pmkid_pos] + b"\x01\x00" + pmkid + body[pmkid_pos:]
        return bytes((0x30, len(body))) + body + self.rsn_ie[2 + body_len:]

    def _zero_mic(self, payload: bytes) -> bytes:
        if len(payload) < _MIC_OFFSET_IN_EAPOL + self._mic_len:
            raise Wpa2ClientError("EAPOL-Key payload is too short for a MIC")
        return (payload[:_MIC_OFFSET_IN_EAPOL] + bytes(self._mic_len) +
                payload[_MIC_OFFSET_IN_EAPOL + self._mic_len:])

    def _verify_mic(self, packet) -> bool:
        if self.ptk is None or packet.payload is None or packet.mic is None:
            return False
        expected = self._eapol_mic(self._zero_mic(packet.payload))
        return hmac.compare_digest(packet.mic, expected)

    def _key_descriptor_version(self):
        if self.akm in ("SAE", "SAE-EXT-KEY", "FT-SAE", "FT-SAE-EXT-KEY"):
            # SAE uses the AKM-defined EAPOL-Key MIC algorithm (version 0).
            return 0
        return HMAC_MD5_RC4 if self.cipher == "TKIP" else HMAC_SHA1_AES

    def _eapol_mic(self, payload: bytes) -> bytes:
        if self.akm in ("SAE", "FT-SAE"):
            return eapol_mic_aes_cmac(self.ptk[:self._kck_len], payload)
        if self.akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY"):
            digestmod = {16: hashlib.sha256, 24: hashlib.sha384,
                         32: hashlib.sha512}[self._kck_len]
            return hmac.new(self.ptk[:self._kck_len], payload,
                            digestmod).digest()[:self._mic_len]
        if self.cipher == "TKIP":
            return eapol_mic_hmac_md5(self.ptk[:16], payload)
        return eapol_mic(self.ptk[:16], payload)

    def _m2(self, replay: bytes) -> bytes:
        assert self.snonce is not None and self.ptk is not None
        rsn_ie = getattr(self, "_ft_rsn_ie", self.rsn_ie)
        key_data = rsn_ie
        if self._ft and self._ft_assoc_mdie is not None:
            key_data += self._ft_assoc_mdie + self._ft_assoc_ftie
        if self.akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY"):
            payload = _build_variable_mic_eapol_key(
                key_info=0x0108 | self._key_descriptor_version(), key_len=0,
                replay=int.from_bytes(replay, "big"), nonce=self.snonce,
                key_data=key_data, mic_len=self._mic_len)
            return (data_header(to_ds=True, bssid=self.ap_mac,
                                client=self.sta_mac) + self.llc_eapol +
                    _set_variable_mic(payload, self._eapol_mic(payload)))
        return build_eapol_m2(
            self.ap_mac, self.sta_mac, self.snonce, self.ptk[:self._kck_len],
            self._key_descriptor_version(), int.from_bytes(replay, "big"),
            key_data, use_hmac_sha256=self.akm == "SAE-EXT-KEY",
        )

    def _m4(self, replay: bytes) -> bytes:
        assert self.ptk is not None
        if self.akm in ("SAE-EXT-KEY", "FT-SAE-EXT-KEY"):
            payload = _build_variable_mic_eapol_key(
                key_info=0x0308 | self._key_descriptor_version(), key_len=0,
                replay=int.from_bytes(replay, "big"), nonce=bytes(32),
                key_data=b"", mic_len=self._mic_len)
            payload = _set_variable_mic(payload, self._eapol_mic(payload))
        else:
            payload = eapol_key(
                key_info=0x0308 | self._key_descriptor_version(),
                key_len=0,
                replay=int.from_bytes(replay, "big"),
                nonce=bytes(32),
                key_data=b"",
            )
            payload = set_mic(payload, self._eapol_mic(payload))
        plain = (data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) +
                 LLC_SNAP_EAPOL + payload)
        if self.cipher == "GCMP-256":
                protected = gcmp_encrypt_mpdu(
                plain, self.ptk[self._tk_offset:self._tk_offset + self._tk_len], self._tx_pn)
        elif self.cipher == "GCMP":
                protected = gcmp_encrypt_mpdu(
                plain, self.ptk[self._tk_offset:self._tk_offset + self._tk_len], self._tx_pn)
        elif self.cipher == "CCMP-256":
            protected = ccmp256_encrypt_mpdu(
                plain, self.ptk[self._tk_offset:self._tk_offset + self._tk_len], self._tx_pn)
        elif self.cipher == "TKIP":
            protected = tkip_encrypt_mpdu(
                plain, self.ptk[self._tk_offset:self._tk_offset + 32], self._tx_pn)
        else:
            protected = ccmp_encrypt_mpdu(
                plain, self.ptk[self._tk_offset:self._tk_offset + 16], self._tx_pn)
        self._tx_pn += 1
        return protected

    def _extract_igtk(self, packet) -> None:
        """Install the IGTK carried in an encrypted M3 KDE for the PMF lab client."""
        if packet.payload is None or not packet.key_data_len:
            return
        start = _EAPOL_KEY_DATA_OFFSET + (self._mic_len - 16)
        end = start + packet.key_data_len
        if len(packet.payload) < end:
            return
        key_data = packet.payload[start:end]
        if getattr(packet, "key_info", 0) & 0x0100:
            if self.ptk is None:
                self.last_error = "encrypted EAPOL-Key data before PTK"
                return
            try:
                key_data = aes_key_unwrap(
                    self.ptk[self._kek_offset:self._kek_offset + self._kek_len],
                    key_data)
            except (InvalidUnwrap, ValueError) as error:
                self.last_error = f"EAPOL-Key data unwrap failed: {error}"
                return
        self.last_key_data_tags = []
        for tag, value, _raw in iter_information_elements(key_data):
            self.last_key_data_tags.append(tag)
            if tag != 0xdd or len(value) < 4 + 2 + 6 + 16:
                continue
            if value[:4] != _IGTK_KDE:
                continue
            key_len = len(value) - (4 + 2 + 6)
            expected_len = (32 if self.pmf_cipher in
                            ("BIP-GMAC-256", "BIP-CMAC-256") else 16)
            if key_len != expected_len:
                continue
            self.igtk_id = int.from_bytes(value[4:6], "little")
            self.igtk = bytes(value[12:12 + key_len])
            # The received IPN is the AP's TX state. Station TX starts at 1
            # and is tracked independently by the peer's replay checker.
            self._bip_tx_ipn = 1
            return

    def protect_management(self, frame: bytes) -> bytes:
        """Protect a robust management frame with the IGTK learned from M3."""
        if self.igtk is None or self.igtk_id is None:
            raise Wpa2ClientError("PMF IGTK has not been received")
        try:
            if self.pmf_cipher == "AES-128-CMAC":
                protector = bip_cmac_protect
            elif self.pmf_cipher == "BIP-GMAC-128":
                protector = bip_gmac_protect
            elif self.pmf_cipher == "BIP-GMAC-256":
                protector = bip_gmac_protect
            else:
                protector = bip_cmac256_protect
            protected = protector(
                bytes(frame), self.igtk, key_id=self.igtk_id,
                ipn=self._bip_tx_ipn)
        except BipError as error:
            raise Wpa2ClientError(str(error)) from error
        self._bip_tx_ipn += 1
        return protected

    def _parse_ap_frame(self, frame: bytes):
        """Parse an AP EAPOL frame, decrypting the negotiated data cipher."""
        plain = frame
        if frame[1] & 0x40:
            if self.ptk is None:
                self.last_error = "protected EAPOL before PTK"
                return None
            try:
                if self.cipher.startswith("GCMP"):
                    pn, plain = gcmp_decrypt_mpdu(
                        frame, self.ptk[self._tk_offset:self._tk_offset + self._tk_len], self._rx_pn)
                elif self.cipher == "CCMP-256":
                    pn, plain = ccmp256_decrypt_mpdu(
                        frame, self.ptk[self._tk_offset:self._tk_offset + self._tk_len], self._rx_pn)
                elif self.cipher == "TKIP":
                    pn, plain = tkip_decrypt_mpdu(
                        frame, self.ptk[self._tk_offset:self._tk_offset + 32], source=self.ap_mac,
                        minimum_tsc=self._rx_pn)
                else:
                    pn, plain = ccmp_decrypt_mpdu(
                        frame, self.ptk[self._tk_offset:self._tk_offset + 16], self._rx_pn)
            except (CcmpError, TkipError) as error:
                self.last_error = f"{self.cipher} decrypt failed: {error}"
                return None
            self._rx_pn = pn
        return WlanFrameParser.parse_80211_frame(
            plain, -30, eapol_mic_len=self._mic_len)

    def handle_frame(self, frame: bytes) -> list[bytes]:
        """Process one AP-to-station frame and return responses to transmit."""
        self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        packet = self._parse_ap_frame(frame)
        if packet is None or getattr(packet, "msg_num", None) not in (1, 3):
            return []
        if packet.replay_counter is None or packet.nonce is None or packet.payload is None:
            self.last_error = "incomplete EAPOL-Key frame"
            return []
        if packet.msg_num == 1:
            if self.replay_counter is not None:
                if packet.replay_counter < self.replay_counter:
                    self.last_error = "replayed M1"
                    return []
                if packet.nonce == self.anonce and self.ptk is not None:
                    # hostapd may retransmit M1 with a new replay counter while
                    # keeping ANonce unchanged. The station must retain its
                    # SNonce/PTK; deriving a new PTK here would make the next
                    # M3 MIC unverifiable. Rebuild M2 only for the new counter.
                    self.replay_counter = bytes(packet.replay_counter)
                    self.state = "M2_SENT"
                    return [self._m2(self.replay_counter)]
            self.anonce = bytes(packet.nonce)
            self.snonce = self._new_snonce()
            pmk = (self._external_pmk if self._external_pmk is not None else
                   derive_pmk(self.passphrase, self.ssid))
            if self._ft:
                if (self._ft_mobility_domain is None or
                        self._ft_r0kh_id is None or self._ft_r1kh_id is None):
                    self.last_error = "FT parameters are not configured"
                    return []
                pmk_r0, pmk_r0_name = derive_pmk_r0(
                    pmk, self.ssid, self._ft_mobility_domain,
                    self._ft_r0kh_id, self.sta_mac)
                pmk_r1, pmk_r1_name = derive_pmk_r1(
                    pmk_r0, pmk_r0_name, self._ft_r1kh_id, self.sta_mac)
                self._ft_pmk_r1_name = pmk_r1_name
                self._ft_rsn_ie = self._rsn_with_pmkid(pmk_r1_name)
                self.ptk = derive_ft_ptk(
                    pmk_r1, pmk_r1_name, self.snonce, self.anonce,
                    self.sta_mac, self.ap_mac,
                    ext_key=self.akm == "FT-SAE-EXT-KEY")
            elif self.akm == "SAE-EXT-KEY":
                derive = _derive_sae_ext_ptk
            elif self.akm == "SAE":
                derive = derive_ptk_sha256
            else:
                derive = derive_ptk
            if not self._ft:
                self.ptk = derive(pmk, self.ap_mac, self.sta_mac,
                                  self.anonce, self.snonce,
                                  self._tk_offset + self._tk_len)
            self.replay_counter = bytes(packet.replay_counter)
            self.state = "M2_SENT"
            return [self._m2(self.replay_counter)]
        if self.state not in ("M2_SENT", "AUTHORIZED") or self.replay_counter is None:
            self.last_error = "M3 before M1"
            return []
        if packet.replay_counter < self.replay_counter:
            self.last_error = "M3 replay counter mismatch"
            return []
        if not self._verify_mic(packet):
            self.last_error = "M3 MIC verification failed"
            return []
        self._extract_igtk(packet)
        # hostapd normally increments the replay counter between M1 and M3;
        # a duplicate M3 after a lost M4 is allowed at the same counter.
        self.replay_counter = bytes(packet.replay_counter)
        self.state = "AUTHORIZED"
        return [self._m4(packet.replay_counter)]

