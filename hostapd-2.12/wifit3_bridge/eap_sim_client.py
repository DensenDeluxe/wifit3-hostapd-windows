from __future__ import annotations

import hashlib
import hmac
import os

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_SIM = 18
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_SIM_SUBTYPE_START = 10
EAP_SIM_SUBTYPE_CHALLENGE = 11
EAP_SIM_AT_RAND = 1
EAP_SIM_AT_NONCE_MT = 7
EAP_SIM_AT_MAC = 11
EAP_SIM_AT_ANY_ID_REQ = 13
EAP_SIM_AT_IDENTITY = 14
EAP_SIM_AT_VERSION_LIST = 15
EAP_SIM_AT_SELECTED_VERSION = 16
EAP_SIM_VERSION = 1
EAP_SIM_NONCE_MT_LEN = 16
EAP_SIM_KC_LEN = 8
EAP_SIM_SRES_LEN = 4
EAP_SIM_MAC_LEN = 16
EAP_SIM_MK_LEN = 20
EAP_SIM_K_ENCR_LEN = 16
EAP_SIM_K_AUT_LEN = 16
EAP_SIM_KEYING_DATA_LEN = 64
EAP_SIM_PRF_LEN = 160
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapSimClientError(ValueError):
    pass


def _rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xffffffff


def _sha1_compress(block: bytes) -> bytes:
    if len(block) != 64:
        raise EapSimClientError("SHA-1 compression requires a 64-byte block")
    words = [int.from_bytes(block[pos:pos + 4], "big")
             for pos in range(0, 64, 4)]
    for pos in range(16, 80):
        words.append(_rol32(words[pos - 3] ^ words[pos - 8] ^
                            words[pos - 14] ^ words[pos - 16], 1))
    initial = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
               0xc3d2e1f0)
    a, b, c, d, e = initial
    for pos, word in enumerate(words):
        if pos < 20:
            function = (b & c) | ((~b) & d)
            constant = 0x5a827999
        elif pos < 40:
            function = b ^ c ^ d
            constant = 0x6ed9eba1
        elif pos < 60:
            function = (b & c) | (b & d) | (c & d)
            constant = 0x8f1bbcdc
        else:
            function = b ^ c ^ d
            constant = 0xca62c1d6
        temporary = (_rol32(a, 5) + function + e + constant + word) & 0xffffffff
        e, d, c, b, a = d, c, _rol32(b, 30), a, temporary
    return b"".join(((left + right) & 0xffffffff).to_bytes(4, "big")
                    for left, right in zip(initial, (a, b, c, d, e)))


def fips186_2_prf(seed: bytes, length: int) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != EAP_SIM_MK_LEN:
        raise EapSimClientError("FIPS 186-2 PRF seed must be 20 bytes")
    if not isinstance(length, int) or length <= 0 or length % 20:
        raise EapSimClientError("FIPS 186-2 PRF length must be a positive multiple of 20")
    xkey = bytearray(seed + b"\x00" * 44)
    output = bytearray()
    modulus = 1 << 160
    for _ in range(length // 20):
        word = _sha1_compress(bytes(xkey))
        output.extend(word)
        next_key = (int.from_bytes(xkey[:20], "big") +
                    int.from_bytes(word, "big") + 1) % modulus
        xkey[:20] = next_key.to_bytes(20, "big")
    return bytes(output)


def derive_keys(identity: bytes, nonce_mt: bytes, triplets: list[tuple[bytes, bytes, bytes]],
                version_list: bytes, selected_version: bytes | int) -> tuple[
                    bytes, bytes, bytes, bytes, bytes]:
    if isinstance(identity, str):
        identity = identity.encode()
    if not isinstance(identity, bytes) or not identity:
        raise EapSimClientError("EAP-SIM identity is required")
    if len(nonce_mt) != EAP_SIM_NONCE_MT_LEN:
        raise EapSimClientError("EAP-SIM NONCE_MT must be 16 bytes")
    if len(triplets) < 2 or len(triplets) > 3:
        raise EapSimClientError("EAP-SIM requires two or three triplets")
    if len(version_list) == 0 or len(version_list) % 2:
        raise EapSimClientError("EAP-SIM version list is invalid")
    if isinstance(selected_version, int):
        selected = selected_version.to_bytes(2, "big")
    else:
        selected = bytes(selected_version)
    if len(selected) != 2:
        raise EapSimClientError("EAP-SIM selected version is invalid")
    kc = bytearray()
    for rand, kc_value, sres in triplets:
        if len(rand) != 16 or len(kc_value) != EAP_SIM_KC_LEN or len(sres) != EAP_SIM_SRES_LEN:
            raise EapSimClientError("EAP-SIM triplet length is invalid")
        kc.extend(kc_value)
    mk = hashlib.sha1(identity + bytes(kc) + nonce_mt + version_list + selected).digest()
    output = fips186_2_prf(mk, EAP_SIM_PRF_LEN)
    return (mk, output[:EAP_SIM_K_ENCR_LEN],
            output[EAP_SIM_K_ENCR_LEN:EAP_SIM_K_ENCR_LEN + EAP_SIM_K_AUT_LEN],
            output[EAP_SIM_K_ENCR_LEN + EAP_SIM_K_AUT_LEN:
                   EAP_SIM_K_ENCR_LEN + EAP_SIM_K_AUT_LEN + EAP_SIM_KEYING_DATA_LEN],
            output[EAP_SIM_K_ENCR_LEN + EAP_SIM_K_AUT_LEN + EAP_SIM_KEYING_DATA_LEN:])


def _attribute(attribute: int, value: int = 0, data: bytes = b"") -> bytes:
    length = 4 + len(data)
    padding = (-length) % 4
    return (bytes((attribute, (length + padding) // 4)) +
            value.to_bytes(2, "big") + data + b"\x00" * padding)


def _parse_attributes(eap: bytes) -> dict[int, tuple[int, bytes, int]]:
    attributes: dict[int, tuple[int, bytes, int]] = {}
    position = 8
    while position < len(eap):
        if len(eap) - position < 4:
            raise EapSimClientError("truncated EAP-SIM attribute")
        length = eap[position + 1] * 4
        if length < 4 or position + length > len(eap):
            raise EapSimClientError("invalid EAP-SIM attribute length")
        attributes[eap[position]] = (
            int.from_bytes(eap[position + 2:position + 4], "big"),
            bytes(eap[position + 4:position + length]),
            position + 4,
        )
        position += length
    return attributes


class EapSimClient:
    eap_type = EAP_SIM

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str | bytes,
                 triplets: list[tuple[bytes, bytes, bytes]],
                 rsn_ie: bytes = ENTERPRISE_RSN_IE,
                 pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not ssid:
            raise ValueError("SSID is required")
        if isinstance(identity, str):
            identity = identity.encode()
        if not isinstance(identity, bytes) or not identity:
            raise ValueError("EAP-SIM identity is required")
        if len(triplets) < 2 or len(triplets) > 3:
            raise ValueError("EAP-SIM requires two or three triplets")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = bytes(identity)
        self.triplets = [(bytes(rand), bytes(kc), bytes(sres))
                         for rand, kc, sres in triplets]
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()
        self.state = "START"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.emsk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.last_sim_subtype: int | None = None
        self.nonce_mt: bytes | None = None
        self.version_list: bytes | None = None
        self.selected_version: int | None = None
        self.k_encr: bytes | None = None
        self.k_aut: bytes | None = None
        self.selected_triplets: list[tuple[bytes, bytes, bytes]] | None = None
        self.last_challenge: bytes | None = None
        self.last_challenge_response: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapSimClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapSimClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapSimClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapSimClientError("truncated EAPOL frame")
        return bytes(frame[eapol + 4:end])

    def _eapol_frame(self, eap: bytes) -> bytes:
        eapol = (bytes((EAPOL_VERSION, EAPOL_TYPE_EAP)) +
                 len(eap).to_bytes(2, "big") + eap)
        return (data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) +
                LLC_SNAP_EAPOL + eapol)

    @staticmethod
    def _eap_response(identifier: int, payload: bytes) -> bytes:
        return (bytes((EAP_RESPONSE, identifier)) +
                (4 + len(payload)).to_bytes(2, "big") + payload)

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapSimClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-sim-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _handle_start(self, identifier: int, eap: bytes) -> bytes:
        if self.state != "START":
            raise EapSimClientError("unexpected EAP-SIM Start")
        attributes = _parse_attributes(eap)
        if EAP_SIM_AT_VERSION_LIST not in attributes:
            raise EapSimClientError("EAP-SIM Start has no version list")
        version_length, version_data, _ = attributes[EAP_SIM_AT_VERSION_LIST]
        version_list = version_data[:version_length]
        if len(version_list) == 0 or len(version_list) % 2:
            raise EapSimClientError("invalid EAP-SIM version list")
        supported = {int.from_bytes(version_list[pos:pos + 2], "big")
                     for pos in range(0, len(version_list), 2)}
        if EAP_SIM_VERSION not in supported:
            raise EapSimClientError("EAP-SIM version 1 is unavailable")
        self.version_list = bytes(version_list)
        self.selected_version = EAP_SIM_VERSION
        self.nonce_mt = os.urandom(EAP_SIM_NONCE_MT_LEN)
        payload = (bytes((EAP_SIM, EAP_SIM_SUBTYPE_START, 0, 0)) +
                   _attribute(EAP_SIM_AT_IDENTITY, len(self.identity), self.identity) +
                   _attribute(EAP_SIM_AT_NONCE_MT, 0, self.nonce_mt) +
                   _attribute(EAP_SIM_AT_SELECTED_VERSION, EAP_SIM_VERSION))
        self.state = "START_DONE"
        return self._eap_response(identifier, payload)

    def _handle_challenge(self, identifier: int, eap: bytes) -> bytes:
        if self.state == "SUCCESS_PENDING" and eap == self.last_challenge:
            if self.last_challenge_response is None:
                raise EapSimClientError("missing EAP-SIM retransmission response")
            return self.last_challenge_response
        if self.state != "START_DONE" or self.nonce_mt is None or self.version_list is None:
            raise EapSimClientError("unexpected EAP-SIM Challenge")
        attributes = _parse_attributes(eap)
        if EAP_SIM_AT_RAND not in attributes or EAP_SIM_AT_MAC not in attributes:
            raise EapSimClientError("EAP-SIM Challenge lacks RAND or MAC")
        rand_data = attributes[EAP_SIM_AT_RAND][1]
        if len(rand_data) not in (32, 48):
            raise EapSimClientError("EAP-SIM Challenge requires two or three RANDs")
        rand_values = [rand_data[pos:pos + 16]
                       for pos in range(0, len(rand_data), 16)]
        if len(set(rand_values)) != len(rand_values):
            raise EapSimClientError("EAP-SIM RAND values must be distinct")
        triplet_map = {rand: (rand, kc, sres) for rand, kc, sres in self.triplets}
        try:
            selected = [triplet_map[rand] for rand in rand_values]
        except KeyError as error:
            raise EapSimClientError("EAP-SIM RAND is unavailable") from error
        self.selected_triplets = selected
        if self.selected_version is None:
            raise EapSimClientError("EAP-SIM version was not selected")
        mk, k_encr, k_aut, msk, emsk = derive_keys(
            self.identity, self.nonce_mt, selected, self.version_list,
            self.selected_version)
        mac_value, _, mac_offset = attributes[EAP_SIM_AT_MAC]
        if mac_value != 0 or len(attributes[EAP_SIM_AT_MAC][1]) != EAP_SIM_MAC_LEN:
            raise EapSimClientError("invalid EAP-SIM server MAC attribute")
        message = bytearray(eap)
        message[mac_offset:mac_offset + EAP_SIM_MAC_LEN] = b"\x00" * EAP_SIM_MAC_LEN
        expected = hmac.new(k_aut, bytes(message) + self.nonce_mt,
                            hashlib.sha1).digest()[:EAP_SIM_MAC_LEN]
        if not hmac.compare_digest(expected, attributes[EAP_SIM_AT_MAC][1]):
            raise EapSimClientError("EAP-SIM server MAC mismatch")
        self.k_encr = k_encr
        self.k_aut = k_aut
        self.msk = msk
        self.emsk = emsk
        response = self._eap_response(
            identifier,
            bytes((EAP_SIM, EAP_SIM_SUBTYPE_CHALLENGE, 0, 0)) +
            _attribute(EAP_SIM_AT_MAC, 0, b"\x00" * EAP_SIM_MAC_LEN),
        )
        response_message = bytearray(response)
        response_mac_offset = len(response_message) - EAP_SIM_MAC_LEN
        response_mac = hmac.new(
            k_aut, bytes(response_message) +
            b"".join(item[2] for item in selected), hashlib.sha1).digest()[:EAP_SIM_MAC_LEN]
        response_message[response_mac_offset:response_mac_offset + EAP_SIM_MAC_LEN] = response_mac
        response = bytes(response_message)
        self.state = "SUCCESS_PENDING"
        self.last_challenge = bytes(eap)
        self.last_challenge_response = response
        return response

    def handle_eap_packet(self, eap: bytes) -> list[bytes]:
        if not isinstance(eap, bytes) or len(eap) < 4:
            return []
        code, identifier = eap[:2]
        length = int.from_bytes(eap[2:4], "big")
        if length < 4 or length > len(eap):
            self.last_error = "invalid EAP length"
            return []
        eap = eap[:length]
        if self.state == "FAILURE":
            return []
        self.last_eap_code = code
        if code == EAP_SUCCESS:
            try:
                self._initialize_wpa()
            except EapSimClientError as error:
                self.last_error = str(error)
                self.state = "FAILURE"
                return []
            self.eap_success = True
            self.state = "WPA"
            return []
        if code == EAP_FAILURE:
            self.state = "FAILURE"
            self.last_error = "EAP peer rejected"
            return []
        if code != EAP_REQUEST or len(eap) < 5:
            return []
        eap_type = eap[4]
        self.last_eap_type = eap_type
        try:
            if eap_type == EAP_IDENTITY:
                return [self._eap_response(
                    identifier, bytes((EAP_IDENTITY,)) + self.identity)]
            if eap_type != EAP_SIM or len(eap) < 8:
                raise EapSimClientError("unsupported EAP method")
            self.last_sim_subtype = eap[5]
            if eap[5] == EAP_SIM_SUBTYPE_START:
                response = self._handle_start(identifier, eap)
            elif eap[5] == EAP_SIM_SUBTYPE_CHALLENGE:
                response = self._handle_challenge(identifier, eap)
            else:
                raise EapSimClientError("unsupported EAP-SIM subtype")
            return [response]
        except EapSimClientError as error:
            self.last_error = str(error)
            self.state = "FAILURE"
            return []

    def handle_frame(self, frame: bytes) -> list[bytes]:
        if self.state != "FAILURE":
            self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        try:
            eap = self._eap_body(frame)
        except EapSimClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_SIM", "EapSimClient", "EapSimClientError", "derive_keys",
           "fips186_2_prf"]
