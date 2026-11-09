from __future__ import annotations

import hashlib
import hmac

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

from .eap_sim_client import _attribute, _parse_attributes


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_AKA_PRIME = 50
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_AKA_PRIME_SUBTYPE_CHALLENGE = 1
EAP_AKA_PRIME_SUBTYPE_IDENTITY = 5
EAP_AKA_PRIME_AT_RAND = 1
EAP_AKA_PRIME_AT_AUTN = 2
EAP_AKA_PRIME_AT_RES = 3
EAP_AKA_PRIME_AT_MAC = 11
EAP_AKA_PRIME_AT_IDENTITY = 14
EAP_AKA_PRIME_AT_CHECKCODE = 134
EAP_AKA_PRIME_AT_KDF_INPUT = 23
EAP_AKA_PRIME_AT_KDF = 24
EAP_AKA_PRIME_KDF = 1
EAP_AKA_PRIME_MAC_LEN = 16
EAP_AKA_PRIME_RES_MAX_LEN = 16
EAP_AKA_PRIME_CHECKCODE_LEN = 32
EAP_AKA_PRIME_K_ENCR_LEN = 16
EAP_AKA_PRIME_K_AUT_LEN = 32
EAP_AKA_PRIME_K_RE_LEN = 32
EAP_AKA_PRIME_MSK_LEN = 64
EAP_AKA_PRIME_EMSK_LEN = 64
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapAkaPrimeClientError(ValueError):
    pass


def _prf_prime(key: bytes, identity: bytes, length: int) -> bytes:
    if len(key) != 32:
        raise EapAkaPrimeClientError("EAP-AKA' PRF key must be 32 bytes")
    if not identity or length <= 0:
        raise EapAkaPrimeClientError("EAP-AKA' PRF input is invalid")
    seed = b"EAP-AKA'" + identity
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            key, previous + seed + bytes((counter,)), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_aka_prime_keys(identity: bytes, ik: bytes, ck: bytes,
                          autn: bytes, network_name: bytes) -> tuple[
                              bytes, bytes, bytes, bytes, bytes, bytes, bytes]:
    if isinstance(identity, str):
        identity = identity.encode()
    if isinstance(network_name, str):
        network_name = network_name.encode()
    if not isinstance(identity, bytes) or not identity:
        raise EapAkaPrimeClientError("EAP-AKA' identity is required")
    if len(ik) != 16 or len(ck) != 16:
        raise EapAkaPrimeClientError("EAP-AKA' IK and CK must be 16 bytes")
    if len(autn) != 16:
        raise EapAkaPrimeClientError("EAP-AKA' AUTN must be 16 bytes")
    if not isinstance(network_name, bytes) or not network_name:
        raise EapAkaPrimeClientError("EAP-AKA' network name is required")
    kdf_input = (b"\x20" + network_name + len(network_name).to_bytes(2, "big") +
                 autn[:6] + b"\x00\x06")
    kdf_output = hmac.new(ck + ik, kdf_input, hashlib.sha256).digest()
    ck_prime, ik_prime = kdf_output[:16], kdf_output[16:]
    material = _prf_prime(
        ik_prime + ck_prime, identity,
        EAP_AKA_PRIME_K_ENCR_LEN + EAP_AKA_PRIME_K_AUT_LEN +
        EAP_AKA_PRIME_K_RE_LEN + EAP_AKA_PRIME_MSK_LEN +
        EAP_AKA_PRIME_EMSK_LEN)
    pos = 0
    k_encr = material[pos:pos + EAP_AKA_PRIME_K_ENCR_LEN]
    pos += EAP_AKA_PRIME_K_ENCR_LEN
    k_aut = material[pos:pos + EAP_AKA_PRIME_K_AUT_LEN]
    pos += EAP_AKA_PRIME_K_AUT_LEN
    k_re = material[pos:pos + EAP_AKA_PRIME_K_RE_LEN]
    pos += EAP_AKA_PRIME_K_RE_LEN
    msk = material[pos:pos + EAP_AKA_PRIME_MSK_LEN]
    pos += EAP_AKA_PRIME_MSK_LEN
    emsk = material[pos:pos + EAP_AKA_PRIME_EMSK_LEN]
    return ck_prime, ik_prime, k_encr, k_aut, k_re, msk, emsk


class EapAkaPrimeClient:
    eap_type = EAP_AKA_PRIME

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str | bytes, rand: bytes, autn: bytes,
                 ik: bytes, ck: bytes, res: bytes,
                 network_name: bytes | str = b"WLAN",
                 rsn_ie: bytes = ENTERPRISE_RSN_IE,
                 pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if isinstance(identity, str):
            identity = identity.encode()
        if isinstance(network_name, str):
            network_name = network_name.encode()
        if not ssid or not identity or not network_name:
            raise ValueError("EAP-AKA' client parameters are incomplete")
        if len(rand) != 16 or len(autn) != 16 or len(ik) != 16 or len(ck) != 16:
            raise ValueError("EAP-AKA' authentication data has an invalid length")
        if len(res) < 4 or len(res) > EAP_AKA_PRIME_RES_MAX_LEN:
            raise ValueError("EAP-AKA' RES length is invalid")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = bytes(identity)
        self.rand = bytes(rand)
        self.autn = bytes(autn)
        self.ik = bytes(ik)
        self.ck = bytes(ck)
        self.res = bytes(res)
        self.network_name = bytes(network_name)
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()
        self.state = "IDENTITY"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.emsk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.last_aka_subtype: int | None = None
        self.k_encr: bytes | None = None
        self.k_aut: bytes | None = None
        self.k_re: bytes | None = None
        self.checkcode: bytes | None = None
        self.identity_messages: list[bytes] = []
        self.last_challenge: bytes | None = None
        self.last_challenge_response: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapAkaPrimeClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapAkaPrimeClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapAkaPrimeClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapAkaPrimeClientError("truncated EAPOL frame")
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
            raise EapAkaPrimeClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-aka-prime",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _identity_response(self, identifier: int, eap: bytes) -> bytes:
        if len(eap) < 8 or eap[5] != EAP_AKA_PRIME_SUBTYPE_IDENTITY:
            raise EapAkaPrimeClientError("invalid EAP-AKA' Identity request")
        payload = (bytes((EAP_AKA_PRIME, EAP_AKA_PRIME_SUBTYPE_IDENTITY, 0, 0)) +
                   _attribute(EAP_AKA_PRIME_AT_IDENTITY, len(self.identity), self.identity))
        response = self._eap_response(identifier, payload)
        self.identity_messages = [bytes(eap), response]
        self.state = "CHALLENGE"
        return response

    def _handle_challenge(self, identifier: int, eap: bytes) -> bytes:
        if self.state == "SUCCESS_PENDING" and eap == self.last_challenge:
            if self.last_challenge_response is None:
                raise EapAkaPrimeClientError("missing EAP-AKA' retransmission response")
            return self.last_challenge_response
        if self.state not in ("CHALLENGE", "IDENTITY"):
            raise EapAkaPrimeClientError("unexpected EAP-AKA' Challenge")
        attributes = _parse_attributes(eap)
        for attribute in (EAP_AKA_PRIME_AT_RAND, EAP_AKA_PRIME_AT_AUTN,
                          EAP_AKA_PRIME_AT_KDF_INPUT, EAP_AKA_PRIME_AT_KDF,
                          EAP_AKA_PRIME_AT_MAC):
            if attribute not in attributes:
                raise EapAkaPrimeClientError("EAP-AKA' Challenge lacks a required attribute")
        if attributes[EAP_AKA_PRIME_AT_RAND][1] != self.rand:
            raise EapAkaPrimeClientError("EAP-AKA' RAND mismatch")
        if attributes[EAP_AKA_PRIME_AT_AUTN][1] != self.autn:
            raise EapAkaPrimeClientError("EAP-AKA' AUTN mismatch")
        if attributes[EAP_AKA_PRIME_AT_KDF][0] != EAP_AKA_PRIME_KDF:
            raise EapAkaPrimeClientError("unsupported EAP-AKA' KDF")
        if attributes[EAP_AKA_PRIME_AT_KDF_INPUT][1] != self.network_name:
            raise EapAkaPrimeClientError("EAP-AKA' network name mismatch")
        if len(attributes[EAP_AKA_PRIME_AT_MAC][1]) != EAP_AKA_PRIME_MAC_LEN:
            raise EapAkaPrimeClientError("invalid EAP-AKA' server MAC attribute")
        ck_prime, ik_prime, k_encr, k_aut, k_re, msk, emsk = derive_aka_prime_keys(
            self.identity, self.ik, self.ck, self.autn, self.network_name)
        del ck_prime, ik_prime
        mac_offset = attributes[EAP_AKA_PRIME_AT_MAC][2]
        message = bytearray(eap)
        message[mac_offset:mac_offset + EAP_AKA_PRIME_MAC_LEN] = b"\x00" * EAP_AKA_PRIME_MAC_LEN
        expected = hmac.new(k_aut, bytes(message), hashlib.sha256).digest()[:EAP_AKA_PRIME_MAC_LEN]
        if not hmac.compare_digest(expected, attributes[EAP_AKA_PRIME_AT_MAC][1]):
            raise EapAkaPrimeClientError("EAP-AKA' server MAC mismatch")
        server_checkcode = attributes.get(EAP_AKA_PRIME_AT_CHECKCODE)
        checkcode = hashlib.sha256(b"".join(self.identity_messages)).digest()
        if server_checkcode is not None and server_checkcode[1] != checkcode:
            raise EapAkaPrimeClientError("EAP-AKA' checkcode mismatch")
        self.k_encr = k_encr
        self.k_aut = k_aut
        self.k_re = k_re
        self.msk = msk
        self.emsk = emsk
        self.checkcode = checkcode
        response = self._eap_response(
            identifier,
            bytes((EAP_AKA_PRIME, EAP_AKA_PRIME_SUBTYPE_CHALLENGE, 0, 0)) +
            _attribute(EAP_AKA_PRIME_AT_RES, len(self.res) * 8, self.res) +
            _attribute(EAP_AKA_PRIME_AT_CHECKCODE, 0, checkcode) +
            _attribute(EAP_AKA_PRIME_AT_MAC, 0, b"\x00" * EAP_AKA_PRIME_MAC_LEN),
        )
        response_message = bytearray(response)
        response_mac_offset = len(response_message) - EAP_AKA_PRIME_MAC_LEN
        response_mac = hmac.new(k_aut, bytes(response_message), hashlib.sha256).digest()[:EAP_AKA_PRIME_MAC_LEN]
        response_message[response_mac_offset:response_mac_offset + EAP_AKA_PRIME_MAC_LEN] = response_mac
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
            except EapAkaPrimeClientError as error:
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
            if eap_type != EAP_AKA_PRIME or len(eap) < 8:
                raise EapAkaPrimeClientError("unsupported EAP method")
            self.last_aka_subtype = eap[5]
            if eap[5] == EAP_AKA_PRIME_SUBTYPE_IDENTITY:
                response = self._identity_response(identifier, eap)
            elif eap[5] == EAP_AKA_PRIME_SUBTYPE_CHALLENGE:
                response = self._handle_challenge(identifier, eap)
            else:
                raise EapAkaPrimeClientError("unsupported EAP-AKA' subtype")
            return [response]
        except EapAkaPrimeClientError as error:
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
        except EapAkaPrimeClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = [
    "EAP_AKA_PRIME", "EapAkaPrimeClient", "EapAkaPrimeClientError",
    "derive_aka_prime_keys", "EAP_AKA_PRIME_AT_AUTN",
    "EAP_AKA_PRIME_AT_CHECKCODE", "EAP_AKA_PRIME_AT_KDF",
    "EAP_AKA_PRIME_AT_KDF_INPUT", "EAP_AKA_PRIME_AT_MAC",
    "EAP_AKA_PRIME_AT_RAND", "EAP_AKA_PRIME_SUBTYPE_CHALLENGE",
    "EAP_AKA_PRIME_SUBTYPE_IDENTITY",
]
