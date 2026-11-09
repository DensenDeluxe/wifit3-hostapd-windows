from __future__ import annotations

import hashlib
import hmac

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

from .eap_sim_client import _attribute, _parse_attributes, fips186_2_prf


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_AKA = 23
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_AKA_SUBTYPE_CHALLENGE = 1
EAP_AKA_SUBTYPE_IDENTITY = 5
EAP_AKA_AT_RAND = 1
EAP_AKA_AT_AUTN = 2
EAP_AKA_AT_RES = 3
EAP_AKA_AT_MAC = 11
EAP_AKA_AT_IDENTITY = 14
EAP_AKA_AT_CHECKCODE = 134
EAP_AKA_AT_BIDDING = 136
EAP_AKA_PRF_LEN = 160
EAP_AKA_RES_MAX_LEN = 16
EAP_AKA_MAC_LEN = 16
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapAkaClientError(ValueError):
    pass


def derive_aka_keys(identity: bytes, ik: bytes, ck: bytes) -> tuple[
        bytes, bytes, bytes, bytes, bytes]:
    if isinstance(identity, str):
        identity = identity.encode()
    if not isinstance(identity, bytes) or not identity:
        raise EapAkaClientError("EAP-AKA identity is required")
    if len(ik) != 16 or len(ck) != 16:
        raise EapAkaClientError("EAP-AKA IK and CK must be 16 bytes")
    mk = hashlib.sha1(identity + ik + ck).digest()
    output = fips186_2_prf(mk, EAP_AKA_PRF_LEN)
    return (mk, output[:16], output[16:32], output[32:96], output[96:160])


class EapAkaClient:
    eap_type = EAP_AKA

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str | bytes, rand: bytes, autn: bytes,
                 ik: bytes, ck: bytes, res: bytes,
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
            raise ValueError("EAP-AKA identity is required")
        if len(rand) != 16 or len(autn) != 16 or len(ik) != 16 or len(ck) != 16:
            raise ValueError("EAP-AKA authentication data has an invalid length")
        if len(res) < 4 or len(res) > EAP_AKA_RES_MAX_LEN:
            raise ValueError("EAP-AKA RES length is invalid")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = bytes(identity)
        self.rand = bytes(rand)
        self.autn = bytes(autn)
        self.ik = bytes(ik)
        self.ck = bytes(ck)
        self.res = bytes(res)
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
        self.checkcode: bytes | None = None
        self.identity_messages: list[bytes] = []
        self.last_challenge: bytes | None = None
        self.last_challenge_response: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapAkaClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapAkaClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapAkaClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapAkaClientError("truncated EAPOL frame")
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
            raise EapAkaClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-aka-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _identity_response(self, identifier: int, eap: bytes) -> bytes:
        if len(eap) < 8 or eap[5] != EAP_AKA_SUBTYPE_IDENTITY:
            raise EapAkaClientError("invalid EAP-AKA Identity request")
        payload = (bytes((EAP_AKA, EAP_AKA_SUBTYPE_IDENTITY, 0, 0)) +
                   _attribute(EAP_AKA_AT_IDENTITY, len(self.identity), self.identity))
        response = self._eap_response(identifier, payload)
        self.identity_messages = [bytes(eap), response]
        self.state = "CHALLENGE"
        return response

    def _handle_challenge(self, identifier: int, eap: bytes) -> bytes:
        if self.state == "SUCCESS_PENDING" and eap == self.last_challenge:
            if self.last_challenge_response is None:
                raise EapAkaClientError("missing EAP-AKA retransmission response")
            return self.last_challenge_response
        if self.state not in ("CHALLENGE", "IDENTITY"):
            raise EapAkaClientError("unexpected EAP-AKA Challenge")
        attributes = _parse_attributes(eap)
        for attribute in (EAP_AKA_AT_RAND, EAP_AKA_AT_AUTN, EAP_AKA_AT_MAC):
            if attribute not in attributes:
                raise EapAkaClientError("EAP-AKA Challenge lacks a required attribute")
        if attributes[EAP_AKA_AT_RAND][1] != self.rand:
            raise EapAkaClientError("EAP-AKA RAND mismatch")
        if attributes[EAP_AKA_AT_AUTN][1] != self.autn:
            raise EapAkaClientError("EAP-AKA AUTN mismatch")
        if len(attributes[EAP_AKA_AT_MAC][1]) != EAP_AKA_MAC_LEN:
            raise EapAkaClientError("invalid EAP-AKA server MAC attribute")
        _, k_encr, k_aut, msk, emsk = derive_aka_keys(
            self.identity, self.ik, self.ck)
        mac_offset = attributes[EAP_AKA_AT_MAC][2]
        message = bytearray(eap)
        message[mac_offset:mac_offset + EAP_AKA_MAC_LEN] = b"\x00" * EAP_AKA_MAC_LEN
        expected = hmac.new(k_aut, bytes(message), hashlib.sha1).digest()[:EAP_AKA_MAC_LEN]
        if not hmac.compare_digest(expected, attributes[EAP_AKA_AT_MAC][1]):
            raise EapAkaClientError("EAP-AKA server MAC mismatch")
        server_checkcode = attributes.get(EAP_AKA_AT_CHECKCODE)
        checkcode = hashlib.sha1(b"".join(self.identity_messages)).digest()
        if server_checkcode is not None and server_checkcode[1] != checkcode:
            raise EapAkaClientError("EAP-AKA checkcode mismatch")
        self.k_encr = k_encr
        self.k_aut = k_aut
        self.msk = msk
        self.emsk = emsk
        self.checkcode = checkcode
        response = self._eap_response(
            identifier,
            bytes((EAP_AKA, EAP_AKA_SUBTYPE_CHALLENGE, 0, 0)) +
            _attribute(EAP_AKA_AT_RES, len(self.res) * 8, self.res) +
            _attribute(EAP_AKA_AT_CHECKCODE, 0, checkcode) +
            _attribute(EAP_AKA_AT_MAC, 0, b"\x00" * EAP_AKA_MAC_LEN),
        )
        response_message = bytearray(response)
        response_mac_offset = len(response_message) - EAP_AKA_MAC_LEN
        response_mac = hmac.new(k_aut, bytes(response_message), hashlib.sha1).digest()[:EAP_AKA_MAC_LEN]
        response_message[response_mac_offset:response_mac_offset + EAP_AKA_MAC_LEN] = response_mac
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
            except EapAkaClientError as error:
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
            if eap_type != EAP_AKA or len(eap) < 8:
                raise EapAkaClientError("unsupported EAP method")
            self.last_aka_subtype = eap[5]
            if eap[5] == EAP_AKA_SUBTYPE_IDENTITY:
                response = self._identity_response(identifier, eap)
            elif eap[5] == EAP_AKA_SUBTYPE_CHALLENGE:
                response = self._handle_challenge(identifier, eap)
            else:
                raise EapAkaClientError("unsupported EAP-AKA subtype")
            return [response]
        except EapAkaClientError as error:
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
        except EapAkaClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_AKA", "EapAkaClient", "EapAkaClientError", "derive_aka_keys"]
