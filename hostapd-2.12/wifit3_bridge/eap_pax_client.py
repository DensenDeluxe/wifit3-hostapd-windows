from __future__ import annotations

import hmac
import os

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_PAX = 46
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_PAX_OP_STD_1 = 0x01
EAP_PAX_OP_STD_2 = 0x02
EAP_PAX_OP_STD_3 = 0x03
EAP_PAX_OP_ACK = 0x21
EAP_PAX_FLAGS_MF = 0x01
EAP_PAX_FLAGS_CE = 0x02
EAP_PAX_MAC_HMAC_SHA1_128 = 0x01
EAP_PAX_DH_GROUP_NONE = 0x00
EAP_PAX_PUBLIC_KEY_NONE = 0x00
EAP_PAX_RAND_LEN = 32
EAP_PAX_MAC_LEN = 16
EAP_PAX_ICV_LEN = 16
EAP_PAX_AK_LEN = 16
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapPaxClientError(ValueError):
    pass


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, "sha1").digest()[:EAP_PAX_MAC_LEN]


def _kdf(key: bytes, identifier: str, entropy: bytes, length: int) -> bytes:
    output = bytearray()
    for counter in range(1, 256):
        output.extend(_mac(key, identifier.encode() + entropy + bytes((counter,))))
        if len(output) >= length:
            return bytes(output[:length])
    raise EapPaxClientError("EAP-PAX KDF output is too long")


def derive_keys(password: bytes, rand_s: bytes, rand_p: bytes) -> tuple[
        bytes, bytes, bytes, bytes, bytes, bytes]:
    if not isinstance(password, bytes) or len(password) != EAP_PAX_AK_LEN:
        raise EapPaxClientError("EAP-PAX requires a 16-octet key")
    if len(rand_s) != EAP_PAX_RAND_LEN or len(rand_p) != EAP_PAX_RAND_LEN:
        raise EapPaxClientError("EAP-PAX random values must be 32 bytes")
    entropy = rand_s + rand_p
    mk = _kdf(password, "Master Key", entropy, 16)
    ck = _kdf(mk, "Confirmation Key", entropy, 16)
    ick = _kdf(mk, "Integrity Check Key", entropy, 16)
    mid = _kdf(mk, "Method ID", entropy, 16)
    msk = _kdf(mk, "Master Session Key", entropy, 64)
    emsk = _kdf(mk, "Extended Master Session Key", entropy, 64)
    return mk, ck, ick, mid, msk, emsk


class EapPaxClient:
    eap_type = EAP_PAX

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: bytes | str,
                 rsn_ie: bytes = ENTERPRISE_RSN_IE,
                 pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not ssid:
            raise ValueError("SSID is required")
        if not identity:
            raise ValueError("EAP identity is required")
        if isinstance(password, str):
            password = password.encode()
        if not isinstance(password, bytes) or len(password) != EAP_PAX_AK_LEN:
            raise ValueError("EAP-PAX requires a 16-octet key")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = bytes(password)
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()
        self.state = "INIT"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.last_pax_opcode: int | None = None
        self.rand_s: bytes | None = None
        self.rand_p: bytes | None = None
        self.mk: bytes | None = None
        self.ck: bytes | None = None
        self.ick: bytes | None = None
        self.mid: bytes | None = None
        self.last_std1: bytes | None = None
        self.last_std2: bytes | None = None
        self.last_std3: bytes | None = None
        self.last_ack: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapPaxClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapPaxClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapPaxClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapPaxClientError("truncated EAPOL frame")
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

    def _pax_frame(self, identifier: int, opcode: int, body: bytes,
                   key: bytes) -> bytes:
        payload = bytes((EAP_PAX, opcode, 0, EAP_PAX_MAC_HMAC_SHA1_128,
                         EAP_PAX_DH_GROUP_NONE, EAP_PAX_PUBLIC_KEY_NONE)) + body
        eap = self._eap_response(identifier, payload + b"\x00" * EAP_PAX_ICV_LEN)
        return eap[:-EAP_PAX_ICV_LEN] + _mac(key, eap[:-EAP_PAX_ICV_LEN])

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapPaxClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-pax-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _handle_std_1(self, identifier: int, eap: bytes) -> bytes:
        if self.state != "INIT":
            if self.state == "STD2" and self.last_std1 == eap and self.last_std2 is not None:
                return self.last_std2
            raise EapPaxClientError("unexpected EAP-PAX STD-1")
        if len(eap) < 10 + EAP_PAX_ICV_LEN:
            raise EapPaxClientError("truncated EAP-PAX STD-1")
        opcode, flags, mac_id, dh_group, public_key = eap[5:10]
        if (opcode != EAP_PAX_OP_STD_1 or flags & (EAP_PAX_FLAGS_MF | EAP_PAX_FLAGS_CE) or
                mac_id != EAP_PAX_MAC_HMAC_SHA1_128 or
                dh_group != EAP_PAX_DH_GROUP_NONE or
                public_key != EAP_PAX_PUBLIC_KEY_NONE):
            raise EapPaxClientError("unsupported EAP-PAX STD-1 parameters")
        if not hmac.compare_digest(eap[-16:], _mac(b"", eap[:-16])):
            raise EapPaxClientError("EAP-PAX STD-1 ICV mismatch")
        payload = eap[10:-16]
        if len(payload) < 2:
            raise EapPaxClientError("missing EAP-PAX server random length")
        rand_len = int.from_bytes(payload[:2], "big")
        if rand_len != EAP_PAX_RAND_LEN or len(payload) < 2 + rand_len:
            raise EapPaxClientError("invalid EAP-PAX server random")
        self.rand_s = bytes(payload[2:2 + rand_len])
        self.rand_p = os.urandom(EAP_PAX_RAND_LEN)
        self.mk, self.ck, self.ick, self.mid, self.msk, _ = derive_keys(
            self.password, self.rand_s, self.rand_p)
        body = (len(self.rand_p).to_bytes(2, "big") + self.rand_p +
                len(self.identity).to_bytes(2, "big") + self.identity +
                EAP_PAX_MAC_LEN.to_bytes(2, "big") + _mac(
                    self.ck, self.rand_s + self.rand_p + self.identity))
        self.state = "STD2"
        response = self._pax_frame(identifier, EAP_PAX_OP_STD_2, body, self.ick)
        self.last_std1 = bytes(eap)
        self.last_std2 = response
        return response

    def _handle_std_3(self, identifier: int, eap: bytes) -> bytes:
        if self.state != "STD2" or self.rand_p is None or self.ck is None or self.ick is None:
            if self.state == "SUCCESS_PENDING" and self.last_std3 == eap and self.last_ack is not None:
                return self.last_ack
            raise EapPaxClientError("unexpected EAP-PAX STD-3")
        if len(eap) < 10 + EAP_PAX_ICV_LEN:
            raise EapPaxClientError("truncated EAP-PAX STD-3")
        opcode, flags, mac_id, dh_group, public_key = eap[5:10]
        if (opcode != EAP_PAX_OP_STD_3 or flags & (EAP_PAX_FLAGS_MF | EAP_PAX_FLAGS_CE) or
                mac_id != EAP_PAX_MAC_HMAC_SHA1_128 or
                dh_group != EAP_PAX_DH_GROUP_NONE or
                public_key != EAP_PAX_PUBLIC_KEY_NONE):
            raise EapPaxClientError("unsupported EAP-PAX STD-3 parameters")
        if not hmac.compare_digest(eap[-16:], _mac(self.ick, eap[:-16])):
            raise EapPaxClientError("EAP-PAX STD-3 ICV mismatch")
        payload = eap[10:-16]
        if len(payload) != 2 + EAP_PAX_MAC_LEN:
            raise EapPaxClientError("invalid EAP-PAX STD-3 payload")
        mac_len = int.from_bytes(payload[:2], "big")
        if mac_len != EAP_PAX_MAC_LEN:
            raise EapPaxClientError("invalid EAP-PAX confirmation length")
        expected = _mac(self.ck, self.rand_p + self.identity)
        if not hmac.compare_digest(payload[2:], expected):
            raise EapPaxClientError("EAP-PAX confirmation mismatch")
        self.state = "SUCCESS_PENDING"
        response = self._pax_frame(identifier, EAP_PAX_OP_ACK, b"", self.ick)
        self.last_std3 = bytes(eap)
        self.last_ack = response
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
            except EapPaxClientError as error:
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
            if eap_type != EAP_PAX:
                raise EapPaxClientError("unsupported EAP method")
            if len(eap) < 10:
                raise EapPaxClientError("truncated EAP-PAX frame")
            self.last_pax_opcode = eap[5]
            if eap[5] == EAP_PAX_OP_STD_1:
                response = self._handle_std_1(identifier, eap)
            elif eap[5] == EAP_PAX_OP_STD_3:
                response = self._handle_std_3(identifier, eap)
            else:
                raise EapPaxClientError("unsupported EAP-PAX opcode")
            return [response]
        except EapPaxClientError as error:
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
        except EapPaxClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_PAX", "EapPaxClient", "EapPaxClientError", "derive_keys"]
