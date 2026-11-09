from __future__ import annotations

import hashlib
import hmac
import os

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

from .bip import aes_cmac


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_GPSK = 51
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_GPSK_OPCODE_GPSK_1 = 1
EAP_GPSK_OPCODE_GPSK_2 = 2
EAP_GPSK_OPCODE_GPSK_3 = 3
EAP_GPSK_OPCODE_GPSK_4 = 4
EAP_GPSK_CIPHER_AES = 1
EAP_GPSK_CIPHER_SHA256 = 2
EAP_GPSK_VENDOR_IETF = 0
EAP_GPSK_RAND_LEN = 32
EAP_GPSK_MIC_LEN = 16
EAP_GPSK_CS_LEN = 6
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapGpskClientError(ValueError):
    pass


def _gkdf(key: bytes, data: bytes, length: int, cipher_specifier: int) -> bytes:
    output = bytearray()
    if cipher_specifier == EAP_GPSK_CIPHER_AES:
        block = lambda value: aes_cmac(key, value)
    elif cipher_specifier == EAP_GPSK_CIPHER_SHA256:
        block = lambda value: hmac.new(key, value, hashlib.sha256).digest()
    else:
        raise EapGpskClientError("unsupported EAP-GPSK ciphersuite")
    for counter in range(1, 65536):
        output.extend(block(counter.to_bytes(2, "big") + data))
        if len(output) >= length:
            return bytes(output[:length])
    raise EapGpskClientError("EAP-GPSK KDF output is too long")


def _mac(key: bytes, data: bytes, cipher_specifier: int) -> bytes:
    if cipher_specifier == EAP_GPSK_CIPHER_AES:
        return aes_cmac(key, data)
    if cipher_specifier == EAP_GPSK_CIPHER_SHA256:
        return hmac.new(key, data, hashlib.sha256).digest()
    raise EapGpskClientError("unsupported EAP-GPSK ciphersuite")


def derive_keys(psk: bytes, rand_peer: bytes, rand_server: bytes,
                id_peer: bytes, id_server: bytes,
                cipher_specifier: int = EAP_GPSK_CIPHER_AES) -> tuple[
                    bytes, bytes, bytes, bytes, bytes]:
    if cipher_specifier == EAP_GPSK_CIPHER_AES:
        if not isinstance(psk, bytes) or len(psk) != 16:
            raise EapGpskClientError("AES EAP-GPSK requires a 16-octet PSK")
        mk_len = 16
        sk_len = 16
    elif cipher_specifier == EAP_GPSK_CIPHER_SHA256:
        if not isinstance(psk, bytes) or len(psk) != 32:
            raise EapGpskClientError("SHA256 EAP-GPSK requires a 32-octet PSK")
        mk_len = 32
        sk_len = 32
    else:
        raise EapGpskClientError("unsupported EAP-GPSK ciphersuite")
    if len(rand_peer) != EAP_GPSK_RAND_LEN or len(rand_server) != EAP_GPSK_RAND_LEN:
        raise EapGpskClientError("EAP-GPSK random values must be 32 bytes")
    seed = rand_peer + id_peer + rand_server + id_server
    data = (len(psk).to_bytes(2, "big") + psk +
            EAP_GPSK_VENDOR_IETF.to_bytes(4, "big") +
            cipher_specifier.to_bytes(2, "big") + seed)
    mk = _gkdf(psk, data, mk_len, cipher_specifier)
    output = _gkdf(mk, seed, 128 + 2 * sk_len, cipher_specifier)
    return (mk, output[:64], output[64:128],
            output[128:128 + sk_len], output[128 + sk_len:])


class EapGpskClient:
    eap_type = EAP_GPSK

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: bytes | str,
                 cipher_specifier: int = EAP_GPSK_CIPHER_AES,
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
        if cipher_specifier == EAP_GPSK_CIPHER_AES:
            expected_length = 16
            error = "AES EAP-GPSK requires a 16-octet PSK"
        elif cipher_specifier == EAP_GPSK_CIPHER_SHA256:
            expected_length = 32
            error = "SHA256 EAP-GPSK requires a 32-octet PSK"
        else:
            raise ValueError("unsupported EAP-GPSK ciphersuite")
        if not isinstance(password, bytes) or len(password) != expected_length:
            raise ValueError(error)
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = bytes(password)
        self.cipher_specifier = cipher_specifier
        self.mic_len = 16 if cipher_specifier == EAP_GPSK_CIPHER_AES else 32
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()
        self.state = "GPSK_1"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.last_gpsk_opcode: int | None = None
        self.rand_server: bytes | None = None
        self.rand_peer: bytes | None = None
        self.id_server: bytes | None = None
        self.sk: bytes | None = None
        self.pk: bytes | None = None
        self.cipher_list: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapGpskClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapGpskClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapGpskClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapGpskClientError("truncated EAPOL frame")
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
            raise EapGpskClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-gpsk-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _handle_gpsk_1(self, identifier: int, eap: bytes) -> bytes:
        if self.state != "GPSK_1":
            raise EapGpskClientError("unexpected EAP-GPSK GPSK-1")
        payload = eap[6:]
        if len(payload) < 2 + 32 + 2:
            raise EapGpskClientError("truncated EAP-GPSK GPSK-1")
        server_len = int.from_bytes(payload[:2], "big")
        if len(payload) < 2 + server_len + 32 + 2:
            raise EapGpskClientError("invalid EAP-GPSK server identity")
        self.id_server = bytes(payload[2:2 + server_len])
        rand_start = 2 + server_len
        self.rand_server = bytes(payload[rand_start:rand_start + 32])
        list_pos = rand_start + 32
        list_len = int.from_bytes(payload[list_pos:list_pos + 2], "big")
        cipher_list = payload[list_pos + 2:list_pos + 2 + list_len]
        if len(cipher_list) != list_len or list_len == 0 or list_len % 6:
            raise EapGpskClientError("invalid EAP-GPSK ciphersuite list")
        selected = None
        for pos in range(0, list_len, 6):
            if (cipher_list[pos:pos + 4] == b"\x00\x00\x00\x00" and
                    int.from_bytes(cipher_list[pos + 4:pos + 6], "big") ==
                    self.cipher_specifier):
                selected = cipher_list[pos:pos + 6]
                break
        if selected is None:
            raise EapGpskClientError("requested EAP-GPSK ciphersuite unavailable")
        self.cipher_list = bytes(cipher_list)
        self.rand_peer = os.urandom(32)
        _, self.msk, _, self.sk, self.pk = derive_keys(
            self.password, self.rand_peer, self.rand_server,
            self.identity, self.id_server, self.cipher_specifier)
        body = (bytes((EAP_GPSK_OPCODE_GPSK_2,)) +
                len(self.identity).to_bytes(2, "big") + self.identity +
                len(self.id_server).to_bytes(2, "big") + self.id_server +
                self.rand_peer + self.rand_server +
                len(self.cipher_list).to_bytes(2, "big") + self.cipher_list +
                selected + b"\x00\x00")
        mic = _mac(self.sk, body[1:], self.cipher_specifier)
        self.state = "GPSK_3"
        return self._eap_response(identifier, bytes((EAP_GPSK,)) + body + mic)

    def _handle_gpsk_3(self, identifier: int, eap: bytes) -> bytes:
        if (self.state != "GPSK_3" or self.rand_peer is None or
                self.rand_server is None or self.id_server is None or
                self.sk is None):
            raise EapGpskClientError("unexpected EAP-GPSK GPSK-3")
        payload = eap[6:]
        if len(payload) < 32 + 32 + 2 + 6 + 2 + self.mic_len:
            raise EapGpskClientError("truncated EAP-GPSK GPSK-3")
        pos = 0
        if payload[pos:pos + 32] != self.rand_peer:
            raise EapGpskClientError("EAP-GPSK peer random mismatch")
        pos += 32
        if payload[pos:pos + 32] != self.rand_server:
            raise EapGpskClientError("EAP-GPSK server random mismatch")
        pos += 32
        server_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        if payload[pos:pos + server_len] != self.id_server:
            raise EapGpskClientError("EAP-GPSK server identity mismatch")
        pos += server_len
        if payload[pos:pos + 6] != (b"\x00\x00\x00\x00" +
                                    self.cipher_specifier.to_bytes(2, "big")):
            raise EapGpskClientError("EAP-GPSK ciphersuite mismatch")
        pos += 6
        pd_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + pd_len
        if pos + self.mic_len != len(payload):
            raise EapGpskClientError("invalid EAP-GPSK GPSK-3 payload")
        if not hmac.compare_digest(
                _mac(self.sk, payload[:pos], self.cipher_specifier),
                payload[pos:]):
            raise EapGpskClientError("EAP-GPSK GPSK-3 MIC mismatch")
        body = bytes((EAP_GPSK_OPCODE_GPSK_4, 0, 0))
        self.state = "SUCCESS_PENDING"
        return self._eap_response(
            identifier, bytes((EAP_GPSK,)) + body +
            _mac(self.sk, body[1:], self.cipher_specifier))

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
            except EapGpskClientError as error:
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
            if eap_type != EAP_GPSK or len(eap) < 6:
                raise EapGpskClientError("unsupported EAP method")
            self.last_gpsk_opcode = eap[5]
            if eap[5] == EAP_GPSK_OPCODE_GPSK_1:
                response = self._handle_gpsk_1(identifier, eap)
            elif eap[5] == EAP_GPSK_OPCODE_GPSK_3:
                response = self._handle_gpsk_3(identifier, eap)
            else:
                raise EapGpskClientError("unsupported EAP-GPSK opcode")
            return [response]
        except EapGpskClientError as error:
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
        except EapGpskClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_GPSK", "EAP_GPSK_CIPHER_AES", "EAP_GPSK_CIPHER_SHA256",
           "EapGpskClient", "EapGpskClientError", "derive_keys"]
