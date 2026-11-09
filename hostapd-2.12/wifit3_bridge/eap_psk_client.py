from __future__ import annotations

import hmac
import os

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

from .bip import aes_cmac
from .ccmp import _aes_encrypt, _expand_key


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_PSK = 47
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_PSK_R_FLAG_CONT = 1
EAP_PSK_R_FLAG_DONE_SUCCESS = 2
EAP_PSK_R_FLAG_DONE_FAILURE = 3
EAP_PSK_E_FLAG = 0x20
EAP_PSK_LENGTH = 16
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapPskClientError(ValueError):
    pass


def key_setup(psk: bytes) -> tuple[bytes, bytes]:
    if not isinstance(psk, bytes) or len(psk) != EAP_PSK_LENGTH:
        raise EapPskClientError("EAP-PSK requires a 16-octet key")
    expanded = _expand_key(psk)
    base = _aes_encrypt(expanded, bytes(16))
    ak_input = base[:-1] + bytes((base[-1] ^ 1,))
    kdk_input = base[:-1] + bytes((base[-1] ^ 2,))
    return _aes_encrypt(expanded, ak_input), _aes_encrypt(expanded, kdk_input)


def derive_keys(kdk: bytes, rand_p: bytes) -> tuple[bytes, bytes, bytes]:
    if not isinstance(kdk, bytes) or len(kdk) != EAP_PSK_LENGTH:
        raise EapPskClientError("KDK must be 16 bytes")
    if not isinstance(rand_p, bytes) or len(rand_p) != EAP_PSK_LENGTH:
        raise EapPskClientError("RAND_P must be 16 bytes")
    expanded = _expand_key(kdk)
    block = bytearray(_aes_encrypt(expanded, rand_p))
    output = []
    for counter in range(1, 10):
        block[-1] ^= counter
        output.append(_aes_encrypt(expanded, bytes(block)))
        block[-1] ^= counter
    return output[0], b"".join(output[1:5]), b"".join(output[5:9])


def _eax_encrypt(key: bytes, nonce: bytes, header: bytes,
                 plaintext: bytes) -> tuple[bytes, bytes]:
    if len(nonce) != 16:
        raise EapPskClientError("EAX nonce must be 16 bytes")
    expanded = _expand_key(key)
    nonce_mac = aes_cmac(key, bytes(15) + b"\x00" + nonce)
    header_mac = aes_cmac(key, bytes(15) + b"\x01" + header)
    ciphertext = bytearray()
    counter = int.from_bytes(nonce_mac, "big")
    for offset in range(0, len(plaintext), 16):
        block = plaintext[offset:offset + 16]
        stream = _aes_encrypt(expanded, counter.to_bytes(16, "big"))
        ciphertext.extend(a ^ b for a, b in zip(block, stream))
        counter = (counter + 1) & ((1 << 128) - 1)
    data_mac = aes_cmac(key, bytes(15) + b"\x02" + bytes(ciphertext))
    tag = bytes(a ^ b ^ c for a, b, c in zip(
        nonce_mac, header_mac, data_mac))
    return bytes(ciphertext), tag


def _eax_decrypt(key: bytes, nonce: bytes, header: bytes,
                 ciphertext: bytes, tag: bytes) -> bytes:
    nonce_mac = aes_cmac(key, bytes(15) + b"\x00" + nonce)
    header_mac = aes_cmac(key, bytes(15) + b"\x01" + header)
    data_mac = aes_cmac(key, bytes(15) + b"\x02" + ciphertext)
    expected = bytes(a ^ b ^ c for a, b, c in zip(
        nonce_mac, header_mac, data_mac))
    if not hmac.compare_digest(expected, tag):
        raise EapPskClientError("EAP-PSK protected channel tag mismatch")
    expanded = _expand_key(key)
    result = bytearray()
    counter = int.from_bytes(nonce_mac, "big")
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        stream = _aes_encrypt(expanded, counter.to_bytes(16, "big"))
        result.extend(a ^ b for a, b in zip(block, stream))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(result)


class EapPskClient:
    eap_type = EAP_PSK

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
        if not isinstance(password, bytes) or len(password) != EAP_PSK_LENGTH:
            raise ValueError("EAP-PSK requires a 16-octet key")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = bytes(password)
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()
        self.ak, self.kdk = key_setup(self.password)
        self.state = "IDENTITY"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.server_id: bytes | None = None
        self.rand_s: bytes | None = None
        self.rand_p: bytes | None = None
        self.tek: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapPskClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapPskClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapPskClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapPskClientError("truncated EAPOL frame")
        return bytes(frame[eapol + 4:end])

    def _eapol_frame(self, eap: bytes) -> bytes:
        eapol = (bytes((EAPOL_VERSION, EAPOL_TYPE_EAP)) +
                 len(eap).to_bytes(2, "big") + eap)
        return (data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) +
                LLC_SNAP_EAPOL + eapol)

    def _eap_response(self, identifier: int, payload: bytes) -> bytes:
        return (bytes((EAP_RESPONSE, identifier)) +
                (4 + len(payload)).to_bytes(2, "big") + payload)

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapPskClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-psk-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _handle_identity(self, identifier: int) -> bytes:
        return self._eap_response(identifier,
                                  bytes((EAP_IDENTITY,)) + self.identity)

    def _handle_psk_1(self, identifier: int, eap: bytes) -> bytes:
        payload = eap[5:]
        if self.state != "IDENTITY" or len(payload) < 18:
            raise EapPskClientError("invalid EAP-PSK first message")
        if payload[0] >> 6 != 0:
            raise EapPskClientError("unexpected EAP-PSK first-message flags")
        self.rand_s = bytes(payload[1:17])
        self.server_id = bytes(payload[17:])
        if not self.server_id:
            raise EapPskClientError("EAP-PSK server identity is empty")
        self.rand_p = os.urandom(EAP_PSK_LENGTH)
        mac_p = aes_cmac(
            self.ak, self.identity + self.server_id + self.rand_s + self.rand_p)
        self.state = "PSK_2"
        return self._eap_response(
            identifier,
            bytes((EAP_PSK, 0x40)) + self.rand_s + self.rand_p + mac_p +
            self.identity)

    def _handle_psk_3(self, identifier: int, eap: bytes) -> bytes:
        payload = eap[5:]
        if self.state != "PSK_2" or self.rand_s is None or self.rand_p is None:
            raise EapPskClientError("unexpected EAP-PSK third message")
        if len(payload) < 54 or payload[0] >> 6 != 2:
            raise EapPskClientError("invalid EAP-PSK third message")
        if payload[1:17] != self.rand_s:
            raise EapPskClientError("EAP-PSK server random mismatch")
        mac_s = aes_cmac(self.ak, self.server_id + self.rand_p)
        if not hmac.compare_digest(mac_s, payload[17:33]):
            raise EapPskClientError("EAP-PSK server MAC mismatch")
        pchannel = payload[33:]
        nonce_value = pchannel[:4]
        nonce = b"\x00" * 12 + nonce_value
        tag = pchannel[4:20]
        encrypted = pchannel[20:]
        self.tek, self.msk, _ = derive_keys(self.kdk, self.rand_p)
        plaintext = _eax_decrypt(self.tek, nonce, eap[:22], encrypted, tag)
        if not plaintext:
            raise EapPskClientError("empty EAP-PSK protected channel")
        if plaintext[0] & EAP_PSK_E_FLAG:
            raise EapPskClientError("EAP-PSK extensions are unsupported")
        if plaintext[0] >> 6 != EAP_PSK_R_FLAG_DONE_SUCCESS:
            raise EapPskClientError("EAP-PSK server rejected authentication")
        next_nonce = (int.from_bytes(nonce_value, "big") + 1) & 0xffffffff
        response_len = 4 + 1 + 17 + 21
        prefix = (bytes((EAP_RESPONSE, identifier)) +
                  response_len.to_bytes(2, "big") +
                  bytes((EAP_PSK, 0xc0)) + self.rand_s)
        next_nonce_bytes = next_nonce.to_bytes(4, "big")
        next_nonce_full = b"\x00" * 12 + next_nonce_bytes
        encrypted_reply, reply_tag = _eax_encrypt(
            self.tek, next_nonce_full, prefix[:22], b"\x80")
        self.state = "SUCCESS_PENDING"
        return prefix + next_nonce_bytes + reply_tag + encrypted_reply

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
            except EapPskClientError as error:
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
                return [self._handle_identity(identifier)]
            if eap_type != EAP_PSK:
                raise EapPskClientError(f"unsupported EAP method {eap_type}")
            if len(eap) < 6:
                raise EapPskClientError("truncated EAP-PSK request")
            exchange = eap[5] >> 6
            if exchange == 0:
                response = self._handle_psk_1(identifier, eap)
            elif exchange == 2:
                response = self._handle_psk_3(identifier, eap)
            else:
                raise EapPskClientError("unsupported EAP-PSK exchange")
            return [response]
        except EapPskClientError as error:
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
        except EapPskClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_PSK", "EapPskClient", "EapPskClientError",
           "derive_keys", "key_setup"]
