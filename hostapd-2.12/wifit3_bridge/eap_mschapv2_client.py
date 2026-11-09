"""Scoped EAP-MSCHAPv2 station for the native wifit3 OTA lab path.

The module implements the EAP-MSCHAPv2 peer exchange and RFC 3079 key
derivation needed to hand the resulting MSK to the existing WPA-Enterprise
four-way state machine.  It is intentionally a small lab supplicant, not a
replacement for Windows WLAN AutoConfig.
"""
from __future__ import annotations

import hashlib
import os
import struct

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_MSCHAPV2 = 26
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0

# WPA2-Enterprise, CCMP, AKM 802.1X.
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapMschapv2ClientError(ValueError):
    """Malformed EAP-MSCHAPv2 data or an unusable key derivation."""


def _bytes(value: bytes | str, name: str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes or str")
    return value


def _md4(data: bytes) -> bytes:
    """Small dependency-free MD4 implementation used by MS-CHAPv2."""
    message = bytearray(data)
    bit_len = len(message) * 8
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message.extend(struct.pack("<Q", bit_len))

    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    def rol(value: int, shift: int) -> int:
        return ((value << shift) | (value >> (32 - shift))) & 0xffffffff

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    for offset in range(0, len(message), 64):
        x = list(struct.unpack("<16I", message[offset:offset + 64]))
        aa, bb, cc, dd = a, b, c, d

        for k in (0, 4, 8, 12):
            a = rol((a + f(b, c, d) + x[k]) & 0xffffffff, 3)
            d = rol((d + f(a, b, c) + x[k + 1]) & 0xffffffff, 7)
            c = rol((c + f(d, a, b) + x[k + 2]) & 0xffffffff, 11)
            b = rol((b + f(c, d, a) + x[k + 3]) & 0xffffffff, 19)

        for k in (0, 1, 2, 3):
            a = rol((a + g(b, c, d) + x[k] + 0x5a827999) & 0xffffffff, 3)
            d = rol((d + g(a, b, c) + x[k + 4] + 0x5a827999) & 0xffffffff, 5)
            c = rol((c + g(d, a, b) + x[k + 8] + 0x5a827999) & 0xffffffff, 9)
            b = rol((b + g(c, d, a) + x[k + 12] + 0x5a827999) & 0xffffffff, 13)

        for k in (0, 2, 1, 3):
            a = rol((a + h(b, c, d) + x[k] + 0x6ed9eba1) & 0xffffffff, 3)
            d = rol((d + h(a, b, c) + x[k + 8] + 0x6ed9eba1) & 0xffffffff, 9)
            c = rol((c + h(d, a, b) + x[k + 4] + 0x6ed9eba1) & 0xffffffff, 11)
            b = rol((b + h(c, d, a) + x[k + 12] + 0x6ed9eba1) & 0xffffffff, 15)

        a = (a + aa) & 0xffffffff
        b = (b + bb) & 0xffffffff
        c = (c + cc) & 0xffffffff
        d = (d + dd) & 0xffffffff

    return struct.pack("<4I", a, b, c, d)


def nt_password_hash(password: bytes | str) -> bytes:
    """Return NtPasswordHash from RFC 2759 section 8.3."""
    raw = _bytes(password, "password")
    try:
        utf16 = raw.decode("utf-8").encode("utf-16le")
    except UnicodeDecodeError as error:
        raise EapMschapv2ClientError("password is not valid UTF-8") from error
    if len(utf16) > 512:
        raise EapMschapv2ClientError("password is too long")
    return _md4(utf16)


def hash_nt_password_hash(password_hash: bytes) -> bytes:
    if len(password_hash) != 16:
        raise EapMschapv2ClientError("PasswordHash must be 16 bytes")
    return _md4(password_hash)


def _challenge_hash(peer_challenge: bytes, auth_challenge: bytes,
                    username: bytes) -> bytes:
    if len(peer_challenge) != 16 or len(auth_challenge) != 16:
        raise EapMschapv2ClientError("MS-CHAPv2 challenges must be 16 bytes")
    return hashlib.sha1(peer_challenge + auth_challenge + username).digest()[:8]


def _des_key(key7: bytes) -> bytes:
    if len(key7) != 7:
        raise EapMschapv2ClientError("DES key material must be 7 bytes")
    key = bytearray(8)
    key[0] = key7[0]
    key[1] = ((key7[0] << 7) | (key7[1] >> 1)) & 0xff
    key[2] = ((key7[1] << 6) | (key7[2] >> 2)) & 0xff
    key[3] = ((key7[2] << 5) | (key7[3] >> 3)) & 0xff
    key[4] = ((key7[3] << 4) | (key7[4] >> 4)) & 0xff
    key[5] = ((key7[4] << 3) | (key7[5] >> 5)) & 0xff
    key[6] = ((key7[5] << 2) | (key7[6] >> 6)) & 0xff
    key[7] = (key7[6] << 1) & 0xff
    for index, value in enumerate(key):
        value &= 0xfe
        if value.bit_count() % 2 == 0:
            value |= 1
        key[index] = value
    return bytes(key)


def _des_encrypt(challenge: bytes, key7: bytes) -> bytes:
    if len(challenge) != 8:
        raise EapMschapv2ClientError("DES challenge must be 8 bytes")
    des_key = _des_key(key7)
    cipher = Cipher(TripleDES(des_key * 3), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


def _challenge_response(challenge: bytes, password_hash: bytes) -> bytes:
    if len(password_hash) != 16:
        raise EapMschapv2ClientError("PasswordHash must be 16 bytes")
    return b"".join((
        _des_encrypt(challenge, password_hash[:7]),
        _des_encrypt(challenge, password_hash[7:14]),
        _des_encrypt(challenge, password_hash[14:16] + b"\x00" * 5),
    ))


def generate_nt_response(auth_challenge: bytes, peer_challenge: bytes,
                         username: bytes | str,
                         password: bytes | str) -> bytes:
    username_bytes = _bytes(username, "username")
    password_hash = nt_password_hash(password)
    challenge = _challenge_hash(peer_challenge, auth_challenge, username_bytes)
    return _challenge_response(challenge, password_hash)


def generate_authenticator_response(password: bytes | str,
                                    peer_challenge: bytes,
                                    auth_challenge: bytes,
                                    username: bytes | str,
                                    nt_response: bytes) -> bytes:
    password_hash = nt_password_hash(password)
    if len(nt_response) != 24:
        raise EapMschapv2ClientError("NT-Response must be 24 bytes")
    first = hashlib.sha1(
        hash_nt_password_hash(password_hash) + nt_response +
        b"Magic server to client signing constant").digest()
    challenge = _challenge_hash(
        peer_challenge, auth_challenge, _bytes(username, "username"))
    return hashlib.sha1(
        first + challenge + b"Pad to make it do more than one iteration").digest()


def get_master_key(password_hash_hash: bytes, nt_response: bytes) -> bytes:
    if len(password_hash_hash) != 16 or len(nt_response) != 24:
        raise EapMschapv2ClientError("invalid MS-CHAPv2 master-key inputs")
    return hashlib.sha1(
        password_hash_hash + nt_response + b"This is the MPPE Master Key"
    ).digest()[:16]


def get_asymmetric_start_key(master_key: bytes, *, send: bool,
                             server: bool = False) -> bytes:
    if len(master_key) != 16:
        raise EapMschapv2ClientError("MasterKey must be 16 bytes")
    magic_send = (
        b"On the client side, this is the send key; on the server side, "
        b"it is the receive key."
    )
    magic_receive = (
        b"On the client side, this is the receive key; on the server side, "
        b"it is the send key."
    )
    if len(magic_send) != 84 or len(magic_receive) != 84:
        raise AssertionError("RFC 3079 magic string length changed")
    if send:
        magic = magic_receive if server else magic_send
    else:
        magic = magic_send if server else magic_receive
    return hashlib.sha1(master_key + b"\x00" * 40 + magic + b"\xf2" * 40).digest()[:16]


def _msk_from_master_key(master_key: bytes) -> bytes:
    # EAP-MSCHAPv2 peer order is MasterSendKey | MasterReceiveKey.
    return (get_asymmetric_start_key(master_key, send=True) +
            get_asymmetric_start_key(master_key, send=False))


class EapMschapv2Client:
    """EAP-MSCHAPv2 peer plus WPA2-Enterprise CCMP station state."""

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: str,
                 rsn_ie: bytes = ENTERPRISE_RSN_IE,
                 pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not ssid or not isinstance(ssid, bytes):
            raise ValueError("SSID must be non-empty bytes")
        if not identity:
            raise ValueError("EAP identity is required")
        if not password:
            raise ValueError("MS-CHAPv2 password is required")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = password
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()

        self.state = "IDENTITY"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.msk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.auth_challenge: bytes | None = None
        self.peer_challenge: bytes | None = None
        self.nt_response: bytes | None = None
        self.authenticator_response: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapMschapv2ClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapMschapv2ClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapMschapv2ClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapMschapv2ClientError("truncated EAPOL frame")
        return bytes(frame[eapol + 4:end])

    def _eapol_frame(self, eap: bytes) -> bytes:
        eapol = (bytes((EAPOL_VERSION, EAPOL_TYPE_EAP)) +
                 len(eap).to_bytes(2, "big") + eap)
        return (data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) +
                LLC_SNAP_EAPOL + eapol)

    def _eap_response(self, identifier: int, payload: bytes) -> bytes:
        eap = (bytes((EAP_RESPONSE, identifier)) +
               (4 + len(payload)).to_bytes(2, "big") + payload)
        return self._eapol_frame(eap)

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapMschapv2ClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "mschapv2-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _challenge_response(self, identifier: int, eap: bytes) -> list[bytes]:
        if len(eap) < 10:
            raise EapMschapv2ClientError("truncated MS-CHAPv2 challenge")
        ms_id = eap[6]
        ms_len = int.from_bytes(eap[7:9], "big")
        end = 5 + ms_len
        if ms_len < 21 or end > len(eap):
            raise EapMschapv2ClientError("invalid MS-CHAPv2 challenge length")
        data = eap[9:end]
        if data[0] != 16 or len(data) < 17:
            raise EapMschapv2ClientError("invalid MS-CHAPv2 challenge value")
        self.auth_challenge = bytes(data[1:17])
        self.peer_challenge = os.urandom(16)
        self.nt_response = generate_nt_response(
            self.auth_challenge, self.peer_challenge,
            self.identity, self.password)
        self.authenticator_response = generate_authenticator_response(
            self.password, self.peer_challenge, self.auth_challenge,
            self.identity, self.nt_response)
        password_hash_hash = hash_nt_password_hash(nt_password_hash(self.password))
        master_key = get_master_key(password_hash_hash, self.nt_response)
        self.msk = _msk_from_master_key(master_key)
        self.state = "MSCHAPV2"
        username = self.identity
        payload = (bytes((EAP_MSCHAPV2, 2, ms_id)) +
                   (4 + 1 + 16 + 8 + 24 + 1 + len(username)).to_bytes(2, "big") +
                   bytes((49,)) + self.peer_challenge + b"\x00" * 8 +
                   self.nt_response + b"\x00" + username)
        return [self._eap_response(identifier, payload)]

    def _success_request(self, identifier: int, eap: bytes) -> list[bytes]:
        if len(eap) < 9:
            raise EapMschapv2ClientError("truncated MS-CHAPv2 success")
        ms_id = eap[6]
        ms_len = int.from_bytes(eap[7:9], "big")
        end = 5 + ms_len
        if ms_len < 4 or end > len(eap):
            raise EapMschapv2ClientError("invalid MS-CHAPv2 success length")
        message = eap[9:end]
        if self.authenticator_response is None:
            raise EapMschapv2ClientError("MS-CHAPv2 authenticator response is missing")
        expected = (b"S=" + self.authenticator_response.hex().upper().encode() +
                    b" M=OK")
        if message != expected:
            raise EapMschapv2ClientError("MS-CHAPv2 authenticator response mismatch")
        self.state = "MSCHAPV2_SUCCESS"
        return [self._eap_response(identifier, bytes((EAP_MSCHAPV2, 3)))]

    def _handle_eap(self, eap: bytes) -> list[bytes]:
        if len(eap) < 4:
            return []
        code, identifier = eap[:2]
        self.last_eap_code = code
        eap_len = int.from_bytes(eap[2:4], "big")
        if eap_len < 4 or eap_len > len(eap):
            self.last_error = "invalid EAP length"
            return []
        eap = eap[:eap_len]
        if code == EAP_SUCCESS:
            try:
                self._initialize_wpa()
            except EapMschapv2ClientError as error:
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
        if eap_type == EAP_IDENTITY:
            return [self._eap_response(identifier,
                                        bytes((EAP_IDENTITY,)) + self.identity)]
        if eap_type != EAP_MSCHAPV2 or len(eap) < 10:
            self.last_error = f"unsupported EAP method {eap_type}"
            return []
        op_code = eap[5]
        try:
            if op_code == 1:
                return self._challenge_response(identifier, eap)
            if op_code == 3:
                return self._success_request(identifier, eap)
            if op_code == 4:
                self.state = "FAILURE"
                self.last_error = "MS-CHAPv2 peer rejected"
                return []
            raise EapMschapv2ClientError(
                f"unsupported MS-CHAPv2 operation {op_code}")
        except EapMschapv2ClientError as error:
            self.last_error = str(error)
            self.state = "FAILURE"
            return []

    def handle_frame(self, frame: bytes) -> list[bytes]:
        """Consume an AP-to-station EAPOL frame and return station frames."""
        self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        try:
            eap = self._eap_body(frame)
        except EapMschapv2ClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return self._handle_eap(eap)

    def close(self) -> None:
        """Match the EAP-TLS lab-client interface; no external state to close."""


__all__ = [
    "EAP_MSCHAPV2", "EAP_RESPONSE", "ENTERPRISE_RSN_IE",
    "EapMschapv2Client", "EapMschapv2ClientError",
    "generate_authenticator_response", "generate_nt_response",
    "get_asymmetric_start_key", "get_master_key", "hash_nt_password_hash",
    "nt_password_hash",
]
