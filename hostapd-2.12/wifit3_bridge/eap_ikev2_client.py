from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_IKEV2 = 49
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0

IKEV2_DH_GROUP2 = 2
IKEV2_ENCR_AES_CBC = 12
IKEV2_PRF_HMAC_SHA1 = 2
IKEV2_INTEG_HMAC_SHA1_96 = 2
IKEV2_PAYLOAD_NONE = 0
IKEV2_PAYLOAD_SA = 33
IKEV2_PAYLOAD_KE = 34
IKEV2_PAYLOAD_IDI = 35
IKEV2_PAYLOAD_IDR = 36
IKEV2_PAYLOAD_AUTH = 39
IKEV2_PAYLOAD_NONCE = 40
IKEV2_PAYLOAD_ENCRYPTED = 46
IKEV2_EXCHANGE_SA_INIT = 34
IKEV2_EXCHANGE_SA_AUTH = 35
IKEV2_HDR_INITIATOR = 0x08
IKEV2_HDR_RESPONSE = 0x20
IKEV2_VERSION = 0x20
IKEV2_ID_KEY_ID = 11
IKEV2_AUTH_SHARED_KEY_MIC = 2
IKEV2_INTEGRITY_LENGTH = 12
IKEV2_KEY_PAD = b"Key Pad for EAP-IKEv2"

IKEV2_DH_GROUP2_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)


class EapIkev2ClientError(ValueError):
    pass


def prf_plus(key: bytes, data: bytes, length: int) -> bytes:
    if not key or not isinstance(data, bytes) or not 0 < length <= 4096:
        raise EapIkev2ClientError("invalid IKEv2 PRF+ input")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        message = data + bytes((counter,)) if counter == 1 else previous + data + bytes((counter,))
        previous = hmac.new(key, message, hashlib.sha1).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive_ikev2_keys(
    nonce_i: bytes,
    nonce_r: bytes,
    spi_i: bytes,
    spi_r: bytes,
    shared_secret: bytes,
    prf: int = IKEV2_PRF_HMAC_SHA1,
    integ: int = IKEV2_INTEG_HMAC_SHA1_96,
    encr: int = IKEV2_ENCR_AES_CBC,
) -> dict[str, bytes]:
    if prf != IKEV2_PRF_HMAC_SHA1 or integ != IKEV2_INTEG_HMAC_SHA1_96 or encr != IKEV2_ENCR_AES_CBC:
        raise EapIkev2ClientError("unsupported IKEv2 proposal")
    if len(spi_i) != 8 or len(spi_r) != 8 or len(shared_secret) != 128:
        raise EapIkev2ClientError("invalid IKEv2 key schedule input")
    skeyseed = hmac.new(nonce_i + nonce_r, shared_secret, hashlib.sha1).digest()
    material = prf_plus(skeyseed, nonce_i + nonce_r + spi_i + spi_r, 132)
    offsets = (20, 20, 20, 16, 16, 20, 20)
    names = ("sk_d", "sk_ai", "sk_ar", "sk_ei", "sk_er", "sk_pi", "sk_pr")
    result: dict[str, bytes] = {}
    offset = 0
    for name, size in zip(names, offsets):
        result[name] = material[offset:offset + size]
        offset += size
    return result


def _payload(next_payload: int, body: bytes) -> bytes:
    return bytes((next_payload, 0)) + struct.pack("!H", 4 + len(body)) + body


def build_sa_payload(next_payload: int | None = None) -> bytes:
    proposal = bytearray((0, 0, 0, 0, 1, 1, 0, 4))
    transforms = bytearray()
    transforms.extend(bytes((3, 0)) + struct.pack("!H", 12) + bytes((1, 0)) + struct.pack("!H", IKEV2_ENCR_AES_CBC) + struct.pack("!HH", 0x800E, 128))
    transforms.extend(bytes((3, 0)) + struct.pack("!H", 8) + bytes((2, 0)) + struct.pack("!H", IKEV2_PRF_HMAC_SHA1))
    transforms.extend(bytes((3, 0)) + struct.pack("!H", 8) + bytes((3, 0)) + struct.pack("!H", IKEV2_INTEG_HMAC_SHA1_96))
    transforms.extend(bytes((0, 0)) + struct.pack("!H", 8) + bytes((4, 0)) + struct.pack("!H", IKEV2_DH_GROUP2))
    if next_payload is not None:
        proposal[2:4] = struct.pack("!H", len(proposal) + len(transforms))
    return _payload(0 if next_payload is None else next_payload, bytes(proposal) + bytes(transforms))


def _parse_payloads(next_payload: int, data: bytes) -> list[tuple[int, bytes]]:
    output: list[tuple[int, bytes]] = []
    offset = 0
    while next_payload != IKEV2_PAYLOAD_NONE:
        if offset + 4 > len(data):
            raise EapIkev2ClientError("truncated IKEv2 payload header")
        next_value, _, length = data[offset], data[offset + 1], int.from_bytes(data[offset + 2:offset + 4], "big")
        if length < 4 or offset + length > len(data):
            raise EapIkev2ClientError("invalid IKEv2 payload length")
        output.append((next_payload, bytes(data[offset + 4:offset + length])))
        if next_payload == IKEV2_PAYLOAD_ENCRYPTED:
            offset += length
            break
        next_payload = next_value
        offset += length
    if offset != len(data):
        raise EapIkev2ClientError("unexpected IKEv2 payload data")
    return output


def _ike_header(spi_i: bytes, spi_r: bytes, next_payload: int, exchange: int, flags: int, message_id: int, length: int) -> bytes:
    return spi_i + spi_r + bytes((next_payload, IKEV2_VERSION, exchange, flags)) + struct.pack("!II", message_id, length)


def _build_ke_payload(public: bytes, next_payload: int = IKEV2_PAYLOAD_NONCE) -> bytes:
    return _payload(next_payload, struct.pack("!HH", IKEV2_DH_GROUP2, 0) + public)


def _build_nonce_payload(nonce: bytes) -> bytes:
    return _payload(IKEV2_PAYLOAD_NONE, nonce)


def _build_id_payload(payload_type: int, identity: bytes, next_payload: int) -> bytes:
    return _payload(next_payload, bytes((IKEV2_ID_KEY_ID, 0, 0, 0)) + identity)


def _build_auth_payload(auth_data: bytes) -> bytes:
    return _payload(IKEV2_PAYLOAD_NONE, bytes((IKEV2_AUTH_SHARED_KEY_MIC, 0, 0, 0)) + auth_data)


def _derive_auth(shared_secret: bytes, sign_message: bytes, identity: bytes, sk_p: bytes, nonce: bytes) -> bytes:
    id_prime = bytes((IKEV2_ID_KEY_ID, 0, 0, 0)) + identity
    inner = hmac.new(sk_p, id_prime, hashlib.sha1).digest()
    key = hmac.new(shared_secret, IKEV2_KEY_PAD, hashlib.sha1).digest()
    return hmac.new(key, sign_message + nonce + inner, hashlib.sha1).digest()


def _encrypt_payload(
    header_prefix: bytes,
    plaintext: bytes,
    next_payload: int,
    key: bytes,
    integrity_key: bytes,
) -> bytes:
    pad_len = 16 - ((len(plaintext) + 1) % 16)
    if pad_len == 16:
        pad_len = 0
    padded = plaintext + bytes((pad_len,)) * pad_len + bytes((pad_len,))
    iv = secrets.token_bytes(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    encrypted_header = bytearray(_payload(next_payload, iv + ciphertext))
    encrypted_header[2:4] = (len(encrypted_header) + IKEV2_INTEGRITY_LENGTH).to_bytes(2, "big")
    message = header_prefix + bytes(encrypted_header)
    message = message[:24] + (len(message) + IKEV2_INTEGRITY_LENGTH).to_bytes(4, "big") + message[28:]
    icv = hmac.new(integrity_key, message, hashlib.sha1).digest()[:IKEV2_INTEGRITY_LENGTH]
    return message + icv


def _decrypt_payload(message: bytes, next_payload: int, payload: bytes, key: bytes, integrity_key: bytes) -> tuple[int, bytes]:
    if len(payload) < 16 + 16 + IKEV2_INTEGRITY_LENGTH:
        raise EapIkev2ClientError("truncated encrypted IKEv2 payload")
    expected = hmac.new(integrity_key, message[:-IKEV2_INTEGRITY_LENGTH], hashlib.sha1).digest()[:IKEV2_INTEGRITY_LENGTH]
    if not hmac.compare_digest(expected, message[-IKEV2_INTEGRITY_LENGTH:]):
        raise EapIkev2ClientError("IKEv2 payload integrity failure")
    encrypted = payload[:-IKEV2_INTEGRITY_LENGTH]
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    if not ciphertext or len(ciphertext) % 16:
        raise EapIkev2ClientError("invalid encrypted IKEv2 payload length")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    if pad_len >= len(padded):
        raise EapIkev2ClientError("invalid IKEv2 padding")
    if padded[-pad_len - 1:-1] != bytes(pad_len):
        raise EapIkev2ClientError("invalid IKEv2 padding bytes")
    return next_payload, padded[:len(padded) - pad_len - 1]


class EapIkev2Client:
    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str, *, identity: str, password: str, rsn_ie: bytes, pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not ssid or not identity or not password:
            raise ValueError("EAP-IKEv2 identity, password, and SSID are required")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = password.encode()
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
        self.server_sa_init = b""
        self.client_sa_init = b""
        self.client_sa_auth = b""
        self.spi_i = b""
        self.spi_r = b""
        self.nonce_i = b""
        self.nonce_r = b""
        self.shared_secret = b""
        self.private: int | None = None
        self.keys: dict[str, bytes] | None = None
        self._request_cache: dict[bytes, list[bytes]] = {}

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapIkev2ClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapIkev2ClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapIkev2ClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapIkev2ClientError("truncated EAPOL frame")
        return bytes(frame[eapol + 4:end])

    def _eapol_frame(self, eap: bytes) -> bytes:
        eapol = bytes((EAPOL_VERSION, EAPOL_TYPE_EAP)) + len(eap).to_bytes(2, "big") + eap
        return data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) + LLC_SNAP_EAPOL + eapol

    def _eap_response(self, identifier: int, payload: bytes) -> bytes:
        eap = bytes((EAP_RESPONSE, identifier)) + (4 + len(payload)).to_bytes(2, "big") + payload
        return self._eapol_frame(eap)

    def _eap_ike_response(self, identifier: int, method_data: bytes, integrity_key: bytes | None = None) -> bytes:
        body = bytes((EAP_IKEV2,)) + method_data
        if integrity_key is not None:
            length = 4 + len(body) + IKEV2_INTEGRITY_LENGTH
            eap = bytes((EAP_RESPONSE, identifier)) + length.to_bytes(2, "big") + body
            icv = hmac.new(integrity_key, eap, hashlib.sha1).digest()[:IKEV2_INTEGRITY_LENGTH]
            body += icv
        return self._eap_response(identifier, body)

    @staticmethod
    def _ike_parts(message: bytes) -> tuple[bytes, list[tuple[int, bytes]]]:
        if len(message) < 28:
            raise EapIkev2ClientError("truncated IKEv2 header")
        length = int.from_bytes(message[24:28], "big")
        if length != len(message) or message[18] not in (IKEV2_EXCHANGE_SA_INIT, IKEV2_EXCHANGE_SA_AUTH):
            raise EapIkev2ClientError("invalid IKEv2 header")
        return message[:28], _parse_payloads(message[16], message[28:])

    def _sa_init_response(self, message: bytes) -> bytes:
        header, payloads = self._ike_parts(message)
        fields = {payload_type: body for payload_type, body in payloads}
        if IKEV2_PAYLOAD_SA not in fields or IKEV2_PAYLOAD_KE not in fields or IKEV2_PAYLOAD_NONCE not in fields:
            raise EapIkev2ClientError("incomplete IKEv2 SA_INIT request")
        ke = fields[IKEV2_PAYLOAD_KE]
        if len(ke) != 132 or int.from_bytes(ke[:2], "big") != IKEV2_DH_GROUP2:
            raise EapIkev2ClientError("unsupported IKEv2 DH group")
        self.spi_i = header[:8]
        self.spi_r = secrets.token_bytes(8)
        self.nonce_i = fields[IKEV2_PAYLOAD_NONCE]
        self.nonce_r = secrets.token_bytes(16)
        peer_public = int.from_bytes(ke[4:], "big")
        if not 2 <= peer_public <= IKEV2_DH_GROUP2_PRIME - 2:
            raise EapIkev2ClientError("invalid IKEv2 peer public value")
        self.private = secrets.randbelow(IKEV2_DH_GROUP2_PRIME - 3) + 2
        public = pow(2, self.private, IKEV2_DH_GROUP2_PRIME).to_bytes(128, "big")
        self.shared_secret = pow(peer_public, self.private, IKEV2_DH_GROUP2_PRIME).to_bytes(128, "big")
        self.keys = derive_ikev2_keys(self.nonce_i, self.nonce_r, self.spi_i, self.spi_r, self.shared_secret)
        response_payloads = build_sa_payload(IKEV2_PAYLOAD_KE)
        response_payloads += _build_ke_payload(public)
        response_payloads += _build_nonce_payload(self.nonce_r)
        response = _ike_header(self.spi_i, self.spi_r, IKEV2_PAYLOAD_SA, IKEV2_EXCHANGE_SA_INIT, IKEV2_HDR_RESPONSE, 0, 28 + len(response_payloads)) + response_payloads
        self.server_sa_init = bytes(message)
        self.client_sa_init = response
        self.state = "SA_AUTH"
        return response

    def _sa_auth_response(self, message: bytes) -> bytes:
        if self.keys is None:
            raise EapIkev2ClientError("IKEv2 keys are not available")
        header, payloads = self._ike_parts(message)
        fields = {payload_type: body for payload_type, body in payloads}
        encrypted = fields.get(IKEV2_PAYLOAD_ENCRYPTED)
        if encrypted is None:
            raise EapIkev2ClientError("missing IKEv2 encrypted payload")
        next_payload, plaintext = _decrypt_payload(message, message[28], encrypted, self.keys["sk_ei"], self.keys["sk_ai"])
        inner = _parse_payloads(next_payload, plaintext)
        inner_fields = {payload_type: body for payload_type, body in inner}
        server_id_payload = inner_fields.get(IKEV2_PAYLOAD_IDI)
        server_auth_payload = inner_fields.get(IKEV2_PAYLOAD_AUTH)
        if server_id_payload is None or server_auth_payload is None or len(server_id_payload) < 4 or len(server_auth_payload) < 4:
            raise EapIkev2ClientError("incomplete IKEv2 SA_AUTH request")
        server_id = server_id_payload[4:]
        expected = _derive_auth(self.password, self.server_sa_init, server_id, self.keys["sk_pi"], self.nonce_r)
        if not hmac.compare_digest(expected, server_auth_payload[4:]):
            raise EapIkev2ClientError("server IKEv2 authentication mismatch")
        auth = _derive_auth(self.password, self.client_sa_init, self.identity, self.keys["sk_pr"], self.nonce_i)
        plaintext = _build_id_payload(IKEV2_PAYLOAD_IDR, self.identity, IKEV2_PAYLOAD_AUTH)
        plaintext += _build_auth_payload(auth)
        response_header = _ike_header(self.spi_i, self.spi_r, IKEV2_PAYLOAD_ENCRYPTED, IKEV2_EXCHANGE_SA_AUTH, IKEV2_HDR_RESPONSE, 1, 28)
        response = _encrypt_payload(response_header, plaintext, IKEV2_PAYLOAD_IDR, self.keys["sk_er"], self.keys["sk_ar"])
        self.client_sa_auth = response
        self.msk = prf_plus(self.keys["sk_d"], self.nonce_i + self.nonce_r, 128)[:64]
        self.emsk = prf_plus(self.keys["sk_d"], self.nonce_i + self.nonce_r, 128)[64:]
        self.state = "DONE"
        return response

    def _ike_response(self, identifier: int, method_data: bytes, request: bytes) -> list[bytes]:
        if not method_data:
            return [self._eap_ike_response(identifier, bytes((0,)))]
        flags = method_data[0]
        offset = 1
        if flags & 0x80:
            if len(method_data) < offset + 4:
                raise EapIkev2ClientError("truncated IKEv2 message length")
            offset += 4
        if flags & 0x40:
            raise EapIkev2ClientError("fragmented EAP-IKEv2 messages are not supported")
        end = len(method_data)
        if flags & 0x20:
            if end < offset + IKEV2_INTEGRITY_LENGTH:
                raise EapIkev2ClientError("truncated EAP-IKEv2 ICV")
            if self.keys is None:
                raise EapIkev2ClientError("EAP-IKEv2 ICV arrived before key setup")
            eap = request
            expected = hmac.new(self.keys["sk_ai"], eap[:-IKEV2_INTEGRITY_LENGTH], hashlib.sha1).digest()[:IKEV2_INTEGRITY_LENGTH]
            if not hmac.compare_digest(expected, eap[-IKEV2_INTEGRITY_LENGTH:]):
                raise EapIkev2ClientError("server EAP-IKEv2 ICV mismatch")
            end -= IKEV2_INTEGRITY_LENGTH
        ike = bytes(method_data[offset:end])
        if len(ike) >= 19 and ike[18] == IKEV2_EXCHANGE_SA_INIT and self.client_sa_init:
            return [self._eap_ike_response(identifier, bytes((0,)) + self.client_sa_init)]
        if len(ike) >= 19 and ike[18] == IKEV2_EXCHANGE_SA_AUTH and self.client_sa_auth:
            return [self._eap_ike_response(identifier, bytes((0x20,)) + self.client_sa_auth, self.keys["sk_ar"] if self.keys else None)]
        if self.state == "IDENTITY":
            response = self._sa_init_response(ike)
            return [self._eap_ike_response(identifier, bytes((0,)) + response)]
        if self.state == "SA_AUTH":
            response = self._sa_auth_response(ike)
            return [self._eap_ike_response(identifier, bytes((0x20,)) + response, self.keys["sk_ar"] if self.keys else None)]
        raise EapIkev2ClientError("unexpected EAP-IKEv2 state")

    def _handle_eap(self, eap: bytes) -> list[bytes]:
        if len(eap) < 4:
            return []
        code, identifier = eap[:2]
        self.last_eap_code = code
        length = int.from_bytes(eap[2:4], "big")
        if length < 4 or length > len(eap):
            self.last_error = "invalid EAP length"
            return []
        eap = eap[:length]
        if code == EAP_SUCCESS:
            if self.msk is None:
                self.last_error = "EAP-IKEv2 MSK is not available"
                self.state = "FAILURE"
                return []
            from .wpa2_client import Wpa2PskClient
            self.pmk = self.msk[:32]
            self.wpa_client = Wpa2PskClient(self.ap_mac, self.sta_mac, self.ssid, "ikev2-lab-pass", rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk, pmf_cipher=self.pmf_cipher)
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
            cached = self._request_cache.get(bytes(eap))
            if cached is not None:
                return []
            response = self._eap_response(identifier, bytes((EAP_IDENTITY,)) + self.identity)
            self._request_cache[bytes(eap)] = [response]
            return [response]
        if eap_type != EAP_IKEV2 or len(eap) < 6:
            self.last_error = f"unsupported EAP method {eap_type}"
            return []
        cached = self._request_cache.get(bytes(eap))
        if cached is not None:
            return list(cached)
        try:
            responses = self._ike_response(identifier, eap[5:], eap)
        except (EapIkev2ClientError, ValueError) as error:
            if self.last_error is None:
                self.last_error = str(error)
            self.state = "FAILURE"
            return []
        self._request_cache[bytes(eap)] = list(responses)
        return responses

    def handle_frame(self, frame: bytes) -> list[bytes]:
        if self.state != "FAILURE":
            self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        if self.wpa_client is not None:
            try:
                eap = self._eap_body(frame)
            except EapIkev2ClientError:
                return self.wpa_client.handle_frame(frame)
            if len(eap) >= 4 and eap[0] not in (EAP_REQUEST, EAP_SUCCESS, EAP_FAILURE):
                return self.wpa_client.handle_frame(frame)
        try:
            eap = self._eap_body(frame)
        except EapIkev2ClientError:
            return []
        return self._handle_eap(eap)

    def close(self) -> None:
        return None


__all__ = [
    "EAP_IKEV2", "EapIkev2Client", "EapIkev2ClientError",
    "IKEV2_DH_GROUP2", "IKEV2_DH_GROUP2_PRIME", "IKEV2_ENCR_AES_CBC",
    "IKEV2_INTEG_HMAC_SHA1_96", "IKEV2_PRF_HMAC_SHA1", "build_sa_payload",
    "derive_ikev2_keys", "prf_plus",
]
