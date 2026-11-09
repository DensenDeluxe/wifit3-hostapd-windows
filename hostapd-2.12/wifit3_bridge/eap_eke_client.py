from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_EKE = 53
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_EKE_ID = 1
EAP_EKE_COMMIT = 2
EAP_EKE_CONFIRM = 3
EAP_EKE_FAILURE = 4
EAP_EKE_DHGROUP_EKE_2 = 1
EAP_EKE_DHGROUP_EKE_5 = 2
EAP_EKE_DHGROUP_EKE_14 = 3
EAP_EKE_DHGROUP_EKE_15 = 4
EAP_EKE_DHGROUP_EKE_16 = 5
EAP_EKE_ENCR_AES128_CBC = 1
EAP_EKE_PRF_HMAC_SHA1 = 1
EAP_EKE_PRF_HMAC_SHA2_256 = 2
EAP_EKE_MAC_HMAC_SHA1 = 1
EAP_EKE_MAC_HMAC_SHA2_256 = 2
EAP_EKE_ID_NAI = 2
EAP_EKE_MAX_NONCE_LEN = 16
EAP_MSK_LEN = 64
EAP_EMSK_LEN = 64

_GROUP14 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)


class EapEkeClientError(ValueError):
    pass


def _hash_name(identifier: int) -> str:
    if identifier == EAP_EKE_PRF_HMAC_SHA1:
        return "sha1"
    if identifier == EAP_EKE_PRF_HMAC_SHA2_256:
        return "sha256"
    raise EapEkeClientError("unsupported EAP-EKE PRF")


def _mac_hash_name(identifier: int) -> str:
    if identifier == EAP_EKE_MAC_HMAC_SHA1:
        return "sha1"
    if identifier == EAP_EKE_MAC_HMAC_SHA2_256:
        return "sha256"
    raise EapEkeClientError("unsupported EAP-EKE MAC")


def _prf_len(identifier: int) -> int:
    return hashlib.new(_hash_name(identifier)).digest_size


def _dh_len(group: int) -> int:
    lengths = {
        EAP_EKE_DHGROUP_EKE_2: 128,
        EAP_EKE_DHGROUP_EKE_5: 192,
        EAP_EKE_DHGROUP_EKE_14: 256,
        EAP_EKE_DHGROUP_EKE_15: 384,
        EAP_EKE_DHGROUP_EKE_16: 512,
    }
    try:
        return lengths[group]
    except KeyError as error:
        raise EapEkeClientError("unsupported EAP-EKE DH group") from error


def _dh_generator(group: int) -> int:
    generators = {
        EAP_EKE_DHGROUP_EKE_2: 5,
        EAP_EKE_DHGROUP_EKE_5: 31,
        EAP_EKE_DHGROUP_EKE_14: 11,
        EAP_EKE_DHGROUP_EKE_15: 5,
        EAP_EKE_DHGROUP_EKE_16: 5,
    }
    try:
        return generators[group]
    except KeyError as error:
        raise EapEkeClientError("unsupported EAP-EKE DH group") from error


def dh_parameters(group: int) -> tuple[int, int, int]:
    if group != EAP_EKE_DHGROUP_EKE_14:
        raise EapEkeClientError("EAP-EKE OTA client supports DH group 14")
    return _GROUP14, _dh_generator(group), _dh_len(group)


def prf_plus(prf: str, key: bytes, data: bytes, length: int) -> bytes:
    if prf not in ("sha1", "sha256"):
        raise EapEkeClientError("unsupported EAP-EKE PRF")
    if not key or not isinstance(data, bytes) or not 0 < length <= 4096:
        raise EapEkeClientError("invalid EAP-EKE PRF+ input")
    digest = getattr(hashlib, prf)
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        if counter == 1:
            previous = hmac.new(key, data + bytes((counter,)), digest).digest()
        else:
            previous = hmac.new(
                key, previous + data + bytes((counter,)), digest).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


@dataclass
class EapEkeSession:
    dhgroup: int
    encr: int
    prf: int
    mac: int
    shared_secret: bytes = b""
    ke: bytes = b""
    ki: bytes = b""
    ka: bytes = b""

    def __post_init__(self) -> None:
        if self.encr != EAP_EKE_ENCR_AES128_CBC:
            raise EapEkeClientError("unsupported EAP-EKE encryption")
        self.prf_len = _prf_len(self.prf)
        self.nonce_len = 16 if self.prf_len <= 32 else (self.prf_len + 1) // 2
        self.auth_len = self.prf_len
        self.dhcomp_len = 16 + _dh_len(self.dhgroup)
        self.mac_len = hashlib.new(_mac_hash_name(self.mac)).digest_size
        self.pnonce_len = 16 + 16 + self.mac_len
        self.pnonce_ps_len = 16 + 32 + self.mac_len


def derive_key(session: EapEkeSession, password: bytes, id_s: bytes,
               id_p: bytes) -> bytes:
    zeros = bytes(session.prf_len)
    temp = hmac.new(zeros, password, _hash_name(session.prf)).digest()
    return prf_plus(_hash_name(session.prf), temp, id_s + id_p, 16)


def dh_component(session: EapEkeSession, key: bytes, public: bytes,
                 *, iv: bytes | None = None) -> bytes:
    if len(key) != 16 or len(public) != _dh_len(session.dhgroup):
        raise EapEkeClientError("invalid EAP-EKE DHComponent input")
    iv = secrets.token_bytes(16) if iv is None else bytes(iv)
    if len(iv) != 16:
        raise EapEkeClientError("invalid EAP-EKE DHComponent IV")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(public) + encryptor.finalize()
    return iv + ciphertext


def dh_shared_secret(session: EapEkeSession, key: bytes, private: int,
                     peer_component: bytes) -> bytes:
    prime, _, length = dh_parameters(session.dhgroup)
    if len(key) != 16 or len(peer_component) != 16 + length:
        raise EapEkeClientError("invalid EAP-EKE peer DHComponent")
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(peer_component[:16])
    ).decryptor()
    peer_public = decryptor.update(peer_component[16:]) + decryptor.finalize()
    peer_value = int.from_bytes(peer_public, "big")
    if not 2 <= peer_value <= prime - 2:
        raise EapEkeClientError("invalid EAP-EKE peer public value")
    shared = pow(peer_value, private, prime).to_bytes(length, "big")
    return hmac.new(bytes(session.auth_len), shared,
                    _hash_name(session.prf)).digest()


def derive_ke_ki(session: EapEkeSession, id_s: bytes, id_p: bytes) -> tuple[bytes, bytes]:
    material = prf_plus(
        _hash_name(session.prf), session.shared_secret,
        b"EAP-EKE Keys" + id_s + id_p, 16 + session.mac_len)
    session.ke = material[:16]
    session.ki = material[16:]
    return session.ke, session.ki


def derive_ka(session: EapEkeSession, id_s: bytes, id_p: bytes,
              nonce_p: bytes, nonce_s: bytes) -> bytes:
    session.ka = prf_plus(
        _hash_name(session.prf), session.shared_secret,
        b"EAP-EKE Ka" + id_s + id_p + nonce_p + nonce_s,
        session.prf_len)
    return session.ka


def derive_msk(session: EapEkeSession, id_s: bytes, id_p: bytes,
               nonce_first: bytes, nonce_second: bytes) -> tuple[bytes, bytes]:
    material = prf_plus(
        _hash_name(session.prf), session.shared_secret,
        b"EAP-EKE Exported Keys" + id_s + id_p + nonce_first + nonce_second,
        EAP_MSK_LEN + EAP_EMSK_LEN)
    return material[:EAP_MSK_LEN], material[EAP_MSK_LEN:]


def auth(session: EapEkeSession, ka: bytes, label: str, messages: bytes) -> bytes:
    return hmac.new(ka, label.encode("ascii") + messages,
                    _hash_name(session.prf)).digest()


def protect(session: EapEkeSession, data: bytes, *, iv: bytes | None = None,
            padding: bytes | None = None) -> bytes:
    pad_len = (-len(data)) % 16
    if padding is None:
        padding = secrets.token_bytes(pad_len)
    if len(padding) != pad_len:
        raise EapEkeClientError("invalid EAP-EKE padding")
    iv = secrets.token_bytes(16) if iv is None else bytes(iv)
    if len(iv) != 16:
        raise EapEkeClientError("invalid EAP-EKE protected IV")
    plaintext = data + padding
    encryptor = Cipher(algorithms.AES(session.ke), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    integrity = hmac.new(session.ki, ciphertext,
                         _mac_hash_name(session.mac)).digest()
    return iv + ciphertext + integrity


def decrypt_protected(session: EapEkeSession, protected: bytes) -> bytes:
    if len(protected) < 32 + session.mac_len or (len(protected) - session.mac_len) % 16:
        raise EapEkeClientError("invalid EAP-EKE protected data length")
    ciphertext = protected[16:-session.mac_len]
    expected = hmac.new(session.ki, ciphertext,
                        _mac_hash_name(session.mac)).digest()
    if not hmac.compare_digest(expected, protected[-session.mac_len:]):
        raise EapEkeClientError("EAP-EKE protected data integrity failure")
    decryptor = Cipher(
        algorithms.AES(session.ke), modes.CBC(protected[:16])
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


class EapEkeClient:
    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: str,
                 rsn_ie: bytes,
                 pmf_cipher: str = "AES-128-CMAC"):
        if len(ap_mac) != 6 or len(sta_mac) != 6 or ap_mac == sta_mac:
            raise ValueError("AP and station MACs must be distinct six-octet values")
        if isinstance(ssid, str):
            ssid = ssid.encode()
        if not ssid or not identity or not password:
            raise ValueError("EAP-EKE identity, password, and SSID are required")
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
        self.last_eap_exchange: int | None = None
        self.server_id = b""
        self.session: EapEkeSession | None = None
        self.private: int | None = None
        self.nonce_p = b""
        self.nonce_s = b""
        self.messages = bytearray()
        self.eap_trace: list[tuple[int, int, int, int]] = []
        self._request_cache: dict[bytes, list[bytes]] = {}

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapEkeClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapEkeClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapEkeClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapEkeClientError("truncated EAPOL frame")
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

    def _append_messages(self, request: bytes, response: bytes) -> None:
        self.messages.extend(request)
        response_body = self._eap_body(response)
        eapol_start = response.find(LLC_SNAP_EAPOL, 24, min(len(response), 48))
        eap_start = eapol_start + len(LLC_SNAP_EAPOL) + 4
        self.messages.extend(response[eap_start:eap_start + int.from_bytes(
            response[eapol_start + len(LLC_SNAP_EAPOL) + 2:
            eapol_start + len(LLC_SNAP_EAPOL) + 4], "big")])

    def _id_response(self, identifier: int, request: bytes, payload: bytes) -> list[bytes]:
        if len(payload) < 8:
            raise EapEkeClientError("truncated EAP-EKE identity request")
        count = payload[1]
        if len(payload) < 3 + count * 4 + 1:
            raise EapEkeClientError("truncated EAP-EKE proposals")
        selected = None
        for offset in range(3, 3 + count * 4, 4):
            proposal = bytes(payload[offset:offset + 4])
            if proposal == bytes((EAP_EKE_DHGROUP_EKE_14,
                                  EAP_EKE_ENCR_AES128_CBC,
                                  EAP_EKE_PRF_HMAC_SHA1,
                                  EAP_EKE_MAC_HMAC_SHA1)):
                selected = proposal
                break
        if selected is None:
            raise EapEkeClientError("no supported EAP-EKE proposal")
        server_offset = 3 + count * 4
        self.server_id = bytes(payload[server_offset + 1:])
        self.session = EapEkeSession(selected[0], selected[1], selected[2], selected[3])
        body = bytes((EAP_EKE, EAP_EKE_ID, 1, 0)) + selected + bytes((EAP_EKE_ID_NAI,)) + self.identity
        response = self._eap_response(identifier, body)
        self._append_messages(request, response)
        self.state = "COMMIT"
        return [response]

    def _commit_response(self, identifier: int, request: bytes, payload: bytes) -> list[bytes]:
        if self.session is None or len(payload) < 1 + self.session.dhcomp_len:
            raise EapEkeClientError("truncated EAP-EKE commit request")
        if self.state != "COMMIT":
            raise EapEkeClientError("unexpected EAP-EKE commit request")
        session = self.session
        key = derive_key(session, self.password, self.server_id, self.identity)
        prime, generator, length = dh_parameters(session.dhgroup)
        self.private = secrets.randbelow(prime - 3) + 2
        public = pow(generator, self.private, prime).to_bytes(length, "big")
        session.shared_secret = dh_shared_secret(
            session, key, self.private, payload[1:1 + session.dhcomp_len])
        derive_ke_ki(session, self.server_id, self.identity)
        self.nonce_p = secrets.token_bytes(session.nonce_len)
        response_payload = (
            bytes((EAP_EKE, EAP_EKE_COMMIT)) +
            dh_component(session, key, public) + protect(session, self.nonce_p)
        )
        response = self._eap_response(identifier, response_payload)
        self._append_messages(request, response)
        self.state = "CONFIRM"
        return [response]

    def _confirm_response(self, identifier: int, request: bytes, payload: bytes) -> list[bytes]:
        if self.session is None or self.state != "CONFIRM":
            raise EapEkeClientError("unexpected EAP-EKE confirm request")
        session = self.session
        if len(payload) < 1 + session.pnonce_ps_len + session.prf_len:
            raise EapEkeClientError("truncated EAP-EKE confirm request")
        protected = payload[1:1 + session.pnonce_ps_len]
        nonces = decrypt_protected(session, protected)
        if len(nonces) < 2 * session.nonce_len:
            raise EapEkeClientError("invalid EAP-EKE nonce payload")
        if not hmac.compare_digest(nonces[:session.nonce_len], self.nonce_p):
            raise EapEkeClientError("EAP-EKE peer nonce mismatch")
        self.nonce_s = bytes(nonces[session.nonce_len:2 * session.nonce_len])
        ka = derive_ka(session, self.server_id, self.identity,
                       self.nonce_p, self.nonce_s)
        expected = auth(session, ka, "EAP-EKE server", bytes(self.messages))
        received = payload[1 + session.pnonce_ps_len:1 + session.pnonce_ps_len + session.prf_len]
        if not hmac.compare_digest(expected, received):
            raise EapEkeClientError("EAP-EKE server authentication mismatch")
        response_payload = bytes((EAP_EKE, EAP_EKE_CONFIRM)) + protect(session, self.nonce_s)
        response_payload += auth(session, ka, "EAP-EKE peer", bytes(self.messages))
        response = self._eap_response(identifier, response_payload)
        self.msk, self.emsk = derive_msk(
            session, self.server_id, self.identity, self.nonce_s, self.nonce_p)
        self._append_messages(request, response)
        self.state = "SUCCESS"
        return [response]

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
                self.last_error = "EAP-EKE MSK is not available"
                self.state = "FAILURE"
                return []
            from .wpa2_client import Wpa2PskClient
            self.pmk = self.msk[:32]
            self.wpa_client = Wpa2PskClient(
                self.ap_mac, self.sta_mac, self.ssid, "eke-lab-pass",
                rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
                pmf_cipher=self.pmf_cipher)
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
        if eap_type != EAP_EKE or len(eap) < 6:
            self.last_error = f"unsupported EAP method {eap_type}"
            return []
        exchange = eap[5]
        self.last_eap_exchange = exchange
        if len(self.eap_trace) < 32:
            self.eap_trace.append((identifier, exchange, len(eap), self.state))
        cached = self._request_cache.get(bytes(eap))
        if cached is not None:
            return list(cached)
        payload = eap[5:]
        try:
            if exchange == EAP_EKE_ID:
                responses = self._id_response(identifier, eap, payload)
            elif exchange == EAP_EKE_COMMIT:
                responses = self._commit_response(identifier, eap, payload)
            elif exchange == EAP_EKE_CONFIRM:
                responses = self._confirm_response(identifier, eap, payload)
            elif exchange == EAP_EKE_FAILURE:
                self.state = "FAILURE"
                self.last_error = "EAP-EKE peer rejected"
                responses = []
            else:
                raise EapEkeClientError("unsupported EAP-EKE exchange")
        except (EapEkeClientError, ValueError) as error:
            self.last_error = str(error)
            self.state = "FAILURE"
            return []
        self._request_cache[bytes(eap)] = list(responses)
        return responses

    def handle_frame(self, frame: bytes) -> list[bytes]:
        self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        try:
            eap = self._eap_body(frame)
        except EapEkeClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return self._handle_eap(eap)

    def close(self) -> None:
        return None


__all__ = [
    "EAP_EKE_DHGROUP_EKE_14", "EAP_EKE_ENCR_AES128_CBC",
    "EAP_EKE_MAC_HMAC_SHA1", "EAP_EKE_MAC_HMAC_SHA2_256",
    "EAP_EKE_PRF_HMAC_SHA1", "EAP_EKE_PRF_HMAC_SHA2_256",
    "EapEkeClient", "EapEkeClientError", "EapEkeSession", "auth",
    "derive_key", "derive_ka", "derive_ke_ki", "derive_msk",
    "dh_component", "dh_parameters", "dh_shared_secret",
    "decrypt_protected", "prf_plus", "protect",
]
