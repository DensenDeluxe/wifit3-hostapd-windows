from __future__ import annotations

import hashlib
import hmac
import secrets

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

from .sae_client import (
    SAE_CURVES,
    _curve_for_group,
    _point_add,
    _point_decode,
    _point_encode,
    _point_mul,
)


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_PWD = 52
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_PWD_DEFAULT_RAND_FUNC = 1
EAP_PWD_DEFAULT_PRF = 1
EAP_PWD_PREP_NONE = 0
EAP_PWD_ID_EXCH = 1
EAP_PWD_COMMIT_EXCH = 2
EAP_PWD_CONFIRM_EXCH = 3
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapPwdClientError(ValueError):
    pass


def _h(data: bytes) -> bytes:
    return hmac.new(bytes(32), data, hashlib.sha256).digest()


def _kdf(key: bytes, label: bytes, bit_length: int) -> bytes:
    byte_length = (bit_length + 7) // 8
    output = bytearray()
    counter = 0
    previous = b""
    while len(output) < byte_length:
        counter += 1
        previous = hmac.new(
            key,
            previous + counter.to_bytes(2, "big") + label +
            bit_length.to_bytes(2, "big"),
            hashlib.sha256,
        ).digest()
        output.extend(previous)
    result = bytearray(output[:byte_length])
    if bit_length % 8:
        shifted = int.from_bytes(result, "big") >> (8 - bit_length % 8)
        result[:] = shifted.to_bytes(byte_length, "big")
    return bytes(result)


def _pwd_pwe(group: int, token: bytes, peer_id: bytes, server_id: bytes,
             password: bytes) -> tuple[int, int]:
    curve = _curve_for_group(group)
    prime = curve.prime
    for counter in range(1, 41):
        digest = _h(token + peer_id + server_id + password + bytes((counter,)))
        candidate = int.from_bytes(
            _kdf(digest, b"EAP-pwd Hunting And Pecking", curve.prime_bits),
            "big",
        )
        if candidate >= prime:
            continue
        y2 = (pow(candidate, 3, prime) + curve.curve_a * candidate +
              curve.curve_b) % prime
        if pow(y2, (prime - 1) // 2, prime) != 1:
            continue
        y = pow(y2, (prime + 1) // 4, prime)
        if (y & 1) != (digest[-1] & 1):
            y = prime - y
        return candidate, y
    raise EapPwdClientError("unable to derive EAP-PWD password element")


class EapPwdClient:
    eap_type = EAP_PWD

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: str, group: int = 19,
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
        if not password:
            raise ValueError("EAP-PWD password is required")
        if group not in SAE_CURVES:
            raise ValueError("EAP-PWD group must be 19, 20, or 21")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = password.encode()
        self.group = group
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
        self.server_id: bytes | None = None
        self.token: bytes | None = None
        self.server_element: tuple[int, int] | None = None
        self.client_element: tuple[int, int] | None = None
        self.server_scalar: int | None = None
        self.client_scalar: int | None = None
        self.client_private: int | None = None
        self.shared_secret: bytes | None = None
        self.server_confirm: bytes | None = None
        self.client_confirm: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapPwdClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapPwdClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapPwdClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapPwdClientError("truncated EAPOL frame")
        return bytes(frame[eapol + 4:end])

    def _eapol_frame(self, eap: bytes) -> bytes:
        eapol = (bytes((EAPOL_VERSION, EAPOL_TYPE_EAP)) +
                 len(eap).to_bytes(2, "big") + eap)
        return (data_header(to_ds=True, bssid=self.ap_mac, client=self.sta_mac) +
                LLC_SNAP_EAPOL + eapol)

    def _eap_response(self, identifier: int, payload: bytes) -> bytes:
        eap = (bytes((EAP_RESPONSE, identifier)) +
               (4 + len(payload)).to_bytes(2, "big") + payload)
        return eap

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapPwdClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-pwd-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _handle_identity(self, identifier: int) -> bytes:
        return self._eap_response(identifier,
                                  bytes((EAP_IDENTITY,)) + self.identity)

    def _handle_id_exchange(self, identifier: int, payload: bytes) -> bytes:
        if self.state != "IDENTITY" or len(payload) < 1 + 2 + 1 + 1 + 4 + 1:
            raise EapPwdClientError("invalid EAP-PWD identity exchange")
        group = int.from_bytes(payload[1:3], "big")
        if group != self.group:
            raise EapPwdClientError("unexpected EAP-PWD group")
        if payload[3] != EAP_PWD_DEFAULT_RAND_FUNC or payload[4] != EAP_PWD_DEFAULT_PRF:
            raise EapPwdClientError("unsupported EAP-PWD random function or PRF")
        if payload[9] != EAP_PWD_PREP_NONE:
            raise EapPwdClientError("only unpreprocessed EAP-PWD passwords are supported")
        self.token = bytes(payload[5:9])
        self.server_id = bytes(payload[10:])
        self.state = "COMMIT"
        response = bytes((EAP_PWD,)) + payload[:10] + self.identity
        return self._eap_response(identifier, response)

    def _handle_commit_exchange(self, identifier: int, payload: bytes) -> bytes:
        if self.state != "COMMIT" or self.server_id is None or self.token is None:
            raise EapPwdClientError("unexpected EAP-PWD commit exchange")
        curve = _curve_for_group(self.group)
        prime_len = curve.prime_len
        order_len = curve.order_len
        if len(payload) != 1 + 2 * prime_len + order_len:
            raise EapPwdClientError("invalid EAP-PWD commit length")
        self.server_element = _point_decode(
            payload[1:1 + 2 * prime_len], curve)
        scalar_start = 1 + 2 * prime_len
        self.server_scalar = int.from_bytes(payload[scalar_start:], "big")
        if not 1 < self.server_scalar < curve.order:
            raise EapPwdClientError("invalid EAP-PWD server scalar")
        pwe = _pwd_pwe(self.group, self.token, self.identity,
                       self.server_id, self.password)
        self.client_private = secrets.randbelow(curve.order - 2) + 2
        mask = secrets.randbelow(curve.order - 2) + 2
        self.client_scalar = (self.client_private + mask) % curve.order
        if self.client_scalar in (0, 1):
            raise EapPwdClientError("invalid EAP-PWD client scalar")
        element = _point_mul(pwe, mask, curve)
        if element is None:
            raise EapPwdClientError("invalid EAP-PWD client element")
        self.client_element = (element[0], (-element[1]) % curve.prime)
        inner = _point_add(
            _point_mul(pwe, self.server_scalar, curve),
            self.server_element,
            curve,
        )
        shared = _point_mul(inner, self.client_private, curve)
        if shared is None:
            raise EapPwdClientError("invalid EAP-PWD shared point")
        self.shared_secret = shared[0].to_bytes(curve.prime_len, "big")
        self.state = "CONFIRM"
        commit = (bytes((EAP_PWD, EAP_PWD_COMMIT_EXCH)) +
                  _point_encode(self.client_element, curve) +
                  self.client_scalar.to_bytes(order_len, "big"))
        return self._eap_response(identifier, commit)

    def _handle_confirm_exchange(self, identifier: int, payload: bytes) -> bytes:
        if self.state != "CONFIRM" or self.shared_secret is None:
            raise EapPwdClientError("unexpected EAP-PWD confirm exchange")
        if len(payload) != 1 + hashlib.sha256().digest_size:
            raise EapPwdClientError("invalid EAP-PWD confirm length")
        curve = _curve_for_group(self.group)
        if self.server_element is None or self.client_element is None:
            raise EapPwdClientError("EAP-PWD elements are unavailable")
        if self.server_scalar is None or self.client_scalar is None:
            raise EapPwdClientError("EAP-PWD scalars are unavailable")
        suite = self.group.to_bytes(2, "big") + bytes((1, 1))
        server_confirm = bytes(payload[1:])
        expected = _h(
            self.shared_secret + _point_encode(self.server_element, curve) +
            self.server_scalar.to_bytes(curve.order_len, "big") +
            _point_encode(self.client_element, curve) +
            self.client_scalar.to_bytes(curve.order_len, "big") + suite
        )
        if not hmac.compare_digest(expected, server_confirm):
            raise EapPwdClientError("EAP-PWD server confirm mismatch")
        self.server_confirm = server_confirm
        self.client_confirm = _h(
            self.shared_secret + _point_encode(self.client_element, curve) +
            self.client_scalar.to_bytes(curve.order_len, "big") +
            _point_encode(self.server_element, curve) +
            self.server_scalar.to_bytes(curve.order_len, "big") + suite
        )
        session_id = bytes((EAP_PWD,)) + _h(
            suite + self.client_scalar.to_bytes(curve.order_len, "big") +
            self.server_scalar.to_bytes(curve.order_len, "big"))
        mk = _h(self.shared_secret + self.client_confirm + self.server_confirm)
        self.msk = _kdf(mk, session_id, 1024)[:64]
        self.state = "SUCCESS_PENDING"
        confirm = bytes((EAP_PWD, EAP_PWD_CONFIRM_EXCH)) + self.client_confirm
        return self._eap_response(identifier, confirm)

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
            except EapPwdClientError as error:
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
            if eap_type != EAP_PWD or len(eap) < 6:
                raise EapPwdClientError(f"unsupported EAP method {eap_type}")
            exchange = eap[5] & 0x3f
            payload = eap[5:]
            if exchange == EAP_PWD_ID_EXCH:
                response = self._handle_id_exchange(identifier, payload)
            elif exchange == EAP_PWD_COMMIT_EXCH:
                response = self._handle_commit_exchange(identifier, payload)
            elif exchange == EAP_PWD_CONFIRM_EXCH:
                response = self._handle_confirm_exchange(identifier, payload)
            else:
                raise EapPwdClientError("unsupported EAP-PWD exchange")
            return [response]
        except EapPwdClientError as error:
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
        except EapPwdClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_PWD", "EapPwdClient", "EapPwdClientError"]
