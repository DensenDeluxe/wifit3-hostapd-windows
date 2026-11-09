from __future__ import annotations

import hmac
import os

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_SAKE = 48
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAP_SAKE_VERSION = 2
EAP_SAKE_SUBTYPE_CHALLENGE = 1
EAP_SAKE_SUBTYPE_CONFIRM = 2
EAP_SAKE_SUBTYPE_AUTH_REJECT = 3
EAP_SAKE_SUBTYPE_IDENTITY = 4
EAP_SAKE_AT_RAND_S = 1
EAP_SAKE_AT_RAND_P = 2
EAP_SAKE_AT_MIC_S = 3
EAP_SAKE_AT_MIC_P = 4
EAP_SAKE_AT_SERVERID = 5
EAP_SAKE_AT_PEERID = 6
EAP_SAKE_AT_PERM_ID_REQ = 10
EAP_SAKE_RAND_LEN = 16
EAP_SAKE_MIC_LEN = 16
EAP_SAKE_ROOT_SECRET_LEN = 16
EAP_SAKE_TEK_AUTH_LEN = 16
EAP_SAKE_TEK_CIPHER_LEN = 16
EAP_SAKE_PASSWORD_LEN = 32
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


class EapSakeClientError(ValueError):
    pass


def _kdf(key: bytes, label: str, data: bytes, data2: bytes,
         length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hmac.new(
            key, label.encode() + b"\x00" + data + data2 + bytes((counter,)),
            "sha1").digest())
        counter += 1
    return bytes(output[:length])


def derive_keys(password: bytes, rand_s: bytes, rand_p: bytes) -> tuple[
        bytes, bytes, bytes, bytes]:
    if not isinstance(password, bytes) or len(password) != EAP_SAKE_PASSWORD_LEN:
        raise EapSakeClientError("EAP-SAKE requires a 32-octet key")
    if len(rand_s) != EAP_SAKE_RAND_LEN or len(rand_p) != EAP_SAKE_RAND_LEN:
        raise EapSakeClientError("EAP-SAKE random values must be 16 bytes")
    root_a = password[:EAP_SAKE_ROOT_SECRET_LEN]
    root_b = password[EAP_SAKE_ROOT_SECRET_LEN:]
    sms_a = _kdf(root_a, "SAKE Master Secret A", rand_p, rand_s, 16)
    tek = _kdf(sms_a, "Transient EAP Key", rand_s, rand_p, 32)
    sms_b = _kdf(root_b, "SAKE Master Secret B", rand_p, rand_s, 16)
    keys = _kdf(sms_b, "Master Session Key", rand_s, rand_p, 128)
    return tek[:16], tek[16:], keys[:64], keys[64:]


def compute_mic(tek_auth: bytes, rand_s: bytes, rand_p: bytes,
                server_id: bytes, peer_id: bytes, peer: bool, eap: bytes,
                mic_pos: int) -> bytes:
    if len(tek_auth) != 16 or len(rand_s) != 16 or len(rand_p) != 16:
        raise EapSakeClientError("invalid EAP-SAKE MIC inputs")
    if mic_pos < 0 or mic_pos + 16 > len(eap):
        raise EapSakeClientError("invalid EAP-SAKE MIC position")
    ids = ((peer_id + b"\x00" + server_id + b"\x00") if peer else
           (server_id + b"\x00" + peer_id + b"\x00"))
    rand = rand_s + rand_p if peer else rand_p + rand_s
    message = ids + eap[:mic_pos] + b"\x00" * 16 + eap[mic_pos + 16:]
    return _kdf(tek_auth, "Peer MIC" if peer else "Server MIC",
                rand, message, 16)


def _attr(attr_type: int, value: bytes) -> bytes:
    return bytes((attr_type, len(value) + 2)) + value


def _parse_attrs(payload: bytes, base_offset: int) -> tuple[dict[int, bytes], dict[int, int]]:
    attrs = {}
    positions = {}
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 2:
            raise EapSakeClientError("truncated EAP-SAKE attribute")
        attr_type = payload[offset]
        attr_len = payload[offset + 1]
        if attr_len < 2 or offset + attr_len > len(payload):
            raise EapSakeClientError("invalid EAP-SAKE attribute length")
        value = payload[offset + 2:offset + attr_len]
        if attr_type < 128 and attr_type not in {
                EAP_SAKE_AT_RAND_S, EAP_SAKE_AT_RAND_P,
                EAP_SAKE_AT_MIC_S, EAP_SAKE_AT_MIC_P,
                EAP_SAKE_AT_SERVERID, EAP_SAKE_AT_PEERID,
                EAP_SAKE_AT_PERM_ID_REQ}:
            raise EapSakeClientError("unknown EAP-SAKE attribute")
        if attr_type in {EAP_SAKE_AT_RAND_S, EAP_SAKE_AT_RAND_P,
                         EAP_SAKE_AT_MIC_S, EAP_SAKE_AT_MIC_P} and len(value) != 16:
            raise EapSakeClientError("invalid EAP-SAKE fixed attribute")
        attrs[attr_type] = bytes(value)
        positions[attr_type] = base_offset + offset + 2
        offset += attr_len
    return attrs, positions


class EapSakeClient:
    eap_type = EAP_SAKE

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
        if not isinstance(password, bytes) or len(password) != EAP_SAKE_PASSWORD_LEN:
            raise ValueError("EAP-SAKE requires a 32-octet key")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.password = bytes(password)
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
        self.last_sake_subtype: int | None = None
        self.session_id: int | None = None
        self.server_id = b""
        self.peer_id = self.identity
        self.rand_s: bytes | None = None
        self.rand_p: bytes | None = None
        self.tek_auth: bytes | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        if self.wpa_client is None:
            raise EapSakeClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapSakeClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapSakeClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapSakeClientError("truncated EAPOL frame")
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

    def _method_response(self, identifier: int, subtype: int,
                         attrs: bytes) -> bytes:
        if self.session_id is None:
            raise EapSakeClientError("EAP-SAKE session is not initialized")
        payload = bytes((EAP_SAKE, EAP_SAKE_VERSION, self.session_id,
                         subtype)) + attrs
        return self._eap_response(identifier, payload)

    def _initialize_wpa(self) -> None:
        if self.wpa_client is not None:
            return
        if self.msk is None:
            raise EapSakeClientError("MSK is not available")
        from .wpa2_client import Wpa2PskClient
        self.pmk = self.msk[:32]
        self.wpa_client = Wpa2PskClient(
            self.ap_mac, self.sta_mac, self.ssid, "eap-sake-lab",
            rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
            pmf_cipher=self.pmf_cipher)

    def _identity_response(self, identifier: int) -> bytes:
        return self._eap_response(identifier,
                                  bytes((EAP_IDENTITY,)) + self.identity)

    def _handle_identity(self, identifier: int, payload: bytes) -> bytes:
        attrs, _ = _parse_attrs(payload, 8)
        if EAP_SAKE_AT_PERM_ID_REQ not in attrs:
            raise EapSakeClientError("EAP-SAKE identity request is missing ID request")
        self.state = "CHALLENGE"
        return self._method_response(
            identifier, EAP_SAKE_SUBTYPE_IDENTITY,
            _attr(EAP_SAKE_AT_PEERID, self.peer_id))

    def _handle_challenge(self, identifier: int, eap: bytes,
                          payload: bytes) -> bytes:
        if self.state not in {"CHALLENGE", "IDENTITY"}:
            raise EapSakeClientError("unexpected EAP-SAKE challenge")
        attrs, _ = _parse_attrs(payload, 8)
        rand_s = attrs.get(EAP_SAKE_AT_RAND_S)
        server_id = attrs.get(EAP_SAKE_AT_SERVERID)
        if rand_s is None or server_id is None:
            raise EapSakeClientError("EAP-SAKE challenge is incomplete")
        self.rand_s = rand_s
        self.server_id = server_id
        self.rand_p = os.urandom(EAP_SAKE_RAND_LEN)
        self.tek_auth, _, self.msk, _ = derive_keys(
            self.password, self.rand_s, self.rand_p)
        response = self._method_response(
            identifier, EAP_SAKE_SUBTYPE_CHALLENGE,
            _attr(EAP_SAKE_AT_RAND_P, self.rand_p) +
            _attr(EAP_SAKE_AT_PEERID, self.peer_id) +
            _attr(EAP_SAKE_AT_MIC_P, b"\x00" * EAP_SAKE_MIC_LEN))
        mic_pos = response.index(bytes((EAP_SAKE_AT_MIC_P,
                                        2 + EAP_SAKE_MIC_LEN)), 8) + 2
        mic = compute_mic(self.tek_auth, self.rand_s, self.rand_p,
                          self.server_id, self.peer_id, True, response,
                          mic_pos)
        self.state = "CONFIRM"
        return response[:mic_pos] + mic + response[mic_pos + 16:]

    def _handle_confirm(self, identifier: int, eap: bytes,
                        payload: bytes) -> bytes:
        if self.state != "CONFIRM" or self.rand_s is None or self.rand_p is None:
            raise EapSakeClientError("unexpected EAP-SAKE confirmation")
        attrs, positions = _parse_attrs(payload, 8)
        mic_s = attrs.get(EAP_SAKE_AT_MIC_S)
        if mic_s is None or self.tek_auth is None:
            raise EapSakeClientError("EAP-SAKE confirmation is incomplete")
        expected = compute_mic(
            self.tek_auth, self.rand_s, self.rand_p, self.server_id,
            self.peer_id, False, eap, positions[EAP_SAKE_AT_MIC_S])
        if not hmac.compare_digest(mic_s, expected):
            self.state = "FAILURE"
            return self._method_response(
                identifier, EAP_SAKE_SUBTYPE_AUTH_REJECT, b"")
        response = self._method_response(
            identifier, EAP_SAKE_SUBTYPE_CONFIRM,
            _attr(EAP_SAKE_AT_MIC_P, b"\x00" * EAP_SAKE_MIC_LEN))
        mic_pos = response.index(bytes((EAP_SAKE_AT_MIC_P,
                                        2 + EAP_SAKE_MIC_LEN)), 8) + 2
        mic = compute_mic(
            self.tek_auth, self.rand_s, self.rand_p, self.server_id,
            self.peer_id, True, response, mic_pos)
        self.state = "SUCCESS_PENDING"
        return response[:mic_pos] + mic + response[mic_pos + 16:]

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
            except EapSakeClientError as error:
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
                return [self._identity_response(identifier)]
            if eap_type != EAP_SAKE or len(eap) < 8:
                raise EapSakeClientError("unsupported EAP method")
            version, session_id, subtype = eap[5:8]
            if version != EAP_SAKE_VERSION:
                raise EapSakeClientError("unsupported EAP-SAKE version")
            if self.session_id is not None and self.session_id != session_id:
                raise EapSakeClientError("EAP-SAKE session mismatch")
            self.session_id = session_id
            self.last_sake_subtype = subtype
            payload = eap[8:]
            if subtype == EAP_SAKE_SUBTYPE_IDENTITY:
                response = self._handle_identity(identifier, payload)
            elif subtype == EAP_SAKE_SUBTYPE_CHALLENGE:
                response = self._handle_challenge(identifier, eap, payload)
            elif subtype == EAP_SAKE_SUBTYPE_CONFIRM:
                response = self._handle_confirm(identifier, eap, payload)
            else:
                raise EapSakeClientError("unsupported EAP-SAKE subtype")
            return [response]
        except EapSakeClientError as error:
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
        except EapSakeClientError:
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return [self._eapol_frame(response)
                for response in self.handle_eap_packet(eap)]

    def close(self) -> None:
        return None


__all__ = ["EAP_SAKE", "EapSakeClient", "EapSakeClientError",
           "compute_mic", "derive_keys"]
