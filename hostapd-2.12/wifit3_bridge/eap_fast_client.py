from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import ssl

from .eap_mschapv2_client import EapMschapv2Client
from .eap_tls_client import (
    EAP_FAILURE,
    EAP_IDENTITY,
    EAP_REQUEST,
    EAP_SUCCESS,
    EAP_TLS_FLAG_LENGTH,
    EAP_TLS_FLAG_MORE,
    EAP_TLS_FLAG_START,
    EapTlsClient,
    EapTlsClientError,
)


EAP_FAST = 43
EAP_TLV_RESULT = 3
EAP_TLV_INTERMEDIATE_RESULT = 10
EAP_TLV_EAP_PAYLOAD = 9
EAP_TLV_CRYPTO_BINDING = 12
EAP_TLV_TYPE_MANDATORY = 0x8000
EAP_TLV_RESULT_SUCCESS = 1
EAP_TLV_CRYPTO_BINDING_REQUEST = 0
EAP_TLV_CRYPTO_BINDING_RESPONSE = 1
EAP_FAST_VERSION = 1
EAP_FAST_CMK_LEN = 20
EAP_FAST_SIMCK_LEN = 40


@dataclass(frozen=True)
class FastTlvs:
    eap_payload: bytes | None = None
    crypto_binding: bytes | None = None
    result: int | None = None
    intermediate_result: int | None = None
    request_action: int | None = None
    pac: bytes | None = None


def sha1_t_prf(key: bytes, label: bytes | str, seed: bytes,
               length: int) -> bytes:
    if isinstance(label, str):
        label = label.encode("ascii")
    if len(key) == 0 or not isinstance(label, bytes) or not isinstance(seed, bytes):
        raise EapTlsClientError("EAP-FAST T-PRF input is invalid")
    if not 0 < length <= 4096:
        raise EapTlsClientError("EAP-FAST T-PRF length is invalid")
    label_seed = label + b"\x00" + seed + length.to_bytes(2, "big")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            key, previous + label_seed + bytes((counter,)), hashlib.sha1
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _tlv(tlv_type: int, value: bytes) -> bytes:
    return (tlv_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value)


def build_eap_payload_tlv(payload: bytes) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_EAP_PAYLOAD, bytes(payload))


def build_result_tlv(status: int = EAP_TLV_RESULT_SUCCESS) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_RESULT, status.to_bytes(2, "big"))


def build_intermediate_result_tlv(status: int = EAP_TLV_RESULT_SUCCESS) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_INTERMEDIATE_RESULT,
                status.to_bytes(2, "big"))


def eap_fast_mschapv2_msk(msk: bytes) -> bytes:
    if len(msk) != 32:
        raise EapTlsClientError("EAP-FAST MSCHAPv2 MSK length is invalid")
    return bytes(msk[16:] + msk[:16])


def parse_fast_tlvs(data: bytes) -> FastTlvs:
    eap_payload = None
    crypto_binding = None
    result = None
    intermediate_result = None
    request_action = None
    pac = None
    offset = 0
    while offset + 4 <= len(data):
        raw_type = int.from_bytes(data[offset:offset + 2], "big")
        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        start = offset + 4
        end = start + length
        if end > len(data):
            raise EapTlsClientError("EAP-FAST TLV exceeds plaintext length")
        tlv_type = raw_type & 0x3fff
        value = bytes(data[start:end])
        if tlv_type == EAP_TLV_EAP_PAYLOAD:
            if eap_payload is not None:
                raise EapTlsClientError("multiple EAP-FAST payload TLVs")
            eap_payload = value
        elif tlv_type == EAP_TLV_CRYPTO_BINDING:
            if crypto_binding is not None:
                raise EapTlsClientError("multiple EAP-FAST crypto bindings")
            if len(value) != 56:
                raise EapTlsClientError("invalid EAP-FAST crypto binding length")
            crypto_binding = bytes(data[offset:end])
        elif tlv_type == EAP_TLV_RESULT:
            if len(value) < 2:
                raise EapTlsClientError("invalid EAP-FAST result TLV")
            result = int.from_bytes(value[:2], "big")
        elif tlv_type == 10:
            if len(value) < 2:
                raise EapTlsClientError("invalid EAP-FAST intermediate result TLV")
            intermediate_result = int.from_bytes(value[:2], "big")
        elif tlv_type == 19:
            if len(value) < 2:
                raise EapTlsClientError("invalid EAP-FAST request action TLV")
            request_action = int.from_bytes(value[:2], "big")
        elif tlv_type == 11:
            pac = value
        offset = end
    if offset != len(data):
        raise EapTlsClientError("truncated EAP-FAST TLV header")
    return FastTlvs(eap_payload, crypto_binding, result,
                    intermediate_result, request_action, pac)


def build_crypto_binding_response(request: bytes, cmk: bytes) -> bytes:
    if len(request) != 60 or len(cmk) != EAP_FAST_CMK_LEN:
        raise EapTlsClientError("invalid EAP-FAST crypto binding input")
    raw_type = int.from_bytes(request[:2], "big")
    if raw_type & 0x3fff != EAP_TLV_CRYPTO_BINDING:
        raise EapTlsClientError("unexpected EAP-FAST crypto binding type")
    if int.from_bytes(request[2:4], "big") != 56:
        raise EapTlsClientError("invalid EAP-FAST crypto binding size")
    if request[4] != 0 or request[5] != EAP_FAST_VERSION or request[7] != EAP_TLV_CRYPTO_BINDING_REQUEST:
        raise EapTlsClientError("invalid EAP-FAST crypto binding request")
    nonce = bytearray(request[8:40])
    for index in range(len(nonce) - 1, -1, -1):
        nonce[index] = (nonce[index] + 1) & 0xff
        if nonce[index] != 0:
            break
    response = bytearray(
        (EAP_TLV_TYPE_MANDATORY | EAP_TLV_CRYPTO_BINDING).to_bytes(2, "big") +
        (56).to_bytes(2, "big") + bytes((0, EAP_FAST_VERSION, request[5], EAP_TLV_CRYPTO_BINDING_RESPONSE)) +
        bytes(nonce) + b"\x00" * 20
    )
    response[40:60] = hmac.new(cmk, bytes(response), hashlib.sha1).digest()
    return bytes(response)


class EapFastClient(EapTlsClient):
    eap_type = EAP_FAST
    eap_version = EAP_FAST_VERSION

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, outer_identity: str, inner_identity: str, password: str,
                 keylog_file: str | Path, fragment_size: int = 1000,
                 rsn_ie: bytes | None = None,
                 pmf_cipher: str = "AES-128-CMAC"):
        super().__init__(
            ap_mac, sta_mac, ssid, identity=outer_identity,
            client_cert=None, client_key=None, keylog_file=keylog_file,
            client_auth=False, fragment_size=fragment_size,
            rsn_ie=(rsn_ie if rsn_ie is not None else
                    bytes.fromhex("30140100000fac040100000fac040100000fac010000")),
            pmf_cipher=pmf_cipher)
        self.inner_identity = inner_identity
        self.inner_password = password
        self.inner_success = False
        self.inner_trace: list[tuple[int, int, int | None, int]] = []
        self._inner_client: EapMschapv2Client | None = None
        self._simck: bytes | None = None
        self._cmk: bytes | None = None
        self.msk: bytes | None = None

    def _ensure_tls(self) -> None:
        if self._tls is not None:
            return
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("AES128-SHA:AES256-SHA")
        self.keylog_file.parent.mkdir(parents=True, exist_ok=True)
        context.keylog_filename = str(self.keylog_file)
        self._tls_in = ssl.MemoryBIO()
        self._tls_out = ssl.MemoryBIO()
        self._tls = context.wrap_bio(
            self._tls_in, self._tls_out, server_side=False,
            server_hostname=None)

    def _inner(self) -> EapMschapv2Client:
        if self._inner_client is None:
            self._inner_client = EapMschapv2Client(
                self.ap_mac, self.sta_mac, self.ssid,
                identity=self.inner_identity, password=self.inner_password)
        return self._inner_client

    def _derive_simck(self) -> None:
        self._read_keylog()
        if (self._master_secret is None or self._client_random is None or
                self._server_random is None or self._tls is None):
            raise EapTlsClientError("EAP-FAST TLS key material is unavailable")
        cipher = self._tls.cipher()[0]
        self.tls_cipher = cipher
        mac_len = 0 if any(token in cipher for token in ("GCM", "CHACHA")) else 20
        enc_len = 32 if "AES256" in cipher else 16
        iv_len = 4 if any(token in cipher for token in ("GCM", "CHACHA")) else 16
        skip = 2 * (mac_len + enc_len + iv_len)
        key_block = self._tls_prf_key_block(skip + EAP_FAST_SIMCK_LEN)
        self._simck = key_block[skip:]

    def _tls_prf_key_block(self, length: int) -> bytes:
        from .eap_tls_client import tls12_prf
        return tls12_prf(
            self._master_secret, b"key expansion",
            self._server_random + self._client_random, length,
            hash_name="sha256")

    def _derive_cmk(self) -> None:
        if self._simck is None or self._inner().msk is None:
            raise EapTlsClientError("EAP-FAST inner key material is unavailable")
        imck = sha1_t_prf(
            self._simck, b"Inner Methods Compound Keys",
            eap_fast_mschapv2_msk(self._inner().msk[:32]), 60)
        self._simck = imck[:EAP_FAST_SIMCK_LEN]
        self._cmk = imck[EAP_FAST_SIMCK_LEN:]
        self.msk = sha1_t_prf(
            self._simck, b"Session Key Generating Function", b"", 64)

    def _handle_inner(self, eap: bytes) -> bytes | None:
        if len(eap) < 4:
            raise EapTlsClientError("truncated EAP-FAST inner EAP packet")
        length = int.from_bytes(eap[2:4], "big")
        if length < 4 or length > len(eap):
            raise EapTlsClientError("invalid EAP-FAST inner EAP length")
        if len(self.inner_trace) < 64:
            self.inner_trace.append((eap[0], eap[1], eap[4] if length >= 5 else None, length))
        responses = self._inner()._handle_eap(eap[:length])
        if (self._inner().eap_success or
                self._inner().state == "MSCHAPV2_SUCCESS"):
            self.inner_success = True
        if self._inner().last_error is not None:
            raise EapTlsClientError(self._inner().last_error)
        if not responses:
            return None
        return self._inner()._eap_body(responses[0])

    def _drain_tls_plaintext(self) -> bytes:
        if self._tls is None:
            return b""
        chunks = []
        while True:
            try:
                chunk = self._tls.read()
            except ssl.SSLWantReadError:
                break
            except ssl.SSLZeroReturnError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def _process_tls(self, identifier: int, data: bytes) -> list[bytes]:
        self._ensure_tls()
        self._observe_server_random(data)
        assert self._tls_in is not None and self._tls is not None
        if data:
            self._tls_in.write(data)
        if not self._tls_handshake_complete:
            try:
                self._tls.do_handshake()
                self._tls_handshake_complete = True
                self._read_keylog()
                self._derive_simck()
            except ssl.SSLWantReadError:
                pass
            except (ssl.SSLError, EapTlsClientError) as error:
                self.last_error = f"EAP-FAST TLS handshake failed: {error}"
                self.state = "FAILURE"
                return []
        plaintext = self._drain_tls_plaintext()
        try:
            if plaintext:
                tlvs = parse_fast_tlvs(plaintext)
                if tlvs.crypto_binding is not None:
                    if self._cmk is None:
                        self._derive_cmk()
                    result = (build_result_tlv() if tlvs.result is not None else
                              build_intermediate_result_tlv())
                    response = result + build_crypto_binding_response(
                        tlvs.crypto_binding, self._cmk)
                    self._tls.write(response)
                elif tlvs.eap_payload is not None:
                    response = self._handle_inner(tlvs.eap_payload)
                    if response is not None:
                        self._tls.write(build_eap_payload_tlv(response))
        except (EapTlsClientError, ssl.SSLWantWriteError) as error:
            self.last_error = str(error)
            self.state = "FAILURE"
            return []
        output = self._drain_tls_output()
        self.last_tls_rx_len = len(data)
        self.last_tls_tx_len = len(output)
        if output:
            return self._queue_tls_message(identifier, output)
        return [self._eap_response(identifier, bytes((self.eap_type, self.eap_version)))]

    def _handle_eap(self, eap: bytes) -> list[bytes]:
        if len(eap) >= 4 and eap[0] == EAP_SUCCESS:
            if self.msk is None:
                self.last_error = "EAP-FAST MSK is not available"
                self.state = "FAILURE"
                return []
            self.inner_success = self._inner().state == "MSCHAPV2_SUCCESS"
            from .wpa2_client import Wpa2PskClient
            self.pmk = self.msk[:32]
            self.wpa_client = Wpa2PskClient(
                self.ap_mac, self.sta_mac, self.ssid, "fast-lab",
                rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
                pmf_cipher=self.pmf_cipher)
            self.eap_success = True
            self.state = "WPA"
            return []
        return super()._handle_eap(eap)


__all__ = [
    "EAP_FAST", "EAP_TLV_CRYPTO_BINDING", "EAP_TLV_EAP_PAYLOAD",
    "EapFastClient", "FastTlvs", "build_crypto_binding_response",
    "build_eap_payload_tlv", "build_intermediate_result_tlv",
    "eap_fast_mschapv2_msk", "parse_fast_tlvs", "sha1_t_prf",
]
