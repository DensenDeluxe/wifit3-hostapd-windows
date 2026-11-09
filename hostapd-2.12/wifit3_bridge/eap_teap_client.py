from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import ssl
import threading

from .eap_fast_client import eap_fast_mschapv2_msk
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
    tls12_prf,
)


EAP_TEAP = 55
EAP_TLV_AUTHORITY_ID = 1
EAP_TLV_RESULT = 3
EAP_TLV_EAP_PAYLOAD = 9
EAP_TLV_INTERMEDIATE_RESULT = 10
EAP_TLV_CRYPTO_BINDING = 12
EAP_TLV_TYPE_MANDATORY = 0x8000
EAP_TLV_RESULT_SUCCESS = 1
EAP_TEAP_VERSION = 1
EAP_TEAP_EXPORTER_LABEL = b"EXPORTER: teap session key seed"
EAP_TEAP_SIMCK_LEN = 40
EAP_TEAP_CMK_LEN = 20
EAP_TEAP_NONCE_LEN = 32
EAP_TEAP_CRYPTO_BINDING_VALUE_LEN = 76
EAP_TEAP_OUTER_TLV_LEN = 0x10
EAP_TEAP_CRYPTO_BINDING_REQUEST = 0
EAP_TEAP_CRYPTO_BINDING_RESPONSE = 1


@dataclass(frozen=True)
class TeapTlvs:
    eap_payload: bytes | None = None
    crypto_binding: bytes | None = None
    result: int | None = None
    intermediate_result: int | None = None


def _tlv(tlv_type: int, value: bytes) -> bytes:
    if len(value) > 0xffff:
        raise EapTlsClientError("EAP-TEAP TLV value is too long")
    return (tlv_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value)


def build_eap_payload_tlv(payload: bytes) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_EAP_PAYLOAD, bytes(payload))


def build_result_tlv(status: int = EAP_TLV_RESULT_SUCCESS) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_RESULT,
                status.to_bytes(2, "big"))


def build_intermediate_result_tlv(status: int = EAP_TLV_RESULT_SUCCESS) -> bytes:
    return _tlv(EAP_TLV_TYPE_MANDATORY | EAP_TLV_INTERMEDIATE_RESULT,
                status.to_bytes(2, "big"))


def tls_exporter(master_secret: bytes, client_random: bytes,
                 server_random: bytes, length: int,
                 *, hash_name: str = "sha256") -> bytes:
    if len(client_random) != 32 or len(server_random) != 32:
        raise EapTlsClientError("TLS random values must be 32 bytes")
    return tls12_prf(master_secret, EAP_TEAP_EXPORTER_LABEL,
                     client_random + server_random, length,
                     hash_name=hash_name)


def derive_teap_imck(prev_s_imck: bytes, inner_msk: bytes,
                     *, hash_name: str = "sha256") -> tuple[bytes, bytes]:
    if len(prev_s_imck) != EAP_TEAP_SIMCK_LEN:
        raise EapTlsClientError("TEAP session key seed must be 40 bytes")
    if not inner_msk:
        raise EapTlsClientError("TEAP inner MSK is required")
    imsk = bytes(inner_msk[:32]).ljust(32, b"\x00")
    imck = tls12_prf(prev_s_imck, b"Inner Methods Compound Keys", imsk, 60,
                    hash_name=hash_name)
    return imck[:40], imck[40:]


def derive_teap_msk(simck: bytes, *, hash_name: str = "sha256") -> bytes:
    if len(simck) != EAP_TEAP_SIMCK_LEN:
        raise EapTlsClientError("TEAP S-IMCK must be 40 bytes")
    return tls12_prf(simck, b"Session Key Generating Function", b"", 64,
                     hash_name=hash_name)


def parse_teap_tlvs(data: bytes) -> TeapTlvs:
    eap_payload = None
    crypto_binding = None
    result = None
    intermediate_result = None
    offset = 0
    while offset + 4 <= len(data):
        raw_type = int.from_bytes(data[offset:offset + 2], "big")
        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        start = offset + 4
        end = start + length
        if end > len(data):
            raise EapTlsClientError("EAP-TEAP TLV exceeds plaintext length")
        tlv_type = raw_type & 0x3fff
        value = bytes(data[start:end])
        if tlv_type == EAP_TLV_EAP_PAYLOAD:
            if eap_payload is not None:
                raise EapTlsClientError("multiple EAP-TEAP payload TLVs")
            eap_payload = value
        elif tlv_type == EAP_TLV_CRYPTO_BINDING:
            if crypto_binding is not None:
                raise EapTlsClientError("multiple EAP-TEAP crypto bindings")
            if length != EAP_TEAP_CRYPTO_BINDING_VALUE_LEN:
                raise EapTlsClientError("invalid EAP-TEAP crypto binding length")
            crypto_binding = bytes(data[offset:end])
        elif tlv_type == EAP_TLV_RESULT:
            if length < 2:
                raise EapTlsClientError("invalid EAP-TEAP result TLV")
            result = int.from_bytes(value[:2], "big")
        elif tlv_type == EAP_TLV_INTERMEDIATE_RESULT:
            if length < 2:
                raise EapTlsClientError("invalid EAP-TEAP intermediate result TLV")
            intermediate_result = int.from_bytes(value[:2], "big")
        offset = end
    if offset != len(data):
        raise EapTlsClientError("truncated EAP-TEAP TLV header")
    return TeapTlvs(eap_payload, crypto_binding, result, intermediate_result)


def _increment_nonce(nonce: bytes) -> bytes:
    value = bytearray(nonce)
    for index in range(len(value) - 1, -1, -1):
        value[index] = (value[index] + 1) & 0xff
        if value[index] != 0:
            break
    return bytes(value)


def _compound_mac(binding: bytes, cmk: bytes, server_outer_tlvs: bytes,
                  peer_outer_tlvs: bytes, *, hash_name: str) -> bytes:
    if len(binding) != 80 or len(cmk) != EAP_TEAP_CMK_LEN:
        raise EapTlsClientError("invalid EAP-TEAP compound MAC input")
    buffer = bytearray(binding)
    buffer[40:80] = b"\x00" * 40
    buffer.extend(bytes((EAP_TEAP,)))
    buffer.extend(server_outer_tlvs)
    buffer.extend(peer_outer_tlvs)
    return hmac.new(cmk, bytes(buffer), getattr(hashlib, hash_name)).digest()[:20]


def build_crypto_binding_response(request: bytes, cmk: bytes,
                                  mac_builder=None) -> bytes:
    if len(request) != 80 or len(cmk) != EAP_TEAP_CMK_LEN:
        raise EapTlsClientError("invalid EAP-TEAP crypto binding input")
    raw_type = int.from_bytes(request[:2], "big")
    if raw_type & 0x3fff != EAP_TLV_CRYPTO_BINDING:
        raise EapTlsClientError("unexpected EAP-TEAP crypto binding type")
    if int.from_bytes(request[2:4], "big") != EAP_TEAP_CRYPTO_BINDING_VALUE_LEN:
        raise EapTlsClientError("invalid EAP-TEAP crypto binding size")
    if request[4] != 0 or request[5] != EAP_TEAP_VERSION:
        raise EapTlsClientError("invalid EAP-TEAP crypto binding request")
    if request[7] & 0x0f != EAP_TEAP_CRYPTO_BINDING_REQUEST:
        raise EapTlsClientError("invalid EAP-TEAP crypto binding subtype")
    flags = request[7] >> 4
    if flags not in (1, 2, 3):
        raise EapTlsClientError("invalid EAP-TEAP crypto binding flags")
    response = bytearray(
        (EAP_TLV_TYPE_MANDATORY | EAP_TLV_CRYPTO_BINDING).to_bytes(2, "big") +
        EAP_TEAP_CRYPTO_BINDING_VALUE_LEN.to_bytes(2, "big") +
        bytes((0, EAP_TEAP_VERSION, request[6],
               (2 << 4) | EAP_TEAP_CRYPTO_BINDING_RESPONSE)) +
        _increment_nonce(request[8:40]) + b"\x00" * 40
    )
    if mac_builder is None:
        mac_builder = lambda value: _compound_mac(value, cmk, b"", b"",
                                                   hash_name="sha1")
    response[60:80] = mac_builder(bytes(response))
    return bytes(response)


class EapTeapClient(EapTlsClient):
    eap_type = EAP_TEAP
    eap_version = EAP_TEAP_VERSION

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
        self.server_outer_tlvs = b""
        self.peer_outer_tlvs = b""
        self._teap_lock = threading.RLock()
        self._last_eap_request: bytes | None = None
        self._last_eap_response: list[bytes] | None = None

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
                self._server_random is None):
            raise EapTlsClientError("EAP-TEAP TLS key material is unavailable")
        cipher = self._tls.cipher()[0] if self._tls is not None else ""
        self.tls_cipher = cipher
        hash_name = "sha384" if "SHA384" in cipher else "sha256"
        self._simck = tls_exporter(
            self._master_secret, self._client_random, self._server_random,
            EAP_TEAP_SIMCK_LEN, hash_name=hash_name)

    def _derive_cmk(self) -> None:
        if self._simck is None or self._inner().msk is None:
            raise EapTlsClientError("EAP-TEAP inner key material is unavailable")
        cipher = self.tls_cipher or ""
        hash_name = "sha384" if "SHA384" in cipher else "sha256"
        inner_msk = eap_fast_mschapv2_msk(self._inner().msk)
        self._simck, self._cmk = derive_teap_imck(
            self._simck, inner_msk, hash_name=hash_name)
        self.msk = derive_teap_msk(self._simck, hash_name=hash_name)

    def _handle_inner(self, eap: bytes) -> bytes | None:
        if len(eap) < 4:
            raise EapTlsClientError("truncated EAP-TEAP inner EAP packet")
        length = int.from_bytes(eap[2:4], "big")
        if length < 4 or length > len(eap):
            raise EapTlsClientError("invalid EAP-TEAP inner EAP length")
        if len(self.inner_trace) < 64:
            self.inner_trace.append((eap[0], eap[1], eap[4] if length >= 5 else None, length))
        responses = self._inner()._handle_eap(eap[:length])
        if self._inner().eap_success or self._inner().state == "MSCHAPV2_SUCCESS":
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

    def _drain_tls_output(self) -> bytes:
        if self._tls_out is None:
            return b""
        chunks = []
        while self._tls_out.pending:
            chunks.append(self._tls_out.read())
        return b"".join(chunks)

    def _compound_mac_for(self, binding: bytes, cmk: bytes) -> bytes:
        cipher = self.tls_cipher or ""
        hash_name = "sha384" if "SHA384" in cipher else (
            "sha256" if "SHA256" in cipher else "sha1")
        mac = _compound_mac(binding, cmk, self.server_outer_tlvs,
                            self.peer_outer_tlvs, hash_name=hash_name)
        return mac

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
                self.last_error = f"EAP-TEAP TLS handshake failed: {error}"
                self.state = "FAILURE"
                return []
        plaintext = self._drain_tls_plaintext()
        try:
            if plaintext:
                tlvs = parse_teap_tlvs(plaintext)
                if tlvs.crypto_binding is not None:
                    if self._cmk is None:
                        self._derive_cmk()
                    result = b""
                    if tlvs.intermediate_result is not None:
                        result += build_intermediate_result_tlv()
                    if tlvs.result is not None:
                        result += build_result_tlv()
                    response = result + build_crypto_binding_response(
                        tlvs.crypto_binding, self._cmk,
                        lambda binding: self._compound_mac_for(binding, self._cmk))
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
        with self._teap_lock:
            request = bytes(eap)
            if request == self._last_eap_request and self._last_eap_response is not None:
                return list(self._last_eap_response)
            response = self._handle_eap_impl(request)
            self._last_eap_request = request
            self._last_eap_response = list(response)
            return response

    def _handle_eap_impl(self, eap: bytes) -> list[bytes]:
        if len(eap) >= 4 and eap[0] == EAP_SUCCESS:
            if self.msk is None:
                self.last_error = "EAP-TEAP MSK is not available"
                self.state = "FAILURE"
                return []
            from .wpa2_client import Wpa2PskClient
            self.pmk = self.msk[:32]
            self.wpa_client = Wpa2PskClient(
                self.ap_mac, self.sta_mac, self.ssid, "teap-lab",
                rsn_ie=self.rsn_ie, cipher="CCMP", akm="WPA-EAP", pmk=self.pmk,
                pmf_cipher=self.pmf_cipher)
            self.eap_success = True
            self.state = "WPA"
            return []
        if len(eap) < 5 or eap[0] != EAP_REQUEST:
            return super()._handle_eap(eap)
        identifier = eap[1]
        if eap[4] != self.eap_type or len(eap) < 6:
            return super()._handle_eap(eap)
        flags = eap[5]
        if flags & EAP_TLS_FLAG_START:
            if flags & EAP_TEAP_OUTER_TLV_LEN:
                if len(eap) < 10:
                    self.last_error = "truncated EAP-TEAP outer TLV length"
                    self.state = "FAILURE"
                    return []
                outer_length = int.from_bytes(eap[6:10], "big")
                if len(eap) < 10 + outer_length:
                    self.last_error = "truncated EAP-TEAP outer TLVs"
                    self.state = "FAILURE"
                    return []
                self.server_outer_tlvs = bytes(eap[10:10 + outer_length])
            self._tls_started = True
            return self._process_tls(identifier, b"")
        if not (flags & (EAP_TLS_FLAG_LENGTH | EAP_TLS_FLAG_MORE)) and len(eap) == 6:
            return self._next_tls_fragment(identifier)
        offset = 6
        if flags & EAP_TLS_FLAG_LENGTH:
            if len(eap) < offset + 4:
                self.last_error = "truncated EAP-TEAP length"
                return []
            self._rx_tls_expected = int.from_bytes(eap[offset:offset + 4], "big")
            offset += 4
            self._rx_tls_message.clear()
        self._rx_tls_message.extend(eap[offset:])
        if len(self.eap_tls_trace) < 64:
            self.eap_tls_trace.append((identifier, flags, self._rx_tls_expected,
                                       len(eap[offset:]), len(self._rx_tls_message)))
        if flags & EAP_TLS_FLAG_MORE:
            return [self._eap_response(identifier,
                                       bytes((self.eap_type, self.eap_version)))]
        if (self._rx_tls_expected is not None and
                len(self._rx_tls_message) != self._rx_tls_expected):
            self.last_error = "EAP-TEAP fragment length mismatch"
            return []
        data = bytes(self._rx_tls_message)
        self._rx_tls_message.clear()
        self._rx_tls_expected = None
        self._tls_started = True
        return self._process_tls(identifier, data)


__all__ = [
    "EAP_TEAP", "EapTeapClient", "TeapTlvs", "build_crypto_binding_response",
    "build_eap_payload_tlv", "build_intermediate_result_tlv", "build_result_tlv",
    "derive_teap_imck", "derive_teap_msk", "parse_teap_tlvs", "tls_exporter",
]
