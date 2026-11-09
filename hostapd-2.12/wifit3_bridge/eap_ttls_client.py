"""Scoped EAP-TTLS/MSCHAPv2 station for the native wifit3 OTA lab path."""
from __future__ import annotations

import hashlib
import os
import ssl
from pathlib import Path

from .eap_mschapv2_client import (
    generate_authenticator_response,
    generate_nt_response,
)
from .eap_tls_client import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_SUCCESS,
    EapTlsClient,
    EapTlsClientError,
    tls12_prf,
)

EAP_RESPONSE = 2
EAP_IDENTITY = 1
EAP_TTLS = 21
EAP_TLS_FLAG_MORE = 0x40
EAP_TLS_FLAG_LENGTH = 0x80
EAP_TLS_FLAG_START = 0x20

RADIUS_VENDOR_ID_MICROSOFT = 311
RADIUS_ATTR_USER_NAME = 1
RADIUS_ATTR_MS_CHAP_CHALLENGE = 11
RADIUS_ATTR_MS_CHAP2_RESPONSE = 25
RADIUS_ATTR_MS_CHAP2_SUCCESS = 26
AVP_FLAGS_MANDATORY = 0x40
AVP_FLAGS_VENDOR = 0x80


class EapTtlsMschapv2Client(EapTlsClient):
    """EAP-TTLS v1 with the non-EAP MS-CHAPv2 phase-2 method."""

    eap_type = EAP_TTLS
    eap_version = 1
    tls_key_label = "ttls keying material"

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, password: str,
                 outer_identity: str | None = None,
                 keylog_file: str | Path,
                 fragment_size: int = 1000,
                 rsn_ie: bytes | None = None,
                 pmf_cipher: str = "AES-128-CMAC"):
        super().__init__(
            ap_mac, sta_mac, ssid,
            identity=outer_identity or identity,
            client_cert=None,
            client_key=None,
            keylog_file=keylog_file,
            client_auth=False,
            fragment_size=fragment_size,
            rsn_ie=(rsn_ie if rsn_ie is not None else
                    bytes.fromhex("30140100000fac040100000fac040100000fac010000")),
            pmf_cipher=pmf_cipher,
        )
        self.inner_identity = identity
        self.inner_password = password
        self.ttls_challenge: bytes | None = None
        self.ttls_ident: int | None = None
        self.ttls_authenticator_response = b""
        self.ttls_inner_success = False
        self.ttls_request_sent = False
        self.ttls_trace: list[tuple[int, int | None, int]] = []

    @property
    def inner_success(self) -> bool:
        """Expose phase-2 success through the common Enterprise-client API."""
        return self.ttls_inner_success

    @property
    def inner_trace(self) -> list[tuple[int, int | None, int]]:
        """Expose TTLS diagnostics through the common Enterprise-client API."""
        return self.ttls_trace

    def _tls_prf_hash(self) -> str:
        cipher = self.tls_cipher
        if cipher is None and self._tls is not None and self._tls.cipher():
            cipher = self._tls.cipher()[0]
        return "sha384" if cipher and "SHA384" in cipher else "sha256"

    def _ttls_key(self, label: bytes, length: int) -> bytes:
        self._read_keylog()
        if (self._master_secret is None or self._client_random is None or
                self._server_random is None):
            raise EapTlsClientError("TTLS TLS key material is unavailable")
        return tls12_prf(
            self._master_secret, label,
            self._client_random + self._server_random,
            length,
            hash_name=self._tls_prf_hash(),
        )

    def _build_avp(self, code: int, value: bytes,
                   vendor: int | None = None) -> bytes:
        vendor_bytes = (vendor.to_bytes(4, "big") if vendor is not None else b"")
        header_len = 12 if vendor is not None else 8
        flags = AVP_FLAGS_MANDATORY | (
            AVP_FLAGS_VENDOR if vendor is not None else 0)
        length = header_len + len(value)
        header = (code.to_bytes(4, "big") +
                  ((flags << 24) | length).to_bytes(4, "big") +
                  vendor_bytes)
        packet = header + value
        return packet + b"\x00" * ((4 - (len(packet) & 3)) & 3)

    def _build_phase2_request(self) -> bytes:
        challenge_material = self._ttls_key(b"ttls challenge", 17)
        self.ttls_challenge = challenge_material[:16]
        self.ttls_ident = challenge_material[16]
        peer_challenge = os.urandom(16)
        nt_response = generate_nt_response(
            self.ttls_challenge, peer_challenge,
            self.inner_identity, self.inner_password)
        self.ttls_authenticator_response = generate_authenticator_response(
            self.inner_password, peer_challenge, self.ttls_challenge,
            self.inner_identity, nt_response)
        response = (bytes((self.ttls_ident, 0)) + peer_challenge +
                    b"\x00" * 8 + nt_response)
        return b"".join((
            self._build_avp(RADIUS_ATTR_USER_NAME,
                            self.inner_identity.encode("utf-8")),
            self._build_avp(RADIUS_ATTR_MS_CHAP_CHALLENGE,
                            self.ttls_challenge, RADIUS_VENDOR_ID_MICROSOFT),
            self._build_avp(RADIUS_ATTR_MS_CHAP2_RESPONSE,
                            response, RADIUS_VENDOR_ID_MICROSOFT),
        ))

    def _parse_server_avps(self, data: bytes) -> None:
        offset = 0
        found_success = False
        while offset < len(data):
            if len(data) - offset < 8:
                raise EapTlsClientError("truncated TTLS AVP header")
            code = int.from_bytes(data[offset:offset + 4], "big")
            word = int.from_bytes(data[offset + 4:offset + 8], "big")
            flags = (word >> 24) & 0xff
            length = word & 0x00ffffff
            if length < 8 or offset + length > len(data):
                raise EapTlsClientError("invalid TTLS AVP length")
            cursor = offset + 8
            vendor = None
            if flags & AVP_FLAGS_VENDOR:
                if length < 12:
                    raise EapTlsClientError("truncated TTLS vendor AVP")
                vendor = int.from_bytes(data[cursor:cursor + 4], "big")
                cursor += 4
            value = data[cursor:offset + length]
            if (vendor == RADIUS_VENDOR_ID_MICROSOFT and
                    code == RADIUS_ATTR_MS_CHAP2_SUCCESS):
                if self.ttls_ident is None or len(value) != 43:
                    raise EapTlsClientError("invalid TTLS MS-CHAP2 success AVP")
                if value[0] != self.ttls_ident:
                    raise EapTlsClientError("TTLS MS-CHAP2 identifier mismatch")
                expected = (b"S=" +
                            self.ttls_authenticator_response.hex().upper().encode())
                if value[1:] != expected:
                    raise EapTlsClientError("TTLS authenticator response mismatch")
                found_success = True
            offset += length + ((4 - (length & 3)) & 3)
        if found_success:
            self.ttls_inner_success = True

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
                self.tls_cipher = self._tls.cipher()[0]
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as error:
                self.last_error = f"TTLS TLS handshake failed: {error}"
                self.state = "FAILURE"
                return []

        plaintext = self._drain_tls_plaintext()
        try:
            if plaintext:
                self._parse_server_avps(plaintext)
            if (self._tls_handshake_complete and not self.ttls_request_sent and
                    not self.ttls_inner_success):
                self._tls.write(self._build_phase2_request())
                self.ttls_request_sent = True
        except (EapTlsClientError, ssl.SSLWantWriteError) as error:
            self.last_error = str(error)
            self.state = "FAILURE"
            return []

        output = self._drain_tls_output()
        self.last_tls_rx_len = len(data)
        self.last_tls_tx_len = len(output)
        if output:
            return self._queue_tls_message(identifier, output)
        return [self._eap_response(
            identifier, bytes((self.eap_type, self.eap_version)))]

    def close(self) -> None:
        super().close()


__all__ = ["EAP_TTLS", "EapTtlsMschapv2Client"]
