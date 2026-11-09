"""Scoped EAP-PEAPv1/MSCHAPv2 station for the native wifit3 OTA lab path.

The client deliberately covers the interoperable PEAPv1 tunnel used by the
local hostapd test server: server-authenticated TLS, encrypted inner EAP and
inner EAP-MSCHAPv2.  It reuses the EAP-TLS MemoryBIO and WPA-EAP handoff while
keeping the implementation separate from Windows WLAN AutoConfig.
"""
from __future__ import annotations

import ssl
from pathlib import Path

from .eap_mschapv2_client import EapMschapv2Client
from .eap_tls_client import (
    EAP_FAILURE,
    EAP_REQUEST,
    EAP_SUCCESS,
    EAP_TLS_FLAG_LENGTH,
    EAP_TLS_FLAG_MORE,
    EAP_TLS_FLAG_START,
    EapTlsClient,
    EapTlsClientError,
)

EAP_RESPONSE = 2
EAP_IDENTITY = 1
EAP_MSCHAPV2 = 26
EAP_PEAP = 25


class EapPeapMschapv2Client(EapTlsClient):
    """PEAPv1 outer TLS plus an inner EAP-MSCHAPv2 peer."""

    eap_type = EAP_PEAP
    eap_version = 1

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, outer_identity: str, inner_identity: str, password: str,
                 keylog_file: str | Path,
                 fragment_size: int = 1000,
                 rsn_ie: bytes | None = None,
                 pmf_cipher: str = "AES-128-CMAC"):
        super().__init__(
            ap_mac, sta_mac, ssid,
            identity=outer_identity,
            client_cert=None,
            client_key=None,
            keylog_file=keylog_file,
            client_auth=False,
            fragment_size=fragment_size,
            rsn_ie=(rsn_ie if rsn_ie is not None else
                    bytes.fromhex("30140100000fac040100000fac040100000fac010000")),
            pmf_cipher=pmf_cipher,
        )
        self.inner_identity = inner_identity
        self.inner_password = password
        self.inner_success = False
        self.inner_trace: list[tuple[int, int, int | None, int]] = []
        self.peap_version = self.eap_version
        self._inner_mschap: EapMschapv2Client | None = None

    def _inner_client(self) -> EapMschapv2Client:
        if self._inner_mschap is None:
            self._inner_mschap = EapMschapv2Client(
                self.ap_mac,
                self.sta_mac,
                self.ssid,
                identity=self.inner_identity,
                password=self.inner_password,
            )
        return self._inner_mschap

    def _handle_inner_eap(self, eap: bytes) -> list[bytes]:
        """Process a complete inner EAP packet and return inner EAP packets."""
        if not isinstance(eap, bytes) or len(eap) < 4:
            raise EapTlsClientError("truncated PEAP inner EAP packet")
        length = int.from_bytes(eap[2:4], "big")
        if length < 4 or length > len(eap):
            raise EapTlsClientError("invalid PEAP inner EAP length")
        eap_type = eap[4] if length >= 5 else None
        if len(self.inner_trace) < 64:
            self.inner_trace.append((eap[0], eap[1], eap_type, length))
        client = self._inner_client()
        responses = client._handle_eap(eap[:length])
        if client.eap_success:
            self.inner_success = True
        if client.last_error is not None:
            self.last_error = client.last_error
        return [client._eap_body(frame) for frame in responses]

    @staticmethod
    def _split_inner_eap(data: bytes) -> list[bytes]:
        packets = []
        offset = 0
        while offset < len(data):
            if len(data) - offset < 4:
                raise EapTlsClientError("truncated PEAP inner EAP stream")
            length = int.from_bytes(data[offset + 2:offset + 4], "big")
            if length < 4 or offset + length > len(data):
                raise EapTlsClientError("invalid PEAP inner EAP stream length")
            packets.append(data[offset:offset + length])
            offset += length
        return packets

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
        """Run TLS phase 1 and exchange encrypted PEAP phase-2 EAP."""
        self._ensure_tls()
        self._observe_server_random(data)
        assert self._tls_in is not None and self._tls is not None
        if data:
            self._tls_in.write(data)
        if not self._tls_handshake_complete:
            try:
                self._tls.do_handshake()
                self._tls_handshake_complete = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as error:
                self.last_error = f"PEAP TLS handshake failed: {error}"
                self.state = "FAILURE"
                return []

        plaintext = self._drain_tls_plaintext()
        if plaintext and self._tls_handshake_complete:
            for inner_request in self._split_inner_eap(plaintext):
                for inner_response in self._handle_inner_eap(inner_request):
                    try:
                        self._tls.write(inner_response)
                    except ssl.SSLWantWriteError as error:
                        self.last_error = f"PEAP TLS write blocked: {error}"
                        self.state = "FAILURE"
                        return []

        output = self._drain_tls_output()
        self.last_tls_rx_len = len(data)
        self.last_tls_tx_len = len(output)
        if output:
            return self._queue_tls_message(identifier, output)
        # PEAP uses an empty response as the TLS/fragment ACK.  A successful
        # inner EAP-Success is acknowledged here before outer EAP-Success.
        return [self._eap_response(
            identifier, bytes((self.eap_type, self.eap_version)))]

    def close(self) -> None:
        super().close()


__all__ = [
    "EAP_IDENTITY", "EAP_MSCHAPV2", "EAP_PEAP", "EAP_RESPONSE",
    "EapPeapMschapv2Client",
]
