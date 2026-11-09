"""Scoped EAP-TLS/CCMP station for the native wifit3 OTA lab path.

This is deliberately a lab client, not a Windows supplicant replacement.  It
uses Python's TLS 1.2 MemoryBIO for the EAP-TLS exchange and feeds the derived
MSK into the existing WPA four-way station state machine.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import ssl

from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header


EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_IDENTITY = 1
EAP_TLS = 13
EAP_TLS_FLAG_MORE = 0x40
EAP_TLS_FLAG_LENGTH = 0x80
EAP_TLS_FLAG_START = 0x20
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0

# WPA2-Enterprise, CCMP, AKM 802.1X.
ENTERPRISE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac010000"
)


def tls12_prf(secret: bytes, label: bytes, seed: bytes, length: int,
              *, hash_name: str = "sha256") -> bytes:
    """TLS 1.2 PRF used by the EAP-TLS key export."""
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("TLS PRF secret is required")
    if not isinstance(label, bytes) or not label:
        raise ValueError("TLS PRF label is required")
    if not isinstance(seed, bytes):
        raise ValueError("TLS PRF seed must be bytes")
    if not 0 < length <= 4096:
        raise ValueError("TLS PRF length is out of range")
    try:
        digest = getattr(hashlib, hash_name)
    except AttributeError as error:
        raise ValueError(f"unsupported TLS PRF hash: {hash_name}") from error
    label_seed = label + seed
    a = hmac.new(secret, label_seed, digest).digest()
    output = bytearray()
    while len(output) < length:
        output.extend(hmac.new(secret, a + label_seed, digest).digest())
        a = hmac.new(secret, a, digest).digest()
    return bytes(output[:length])


class EapTlsClientError(ValueError):
    """Malformed EAP-TLS data or an unusable TLS key export."""


class EapTlsClient:
    """EAP-TLS peer plus WPA2-Enterprise CCMP four-way station state."""

    eap_type = EAP_TLS
    eap_version = 0
    tls_key_label = "client EAP encryption"

    def __init__(self, ap_mac: bytes, sta_mac: bytes, ssid: bytes | str,
                 *, identity: str, client_cert: str | Path | None,
                 client_key: str | Path | None, keylog_file: str | Path,
                 client_auth: bool = True,
                 fragment_size: int = 1000, server_hostname: str | None = None,
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
        if not 1 <= fragment_size <= 1800:
            raise ValueError("EAP-TLS fragment size is out of range")
        self.ap_mac = bytes(ap_mac)
        self.sta_mac = bytes(sta_mac)
        self.ssid = bytes(ssid)
        self.identity = identity.encode()
        self.client_cert = Path(client_cert) if client_cert is not None else None
        self.client_key = Path(client_key) if client_key is not None else None
        self.keylog_file = Path(keylog_file)
        self.client_auth = bool(client_auth)
        self.fragment_size = fragment_size
        self.server_hostname = server_hostname
        self.rsn_ie = bytes(rsn_ie)
        self.pmf_cipher = pmf_cipher.upper()

        self.state = "IDENTITY"
        self.last_error: str | None = None
        self.eap_success = False
        self.pmk: bytes | None = None
        self.wpa_client = None
        self.last_eap_code: int | None = None
        self.last_eap_type: int | None = None
        self.last_tls_flags: int | None = None
        self.last_tls_rx_len = 0
        self.last_tls_tx_len = 0
        self.tls_cipher: str | None = None
        self.eap_tls_trace: list[tuple[int, int, int | None, int, int]] = []

        self._tls = None
        self._tls_in: ssl.MemoryBIO | None = None
        self._tls_out: ssl.MemoryBIO | None = None
        self._tls_started = False
        self._tls_handshake_complete = False
        self._tls_wire = bytearray()
        self._tls_handshake_messages = bytearray()
        self._server_random: bytes | None = None
        self._client_random: bytes | None = None
        self._master_secret: bytes | None = None
        self._rx_tls_message = bytearray()
        self._rx_tls_expected: int | None = None
        self._tx_tls_message = b""
        self._tx_tls_offset = 0

    @property
    def authorized(self) -> bool:
        return bool(self.wpa_client is not None and self.wpa_client.authorized)

    def protect_management(self, frame: bytes) -> bytes:
        """Protect a PMF management frame with the post-EAP WPA client."""
        if self.wpa_client is None:
            raise EapTlsClientError("WPA client is not initialized")
        return self.wpa_client.protect_management(frame)

    @staticmethod
    def _eap_body(frame: bytes) -> bytes:
        """Extract the length-bounded EAP body from an 802.11 EAPOL frame."""
        start = frame.find(LLC_SNAP_EAPOL, 24, min(len(frame), 48))
        if start < 0 or len(frame) < start + 12:
            raise EapTlsClientError("missing EAPOL/SNAP header")
        eapol = start + len(LLC_SNAP_EAPOL)
        if frame[eapol + 1] != EAPOL_TYPE_EAP:
            raise EapTlsClientError("not an EAP-Packet frame")
        body_len = int.from_bytes(frame[eapol + 2:eapol + 4], "big")
        end = eapol + 4 + body_len
        if end > len(frame) or body_len < 4:
            raise EapTlsClientError("truncated EAPOL frame")
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

    def _build_tls_responses(self, identifier: int, data: bytes) -> list[bytes]:
        """Build one or more EAP-TLS responses for one TLS message."""
        if not data:
            return [self._eap_response(
                identifier, bytes((self.eap_type, self.eap_version)))]
        result: list[bytes] = []
        offset = 0
        first = True
        while offset < len(data):
            chunk = data[offset:offset + self.fragment_size]
            offset += len(chunk)
            flags = 0
            prefix = b""
            if first:
                flags |= EAP_TLS_FLAG_LENGTH
                prefix = len(data).to_bytes(4, "big")
            if offset < len(data):
                flags |= EAP_TLS_FLAG_MORE
            result.append(self._eap_response(
                identifier, bytes((self.eap_type, flags | self.eap_version)) + prefix + chunk))
            first = False
        return result

    def _next_tls_fragment(self, identifier: int) -> list[bytes]:
        if not self._tx_tls_message:
            return []
        offset = self._tx_tls_offset
        chunk = self._tx_tls_message[offset:offset + self.fragment_size]
        self._tx_tls_offset += len(chunk)
        flags = 0
        prefix = b""
        if offset == 0:
            flags |= EAP_TLS_FLAG_LENGTH
            prefix = len(self._tx_tls_message).to_bytes(4, "big")
        if self._tx_tls_offset < len(self._tx_tls_message):
            flags |= EAP_TLS_FLAG_MORE
        response = self._eap_response(
            identifier, bytes((self.eap_type, flags | self.eap_version)) + prefix + chunk)
        if self._tx_tls_offset >= len(self._tx_tls_message):
            self._tx_tls_message = b""
            self._tx_tls_offset = 0
        return [response]

    def _queue_tls_message(self, identifier: int, data: bytes) -> list[bytes]:
        if not data:
            return []
        if self._tx_tls_message:
            raise EapTlsClientError("another EAP-TLS message is already queued")
        self._tx_tls_message = bytes(data)
        self._tx_tls_offset = 0
        return self._next_tls_fragment(identifier)

    def _ensure_tls(self) -> None:
        if self._tls is not None:
            return
        if (self.client_auth and
                (self.client_cert is None or self.client_key is None or
                 not self.client_cert.is_file() or
                 not self.client_key.is_file())):
            raise EapTlsClientError("EAP-TLS client certificate or key is missing")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if self.client_auth:
            context.load_cert_chain(str(self.client_cert), str(self.client_key))
        self.keylog_file.parent.mkdir(parents=True, exist_ok=True)
        context.keylog_filename = str(self.keylog_file)
        self._tls_in = ssl.MemoryBIO()
        self._tls_out = ssl.MemoryBIO()
        self._tls = context.wrap_bio(
            self._tls_in, self._tls_out, server_side=False,
            server_hostname=self.server_hostname)

    def _drain_tls_output(self) -> bytes:
        if self._tls_out is None:
            return b""
        chunks = []
        while self._tls_out.pending:
            chunks.append(self._tls_out.read())
        return b"".join(chunks)

    def _observe_server_random(self, data: bytes) -> None:
        self._tls_wire.extend(data)
        while len(self._tls_wire) >= 5:
            record_len = int.from_bytes(self._tls_wire[3:5], "big")
            if len(self._tls_wire) < 5 + record_len:
                return
            content_type = self._tls_wire[0]
            payload = bytes(self._tls_wire[5:5 + record_len])
            del self._tls_wire[:5 + record_len]
            if content_type != 22:
                continue
            self._tls_handshake_messages.extend(payload)
            while len(self._tls_handshake_messages) >= 4:
                message_len = int.from_bytes(self._tls_handshake_messages[1:4], "big")
                if len(self._tls_handshake_messages) < 4 + message_len:
                    break
                message_type = self._tls_handshake_messages[0]
                body = bytes(self._tls_handshake_messages[4:4 + message_len])
                del self._tls_handshake_messages[:4 + message_len]
                if message_type == 2 and len(body) >= 34:
                    self._server_random = body[2:34]

    def _read_keylog(self) -> None:
        if not self.keylog_file.is_file():
            return
        for line in self.keylog_file.read_text(encoding="ascii", errors="ignore").splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[0] == "CLIENT_RANDOM":
                try:
                    self._client_random = bytes.fromhex(fields[1])
                    self._master_secret = bytes.fromhex(fields[2])
                except ValueError:
                    continue
                return

    def _derive_pmk(self) -> bytes:
        self._read_keylog()
        if self._master_secret is None or self._client_random is None:
            raise EapTlsClientError("TLS 1.2 key log has no CLIENT_RANDOM secret")
        if self._server_random is None:
            raise EapTlsClientError("TLS ServerHello random was not observed")
        self.tls_cipher = (self._tls.cipher()[0]
                           if self._tls is not None and self._tls.cipher()
                           else None)
        prf_hash = "sha384" if self.tls_cipher and "SHA384" in self.tls_cipher else "sha256"
        key_material = tls12_prf(
            self._master_secret, self.tls_key_label.encode("ascii"),
            self._client_random + self._server_random, 128,
            hash_name=prf_hash)
        return key_material[:32]

    def _process_tls(self, identifier: int, data: bytes) -> list[bytes]:
        self._ensure_tls()
        self._observe_server_random(data)
        assert self._tls_in is not None and self._tls is not None
        self._tls_in.write(data)
        try:
            self._tls.do_handshake()
            self._tls_handshake_complete = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as error:
            self.last_error = f"TLS handshake failed: {error}"
            self.state = "FAILURE"
            return []
        output = self._drain_tls_output()
        self.last_tls_rx_len = len(data)
        self.last_tls_tx_len = len(output)
        if self._tls_handshake_complete:
            self._read_keylog()
        if output:
            return self._queue_tls_message(identifier, output)
        # The final server TLS record can complete the client-side handshake
        # without producing another client TLS record.  EAP-TLS still needs a
        # response to that request so the server can advance to EAP-Success.
        return ([self._eap_response(identifier, bytes((self.eap_type, self.eap_version)))]
                if data else [])

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
                self.pmk = self._derive_pmk()
            except EapTlsClientError as error:
                self.last_error = str(error)
                self.state = "FAILURE"
                return []
            from .wpa2_client import Wpa2PskClient
            self.wpa_client = Wpa2PskClient(
                self.ap_mac, self.sta_mac, self.ssid, "enterprise-lab",
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
        if eap_type != self.eap_type or len(eap) < 6:
            self.last_error = f"unsupported EAP method {eap_type}"
            return []
        flags = eap[5]
        self.last_tls_flags = flags
        if flags & EAP_TLS_FLAG_START:
            self._ensure_tls()
            self._tls_started = True
            # EAP-TLS Start is followed by the peer's TLS ClientHello.  A
            # zero-length EAP-TLS response only acknowledges the Start and
            # leaves the server waiting for the first TLS record, which
            # results in an empty ACK request/retransmission loop.
            return self._process_tls(identifier, b"")
        if not (flags & (EAP_TLS_FLAG_LENGTH | EAP_TLS_FLAG_MORE)) and len(eap) == 6:
            # ACK for a client-to-server fragment. The next client fragment
            # must use the fresh EAP identifier carried by this ACK request.
            return self._next_tls_fragment(identifier)
        offset = 6
        if flags & EAP_TLS_FLAG_LENGTH:
            if len(eap) < offset + 4:
                self.last_error = "truncated EAP-TLS length"
                return []
            self._rx_tls_expected = int.from_bytes(eap[offset:offset + 4], "big")
            offset += 4
            self._rx_tls_message.clear()
        self._rx_tls_message.extend(eap[offset:])
        if len(self.eap_tls_trace) < 32:
            self.eap_tls_trace.append((identifier, flags, self._rx_tls_expected,
                                       len(eap[offset:]), len(self._rx_tls_message)))
        if flags & EAP_TLS_FLAG_MORE:
            # hostapd enters WAIT_FRAG_ACK after each outgoing TLS fragment.
            # An empty EAP-TLS response acknowledges that fragment and causes
            # the next request fragment to be emitted.
            return [self._eap_response(identifier,
                                       bytes((self.eap_type, self.eap_version)))]
        if (self._rx_tls_expected is not None and
                len(self._rx_tls_message) != self._rx_tls_expected):
            self.last_error = "EAP-TLS fragment length mismatch"
            return []
        data = bytes(self._rx_tls_message)
        self._rx_tls_message.clear()
        self._rx_tls_expected = None
        self._tls_started = True
        return self._process_tls(identifier, data)

    def handle_frame(self, frame: bytes) -> list[bytes]:
        """Consume an AP-to-station EAPOL frame and return station frames."""
        self.last_error = None
        if not isinstance(frame, bytes) or len(frame) < 24:
            return []
        if frame[4:10] != self.sta_mac or frame[10:16] != self.ap_mac:
            return []
        try:
            eap = self._eap_body(frame)
        except EapTlsClientError:
            # After EAP-Success hostapd immediately sends EAPOL-Key M1.  The
            # existing WPA client owns that frame format.
            if self.wpa_client is not None:
                return self.wpa_client.handle_frame(frame)
            return []
        return self._handle_eap(eap)

    def close(self) -> None:
        """Release the OpenSSL key-log handle before a temporary lab directory is removed."""
        if self._tls is not None:
            try:
                self._tls.context.keylog_filename = None
            except (AttributeError, ValueError):
                pass
        self._tls = None
        self._tls_in = None
        self._tls_out = None
