import unittest
from unittest.mock import Mock, patch

from wifit3_bridge.eap_tls_client import (
    EAP_TLS,
    EAP_TLS_FLAG_LENGTH,
    EAP_TLS_FLAG_MORE,
    EapTlsClient,
    tls12_prf,
)


class EapTlsClientTests(unittest.TestCase):
    def test_tls12_prf_matches_fixed_sha256_vector(self):
        result = tls12_prf(b"\x0b" * 16, b"test label", b"seed", 64)
        self.assertEqual(
            result.hex(),
            "72c350bc08df2a9dfede75c55a161228"
            "1929c452d032b6905f95304b92684d1b"
            "a55aa8e50a59b129a9f8e278390bad59"
            "b89a9c31c9b14aab354d9c2427421d24",
        )

    def test_tls12_prf_supports_sha384_cipher_suite(self):
        result = tls12_prf(
            b"\x0b" * 16, b"test label", b"seed", 64, hash_name="sha384")
        self.assertEqual(
            result.hex(),
            "8602ffa71165c01dd1b20f9ee81f91ba"
            "db0689f0a40209cf182ea891bfdf1e8f"
            "b5d7a736c10fb16d6bf4f16a42777969"
            "bbf1685471ffe980e35e3380f2382358",
        )

    def test_eap_tls_response_fragmentation_sets_length_and_more_flags(self):
        client = EapTlsClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="wifit3-client",
            client_cert="client.pem",
            client_key="client.key",
            keylog_file="client.keylog",
            fragment_size=4,
        )
        packets = client._build_tls_responses(7, b"0123456789")
        self.assertEqual(len(packets), 3)
        eap = [client._eap_body(packet) for packet in packets]
        self.assertEqual(eap[0][0:2], bytes((2, 7)))
        self.assertEqual(int.from_bytes(eap[0][2:4], "big"), len(eap[0]))
        self.assertEqual(eap[0][4], EAP_TLS)
        self.assertEqual(eap[0][5], EAP_TLS_FLAG_LENGTH | EAP_TLS_FLAG_MORE)
        self.assertEqual(int.from_bytes(eap[0][6:10], "big"), 10)
        self.assertEqual(eap[1][5], EAP_TLS_FLAG_MORE)
        self.assertEqual(eap[2][5], 0)
        self.assertEqual(
            eap[0][10:] + eap[1][6:] + eap[2][6:],
            b"0123456789",
        )

    def test_server_fragment_with_more_flag_gets_empty_eap_tls_ack(self):
        client = EapTlsClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="wifit3-client",
            client_cert="client.pem",
            client_key="client.key",
            keylog_file="client.keylog",
        )
        eap = bytes((1, 9, 0, 14, EAP_TLS, EAP_TLS_FLAG_LENGTH | EAP_TLS_FLAG_MORE)) + (
            8).to_bytes(4, "big") + b"abcd"
        responses = client._handle_eap(eap)
        self.assertEqual(len(responses), 1)
        ack = client._eap_body(responses[0])
        self.assertEqual(ack, bytes((2, 9, 0, 6, EAP_TLS, 0)))

    def test_eap_tls_start_emits_client_hello_payload(self):
        client = EapTlsClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="wifit3-client",
            client_cert="client.pem",
            client_key="client.key",
            keylog_file="client.keylog",
        )
        expected = object()
        with patch.object(client, "_ensure_tls") as ensure_tls, \
                patch.object(client, "_process_tls", return_value=[expected]) as process_tls:
            responses = client._handle_eap(
                bytes((1, 12, 0, 6, EAP_TLS, 0x20)))
        ensure_tls.assert_called_once_with()
        process_tls.assert_called_once_with(12, b"")
        self.assertIs(responses[0], expected)

    def test_client_tls_fragments_are_released_one_per_server_ack(self):
        client = EapTlsClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="wifit3-client",
            client_cert="client.pem",
            client_key="client.key",
            keylog_file="client.keylog",
            fragment_size=4,
        )
        first = client._queue_tls_message(7, b"0123456789")
        self.assertEqual(len(first), 1)
        self.assertEqual(client._eap_body(first[0])[5], EAP_TLS_FLAG_LENGTH | EAP_TLS_FLAG_MORE)
        ack = bytes((1, 8, 0, 6, EAP_TLS, 0))
        second = client._handle_eap(ack)
        self.assertEqual(len(second), 1)
        self.assertEqual(client._eap_body(second[0])[5], EAP_TLS_FLAG_MORE)

    def test_pmf_protection_delegates_to_post_eap_wpa_client(self):
        client = EapTlsClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="wifit3-client",
            client_cert="client.pem",
            client_key="client.key",
            keylog_file="client.keylog",
        )
        client.wpa_client = Mock()
        client.wpa_client.protect_management.return_value = b"protected"

        result = client.protect_management(b"action")

        self.assertEqual(result, b"protected")
        client.wpa_client.protect_management.assert_called_once_with(b"action")


if __name__ == "__main__":
    unittest.main()
