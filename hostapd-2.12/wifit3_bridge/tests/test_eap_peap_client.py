import unittest

from wifit3_bridge.eap_peap_client import (
    EAP_MSCHAPV2,
    EAP_PEAP,
    EAP_RESPONSE,
    EapPeapMschapv2Client,
)


class EapPeapMschapv2ClientTests(unittest.TestCase):
    def _client(self):
        return EapPeapMschapv2Client(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-peap",
            outer_identity="wifit3-peap",
            inner_identity="User",
            password="clientPass",
            keylog_file="peap-test.keylog",
        )

    def test_inner_identity_uses_inner_identity(self):
        client = self._client()
        request = bytes((1, 3, 0, 5, 1))
        response = client._handle_inner_eap(request)
        self.assertEqual(len(response), 1)
        self.assertEqual(response[0], bytes((2, 3, 0, 9, 1)) + b"User")

    def test_inner_mschapv2_challenge_generates_eap_response(self):
        client = self._client()
        auth_challenge = bytes.fromhex("5b5d7c7d7b3f2f3e3c2c602132262628")
        request = bytes((1, 7, 0, 32, EAP_MSCHAPV2, 1, 7, 0, 27, 16))
        request += auth_challenge + b"server"
        response = client._handle_inner_eap(request)
        self.assertEqual(len(response), 1)
        self.assertEqual(response[0][:5], bytes((EAP_RESPONSE, 7, 0, 63, EAP_MSCHAPV2)))
        self.assertEqual(response[0][5], 2)
        self.assertEqual(response[0][6], 7)

    def test_outer_type_is_peap(self):
        client = self._client()
        self.assertEqual(client.eap_type, EAP_PEAP)

    def test_inner_trace_records_eap_packet_metadata(self):
        client = self._client()
        client._handle_inner_eap(bytes((1, 3, 0, 5, 1)))
        self.assertEqual(client.inner_trace, [(1, 3, 1, 5)])


if __name__ == "__main__":
    unittest.main()
