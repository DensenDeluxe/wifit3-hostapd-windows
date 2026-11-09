import unittest
from unittest.mock import patch

from wifit3_bridge.eap_ttls_client import EAP_TTLS, EapTtlsMschapv2Client


class EapTtlsMschapv2ClientTests(unittest.TestCase):
    def _client(self):
        return EapTtlsMschapv2Client(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-ttls",
            identity="wifit3-mschap",
            password="clientPass",
            keylog_file="ttls-test.keylog",
        )

    def test_outer_type_is_ttls(self):
        client = self._client()
        self.assertEqual(client.eap_type, EAP_TTLS)
        self.assertFalse(client.inner_success)
        self.assertEqual(client.inner_trace, [])

    def test_builds_vendor_mschapv2_avps_from_tls_challenge(self):
        client = self._client()
        client._client_random = bytes(range(32))
        client._server_random = bytes(range(32, 64))
        client._master_secret = bytes(range(64, 96))
        with patch(
            "wifit3_bridge.eap_ttls_client.os.urandom",
            return_value=bytes.fromhex("21402324255e262a28295f2b3a337c7e"),
        ):
            avps = client._build_phase2_request()
        self.assertEqual(len(avps) % 4, 0)
        self.assertEqual(int.from_bytes(avps[0:4], "big"), 1)
        self.assertEqual(int.from_bytes(avps[4:8], "big") & 0x00ffffff, 8 + len("wifit3-mschap"))
        self.assertIn((311).to_bytes(4, "big"), avps)
        self.assertEqual(client.ttls_ident is not None, True)
        self.assertEqual(len(client.ttls_authenticator_response), 20)


if __name__ == "__main__":
    unittest.main()
