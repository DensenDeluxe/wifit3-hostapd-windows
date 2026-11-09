import unittest
from unittest.mock import patch

try:
    from wifit3_bridge.eap_sake_client import (
        EAP_REQUEST,
        EAP_SAKE,
        EapSakeClient,
        derive_keys,
    )
except ImportError:
    EAP_REQUEST = None
    EAP_SAKE = None
    EapSakeClient = None
    derive_keys = None


def _attr(attr_type, value):
    return bytes((attr_type, len(value) + 2)) + value


class EapSakeClientTests(unittest.TestCase):
    def test_key_derivation_vector(self):
        self.assertIsNotNone(derive_keys)
        tek_auth, tek_cipher, msk, emsk = derive_keys(
            bytes(range(32)), bytes(range(32, 48)), bytes(range(48, 64)))
        self.assertEqual(tek_auth.hex(), "6ff699d014dbad8919c5f8a38f49d572")
        self.assertEqual(tek_cipher.hex(), "de214d1e7de16a5f63ecbe86dd2cb1b3")
        self.assertEqual(
            msk.hex(),
            "544f2ed29f2c1e05303b5b957e4f18747d4369bf53e2454d6615ade0252e8249"
            "b79ad53a4a10c384335a47856615af7e157e245f62efc1976ef6f2edabc3d5cf",
        )
        self.assertEqual(
            emsk.hex(),
            "047ecb717b6ad402bfc2e852daad36f1419e16539fe2172b803f6e597ac0a6b1"
            "689b35c4ced313cd631967596468102edebe35da421f67eb6aab7602397f8432",
        )

    def test_client_completes_exchange(self):
        self.assertIsNotNone(EapSakeClient)
        client = EapSakeClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-sake",
            identity="peer",
            password=bytes(range(32)),
        )
        server_id = b"server"
        session_id = 0x42
        identity = bytes((EAP_REQUEST, 1, 0, 20, EAP_SAKE, 2,
                          session_id, 4))
        identity += _attr(10, b"\x00\x00") + _attr(5, server_id)
        responses = client.handle_eap_packet(identity)
        self.assertEqual(
            responses[0].hex(),
            "0201000e30024204060670656572",
        )
        rand_s = bytes(range(32, 48))
        challenge = bytes((EAP_REQUEST, 2, 0, 34, EAP_SAKE, 2,
                           session_id, 1))
        challenge += _attr(1, rand_s) + _attr(5, server_id)
        with patch(
            "wifit3_bridge.eap_sake_client.os.urandom",
            return_value=bytes(range(48, 64)),
        ):
            responses = client.handle_eap_packet(challenge)
        self.assertEqual(len(responses), 1)
        self.assertEqual(
            responses[0].hex(),
            "02020032300242010212303132333435363738393a3b3c3d3e3f"
            "060670656572041248e35377f21ba143584b2893a84cf0f9",
        )
        confirm = bytes.fromhex(
            "0103001a3002420203126d188fedb0f5c0728adac0f2780cb1cb")
        responses = client.handle_eap_packet(confirm)
        self.assertEqual(
            responses[0].hex(),
            "0203001a30024202041285cdbfb530e8f2e51047480049f91898",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03040004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(client.msk.hex(),
                         "544f2ed29f2c1e05303b5b957e4f18747d4369bf53e2454d6615ade0252e8249"
                         "b79ad53a4a10c384335a47856615af7e157e245f62efc1976ef6f2edabc3d5cf")


if __name__ == "__main__":
    unittest.main()
