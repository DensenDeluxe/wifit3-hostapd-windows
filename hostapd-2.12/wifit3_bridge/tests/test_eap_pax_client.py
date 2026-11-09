import unittest
from unittest.mock import patch

try:
    from wifit3_bridge.eap_pax_client import (
        EAP_PAX,
        EAP_REQUEST,
        EapPaxClient,
        derive_keys,
    )
except ImportError:
    EAP_PAX = None
    EAP_REQUEST = None
    EapPaxClient = None
    derive_keys = None


class EapPaxClientTests(unittest.TestCase):
    def test_key_derivation_vector(self):
        self.assertIsNotNone(derive_keys)
        keys = derive_keys(
            bytes(range(16)), bytes(range(32)), bytes(range(32, 64)))
        self.assertEqual(keys[0].hex(), "6b3f43840986879ddd0e09940bf93e7c")
        self.assertEqual(keys[1].hex(), "e981750c03ec2488dbb08da9f1432d51")
        self.assertEqual(keys[2].hex(), "d98c22ca8076e8d62d3eb77f316f08ee")
        self.assertEqual(keys[3].hex(), "18768474452dfcc4d121e4faec7445c8")
        self.assertEqual(
            keys[4].hex(),
            "794ab6a57958d9e6288bc5ee15f34130d1f285e0bf704bd8390b8fbf315bac75"
            "8b8800b88a5b0f1020a28ac40137d20e95c66b55768d57f9b74ca47359f890d0",
        )
        self.assertEqual(
            keys[5].hex(),
            "6b15164640f40460c555a12503179d87a3e6852b56342603fd8a1e1f2fccda49"
            "5a7aba220b80108eba737382cb300a2fa305d9333a79e7d0e042f2046ebb86e5",
        )

    def test_client_completes_standard_exchange(self):
        self.assertIsNotNone(EapPaxClient)
        client = EapPaxClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-pax",
            identity="peer",
            password=bytes(range(16)),
        )
        request = bytes.fromhex(
            "0103003c2e01000100000020000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1fdb87cdba27d9d1b026793060ec584cb7"
        )
        with patch(
            "wifit3_bridge.eap_pax_client.os.urandom",
            return_value=bytes(range(32, 64)),
        ):
            responses = client.handle_eap_packet(request)
        self.assertEqual(len(responses), 1)
        self.assertEqual(
            responses[0].hex(),
            "020300542e02000100000020202122232425262728292a2b2c2d2e2f303132"
            "333435363738393a3b3c3d3e3f0004706565720010d830c02858b69a885f6182c66ffc3298"
            "971ace1fd2358a50227dcc3f3e478d75",
        )
        self.assertEqual(client.handle_eap_packet(request), responses)
        request = bytes.fromhex(
            "0104002c2e030001000000107390e1b4115b4c7b7acb205561b5ec04"
            "38eeb95676cbdfb38d7daa1f6c7ba2aa"
        )
        responses = client.handle_eap_packet(request)
        self.assertEqual(
            responses[0].hex(),
            "0204001a2e21000100009a5eecf3900b96a55eaa9555682c2785",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03050004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(client.msk.hex(),
                         "794ab6a57958d9e6288bc5ee15f34130d1f285e0bf704bd8390b8fbf315bac75"
                         "8b8800b88a5b0f1020a28ac40137d20e95c66b55768d57f9b74ca47359f890d0")


if __name__ == "__main__":
    unittest.main()
