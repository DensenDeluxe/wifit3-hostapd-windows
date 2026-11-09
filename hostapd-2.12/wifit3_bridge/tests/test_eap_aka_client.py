import unittest

try:
    from wifit3_bridge.eap_aka_client import (
        EAP_AKA,
        EapAkaClient,
        derive_aka_keys,
    )
except ImportError:
    EAP_AKA = None
    EapAkaClient = None
    derive_aka_keys = None


class EapAkaClientTests(unittest.TestCase):
    def test_aka_key_derivation_vector(self):
        self.assertIsNotNone(derive_aka_keys)
        keys = derive_aka_keys(
            b"0123456789012345",
            bytes(range(32, 48)),
            bytes(range(48, 64)),
        )
        self.assertEqual(keys[0].hex(), "40b33f305e6da2fce82caee57abcee2ba215a9fb")
        self.assertEqual(keys[1].hex(), "68d645dc3d68304f60558100db2f4b65")
        self.assertEqual(keys[2].hex(), "286dd63e2d7f94c1b5b3098e2ea84239")
        self.assertEqual(
            keys[3].hex(),
            "c19067f776dd040d9778922e6aa8be43f5a29d9d996aa288f6fc897b5887694ecea9b88f40ea74824b0e61e797ed634823f9d131c5f0983ce10dfb27bb7a491c",
        )

    def test_client_completes_aka_exchange(self):
        self.assertIsNotNone(EapAkaClient)
        client = EapAkaClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-aka",
            identity="0123456789012345",
            rand=bytes(range(16)),
            autn=bytes(range(16, 32)),
            ik=bytes(range(32, 48)),
            ck=bytes(range(48, 64)),
            res=bytes(range(64, 72)),
        )
        identity_request = bytes.fromhex("0101000c170500000d010000")
        responses = client.handle_eap_packet(identity_request)
        self.assertEqual(
            responses[0].hex(),
            "0201001c170500000e05001030313233343536373839303132333435",
        )
        challenge = bytes.fromhex(
            "010200601701000001050000000102030405060708090a0b0c0d0e0f02050000101112131415161718191a1b1c1d1e1f86060000fb026cfe88d96870923c0325284722ad6b625e77880100000b0500001725722b17266b5694adfe6a2683c745"
        )
        responses = client.handle_eap_packet(challenge)
        self.assertEqual(
            responses[0].hex(),
            "020200401701000003030040404142434445464786060000fb026cfe88d96870923c0325284722ad6b625e770b050000ca46a88f4dc3a1243534da8558084afc",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03030004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(
            client.msk.hex(),
            "c19067f776dd040d9778922e6aa8be43f5a29d9d996aa288f6fc897b5887694ecea9b88f40ea74824b0e61e797ed634823f9d131c5f0983ce10dfb27bb7a491c",
        )


if __name__ == "__main__":
    unittest.main()
