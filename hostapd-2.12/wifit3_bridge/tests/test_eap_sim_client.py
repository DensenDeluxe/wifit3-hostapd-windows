import unittest
from unittest.mock import patch

try:
    from wifit3_bridge.eap_sim_client import (
        EapSimClient,
        derive_keys,
        fips186_2_prf,
    )
except ImportError:
    EapSimClient = None
    derive_keys = None
    fips186_2_prf = None


class EapSimClientTests(unittest.TestCase):
    def test_fips186_2_prf_vector(self):
        self.assertIsNotNone(fips186_2_prf)
        seed = bytes.fromhex(
            "bd029bbe7f51960bcf9edb2b61f06f0feb5a38b6"
        )
        self.assertEqual(
            fips186_2_prf(seed, 40).hex(),
            "2070b3223dba372fde1c0ffc7b2e3b498b2606143c6c18bacb0f6c55babb13788e20d737a3275116",
        )

    def test_eap_sim_key_derivation_vector(self):
        self.assertIsNotNone(derive_keys)
        keys = derive_keys(
            b"1123456789012345",
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            [
                (
                    bytes(range(16)),
                    bytes.fromhex("a0a1a2a3a4a5a6a7"),
                    bytes.fromhex("d0d1d2d3"),
                ),
                (
                    bytes(range(16, 32)),
                    bytes.fromhex("b0b1b2b3b4b5b6b7"),
                    bytes.fromhex("e0e1e2e3"),
                ),
            ],
            b"\x00\x01",
            b"\x00\x01",
        )
        self.assertEqual(keys[0].hex(), "98eab9b966efda8b98b5ca956f6189a040f83c61")
        self.assertEqual(keys[1].hex(), "c00d3f554d7c96ae52fb83c915a911fe")
        self.assertEqual(keys[2].hex(), "c47e837ba635f2571d6c8f5d04808235")
        self.assertEqual(
            keys[3].hex(),
            "ab4aedef0c971af243baa6d0483d2d7809cced3a5ca131f024082c665cf84c55033a6581a7932edeeaa05d19b47d60658e7a9bfc8e83e9cf7d2ae570dc2f624c",
        )

    def test_client_completes_two_triplet_exchange(self):
        self.assertIsNotNone(EapSimClient)
        client = EapSimClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-sim",
            identity="1123456789012345",
            triplets=[
                (
                    bytes(range(16)),
                    bytes.fromhex("a0a1a2a3a4a5a6a7"),
                    bytes.fromhex("d0d1d2d3"),
                ),
                (
                    bytes(range(16, 32)),
                    bytes.fromhex("b0b1b2b3b4b5b6b7"),
                    bytes.fromhex("e0e1e2e3"),
                ),
            ],
        )
        start = bytes.fromhex(
            "01010014120a00000d0100000f02000200010000"
        )
        with patch(
            "wifit3_bridge.eap_sim_client.os.urandom",
            return_value=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ):
            responses = client.handle_eap_packet(start)
        self.assertEqual(
            responses[0].hex(),
            "02010034120a00000e050010313132333435363738393031323334350705000000112233445566778899aabbccddeeff10010001",
        )
        challenge = bytes.fromhex(
            "01020040120b000001090000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0b0500005ff2551627ff28a296d4a17a6d2a205a"
        )
        responses = client.handle_eap_packet(challenge)
        self.assertEqual(
            responses[0].hex(),
            "0202001c120b00000b050000b216a11d0e06cce263e54ea419df4de4",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03050004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(
            client.msk.hex(),
            "ab4aedef0c971af243baa6d0483d2d7809cced3a5ca131f024082c665cf84c55033a6581a7932edeeaa05d19b47d60658e7a9bfc8e83e9cf7d2ae570dc2f624c",
        )


if __name__ == "__main__":
    unittest.main()
