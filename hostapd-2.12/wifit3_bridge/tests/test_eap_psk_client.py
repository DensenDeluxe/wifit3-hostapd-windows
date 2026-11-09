import unittest
from unittest.mock import patch

try:
    from wifit3_bridge.eap_psk_client import (
        EAP_PSK,
        EAP_REQUEST,
        EapPskClient,
        derive_keys,
        key_setup,
    )
except ImportError:
    EAP_PSK = None
    EAP_REQUEST = None
    EapPskClient = None
    derive_keys = None
    key_setup = None


class EapPskClientTests(unittest.TestCase):
    def test_key_setup_and_modified_counter_mode_vectors(self):
        self.assertIsNotNone(key_setup)
        self.assertIsNotNone(derive_keys)
        ak, kdk = key_setup(bytes(range(16)))
        self.assertEqual(ak.hex(), "18b62d2c84c5e4571afc41a29db71f4d")
        self.assertEqual(kdk.hex(), "97b704350085028363924612565b9b0d")
        tek, msk, emsk = derive_keys(
            kdk, bytes.fromhex("101112131415161718191a1b1c1d1e1f"))
        self.assertEqual(tek.hex(), "4a60ff36b8435790bfc64569b677d613")
        self.assertEqual(
            msk.hex(),
            "3d57fffaa740360b2b43888b4ce41fa529e312778f822900"
            "3bb5bc14b27d6d2d881186b8ae4d7c0ad958f78c47a6fa2b"
            "548f4f4a046f44e6ab57a80eb60c7fda",
        )
        self.assertEqual(
            emsk.hex(),
            "6ece6f68c11f4478a3727a47b40e2a44b5b16a1a8c37f762"
            "22ed64675796671cf1310d5eef048aab68da1fa507338efe"
            "0a1915ec9d1bfae0f591fc058cd9fc14",
        )

    def test_client_completes_standard_four_message_exchange(self):
        self.assertIsNotNone(EapPskClient)
        client = EapPskClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-psk",
            identity="peer",
            password=bytes(range(16)),
        )
        rand_s = bytes.fromhex("00112233445566778899aabbccddeeff")
        first = bytes((EAP_REQUEST, 7, 0, 28, EAP_PSK, 0)) + rand_s + b"server"
        with patch(
            "wifit3_bridge.eap_psk_client.os.urandom",
            return_value=bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
        ):
            responses = client.handle_eap_packet(first)
        self.assertEqual(len(responses), 1)
        self.assertEqual(
            responses[0].hex(),
            "0207003a2f4000112233445566778899aabbccddeeff"
            "101112131415161718191a1b1c1d1e1f"
            "a66f8360c00935856d4263f85a873ec2"
            "70656572",
        )
        third = bytes.fromhex(
            "0108003b2f8000112233445566778899aabbccddeeff"
            "3d4dbe136cb2551847891b00a7dcebd3"
            "00000000c673775df27485e49e92acb6e7f52bb1a7"
        )
        responses = client.handle_eap_packet(third)
        self.assertEqual(len(responses), 1)
        self.assertEqual(
            responses[0].hex(),
            "0208002b2fc000112233445566778899aabbccddeeff"
            "00000001f8a79b59740e4bcceb3a4e16cd7e680664",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        self.assertEqual(client.msk.hex(),
                         "3d57fffaa740360b2b43888b4ce41fa529e312778f822900"
                         "3bb5bc14b27d6d2d881186b8ae4d7c0ad958f78c47a6fa2b"
                         "548f4f4a046f44e6ab57a80eb60c7fda")


if __name__ == "__main__":
    unittest.main()
