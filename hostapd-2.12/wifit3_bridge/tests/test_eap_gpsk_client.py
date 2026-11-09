import unittest
from unittest.mock import patch

try:
    from wifit3_bridge.eap_gpsk_client import (
        EAP_GPSK,
        EAP_REQUEST,
        EapGpskClient,
        derive_keys,
    )
except ImportError:
    EAP_GPSK = None
    EAP_REQUEST = None
    EapGpskClient = None
    derive_keys = None


class EapGpskClientTests(unittest.TestCase):
    def test_aes_key_derivation_vector(self):
        self.assertIsNotNone(derive_keys)
        keys = derive_keys(
            bytes(range(16)), bytes(range(32, 64)), bytes(range(32)),
            b"peer", b"server")
        self.assertEqual(keys[0].hex(), "f775b09134490b3511d5e6665df3bd0d")
        self.assertEqual(
            keys[1].hex(),
            "31a027e9f5fa8973a1c54c62987227def9d79a742bef975934ba2234e67d60c5"
            "613591bd37f3902f3d2b1bb21d1d8781328eb4c633f18a0f6a86f2bd71c24ab1",
        )
        self.assertEqual(
            keys[2].hex(),
            "854f5a1de9a89775bfc522959aace06300c39bd48e8ff517351d57c772f2d87f"
            "dbb4c315154dc12e30b7aba18b47640efc1a8a7b38f9f361cfe316817c9af9a9",
        )
        self.assertEqual(keys[3].hex(), "49c3da3b9b31d5f64dd5d4d20b937df1")
        self.assertEqual(keys[4].hex(), "af79b080de1b7b3e1c82f5efbb1f95bb")

    def test_client_completes_aes_exchange(self):
        self.assertIsNotNone(EapGpskClient)
        client = EapGpskClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-gpsk",
            identity="peer",
            password=bytes(range(16)),
        )
        gpsk1 = bytes.fromhex(
            "0103003633010006736572766572000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f0006000000000001"
        )
        with patch(
            "wifit3_bridge.eap_gpsk_client.os.urandom",
            return_value=bytes(range(32, 64)),
        ):
            responses = client.handle_eap_packet(gpsk1)
        self.assertEqual(
            responses[0].hex(),
            "0203007433020004706565720006736572766572202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f10111213"
            "1415161718191a1b1c1d1e1f00060000000000010000000000010000d3c8e9d31d90a926"
            "4bc1e20019d572e0",
        )
        gpsk3 = bytes.fromhex(
            "010400663303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0006736572766572"
            "000000000001000057f51d01b8f0e0fa5bc7ddd1b4388307"
        )
        responses = client.handle_eap_packet(gpsk3)
        self.assertEqual(
            responses[0].hex(),
            "02040018330400002690c1a478cb23f724b2df9ecd973427",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03050004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(client.msk.hex(),
                         "31a027e9f5fa8973a1c54c62987227def9d79a742bef975934ba2234e67d60c5"
                         "613591bd37f3902f3d2b1bb21d1d8781328eb4c633f18a0f6a86f2bd71c24ab1")

    def test_client_completes_sha256_exchange(self):
        self.assertIsNotNone(EapGpskClient)
        client = EapGpskClient(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap-gpsk-sha256",
            identity="peer",
            password=bytes(range(32)),
            cipher_specifier=2,
        )
        gpsk1 = bytes.fromhex(
            "0103003c33010006736572766572404142434445464748494a4b4c4d4e4f505152535455"
            "565758595a5b5c5d5e5f000c000000000001000000000002"
        )
        with patch(
            "wifit3_bridge.eap_gpsk_client.os.urandom",
            return_value=bytes(range(32, 64)),
        ):
            responses = client.handle_eap_packet(gpsk1)
        self.assertEqual(
            responses[0].hex(),
            "0203008a33020004706565720006736572766572202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253"
            "5455565758595a5b5c5d5e5f000c00000000000100000000000200000000000200000a9f4"
            "62eecff962375b11bf2ccbe0cc322f160e892465c7204686ff5fc8ed0cb",
        )
        gpsk3 = bytes.fromhex(
            "010400763303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0006736572766572"
            "0000000000020000e3832681cbdacfe94484f8b819b5ccd9abf607723b08aab5e17c997367e1251d"
        )
        responses = client.handle_eap_packet(gpsk3)
        self.assertEqual(
            responses[0].hex(),
            "020400283304000025c249349b802a174b8701b53e7eb468e63276dc394a87a090b50e1f9af83d1e",
        )
        self.assertEqual(client.state, "SUCCESS_PENDING")
        client.handle_eap_packet(bytes.fromhex("03050004"))
        self.assertEqual(client.state, "WPA")
        self.assertTrue(client.eap_success)
        self.assertEqual(
            client.msk.hex(),
            "150a8a30da16f063a96480ce7d6a1ec1ef6a87600fe94430e37cc385d9d38eabd1a20fb99cf55b5ee"
            "1306c6bb85f2df95eed4c29503112cbf264aaa1fe1214c7",
        )


if __name__ == "__main__":
    unittest.main()
