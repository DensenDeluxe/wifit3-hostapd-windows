import unittest

from wifit3_bridge.ccmp import (
    CCMP_BROADCAST,
    CCMP_KEY_FLAG_GROUP,
    CCMP_KEY_FLAG_PAIRWISE_NEXT,
    CCMP_KEY_FLAG_PAIRWISE_RX_TX,
    CcmpKeyStore,
    CcmpError,
    Ccmp256KeyStore,
    WPA_ALG_CCMP,
    WPA_ALG_CCMP_256,
    WPA_ALG_NONE,
    _aes_encrypt,
    _expand_key,
    aes_gcm_encrypt,
    ccmp_decrypt_mpdu,
    ccmp_encrypt_mpdu,
    ccmp256_decrypt_mpdu,
    ccmp256_encrypt_mpdu,
    gcmp_decrypt_mpdu,
    gcmp_encrypt_mpdu,
    _aad,
    _header_length,
)
from wifit3_bridge.gcmp import (
    Gcmp256KeyStore,
    GcmpKeyStore,
    WPA_ALG_GCMP,
    WPA_ALG_GCMP_256,
)


AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("0a1122334455")
DA = bytes.fromhex("0c1122334455")
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def _data_frame(payload: bytes) -> bytes:
    # Client -> AP, ToDS, normal data, sequence number 7.
    return (b"\x08\x01\x00\x00" + AP + STA + DA + b"\x70\x00" + payload)


class CcmpTests(unittest.TestCase):
    def test_aes_gcm_nist_vector(self):
        ciphertext, tag = aes_gcm_encrypt(
            bytes(16), bytes(12), b"", bytes(16))
        self.assertEqual(
            ciphertext.hex(),
            "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(
            tag.hex(),
            "ab6e47d42cec13bdf53a67b21257bddf")

    def test_aes256_gcm_nist_vector(self):
        ciphertext, tag = aes_gcm_encrypt(
            bytes(32), bytes(12), b"", bytes(16))
        self.assertEqual(
            ciphertext.hex(),
            "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(
            tag.hex(),
            "d0d1c8a799996bf0265b98b5d48ab919")

    def test_gcmp128_round_trip_and_replay_rejection(self):
        plain = _data_frame(b"gcmp-payload")
        protected = gcmp_encrypt_mpdu(plain, KEY, 1)
        self.assertEqual(protected[:2], b"\x08\x41")
        self.assertEqual(len(protected), len(plain) + 8 + 16)
        pn, decoded = gcmp_decrypt_mpdu(protected, KEY)
        self.assertEqual(pn, 1)
        self.assertEqual(decoded, plain)
        with self.assertRaises(CcmpError):
            gcmp_decrypt_mpdu(protected, KEY, minimum_pn=1)

    def test_gcmp_key_store_keeps_replay_state(self):
        store = GcmpKeyStore()
        self.assertTrue(store.install(WPA_ALG_GCMP, 0, STA, 0, b"", KEY))
        self.assertEqual(store.last_tx_tsc(STA, 0), 0)
        protected = store.encrypt(_data_frame(b"store"), STA)
        self.assertEqual(store.last_tx_tsc(STA, 0), 1)
        self.assertEqual(store.decrypt(protected, STA)[0], 1)
        with self.assertRaises(CcmpError):
            store.decrypt(protected, STA)
        self.assertNotIn(KEY.hex(), repr(store.snapshot()))

    def test_gcmp256_key_store_keeps_replay_state(self):
        store = Gcmp256KeyStore()
        key = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "102132435465768798a9bacbdcedfe0f")
        self.assertTrue(store.install(WPA_ALG_GCMP_256, 0, STA, 0, b"", key))
        protected = store.encrypt(_data_frame(b"gcmp256"), STA)
        self.assertEqual(store.decrypt(protected, STA)[0], 1)
        with self.assertRaises(CcmpError):
            store.decrypt(protected, STA)
        self.assertNotIn(key.hex(), repr(store.snapshot()))

    def test_aes128_fips_vector(self):
        self.assertEqual(
            _aes_encrypt(_expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f")),
                         bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        )

    def test_aes256_fips_vector(self):
        self.assertEqual(
            _aes_encrypt(_expand_key(bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f")),
                         bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    def test_round_trip_preserves_header_and_payload(self):
        plain = _data_frame(b"\xaa\xaa\x03\x00\x00\x00\x88\x8ehello")
        protected = ccmp_encrypt_mpdu(plain, KEY, 1)
        self.assertEqual(protected[:2], b"\x08\x41")
        self.assertNotEqual(protected, plain)
        pn, decoded = ccmp_decrypt_mpdu(protected, KEY)
        self.assertEqual(pn, 1)
        self.assertEqual(decoded, plain)

    def test_data_aad_matches_ieee_mask(self):
        plain = _data_frame(b"payload")
        header_len = _header_length(plain)
        aad = _aad(plain, header_len)
        self.assertEqual(
            aad.hex(),
            "08410211223344550a11223344550c11223344550000")
        retried = bytearray(plain)
        retried[1] |= 0x08  # Retry
        self.assertEqual(_aad(bytes(retried), header_len), aad)
        qos = bytearray(b"\x88\x01\x00\x00" + AP + STA + DA + b"\x70\x00" +
                        b"\x0f\xff" + b"payload")
        qos_aad = _aad(bytes(qos), _header_length(bytes(qos)))
        ordered = bytearray(qos)
        ordered[1] |= 0x80  # Order / +HTC flag in the FC field
        # Header length rejects a real HTC field. The AAD mask still clears
        # Order on the same 26-octet QoS header, so the two AADs match.
        self.assertEqual(_aad(bytes(ordered), 26), qos_aad)
        self.assertEqual(qos_aad[:2], b"\x88\x41")
        self.assertEqual(qos_aad[-2:], b"\x0f\x00")

    def test_ccmp256_matches_aesccm_reference_vector(self):
        plain = (bytes.fromhex(
            "080100000211223344550a11223344550c11223344557000") +
                b"payload-ccmp256")
        protected = ccmp256_encrypt_mpdu(plain, bytes(32), 1)
        # Independent AES-CCM (cryptography.AESCCM, 13-octet nonce, 16-octet
        # tag) over the IEEE AAD produces the same ciphertext and MIC.
        self.assertEqual(
            protected.hex(),
            "084100000211223344550a11223344550c11223344557000"
            "0100000000000000"
            "a69f3fb5c5236c34d7fcd0c14c944f"
            "de5528a68b32cf98ab31a125083735be")
        pn, decoded = ccmp256_decrypt_mpdu(protected, bytes(32))
        self.assertEqual(pn, 1)
        self.assertEqual(decoded, plain)

    def test_last_used_pn_is_little_endian_and_trails_the_next_pn(self):
        store = CcmpKeyStore()
        self.assertIsNone(store.last_tx_tsc(STA, 0))
        self.assertTrue(store.install(WPA_ALG_CCMP, 0, STA, 0, b"", KEY))
        self.assertEqual(store.last_tx_tsc(STA, 0), 0)
        store.encrypt(_data_frame(b"one"), STA)
        self.assertEqual(store.last_tx_tsc(STA, 0), 1)
        sequenced = CcmpKeyStore()
        # 5 as a little-endian PN. A big-endian read would be 5 << 40.
        self.assertTrue(sequenced.install(
            WPA_ALG_CCMP, 0, STA, 0, (5).to_bytes(6, "little"), KEY))
        self.assertEqual(sequenced.last_tx_tsc(STA, 0), 4)
        swapped = CcmpKeyStore()
        self.assertTrue(swapped.install(
            WPA_ALG_CCMP, 0, STA, 0, b"\x00\x00\x00\x00\x00\x05", KEY))
        self.assertEqual(swapped.last_tx_tsc(STA, 0), (5 << 40) - 1)

    def test_ccmp256_key_store_keeps_replay_state(self):
        store = Ccmp256KeyStore()
        key = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "102132435465768798a9bacbdcedfe0f")
        self.assertTrue(store.install(WPA_ALG_CCMP_256, 0, STA, 0, b"", key))
        protected = store.encrypt(_data_frame(b"ccmp256"), STA)
        self.assertEqual(store.decrypt(protected, STA)[0], 1)
        with self.assertRaises(CcmpError):
            store.decrypt(protected, STA)
        self.assertNotIn(key.hex(), repr(store.snapshot()))

    def test_mic_failure_and_replay_fail_closed(self):
        protected = bytearray(ccmp_encrypt_mpdu(_data_frame(b"payload"), KEY, 9))
        protected[-1] ^= 0x01
        with self.assertRaises(CcmpError):
            ccmp_decrypt_mpdu(bytes(protected), KEY)
        good = ccmp_encrypt_mpdu(_data_frame(b"payload"), KEY, 9)
        with self.assertRaises(CcmpError):
            ccmp_decrypt_mpdu(good, KEY, minimum_pn=9)

    def test_rejects_malformed_or_exhausted_packet_number(self):
        with self.assertRaises(CcmpError):
            ccmp_encrypt_mpdu(_data_frame(b"x"), KEY, 1 << 48)
        with self.assertRaises(CcmpError):
            ccmp_decrypt_mpdu(b"\x08\x41" + bytes(30), KEY)

    def test_key_store_keeps_key_material_private_and_replays_fail(self):
        store = CcmpKeyStore()
        self.assertTrue(store.install(WPA_ALG_CCMP, 0, STA, 0, b"", KEY))
        protected = store.encrypt(
            _data_frame(b"payload").replace(AP + STA + DA, STA + AP + AP), STA
        )
        self.assertIn("0a:11:22:33:44:55/0", store.snapshot())
        self.assertNotIn(KEY.hex(), repr(store.snapshot()))
        # The AP's RX lookup is keyed by the client source address. Install the
        # same key in the group slot only to exercise a rejected unknown source.
        with self.assertRaises(CcmpError):
            store.decrypt(protected, AP)
        self.assertTrue(store.install(WPA_ALG_CCMP, 0, CCMP_BROADCAST,
                                      CCMP_KEY_FLAG_GROUP, b"", KEY))
        with self.assertRaises(CcmpError):
            store.decrypt(protected, AP)
        self.assertTrue(store.install(WPA_ALG_NONE, 0, STA, 0, b"", b""))

    def test_pairwise_next_key_promotes_without_resetting_replay_state(self):
        store = CcmpKeyStore()
        self.assertTrue(store.install(
            WPA_ALG_CCMP, 0, STA, CCMP_KEY_FLAG_PAIRWISE_NEXT, b"", KEY))

        first = ccmp_encrypt_mpdu(_data_frame(b"first"), KEY, 1)
        self.assertEqual(store.decrypt(first, STA)[0], 1)
        self.assertTrue(store.install(
            WPA_ALG_CCMP, 0, STA, CCMP_KEY_FLAG_PAIRWISE_RX_TX, b"", KEY))

        with self.assertRaises(CcmpError):
            store.decrypt(first, STA)
        second = ccmp_encrypt_mpdu(_data_frame(b"second"), KEY, 2)
        self.assertEqual(store.decrypt(second, STA)[0], 2)
        snapshot = store.snapshot()["0a:11:22:33:44:55/0"]
        self.assertEqual(snapshot["flags"], CCMP_KEY_FLAG_PAIRWISE_RX_TX)
        self.assertEqual(snapshot["rx_pn"], 2)


if __name__ == "__main__":
    unittest.main()
