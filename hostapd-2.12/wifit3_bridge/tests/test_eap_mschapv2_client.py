import unittest
from unittest.mock import patch

from wifit3_bridge.eap_mschapv2_client import (
    EAP_MSCHAPV2,
    EAP_RESPONSE,
    generate_authenticator_response,
    generate_nt_response,
    get_asymmetric_start_key,
    get_master_key,
    hash_nt_password_hash,
    nt_password_hash,
    EapMschapv2Client,
)


class EapMschapv2ClientTests(unittest.TestCase):
    def test_rfc2759_crypto_vector(self):
        username = b"User"
        password = b"clientPass"
        auth_challenge = bytes.fromhex("5b5d7c7d7b3f2f3e3c2c602132262628")
        peer_challenge = bytes.fromhex("21402324255e262a28295f2b3a337c7e")

        password_hash = nt_password_hash(password)
        self.assertEqual(
            password_hash.hex(),
            "44ebba8d5312b8d611474411f56989ae",
        )
        nt_response = generate_nt_response(
            auth_challenge, peer_challenge, username, password)
        self.assertEqual(
            nt_response.hex(),
            "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df",
        )
        password_hash_hash = hash_nt_password_hash(password_hash)
        self.assertEqual(
            password_hash_hash.hex(),
            "41c00c584bd2d91c4017a2a12fa59f3f",
        )
        self.assertEqual(
            generate_authenticator_response(
                password, peer_challenge, auth_challenge, username,
                nt_response).hex(),
            "407a5589115fd0d6209f510fe9c04566932cda56",
        )
        master_key = get_master_key(password_hash_hash, nt_response)
        self.assertEqual(
            master_key.hex(),
            "fdece3717a8c838cb388e527ae3cdd31",
        )
        self.assertEqual(
            get_asymmetric_start_key(master_key, send=True, server=True).hex(),
            "8b7cdc149b993a1ba118cb153f56dccb",
        )

    def test_mschapv2_challenge_emits_response_with_fixed_peer_challenge(self):
        client = EapMschapv2Client(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="User",
            password="clientPass",
        )
        auth_challenge = bytes.fromhex("5b5d7c7d7b3f2f3e3c2c602132262628")
        request = bytes((1, 7, 0, 32, EAP_MSCHAPV2, 1, 7, 0, 27, 16))
        request += auth_challenge + b"server"
        with patch(
            "wifit3_bridge.eap_mschapv2_client.os.urandom",
            return_value=bytes.fromhex("21402324255e262a28295f2b3a337c7e"),
        ):
            responses = client._handle_eap(request)
        self.assertEqual(len(responses), 1)
        eap = client._eap_body(responses[0])
        self.assertEqual(eap[:2], bytes((EAP_RESPONSE, 7)))
        self.assertEqual(eap[4], EAP_MSCHAPV2)
        self.assertEqual(eap[5], 2)
        self.assertEqual(eap[6], 7)
        self.assertEqual(eap[9], 49)
        self.assertEqual(eap[10:26], bytes.fromhex(
            "21402324255e262a28295f2b3a337c7e"))
        self.assertEqual(eap[34:58], bytes.fromhex(
            "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df"))
        self.assertEqual(eap[58:], b"\x00User")

    def test_success_validates_authenticator_response_and_starts_wpa(self):
        client = EapMschapv2Client(
            b"\x00\x11\x22\x33\x44\x55",
            b"\x66\x77\x88\x99\xaa\xbb",
            "wifit3-eap",
            identity="User",
            password="clientPass",
        )
        auth_challenge = bytes.fromhex("5b5d7c7d7b3f2f3e3c2c602132262628")
        challenge = bytes((1, 7, 0, 32, EAP_MSCHAPV2, 1, 7, 0, 27, 16))
        challenge += auth_challenge + b"server"
        with patch(
            "wifit3_bridge.eap_mschapv2_client.os.urandom",
            return_value=bytes.fromhex("21402324255e262a28295f2b3a337c7e"),
        ):
            client._handle_eap(challenge)

        message = b"S=" + client.authenticator_response.hex().upper().encode() + b" M=OK"
        success = bytes((1, 8, 0, 9 + len(message), EAP_MSCHAPV2, 3, 7))
        success += (4 + len(message)).to_bytes(2, "big") + message
        responses = client._handle_eap(success)
        self.assertEqual(client.state, "MSCHAPV2_SUCCESS")
        self.assertEqual(client.last_error, None)
        response = client._eap_body(responses[0])
        self.assertEqual(response[:5], bytes((EAP_RESPONSE, 8, 0, 6, EAP_MSCHAPV2)))
        self.assertEqual(response[5:], bytes((3,)))

        client._handle_eap(bytes((3, 9, 0, 4)))
        self.assertTrue(client.eap_success)
        self.assertEqual(client.state, "WPA")
        self.assertIsNotNone(client.wpa_client)
        self.assertEqual(client.pmk, client.msk[:32])


if __name__ == "__main__":
    unittest.main()
