import hashlib
import hmac

from wifit3_bridge.eap_aka_prime_client import (
    EAP_AKA_PRIME,
    EAP_AKA_PRIME_AT_AUTN,
    EAP_AKA_PRIME_AT_CHECKCODE,
    EAP_AKA_PRIME_AT_KDF,
    EAP_AKA_PRIME_AT_KDF_INPUT,
    EAP_AKA_PRIME_AT_MAC,
    EAP_AKA_PRIME_AT_RAND,
    EAP_AKA_PRIME_SUBTYPE_CHALLENGE,
    EAP_AKA_PRIME_SUBTYPE_IDENTITY,
    EapAkaPrimeClient,
    derive_aka_prime_keys,
)
from wifit3_bridge.eap_sim_client import _attribute


def test_derive_aka_prime_keys_reference_vector():
    identity = b"6123456789012345"
    ik = bytes(range(32, 48))
    ck = bytes(range(48, 64))
    autn = bytes.fromhex("101112131415961718191a1b1c1d1e1f")
    keys = derive_aka_prime_keys(identity, ik, ck, autn, b"WLAN")
    assert keys[0].hex() == "4a308f76648559aafd99eeb51afa5b5e"
    assert keys[1].hex() == "a09f59d5bc9a1b2f9dad41c47eeb0910"
    assert keys[2].hex() == "039b821c51af99cb561e77eae8626e1d"
    assert keys[3].hex() == "74849374d6b8c1b977dc513b3d6c4a4d5d8b4cd875c1d03416076bb8f9fda188"
    assert keys[4].hex() == "b27b0ff416a46b909b71098686c1564e3b6e658e03bd74800c205e9413f23768"
    assert keys[5].hex() == "f582607ada9c048dc99eb27d4fa8047aa3195383514a3b3a497583b8ff8790406130605375beab5db39e177e0ada68d0d1c729d4838af599c61b5e1302a4a379"


def test_aka_prime_challenge_response_and_success():
    ap_mac = bytes.fromhex("001122334455")
    sta_mac = bytes.fromhex("66778899aabb")
    identity = b"6123456789012345"
    rand = bytes(range(16))
    autn = bytes.fromhex("101112131415961718191a1b1c1d1e1f")
    ik = bytes(range(32, 48))
    ck = bytes(range(48, 64))
    res = bytes(range(64, 72))
    client = EapAkaPrimeClient(
        ap_mac, sta_mac, b"aka-prime", identity=identity, rand=rand,
        autn=autn, ik=ik, ck=ck, res=res, network_name=b"WLAN")
    identity_request = bytes.fromhex("0101000c32 05000000".replace(" ", ""))
    client.handle_eap_packet(identity_request)
    checkcode = hashlib.sha256(b"".join(client.identity_messages)).digest()
    challenge = (
        bytes.fromhex("01020000") + bytes((EAP_AKA_PRIME, EAP_AKA_PRIME_SUBTYPE_CHALLENGE, 0, 0)) +
        _attribute(EAP_AKA_PRIME_AT_RAND, 0, rand) +
        _attribute(EAP_AKA_PRIME_AT_AUTN, 0, autn) +
        _attribute(EAP_AKA_PRIME_AT_KDF_INPUT, len(b"WLAN"), b"WLAN") +
        _attribute(EAP_AKA_PRIME_AT_KDF, 1) +
        _attribute(EAP_AKA_PRIME_AT_CHECKCODE, 0, checkcode) +
        _attribute(EAP_AKA_PRIME_AT_MAC, 0, b"\x00" * 16)
    )
    challenge = challenge[:2] + len(challenge).to_bytes(2, "big") + challenge[4:]
    _, _, _, k_aut, _, _, _ = derive_aka_prime_keys(identity, ik, ck, autn, b"WLAN")
    mac_offset = len(challenge) - 16
    mac = hmac.new(k_aut, challenge, hashlib.sha256).digest()[:16]
    challenge = challenge[:mac_offset] + mac
    responses = client.handle_eap_packet(challenge)
    assert len(responses) == 1
    assert client.msk is not None
    assert client.state == "SUCCESS_PENDING"
    response = responses[0]
    response_mac_offset = len(response) - 16
    response_for_mac = response[:response_mac_offset] + b"\x00" * 16
    assert hmac.new(k_aut, response_for_mac, hashlib.sha256).digest()[:16] == response[-16:]
    client.handle_eap_packet(bytes.fromhex("03030004"))
    assert client.eap_success is True
    assert client.state == "WPA"
