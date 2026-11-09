import pytest

from wifit3_bridge.bip import (
    BipError,
    BipKeyStore,
    WPA_ALG_BIP_CMAC_128,
    WPA_ALG_BIP_CMAC_256,
    WPA_ALG_BIP_GMAC_128,
    WPA_ALG_BIP_GMAC_256,
    bip_cmac_protect,
    bip_cmac_verify,
    bip_cmac256_protect,
    bip_cmac256_verify,
    bip_gmac_protect,
    bip_gmac_verify,
    aes_cmac,
)
from wifit3_bridge.ccmp import CCMP_BROADCAST


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("02aabbccddee")


def _action_frame(body: bytes = b"\x08\x01test") -> bytes:
    # Robust 802.11 action frame: category 8 (SA Query) plus payload.
    return (b"\xd0\x00\x00\x00" + STA + AP + AP + b"\x10\x00" + body)


def test_aes_cmac_matches_rfc4493_single_block_vector():
    assert aes_cmac(KEY, bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) == bytes.fromhex(
        "070a16b46b4d4144f79bdd9dd04a287c"
    )


def test_aes_cmac_256_matches_reference_vector():
    key = bytes.fromhex(
        "2b7e151628aed2a6abf7158809cf4f3c"
        "000102030405060708090a0b0c0d0e0f")
    message = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a") + b"bip256"
    assert aes_cmac(key, message).hex() == "7e4c6fd6f47bb03cf1b3911057048e9e"


def test_bip_cmac_protect_appends_mmie_and_verifies():
    protected = bip_cmac_protect(_action_frame(), KEY, key_id=4, ipn=1)

    assert protected[1] & 0x40
    assert protected[-18:-16] == b"\x4c\x10"
    assert protected[-16:-14] == b"\x04\x00"
    assert protected[-14:-8] == b"\x01\x00\x00\x00\x00\x00"
    assert bip_cmac_verify(protected, KEY, minimum_ipn=0, expected_key_id=4) == 1


def test_bip_cmac_rejects_tampering_and_replay():
    protected = bip_cmac_protect(_action_frame(), KEY, key_id=4, ipn=9)
    tampered = bytearray(protected)
    tampered[-1] ^= 1

    with pytest.raises(BipError):
        bip_cmac_verify(bytes(tampered), KEY, minimum_ipn=0, expected_key_id=4)
    with pytest.raises(BipError):
        bip_cmac_verify(protected, KEY, minimum_ipn=9, expected_key_id=4)


def test_bip_cmac256_matches_reference_and_rejects_replay():
    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f")
    protected = bip_cmac256_protect(_action_frame(), key, key_id=4, ipn=1)
    assert protected[-16:].hex() == "b13e8223e30062a397bcff446a6ed10d"
    assert bip_cmac256_verify(protected, key, minimum_ipn=0, expected_key_id=4) == 1
    with pytest.raises(BipError):
        bip_cmac256_verify(protected, key, minimum_ipn=1, expected_key_id=4)


def test_bip_gmac_128_and_256_match_reference_tags():
    key128 = bytes.fromhex("00112233445566778899aabbccddeeff")
    key256 = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f")
    protected128 = bip_gmac_protect(_action_frame(), key128, key_id=4, ipn=1)
    protected256 = bip_gmac_protect(_action_frame(), key256, key_id=4, ipn=1)
    assert protected128[-16:].hex() == "ab76da20e15bc2e9d625eae0fb3c7dac"
    assert protected256[-16:].hex() == "e16123c004220feafa658f3f71f26d5e"
    assert bip_gmac_verify(protected128, key128, minimum_ipn=0, expected_key_id=4) == 1
    assert bip_gmac_verify(protected256, key256, minimum_ipn=0, expected_key_id=4) == 1


@pytest.mark.parametrize(
    ("algorithm", "key"),
    [
        (WPA_ALG_BIP_CMAC_128, KEY),
        (WPA_ALG_BIP_GMAC_128, bytes.fromhex("00112233445566778899aabbccddeeff")),
        (WPA_ALG_BIP_GMAC_256, bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "102132435465768798a9bacbdcedfe0f")),
        (WPA_ALG_BIP_CMAC_256, bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "102132435465768798a9bacbdcedfe0f")),
    ],
)
def test_bip_key_store_verifies_all_enabled_mmie_sizes(algorithm, key):
    store = BipKeyStore()
    assert store.install(algorithm, 4, CCMP_BROADCAST, 0x10, b"", key)
    assert store.last_tx_tsc(4) == 0
    protected = store.protect(_action_frame())
    assert store.last_tx_tsc(4) == 1
    assert store.verify(protected) == 1
    with pytest.raises(BipError, match="replay"):
        store.verify(protected)
