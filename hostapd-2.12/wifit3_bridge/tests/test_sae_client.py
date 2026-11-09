import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from wifit3_bridge.sae_client import (
    SAE_PK_RSNX_IE, SaePasswordClient, _derive_pwe_h2e, sae_auth_frame)
from wifit3_bridge.examples.windows_wpa_smoke import SAE_EXT_KEY_RSN_IE


AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("02aabbccddee")
PASSWORD = b"wifit3-test-pass"
SAE_EXT_KEY_AKM_IE = bytes.fromhex("ff0572000fac18")


def test_group19_matches_hostapd_annex_j10_vector():
    addr1 = bytes.fromhex("4d3f2fffe387")
    addr2 = bytes.fromhex("a5d8aa958e3c")
    client = SaePasswordClient(
        addr1, addr2, b"mekmitasdigoat",
        rand=int.from_bytes(bytes.fromhex(
            "992465fd3daa3c60aa6565b7f62a2a7f"
            "2e12dd12f198faf4fbed89d7ff1ace94"), "big"),
        mask=int.from_bytes(bytes.fromhex(
            "9507a90f777a044d6a0830b91ea3d5dd"
            "70bece44e1acffb86983b5e1bf9fb322"), "big"),
    )
    expected_commit = bytes.fromhex(
        "13002e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e"
        "5c2871b774f6c2575c65d5ad9e00829707aa36ba8b859738"
        "fc961d08243505f47c035376d7ac4bc8d7b95083bf43827d"
        "0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325"
        "dbe1")
    assert client.start() == expected_commit

    peer_commit = bytes.fromhex(
        "1300591b96f3397fb945100848e7b550543b6720d88337ee"
        "93fc49fd6df7e08b5223e71b9bb048d3873f20556953a96c"
        "91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8"
        "ef5537858074db06687032399862999b511e0a1552a5fea3"
        "17c2")
    client.process_commit(peer_commit)
    assert client.kck == bytes.fromhex(
        "1e733f6d9bd53256287304338831b09a39406d121017073a"
        "5c30db36f36cb81a")
    assert client.pmk == bytes.fromhex(
        "4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63"
        "605ba663f8a7fe59")
    assert client.pmkid == bytes.fromhex(
        "8747a600eea3f9f22475df58ca1e5498")


def test_group19_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD,
        rand=5,
        mask=7,
    )
    sta = SaePasswordClient(
        STA, AP, PASSWORD,
        rand=11,
        mask=13,
    )

    ap_commit = ap.start()
    sta_commit = sta.start()
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group20_legacy_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, group=20, rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, group=20, rand=11, mask=13)

    ap_commit = ap.start()
    sta_commit = sta.start()
    assert len(ap_commit) == 2 + 48 + 96
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group20_h2e_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, group=20, ssid=b"wifit3-p384", h2e=True,
        rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, group=20, ssid=b"wifit3-p384", h2e=True,
        rand=11, mask=13)

    ap_commit = ap.start()
    sta_commit = sta.start()
    assert len(ap_commit) == 2 + 48 + 96
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pwe == sta.pwe
    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group21_legacy_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, group=21, rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, group=21, rand=11, mask=13)

    ap_commit = ap.start()
    sta_commit = sta.start()
    assert len(ap_commit) == 2 + 66 + 132
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group21_h2e_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, group=21, ssid=b"wifit3-p521", h2e=True,
        rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, group=21, ssid=b"wifit3-p521", h2e=True,
        rand=11, mask=13)

    ap_commit = ap.start()
    sta_commit = sta.start()
    assert len(ap_commit) == 2 + 66 + 132
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pwe == sta.pwe
    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group19_h2e_peers_derive_the_same_pt_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, ssid=b"wifit3-h2e", h2e=True, rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, ssid=b"wifit3-h2e", h2e=True, rand=11, mask=13)

    ap_commit = ap.start()
    sta_commit = sta.start()
    ap_confirm = ap.process_commit(sta_commit)
    sta_confirm = sta.process_commit(ap_commit)

    assert ap.pwe == sta.pwe
    assert ap.pmk == sta.pmk
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_h2e_commit_includes_password_identifier_extension():
    client = SaePasswordClient(
        AP, STA, PASSWORD, ssid=b"wifit3-h2e", h2e=True,
        password_identifier=b"lab-id", rand=5, mask=7)
    assert client.start()[98:] == bytes.fromhex("ff0721") + b"lab-id"


def test_sae_ext_key_h2e_commit_includes_akm_suite_selector_extension():
    client = SaePasswordClient(
        AP, STA, PASSWORD, ssid=b"wifit3-ext-key", h2e=True,
        sae_ext_key=True, rand=5, mask=7)

    assert client.start()[98:] == SAE_EXT_KEY_AKM_IE


def test_sae_ext_key_association_rsne_has_akm_24_at_the_akm_suite_offset():
    assert SAE_EXT_KEY_RSN_IE == bytes.fromhex(
        "30140100000fac040100000fac040100000fac18c000")


def test_sae_ext_key_group19_peers_derive_the_same_pmk_and_confirm():
    ap = SaePasswordClient(
        AP, STA, PASSWORD, ssid=b"wifit3-ext-key", h2e=True,
        sae_ext_key=True, rand=5, mask=7)
    sta = SaePasswordClient(
        STA, AP, PASSWORD, ssid=b"wifit3-ext-key", h2e=True,
        sae_ext_key=True, rand=11, mask=13)

    ap_confirm = ap.process_commit(sta.start())
    sta_confirm = sta.process_commit(ap.start())

    assert ap.pmk == sta.pmk
    assert ap.pmk is not None and len(ap.pmk) == 32
    assert ap.verify_confirm(sta_confirm)
    assert sta.verify_confirm(ap_confirm)


def test_group19_h2e_matches_hostapd_pt_pwe_vector():
    pwe = _derive_pwe_h2e(
        bytes.fromhex("00095b66ec1e"), bytes.fromhex("000b6bd90246"),
        b"byteme", b"mekmitasdigoat", b"psk4internet")
    assert pwe == (
        int.from_bytes(bytes.fromhex(
            "c93049b9e64000f848201649e999f2b5c22dea69b5632c9d"
            "f4d633b8aa1f6c1e"), "big"),
        int.from_bytes(bytes.fromhex(
            "73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382"
            "ccb f33e614ff59a0".replace(" ", "")), "big"),
    )


def test_h2e_auth_commit_uses_hash_to_element_status_code():
    frame = sae_auth_frame(AP, STA, 1, b"commit", status=126)
    assert frame[24:30] == bytes.fromhex("030001007e00")


def test_sae_pk_uses_status_127_and_pk_rsnxe():
    client = SaePasswordClient(
        AP, STA, b"5a6p-v5wc-tscv", ssid=b"wifit3-pk", h2e=True,
        sae_pk=True, rand=5, mask=7)
    frame = sae_auth_frame(AP, STA, 1, client.start(), status=127)
    assert frame[24:30] == bytes.fromhex("030001007f00")
    assert SAE_PK_RSNX_IE == bytes.fromhex("f40160")


@pytest.mark.parametrize("group", (19, 20, 21))
def test_sae_pk_confirm_verifies_fingerprint_aes_siv_and_keyauth(group):
    password = b"5a6p-v5wc-tscv"
    ssid = b"wifit3-pk"
    ap = SaePasswordClient(AP, STA, password, ssid=ssid, h2e=True,
                           sae_pk=True, group=group, rand=5, mask=7)
    sta = SaePasswordClient(STA, AP, password, ssid=ssid, h2e=True,
                            sae_pk=True, group=group, rand=11, mask=13)
    ap_confirm = ap.process_commit(sta.start())
    sta.process_commit(ap.start())

    key_der = base64.b64decode(
        b"MHcCAQEEIFTCUPy0YecgOEDEhmP8c/gtFDDHxxTwwym1f3AKB2eeoAoGCCqGSM49AwEHoUQDQgAEFbCY+xAZk6agyTSmOH+UpX+3sZbV+MVGSretuDKmiq7Shxn1wQdGJ+UzHE2UjHrcdujYCxU0tWznujeq31O79w==")
    private = serialization.load_der_private_key(key_der, password=None)
    uncompressed_der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    key_offset = uncompressed_der.index(b"\x03\x42\x00\x04")
    x_coordinate = uncompressed_der[key_offset + 4:key_offset + 36]
    y_coordinate = uncompressed_der[key_offset + 36:key_offset + 68]
    public_der = (bytes((0x30, 0x39)) + uncompressed_der[2:key_offset] +
                  bytes((0x03, 0x22, 0, 2 + (y_coordinate[-1] & 1))) +
                  x_coordinate)
    modifier = bytes.fromhex("6c9d3b7aa53acc1e4b155d3dafe52d5c")
    prime_len = ap.curve.prime_len
    order_len = ap.curve.order_len
    signed = (ap.element[0].to_bytes(prime_len, "big") +
              ap.element[1].to_bytes(prime_len, "big") +
              sta.element[0].to_bytes(prime_len, "big") +
              sta.element[1].to_bytes(prime_len, "big") +
              ap.scalar.to_bytes(order_len, "big") +
              sta.scalar.to_bytes(order_len, "big") + modifier + public_der + AP + STA)
    digest = hashlib.sha256(signed).digest()
    signature = private.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    encrypted_modifier = AESSIV(sta.kek).encrypt(modifier, [])
    ies = (b"\xff" + bytes((2 + len(public_der), 12, 2)) + public_der +
           b"\xff" + bytes((1 + len(signature), 3)) + signature +
           b"\xdd" + bytes((4 + len(encrypted_modifier),)) +
           bytes.fromhex("506f9a1f") + encrypted_modifier)
    assert sta.verify_confirm(ap_confirm + ies)


def test_group19_rejects_a_tampered_confirm():
    ap = SaePasswordClient(AP, STA, PASSWORD, rand=5, mask=7)
    sta = SaePasswordClient(STA, AP, PASSWORD, rand=11, mask=13)
    ap_commit = ap.start()
    sta_commit = sta.start()
    ap.process_commit(sta_commit)
    sta_confirm = bytearray(sta.process_commit(ap_commit))
    sta_confirm[-1] ^= 0x01

    assert not ap.verify_confirm(bytes(sta_confirm))
