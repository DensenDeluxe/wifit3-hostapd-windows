import hashlib
import hmac

from wifit3_bridge.eap_ikev2_client import (
    IKEV2_DH_GROUP2,
    IKEV2_ENCR_AES_CBC,
    IKEV2_INTEG_HMAC_SHA1_96,
    IKEV2_PRF_HMAC_SHA1,
    build_sa_payload,
    derive_ikev2_keys,
    prf_plus,
)


def test_prf_plus_uses_rfc4306_first_block_convention():
    key = bytes(range(20))
    data = b"ikev2-test"
    expected = hmac.new(key, data + b"\x01", hashlib.sha1).digest()
    assert prf_plus(key, data, 20) == expected


def test_ikev2_key_schedule_shapes():
    keys = derive_ikev2_keys(
        b"N" * 16,
        b"R" * 16,
        b"I" * 8,
        b"J" * 8,
        b"S" * 128,
        IKEV2_PRF_HMAC_SHA1,
        IKEV2_INTEG_HMAC_SHA1_96,
        IKEV2_ENCR_AES_CBC,
    )
    assert {name: len(value) for name, value in keys.items()} == {
        "sk_d": 20,
        "sk_ai": 20,
        "sk_ar": 20,
        "sk_ei": 16,
        "sk_er": 16,
        "sk_pi": 20,
        "sk_pr": 20,
    }


def test_sa_payload_contains_hostapd_default_proposal():
    payload = build_sa_payload()
    assert payload[:4] == bytes((0, 0, 0, len(payload)))
    assert payload[4:12] == bytes((0, 0, 0, 0, 1, 1, 0, 4))
    assert payload[12 + 6:12 + 8] == IKEV2_ENCR_AES_CBC.to_bytes(2, "big")
    assert IKEV2_DH_GROUP2.to_bytes(2, "big") in payload
