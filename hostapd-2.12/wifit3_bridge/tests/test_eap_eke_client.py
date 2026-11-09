import hashlib
import hmac

import pytest

from wifit3_bridge.eap_eke_client import (
    EAP_EKE_DHGROUP_EKE_14,
    EAP_EKE_MAC_HMAC_SHA1,
    EAP_EKE_PRF_HMAC_SHA1,
    EapEkeSession,
    auth,
    derive_key,
    derive_ka,
    derive_ke_ki,
    derive_msk,
    dh_component,
    dh_parameters,
    dh_shared_secret,
    decrypt_protected,
    prf_plus,
    protect,
)


def test_prf_plus_matches_hmac_chain():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    data = b"EAP-EKE test vector"
    first = hmac.new(key, data + b"\x01", hashlib.sha1).digest()
    second = hmac.new(key, first + data + b"\x02", hashlib.sha1).digest()
    assert prf_plus("sha1", key, data, 37) == (first + second)[:37]


def test_dh_component_and_shared_secret_are_symmetric():
    session = EapEkeSession(3, 1, EAP_EKE_PRF_HMAC_SHA1,
                            EAP_EKE_MAC_HMAC_SHA1)
    prime, generator, length = dh_parameters(EAP_EKE_DHGROUP_EKE_14)
    private_a = 0x123456789
    private_b = 0x234567891
    public_a = pow(generator, private_a, prime).to_bytes(length, "big")
    public_b = pow(generator, private_b, prime).to_bytes(length, "big")
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    component_a = dh_component(session, key, public_a, iv=bytes(range(16)))
    component_b = dh_component(session, key, public_b, iv=bytes(range(16, 32)))
    assert dh_shared_secret(session, key, private_a, component_b) == dh_shared_secret(
        session, key, private_b, component_a)


def test_key_and_export_derivation_is_deterministic():
    session = EapEkeSession(3, 1, EAP_EKE_PRF_HMAC_SHA1,
                            EAP_EKE_MAC_HMAC_SHA1)
    server_id = b"eap-eke.invalid"
    peer_id = b"wifit3-eke"
    password = b"wifit3-password"
    key = derive_key(session, password, server_id, peer_id)
    session.shared_secret = bytes.fromhex(
        "00112233445566778899aabbccddeeff0011223344556677")
    assert len(key) == 16
    ke, ki = derive_ke_ki(session, server_id, peer_id)
    nonce_p = bytes(range(16))
    nonce_s = bytes(range(16, 32))
    ka = derive_ka(session, server_id, peer_id, nonce_p, nonce_s)
    msk, emsk = derive_msk(session, server_id, peer_id, nonce_s, nonce_p)
    assert len(ke) == 16
    assert len(ki) == 20
    assert len(ka) == 20
    assert len(msk) == 64
    assert len(emsk) == 64
    assert auth(session, ka, "EAP-EKE server", b"messages") == hmac.new(
        ka, b"EAP-EKE servermessages", hashlib.sha1).digest()


def test_protected_payload_roundtrip_and_integrity():
    session = EapEkeSession(3, 1, EAP_EKE_PRF_HMAC_SHA1,
                            EAP_EKE_MAC_HMAC_SHA1)
    session.ke = bytes.fromhex("00112233445566778899aabbccddeeff")
    session.ki = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
    payload = b"EAP-EKE protected payload"
    protected = protect(session, payload, iv=bytes(range(16)), padding=bytes(7))
    assert decrypt_protected(session, protected) == payload + bytes(7)
    invalid = bytearray(protected)
    invalid[-1] ^= 1
    with pytest.raises(ValueError):
        decrypt_protected(session, bytes(invalid))
