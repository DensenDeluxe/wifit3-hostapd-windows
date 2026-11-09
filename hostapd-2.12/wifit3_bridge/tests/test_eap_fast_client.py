from wifit3_bridge.eap_fast_client import (
    EAP_TLV_CRYPTO_BINDING,
    EAP_TLV_EAP_PAYLOAD,
    build_crypto_binding_response,
    build_eap_payload_tlv,
    build_intermediate_result_tlv,
    eap_fast_mschapv2_msk,
    parse_fast_tlvs,
    sha1_t_prf,
)


def test_sha1_t_prf_reference_vector():
    assert sha1_t_prf(
        bytes(range(40)), b"Inner Methods Compound Keys", bytes(range(32)), 60
    ).hex() == (
        "a6996c566b2a51a2fe57933beacf0844ae46abcf2449e3436dc12534804887b5da26e21c9cfae465875fccbc7b0431ed0f095e830a19282c1c289c06"
    )


def test_fast_payload_tlv_roundtrip():
    payload = bytes.fromhex("0207000801020304")
    tlv = build_eap_payload_tlv(payload)
    assert tlv[:4] == (0x8000 | EAP_TLV_EAP_PAYLOAD).to_bytes(2, "big") + len(payload).to_bytes(2, "big")
    parsed = parse_fast_tlvs(tlv)
    assert parsed.eap_payload == payload


def test_fast_intermediate_result_tlv_roundtrip():
    parsed = parse_fast_tlvs(build_intermediate_result_tlv())
    assert parsed.intermediate_result == 1


def test_fast_mschapv2_msk_uses_eap_fast_key_order():
    assert eap_fast_mschapv2_msk(bytes(range(32))) == bytes(range(16, 32)) + bytes(range(16))


def test_crypto_binding_response_vector():
    request = bytes.fromhex(
        "800c003800010100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0000000000000000000000000000000000000000"
    )
    response = build_crypto_binding_response(request, bytes(range(20)))
    assert response.hex() == (
        "800c003800010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20c98163545ac62c867e21c61a4894f46cfbb90b2a"
    )
    assert parse_fast_tlvs(response).crypto_binding is not None
    assert EAP_TLV_CRYPTO_BINDING == 12
