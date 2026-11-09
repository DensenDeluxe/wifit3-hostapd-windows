from wifit3_bridge.eap_teap_client import (
    EAP_TEAP,
    build_crypto_binding_response,
    build_eap_payload_tlv,
    build_result_tlv,
    derive_teap_imck,
    derive_teap_msk,
    parse_teap_tlvs,
    tls_exporter,
)


def test_teap_tls_exporter_reference_vector():
    assert tls_exporter(
        bytes(range(48)), bytes(range(32)), bytes(range(32, 64)), 64
    ).hex() == (
        "648143ec2ffcab2c350ade61645f4375bcd078a858b242267d443ceefee11e6d"
        "aa32a22560d563a35e3be117d951960c56320f1f1bbe4959d67c8c1f61716951"
    )


def test_teap_imck_and_msk_reference_vector():
    imck, cmk = derive_teap_imck(
        bytes(range(40)), bytes(range(32)), hash_name="sha256"
    )
    assert imck.hex() == (
        "e1607268c59167d994549bcf00e26db542e30e14d0644b38f5a9ca3a8abe8647"
        "5f50fbbea390bc35"
    )
    assert cmk.hex() == "4445f263a1200b02cbaf6ec4dfd7666798dce6e2"
    assert derive_teap_msk(imck, hash_name="sha256").hex() == (
        "f8a155db19ea30ec40d769b088e27204424eff778b6bf17f24318b1b24af65f3"
        "34b9bb8b74904e0ffe462023a94e9fdadf724933a0687fcb315afbe1dfbb9612"
    )


def test_teap_payload_and_result_tlvs_roundtrip():
    payload = bytes.fromhex("0207000801020304")
    parsed = parse_teap_tlvs(build_eap_payload_tlv(payload) + build_result_tlv())
    assert parsed.eap_payload == payload
    assert parsed.result == 1


def test_teap_crypto_binding_response_uses_nonce_successor():
    request = (
        (0x800c).to_bytes(2, "big") + (76).to_bytes(2, "big") +
            bytes((0, 1, 1, 0x20)) + bytes(range(32)) + bytes(40)
    )
    response = build_crypto_binding_response(
        request, bytes(range(20)), lambda value: bytes(range(20, 40))
    )
    assert len(response) == 80
    assert response[8:40] == bytes(range(31)) + b"\x20"
    assert response[60:80] == bytes(range(20, 40))
    assert EAP_TEAP == 55
