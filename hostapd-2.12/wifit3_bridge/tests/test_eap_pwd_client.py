import hashlib
import hmac

from wifit3_bridge.eap_pwd_client import EAP_IDENTITY, EAP_PWD, EapPwdClient
from wifit3_bridge.eap_pwd_client import _kdf


AP = bytes.fromhex("020000000001")
STA = bytes.fromhex("020000000002")


def test_eap_pwd_client_answers_identity_request():
    client = EapPwdClient(
        AP,
        STA,
        b"eap-pwd-lab",
        identity="alice",
        password="correct horse battery staple",
    )
    request = bytes((1, 9, 0, 5, EAP_IDENTITY))
    responses = client.handle_eap_packet(request)
    assert len(responses) == 1
    assert responses[0][:5] == bytes((2, 9, 0, 10, EAP_IDENTITY))
    assert responses[0][5:] == b"alice"


def test_eap_pwd_client_echoes_pwd_identity_parameters():
    client = EapPwdClient(
        AP,
        STA,
        b"eap-pwd-lab",
        identity="alice",
        password="correct horse battery staple",
    )
    payload = (bytes((EAP_PWD, 1)) + (19).to_bytes(2, "big") +
               bytes((1, 1)) + bytes.fromhex("01020304") + bytes((0,)) +
               b"server")
    request = bytes((1, 10)) + (4 + len(payload)).to_bytes(2, "big") + payload
    response = client.handle_eap_packet(request)[0]
    assert response[:6] == bytes((2, 10, 0, 20, EAP_PWD, 1))
    assert response[5:] == payload[1:11] + b"alice"


def test_eap_pwd_client_keeps_first_failure_reason():
    client = EapPwdClient(
        AP,
        STA,
        b"eap-pwd-lab",
        identity="alice",
        password="correct horse battery staple",
    )
    bad_id = (bytes((1, 11, 0, 21, EAP_PWD, 1)) +
              bytes.fromhex("000001010203040000") + b"server")
    client.handle_eap_packet(bad_id)
    first_error = client.last_error
    client.handle_eap_packet(bytes((1, 12, 0, 6, EAP_PWD, 2)))
    assert first_error == "unexpected EAP-PWD group"
    assert client.last_error == first_error


def test_eap_pwd_kdf_shifts_non_byte_aligned_output():
    key = b"k" * 32
    label = b"EAP-pwd Hunting And Pecking"
    raw = bytearray()
    previous = b""
    for counter in range(1, 4):
        previous = hmac.new(
            key,
            previous + counter.to_bytes(2, "big") + label +
            (521).to_bytes(2, "big"),
            hashlib.sha256,
        ).digest()
        raw.extend(previous)
    expected = (int.from_bytes(raw[:66], "big") >> 7).to_bytes(66, "big")
    assert _kdf(key, label, 521) == expected
