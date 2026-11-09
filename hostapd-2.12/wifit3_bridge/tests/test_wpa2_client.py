import hashlib
import hmac

from wifit3.dot11.ap import eapol_m1
from wifit3.dot11.eapol import (
    HMAC_MD5_RC4,
    HMAC_SHA1_AES,
    data_header,
    eapol_key,
    set_mic,
)
from wifit3.dot11.ie import GENERIC_RSN_IE
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.wpa import (
    derive_pmk,
    derive_ptk,
    derive_ptk_sha256,
    eapol_mic,
    eapol_mic_aes_cmac,
    eapol_mic_hmac_md5,
)
from wifit3_bridge.ccmp import (
    ccmp256_decrypt_mpdu,
    ccmp256_encrypt_mpdu,
    ccmp_decrypt_mpdu,
    ccmp_encrypt_mpdu,
)
from wifit3_bridge.bip import (
    bip_cmac_verify,
    bip_cmac256_verify,
    bip_gmac_verify,
)
from wifit3_bridge.gcmp import gcmp_decrypt_mpdu, gcmp_encrypt_mpdu
from wifit3_bridge.tkip import tkip_decrypt_mpdu, tkip_encrypt_mpdu
from wifit3_bridge.wpa2_client import Wpa2PskClient
import wifit3_bridge.wpa2_client as wpa2_client_module
from wifit3_bridge.eap_tls_client import ENTERPRISE_RSN_IE
from wifit3_bridge.ft_client import (
    FT_SAE_RSN_IE, derive_ft_ptk, derive_pmk_r0, derive_pmk_r1)
from cryptography.hazmat.primitives.keywrap import aes_key_wrap


AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("02aabbccddee")
SSID = b"wifit3-test"
PASSPHRASE = "wifit3-test-pass"
ANONCE = bytes.fromhex("10" * 32)
SNONCE = bytes.fromhex("20" * 32)
GCMP_RSN_IE = bytes.fromhex("30140100000fac080100000fac080100000fac020000")
GCMP256_RSN_IE = bytes.fromhex("30140100000fac090100000fac090100000fac020000")
CCMP256_RSN_IE = bytes.fromhex("30140100000fac0a0100000fac0a0100000fac020000")
TKIP_RSN_IE = bytes.fromhex("30140100000fac020100000fac020100000fac020000")
SAE_RSN_IE = bytes.fromhex("30140100000fac040100000fac040100000fac08c000")
SAE_EXT_KEY_RSN_IE = bytes.fromhex("30140100000fac040100000fac040100000fac18c000")
PMF_RSN_IE = GENERIC_RSN_IE[:-2] + b"\xc0\x00"
IGTK = bytes.fromhex("00112233445566778899aabbccddeeff")


def _igtk_kde(key_id: int = 4, ipn: int = 0, key: bytes = IGTK) -> bytes:
    value = (b"\x00\x0f\xac\x09" + key_id.to_bytes(2, "little") +
             ipn.to_bytes(6, "little") + key)
    return bytes((0xdd, len(value))) + value


def _parsed(frame: bytes):
    packet = WlanFrameParser.parse_80211_frame(frame, -30)
    assert packet is not None
    return packet


def _valid_m3(client: Wpa2PskClient, replay: int, key_data: bytes = b"gtk-test",
              key_len: int = 16) -> bytes:
    ptk = client.ptk
    assert ptk is not None
    if client.akm == "SAE-EXT-KEY" and client._mic_len != 16:
        payload = wpa2_client_module._build_variable_mic_eapol_key(
            key_info=0x03C8, key_len=key_len, replay=replay, nonce=ANONCE,
            key_data=key_data, mic_len=client._mic_len)
        payload = wpa2_client_module._set_variable_mic(
            payload, client._eapol_mic(payload))
        return data_header(to_ds=False, bssid=AP, client=STA) + (
            client.llc_eapol + payload)
    if client.akm in ("SAE", "FT-SAE"):
        descriptor_version = 0
        calculate_mic = eapol_mic_aes_cmac
    elif client.akm == "SAE-EXT-KEY":
        descriptor_version = 0
        calculate_mic = lambda key, payload: hmac.new(
            key, payload, hashlib.sha256).digest()[:16]
    else:
        descriptor_version = (HMAC_MD5_RC4 if client.cipher == "TKIP"
                              else HMAC_SHA1_AES)
        calculate_mic = (eapol_mic_hmac_md5 if client.cipher == "TKIP"
                         else eapol_mic)
    payload = eapol_key(
        key_info=0x03C8 | descriptor_version,
        key_len=key_len,
        replay=replay,
        nonce=ANONCE,
        key_data=key_data,
    )
    mic = calculate_mic(ptk[:16], payload)
    return data_header(to_ds=False, bssid=AP, client=STA) + (
        client.llc_eapol + set_mic(payload, mic)
    )


def test_m1_produces_m2_with_psk_derived_mic():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)

    responses = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=7))

    assert len(responses) == 1
    assert client.state == "M2_SENT"
    m2 = _parsed(responses[0])
    assert m2.msg_num == 2
    assert m2.replay_counter == (7).to_bytes(8, "big")
    assert m2.nonce == SNONCE
    pmk = derive_pmk(PASSPHRASE, SSID)
    ptk = derive_ptk(pmk, AP, STA, ANONCE, SNONCE, 48)
    assert m2.mic == eapol_mic(ptk[:16],
                               bytes(m2.payload[:81]) + bytes(16) + m2.payload[97:])


def test_m1_uses_an_external_sae_pmk_when_supplied():
    pmk = bytes.fromhex("11" * 32)
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=GENERIC_RSN_IE, pmk=pmk,
                           snonce=SNONCE)

    responses = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=6))

    assert len(responses) == 1
    expected = derive_ptk(pmk, AP, STA, ANONCE, SNONCE, 48)
    m2 = _parsed(responses[0])
    assert m2.mic == eapol_mic(expected[:16],
                               bytes(m2.payload[:81]) + bytes(16) + m2.payload[97:])


def test_m1_accepts_external_eap_tls_pmk_for_wpa_enterprise():
    pmk = bytes.fromhex("44" * 32)
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=ENTERPRISE_RSN_IE, pmk=pmk,
                           akm="WPA-EAP", snonce=SNONCE)

    responses = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=9))

    assert len(responses) == 1
    expected = derive_ptk(pmk, AP, STA, ANONCE, SNONCE, 48)
    m2 = _parsed(responses[0])
    assert m2.mic == eapol_mic(expected[:16],
                               bytes(m2.payload[:81]) + bytes(16) + m2.payload[97:])


def test_sae_m1_uses_akm_defined_cmac_and_sha256_ptk():
    pmk = bytes.fromhex("22" * 32)
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=SAE_RSN_IE, pmk=pmk, akm="SAE",
                           snonce=SNONCE)

    responses = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=7))

    assert len(responses) == 1
    m2 = _parsed(responses[0])
    assert m2.key_info & 0x0007 == 0
    expected = derive_ptk_sha256(pmk, AP, STA, ANONCE, SNONCE, 48)
    assert client.ptk == expected
    assert m2.mic == eapol_mic_aes_cmac(
        expected[:16], bytes(m2.payload[:81]) + bytes(16) + m2.payload[97:])


def test_ft_sae_m1_uses_pmk_r0_r1_and_ft_ptk():
    mobility_domain = bytes.fromhex("a1b2")
    r0kh_id = b"wifit3-r0"
    r1kh_id = AP
    pmk = bytes.fromhex("55" * 32)
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=FT_SAE_RSN_IE, pmk=pmk,
        akm="FT-SAE", snonce=SNONCE,
        ft_mobility_domain=mobility_domain, ft_r0kh_id=r0kh_id,
        ft_r1kh_id=r1kh_id)
    m1 = (data_header(to_ds=False, bssid=AP, client=STA) + client.llc_eapol +
          wpa2_client_module._build_variable_mic_eapol_key(
              key_info=0x0088, key_len=16, replay=8, nonce=ANONCE,
              key_data=b"", mic_len=16))

    responses = client.handle_frame(m1)

    assert len(responses) == 1
    pmk_r0, pmk_r0_name = derive_pmk_r0(
        pmk, SSID, mobility_domain, r0kh_id, STA)
    pmk_r1, pmk_r1_name = derive_pmk_r1(
        pmk_r0, pmk_r0_name, r1kh_id, STA)
    assert client.ptk == derive_ft_ptk(
        pmk_r1, pmk_r1_name, SNONCE, ANONCE, STA, AP)
    assert _parsed(responses[0]).key_info & 0x0007 == 0

    responses = client.handle_frame(_valid_m3(client, 9))
    assert len(responses) == 1
    assert client.authorized


def test_valid_m3_produces_m4_and_authorizes_client():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=8))

    responses = client.handle_frame(_valid_m3(client, 9))

    assert len(responses) == 1
    assert client.state == "AUTHORIZED"
    m4 = _parsed(ccmp_decrypt_mpdu(responses[0], client.ptk[32:48], 0)[1])
    assert responses[0][1] & 0x40
    assert m4.msg_num == 4
    assert m4.key_data_len == 0
    assert m4.replay_counter == (9).to_bytes(8, "big")


def test_sae_m3_uses_akm_defined_cmac_and_authorizes_client():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=SAE_RSN_IE, pmk=bytes.fromhex("33" * 32),
                           akm="SAE", snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=8))

    responses = client.handle_frame(_valid_m3(client, 9))

    assert len(responses) == 1
    assert client.authorized
    m4 = _parsed(ccmp_decrypt_mpdu(responses[0], client.ptk[32:48], 0)[1])
    assert m4.msg_num == 4
    assert m4.key_info & 0x0007 == 0


def test_sae_ext_key_uses_48_byte_ptk_hmac_sha256_and_standard_offsets():
    pmk = bytes.fromhex("34" * 32)
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=SAE_EXT_KEY_RSN_IE, pmk=pmk,
        akm="SAE-EXT-KEY", snonce=SNONCE)

    m2 = _parsed(client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=8))[0])

    assert client.ptk is not None and len(client.ptk) == 48
    assert m2.key_info & 0x0007 == 0
    expected_mic = hmac.new(
        client.ptk[:16], bytes(m2.payload[:81]) + bytes(16) + m2.payload[97:],
        hashlib.sha256).digest()[:16]
    assert m2.mic == expected_mic

    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 9), client.ptk[32:48], 1)
    responses = client.handle_frame(protected_m3)

    assert len(responses) == 1
    assert client.authorized
    m4 = _parsed(ccmp_decrypt_mpdu(responses[0], client.ptk[32:48], 0)[1])
    assert m4.msg_num == 4


def test_sae_ext_key_group20_accepts_sha384_pmk_and_variable_ptk_layout():
    pmk = bytes.fromhex("45" * 48)
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=SAE_EXT_KEY_RSN_IE, pmk=pmk,
        akm="SAE-EXT-KEY", snonce=SNONCE)

    m1 = (data_header(to_ds=False, bssid=AP, client=STA) + client.llc_eapol +
          wpa2_client_module._build_variable_mic_eapol_key(
              key_info=0x008a, key_len=16, replay=8, nonce=ANONCE,
              key_data=b"", mic_len=24))
    responses = client.handle_frame(m1)

    assert len(responses) == 1
    assert client.ptk is not None and len(client.ptk) == 72
    assert client._kck_len == 24
    assert client._kek_offset == 24
    assert client._tk_offset == 56

    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 9), client.ptk[56:72], 1)
    responses = client.handle_frame(protected_m3)

    assert len(responses) == 1
    assert client.authorized
    m4_plain = ccmp_decrypt_mpdu(responses[0], client.ptk[56:72], 0)[1]
    m4 = WlanFrameParser.parse_80211_frame(m4_plain, -30, eapol_mic_len=24)
    assert m4 is not None and m4.msg_num == 4
    assert m4.key_data_len == 0


def test_sae_ext_key_group20_unwraps_m3_with_full_sha384_kek():
    pmk = bytes.fromhex("45" * 48)
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=SAE_EXT_KEY_RSN_IE, pmk=pmk,
        akm="SAE-EXT-KEY", snonce=SNONCE)

    m1 = (data_header(to_ds=False, bssid=AP, client=STA) +
          client.llc_eapol +
          wpa2_client_module._build_variable_mic_eapol_key(
              key_info=0x008a, key_len=16, replay=8, nonce=ANONCE,
              key_data=b"", mic_len=24))
    assert len(client.handle_frame(m1)) == 1

    plaintext = _igtk_kde() + b"\x00\x00"
    wrapped = aes_key_wrap(client.ptk[24:56], plaintext)
    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 9, key_data=wrapped), client.ptk[56:72], 1)

    responses = client.handle_frame(protected_m3)

    assert len(responses) == 1
    assert client.authorized
    assert client.last_error is None
    assert client.last_key_data_tags == [0xdd]
    assert client.igtk == IGTK


def test_sae_ext_key_group21_accepts_sha512_pmk_and_variable_ptk_layout():
    pmk = bytes.fromhex("46" * 64)
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=SAE_EXT_KEY_RSN_IE, pmk=pmk,
        akm="SAE-EXT-KEY", snonce=SNONCE)

    m1 = (data_header(to_ds=False, bssid=AP, client=STA) + client.llc_eapol +
          wpa2_client_module._build_variable_mic_eapol_key(
              key_info=0x008a, key_len=16, replay=8, nonce=ANONCE,
              key_data=b"", mic_len=32))
    responses = client.handle_frame(m1)

    assert len(responses) == 1
    assert client.ptk is not None and len(client.ptk) == 80
    assert client._kck_len == 32
    assert client._kek_offset == 32
    assert client._tk_offset == 64


def test_repeated_m1_reuses_the_same_m2_and_accepts_incremented_m3():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)
    m1 = eapol_m1(AP, STA, ANONCE, replay=10)

    first = client.handle_frame(m1)
    repeated = client.handle_frame(m1)

    assert len(first) == 1
    assert repeated == first
    assert client.handle_frame(_valid_m3(client, 11))
    assert client.authorized


def test_retransmitted_m1_with_new_replay_reuses_snonce_and_ptk():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)

    first = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=20))[0]
    repeated = client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=21))[0]

    first_packet = _parsed(first)
    repeated_packet = _parsed(repeated)
    assert first_packet.nonce == repeated_packet.nonce == SNONCE
    assert first_packet.replay_counter == (20).to_bytes(8, "big")
    assert repeated_packet.replay_counter == (21).to_bytes(8, "big")
    assert client.handle_frame(_valid_m3(client, 21))
    assert client.authorized


def test_protected_m3_is_decrypted_before_mic_verification():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=12))
    plain_m3 = _valid_m3(client, 13)
    protected_m3 = ccmp_encrypt_mpdu(plain_m3, client.ptk[32:48], 1)

    assert client.handle_frame(protected_m3)
    assert client.authorized


def test_gcmp128_client_decrypts_m3_and_protects_m4():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=GCMP_RSN_IE, cipher="GCMP",
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=14))
    plain_m3 = _valid_m3(client, 15)
    protected_m3 = gcmp_encrypt_mpdu(plain_m3, client.ptk[32:48], 1)

    responses = client.handle_frame(protected_m3)

    assert client.authorized
    assert len(responses) == 1
    assert responses[0][1] & 0x40
    m4 = _parsed(gcmp_decrypt_mpdu(responses[0], client.ptk[32:48], 0)[1])
    assert m4.msg_num == 4


def test_gcmp256_client_decrypts_m3_and_protects_m4():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=GCMP256_RSN_IE, cipher="GCMP-256",
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=16))
    assert client.ptk is not None and len(client.ptk) == 64
    plain_m3 = _valid_m3(client, 17)
    protected_m3 = gcmp_encrypt_mpdu(plain_m3, client.ptk[32:64], 1)

    responses = client.handle_frame(protected_m3)

    assert client.authorized
    assert len(responses) == 1
    assert responses[0][1] & 0x40
    m4 = _parsed(gcmp_decrypt_mpdu(responses[0], client.ptk[32:64], 0)[1])
    assert m4.msg_num == 4


def test_ccmp256_client_decrypts_m3_and_protects_m4():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=CCMP256_RSN_IE, cipher="CCMP-256",
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=18))
    assert client.ptk is not None and len(client.ptk) == 64
    plain_m3 = _valid_m3(client, 19)
    protected_m3 = ccmp256_encrypt_mpdu(plain_m3, client.ptk[32:64], 1)

    responses = client.handle_frame(protected_m3)

    assert client.authorized
    assert len(responses) == 1
    assert responses[0][1] & 0x40
    m4 = _parsed(ccmp256_decrypt_mpdu(responses[0], client.ptk[32:64], 0)[1])
    assert m4.msg_num == 4


def test_tkip_client_decrypts_m3_and_protects_m4():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=TKIP_RSN_IE, cipher="TKIP",
                           snonce=SNONCE)
    m2 = _parsed(client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=22))[0])
    assert m2.key_info & 0x0007 == HMAC_MD5_RC4
    assert client.ptk is not None and len(client.ptk) == 64
    plain_m3 = _valid_m3(client, 23, key_len=32)
    protected_m3 = tkip_encrypt_mpdu(plain_m3, client.ptk[32:64], 1)

    responses = client.handle_frame(protected_m3)

    assert client.authorized
    assert len(responses) == 1
    assert responses[0][1] & 0x40
    _tsc, m4_plain = tkip_decrypt_mpdu(
        responses[0], client.ptk[32:64], source=STA)
    assert _parsed(m4_plain).msg_num == 4


def test_pmf_client_extracts_igtk_and_protects_management_frame():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=PMF_RSN_IE, snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=24))
    assert client.ptk is not None
    wrapped = aes_key_wrap(client.ptk[16:32], _igtk_kde() + b"\x00\x00")
    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 25, key_data=wrapped), client.ptk[32:48], 1)

    responses = client.handle_frame(protected_m3)

    assert client.authorized
    assert len(responses) == 1
    assert client.igtk == IGTK
    assert client.igtk_id == 4
    action = (b"\xd0\x00\x00\x00" + AP + STA + AP +
              b"\x10\x00\x08\x01test")
    protected_action = client.protect_management(action)
    assert bip_cmac_verify(protected_action, IGTK,
                           minimum_ipn=0, expected_key_id=4) == 1


def test_pmf_client_unwraps_encrypted_igtk_kde_from_m3():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE,
                           rsn_ie=PMF_RSN_IE, snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=26))
    assert client.ptk is not None
    wrapped = aes_key_wrap(client.ptk[16:32], _igtk_kde() + b"\x00\x00")
    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 27, key_data=wrapped), client.ptk[32:48], 1)

    assert client.handle_frame(protected_m3)
    assert client.igtk == IGTK
    assert client.igtk_id == 4


def test_pmf_client_protects_bip_gmac128_management_frame():
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=PMF_RSN_IE,
        pmf_cipher="BIP-GMAC-128", snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=28))
    assert client.ptk is not None
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    wrapped = aes_key_wrap(client.ptk[16:32], _igtk_kde(key=key) + b"\x00\x00")
    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 29, key_data=wrapped), client.ptk[32:48], 1)

    client.handle_frame(protected_m3)
    action = b"\xd0\x00\x00\x00" + AP + STA + AP + b"\x10\x00\x08\x01test"
    protected_action = client.protect_management(action)
    assert bip_gmac_verify(protected_action, key, minimum_ipn=0,
                           expected_key_id=4) == 1


def test_pmf_client_protects_bip_cmac256_management_frame():
    client = Wpa2PskClient(
        AP, STA, SSID, PASSPHRASE, rsn_ie=PMF_RSN_IE,
        pmf_cipher="BIP-CMAC-256", snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=30))
    assert client.ptk is not None
    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f")
    wrapped = aes_key_wrap(client.ptk[16:32], _igtk_kde(key=key) + b"\x00\x00")
    protected_m3 = ccmp_encrypt_mpdu(
        _valid_m3(client, 31, key_data=wrapped), client.ptk[32:48], 1)

    client.handle_frame(protected_m3)
    action = b"\xd0\x00\x00\x00" + AP + STA + AP + b"\x10\x00\x08\x01test"
    protected_action = client.protect_management(action)
    assert bip_cmac256_verify(protected_action, key, minimum_ipn=0,
                              expected_key_id=4) == 1


def test_m3_with_bad_mic_is_rejected_without_authorizing():
    client = Wpa2PskClient(AP, STA, SSID, PASSPHRASE, rsn_ie=GENERIC_RSN_IE,
                           snonce=SNONCE)
    client.handle_frame(eapol_m1(AP, STA, ANONCE, replay=9))
    bad = bytearray(_valid_m3(client, 9))
    # The EAPOL-Key MIC is at 24-byte 802.11 header + 8-byte LLC + 81.
    bad[24 + 8 + 81] ^= 0x01

    assert client.handle_frame(bytes(bad)) == []
    assert client.state == "M2_SENT"

