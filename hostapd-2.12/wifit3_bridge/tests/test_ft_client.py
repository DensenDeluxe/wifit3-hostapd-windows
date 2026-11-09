from wifit3_bridge.ft_client import (
    FT_SAE_RSN_IE,
    FT_SAE_EXT_KEY_RSN_IE,
    build_ft_auth_ies,
    build_ft_auth_request,
    build_ft_reassoc_ies_for_addresses,
    build_ft_reassoc_request,
    build_ft_sae_rsn_ie,
    build_mdie,
    derive_ft_ptk,
    derive_pmk_r0,
    derive_pmk_r1,
    ft_key_lengths,
    ft_mic,
    parse_ft_ies,
    rsn_capabilities,
)


STA = bytes.fromhex("02aabbccddee")
AP = bytes.fromhex("021122334455")
SSID = b"wifit3-ft"
MDID = bytes.fromhex("a1b2")
R0KH = b"wifit3-r0"
R1KH = bytes.fromhex("021122334455")
PMK = bytes.fromhex("11" * 32)
SNonce = bytes.fromhex("22" * 32)
ANonce = bytes.fromhex("33" * 32)


def test_ft_sae_rsn_ie_uses_akm_9_and_optional_pmkid():
    assert FT_SAE_RSN_IE == bytes.fromhex(
        "30140100000fac040100000fac040100000fac09c000")
    pmkid = bytes.fromhex("aa" * 16)
    ie = build_ft_sae_rsn_ie(pmkid=pmkid)
    assert ie[1] == 38
    assert ie[-18:-16] == b"\x01\x00"
    assert ie[-16:] == pmkid
    assert rsn_capabilities(FT_SAE_RSN_IE) == 0x00c0


def test_ft_sae_ext_key_rsn_ie_and_variable_ftie_mic_lengths():
    assert FT_SAE_EXT_KEY_RSN_IE == bytes.fromhex(
        "30140100000fac040100000fac040100000fac19c000")
    ie = build_ft_sae_rsn_ie(
        pmkid=bytes.fromhex("aa" * 16), akm=25,
        capabilities=0x00c0)
    assert ie[16:20] == bytes.fromhex("000fac19")
    ies = build_ft_auth_ies(
        bytes.fromhex("11" * 16), MDID, R0KH, SNonce,
        capabilities=0x00c0, akm=24, ft_mic_len=24)
    parsed = parse_ft_ies(ies, mic_len=24)
    assert parsed.rsn is not None
    assert len(parsed.mic) == 24
    assert parsed.r0kh_id == R0KH
    ext_ftie = parsed.ftie
    ext_mic = ft_mic(
        bytes.fromhex("33" * 16), STA, AP, 5, parsed.mdie, ext_ftie,
        parsed.rsn, ext_key=True)
    assert len(ext_mic) == 16


def test_ft_sae_key_derivation_matches_hostapd_layout():
    pmk_r0, pmk_r0_name = derive_pmk_r0(PMK, SSID, MDID, R0KH, STA)
    pmk_r1, pmk_r1_name = derive_pmk_r1(pmk_r0, pmk_r0_name, R1KH, STA)
    ptk = derive_ft_ptk(pmk_r1, pmk_r1_name, SNonce, ANonce, STA, AP)
    assert len(pmk_r0) == len(pmk_r1) == 32
    assert len(pmk_r0_name) == len(pmk_r1_name) == 16
    assert ft_key_lengths(pmk_r1) == (16, 16, 16)
    assert len(ptk) == 48
    assert ptk[:16] != bytes(16)


def test_ft_auth_and_reassoc_ies_round_trip_and_mic_binds_addresses():
    pmk_r0, pmk_r0_name = derive_pmk_r0(PMK, SSID, MDID, R0KH, STA)
    pmk_r1, pmk_r1_name = derive_pmk_r1(pmk_r0, pmk_r0_name, R1KH, STA)
    ptk = derive_ft_ptk(pmk_r1, pmk_r1_name, SNonce, ANonce, STA, AP)
    auth_ies = build_ft_auth_ies(pmk_r0_name, MDID, R0KH, SNonce)
    auth = parse_ft_ies(auth_ies)
    assert auth.pmkid == pmk_r0_name
    assert auth.r0kh_id == R0KH
    assert auth.r1kh_id is None
    assert auth.anonce == bytes(32)
    assert auth.snonce == SNonce
    reassoc_ies = build_ft_reassoc_ies_for_addresses(
        pmk_r1_name, MDID, R0KH, R1KH, SNonce, ANonce, ptk[:16], STA, AP)
    reassoc = parse_ft_ies(reassoc_ies)
    assert reassoc.pmkid == pmk_r1_name
    assert reassoc.r0kh_id == R0KH
    assert reassoc.r1kh_id == R1KH
    assert reassoc.element_count == 3
    assert reassoc.snonce == SNonce
    assert reassoc.anonce == ANonce
    assert reassoc.mic == ft_mic(
        ptk[:16], STA, AP, 5, reassoc.mdie, reassoc.ftie,
        reassoc.rsn)
    assert reassoc.mic != ft_mic(
        ptk[:16], AP, STA, 5, reassoc.mdie, reassoc.ftie,
        reassoc.rsn)


def test_ft_ota_management_frames_have_expected_subtypes_and_bodies():
    auth = build_ft_auth_request(AP, STA, b"\x36\x03\xa1\xb2\x00")
    assert int.from_bytes(auth[:2], "little") >> 4 & 0x0f == 11
    assert auth[24:30] == b"\x02\x00\x01\x00\x00\x00"

    reassoc = build_ft_reassoc_request(AP, STA, SSID.decode(), 1,
                                       b"\x30\x00")
    assert int.from_bytes(reassoc[:2], "little") >> 4 & 0x0f == 2
    assert reassoc[24:28] == b"\x31\x00\x01\x00"
    assert reassoc[28:34] == AP
    assert reassoc[34:].endswith(b"\x30\x00")
