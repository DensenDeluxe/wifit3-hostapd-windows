"""Small, explicit IEEE 802.11r FT-SAE building blocks for the OTA lab.

The module deliberately contains only the FT-over-the-air material needed by
the Windows wifit3 test station.  It does not implement FT-over-DS, RRB, VLAN,
or an Ethernet transport.  Key derivation follows hostapd's
``wpa_derive_pmk_r0``, ``wpa_derive_pmk_r1`` and ``wpa_pmk_r1_to_ptk`` paths.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

from wifit3.dot11.auth_assoc import assoc_req
from wifit3.dot11.ie import iter_information_elements
from wifit3.dot11.mac import mac_header

from .sae_client import _prf_bits


FT_SAE_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac09c000")
FT_SAE_EXT_KEY_RSN_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac19c000")
WLAN_EID_MOBILITY_DOMAIN = 54
WLAN_EID_FAST_BSS_TRANSITION = 55
FTIE_SUBELEM_R1KH_ID = 1
FTIE_SUBELEM_R0KH_ID = 3
FT_DEFAULT_MGMT_GROUP_CIPHER = bytes.fromhex("000fac06")


def _digest_for_length(length: int):
    try:
        return {32: hashlib.sha256, 48: hashlib.sha384,
                64: hashlib.sha512}[length]
    except KeyError as error:
        raise ValueError("FT key length must be 32, 48, or 64 octets") from error


def _ie(element_id: int, body: bytes) -> bytes:
    if len(body) > 255:
        raise ValueError("information element body is too long")
    return bytes((element_id, len(body))) + body


def build_ft_sae_rsn_ie(*, pmkid: bytes | None = None,
                        akm: int = 9,
                        capabilities: int = 0,
                        mgmt_group_cipher: bytes | None = None) -> bytes:
    """Build a single-AKM CCMP RSNE using an FT-SAE selector."""
    if pmkid is not None and len(pmkid) != 16:
        raise ValueError("FT PMK name must be 16 octets")
    if not 0 <= akm <= 255:
        raise ValueError("FT AKM selector must fit in one octet")
    body = (b"\x01\x00" + bytes.fromhex("000fac04") + b"\x01\x00" +
            bytes.fromhex("000fac04") + b"\x01\x00" +
            bytes.fromhex("000fac") + bytes((akm,)) +
            capabilities.to_bytes(2, "little"))
    if pmkid is None:
        body += b"\x00\x00"
    else:
        body += b"\x01\x00" + pmkid
    if mgmt_group_cipher is not None:
        if len(mgmt_group_cipher) != 4:
            raise ValueError("management group cipher must be four octets")
        body += mgmt_group_cipher
    return _ie(48, body)


def rsn_capabilities(rsn_ie: bytes) -> int:
    """Return the RSN capabilities field from one RSN information element."""
    if len(rsn_ie) < 2 or rsn_ie[0] != 48:
        raise ValueError("invalid RSN information element")
    body = rsn_ie[2:2 + rsn_ie[1]]
    if len(body) != rsn_ie[1] or len(body) < 8:
        raise ValueError("truncated RSN information element")
    pos = 2 + 4
    pairwise_count = int.from_bytes(body[pos:pos + 2], "little")
    pos += 2 + 4 * pairwise_count
    if pos + 2 > len(body):
        raise ValueError("truncated RSN pairwise suite list")
    akm_count = int.from_bytes(body[pos:pos + 2], "little")
    pos += 2 + 4 * akm_count
    if pos + 2 > len(body):
        raise ValueError("RSN capabilities are missing")
    return int.from_bytes(body[pos:pos + 2], "little")


def build_mdie(mobility_domain: bytes, *, ft_capab: int = 0) -> bytes:
    if len(mobility_domain) != 2:
        raise ValueError("mobility domain must be two octets")
    return _ie(WLAN_EID_MOBILITY_DOMAIN, mobility_domain + bytes((ft_capab,)))


def _key_length_from_pmk(pmk: bytes) -> int:
    _digest_for_length(len(pmk))
    return len(pmk)


def derive_pmk_r0(pmk: bytes, ssid: bytes, mobility_domain: bytes,
                  r0kh_id: bytes, sta_mac: bytes) -> tuple[bytes, bytes]:
    """Derive PMK-R0 and PMKR0Name for FT-SAE/FT-SAE-EXT-KEY."""
    q = _key_length_from_pmk(pmk)
    if len(mobility_domain) != 2 or len(sta_mac) != 6:
        raise ValueError("invalid FT mobility-domain or station address")
    if not 1 <= len(r0kh_id) <= 48:
        raise ValueError("R0KH-ID must contain 1..48 octets")
    digestmod = _digest_for_length(q)
    context = (bytes((len(ssid),)) + ssid + mobility_domain +
               bytes((len(r0kh_id),)) + r0kh_id + sta_mac)
    key_data = _prf_bits(pmk, b"FT-R0", context, (q + 16) * 8, digestmod)
    pmk_r0 = key_data[:q]
    pmk_r0_name = hashlib.new(digestmod().name,
                              b"FT-R0N" + key_data[q:]).digest()[:16]
    return pmk_r0, pmk_r0_name


def derive_pmk_r1(pmk_r0: bytes, pmk_r0_name: bytes,
                  r1kh_id: bytes, sta_mac: bytes) -> tuple[bytes, bytes]:
    """Derive PMK-R1 and PMKR1Name for a target R1KH."""
    q = _key_length_from_pmk(pmk_r0)
    if len(pmk_r0_name) != 16 or len(r1kh_id) != 6 or len(sta_mac) != 6:
        raise ValueError("invalid FT PMK name, R1KH-ID, or station address")
    digestmod = _digest_for_length(q)
    pmk_r1 = _prf_bits(pmk_r0, b"FT-R1", r1kh_id + sta_mac,
                       q * 8, digestmod)
    pmk_r1_name = hashlib.new(
        digestmod().name,
        b"FT-R1N" + pmk_r0_name + r1kh_id + sta_mac,
    ).digest()[:16]
    return pmk_r1, pmk_r1_name


def ft_key_lengths(pmk_r1: bytes, *, ext_key: bool = False) -> tuple[int, int, int]:
    """Return KCK, KEK, TK lengths for CCMP FT PTK material."""
    q = _key_length_from_pmk(pmk_r1)
    if ext_key:
        return q // 2, (16 if q <= 32 else 32), 16
    return 16, 16, 16


def derive_ft_ptk(pmk_r1: bytes, pmk_r1_name: bytes, snonce: bytes,
                  anonce: bytes, sta_mac: bytes, ap_mac: bytes,
                  *, ext_key: bool = False) -> bytes:
    """Derive the hostapd FT-PTK byte layout: KCK || KEK || TK."""
    if len(pmk_r1_name) != 16 or len(snonce) != 32 or len(anonce) != 32:
        raise ValueError("invalid FT nonce or PMK name")
    if len(sta_mac) != 6 or len(ap_mac) != 6:
        raise ValueError("invalid FT station/AP address")
    kck_len, kek_len, tk_len = ft_key_lengths(pmk_r1, ext_key=ext_key)
    q = len(pmk_r1)
    digestmod = _digest_for_length(q)
    context = snonce + anonce + ap_mac + sta_mac
    return _prf_bits(pmk_r1, b"FT-PTK", context,
                     (kck_len + kek_len + tk_len) * 8, digestmod)


def ft_mic(kck: bytes, sta_mac: bytes, ap_mac: bytes, transaction: int,
           mdie: bytes, ftie: bytes, rsnie: bytes,
           *, rsnxe: bytes = b"", ric: bytes = b"", ext_key: bool = False) -> bytes:
    """Calculate the IEEE 802.11r FT MIC with the FTIE MIC field zeroed."""
    if len(sta_mac) != 6 or len(ap_mac) != 6 or not 0 <= transaction <= 255:
        raise ValueError("invalid FT MIC address or transaction")
    mic_len = len(kck)
    if mic_len not in (16, 24, 32):
        raise ValueError("FT KCK must contain 16, 24, or 32 octets")
    if len(ftie) < 4 + mic_len:
        raise ValueError("FTIE is too short for the KCK length")
    zeroed_ftie = (ftie[:4] + bytes(mic_len) +
                   ftie[4 + mic_len:])
    data = (sta_mac + ap_mac + bytes((transaction,)) + rsnie + mdie +
            zeroed_ftie + ric + rsnxe)
    if mic_len == 16 and not ext_key:
        mac = cmac.CMAC(algorithms.AES(kck))
        mac.update(data)
        return mac.finalize()
    digestmod = {16: hashlib.sha256, 24: hashlib.sha384,
                 32: hashlib.sha512}[mic_len]
    return hmac.new(kck, data, digestmod).digest()[:mic_len]


def _build_ftie(*, snonce: bytes, anonce: bytes | None,
                r0kh_id: bytes, r1kh_id: bytes | None,
                mic: bytes | None = None, element_count: int = 0,
                mic_len: int = 16) -> bytes:
    if len(snonce) != 32 or (anonce is not None and len(anonce) != 32):
        raise ValueError("FT nonces must be 32 octets")
    if not 1 <= len(r0kh_id) <= 48:
        raise ValueError("R0KH-ID must contain 1..48 octets")
    if r1kh_id is not None and len(r1kh_id) != 6:
        raise ValueError("R1KH-ID must contain six octets")
    if mic_len not in (16, 24, 32):
        raise ValueError("FT MIC must contain 16, 24, or 32 octets")
    if len(mic or b"") not in (0, mic_len):
        raise ValueError("FT MIC has the wrong length")
    mic_control = {16: 0, 24: 1, 32: 2}[mic_len] << 1
    body = (bytes((mic_control, element_count)) + (mic or bytes(mic_len)) +
            (anonce or bytes(32)) + snonce)
    if r1kh_id is not None:
        body += bytes((FTIE_SUBELEM_R1KH_ID, 6)) + r1kh_id
    body += bytes((FTIE_SUBELEM_R0KH_ID, len(r0kh_id))) + r0kh_id
    return _ie(WLAN_EID_FAST_BSS_TRANSITION, body)


def build_ft_auth_ies(pmk_r0_name: bytes, mobility_domain: bytes,
                      r0kh_id: bytes, snonce: bytes, *,
                      akm: int = 9,
                      capabilities: int = 0,
                      ft_mic_len: int = 16,
                      mgmt_group_cipher: bytes | None =
                      FT_DEFAULT_MGMT_GROUP_CIPHER) -> bytes:
    """Build the IEs for an FT Authentication Request (transaction 1)."""
    return (build_ft_sae_rsn_ie(
                pmkid=pmk_r0_name, capabilities=capabilities,
                akm=akm,
                mgmt_group_cipher=mgmt_group_cipher) +
            build_mdie(mobility_domain) +
            _build_ftie(snonce=snonce, anonce=None, r0kh_id=r0kh_id,
                        r1kh_id=None, mic_len=ft_mic_len))


def build_ft_reassoc_ies(pmk_r1_name: bytes, mobility_domain: bytes,
                         r0kh_id: bytes, r1kh_id: bytes, snonce: bytes,
                         anonce: bytes, kck: bytes, *, capabilities: int = 0,
                         mgmt_group_cipher: bytes | None =
                         FT_DEFAULT_MGMT_GROUP_CIPHER,
                         rsnxe: bytes = b"", akm: int = 9) -> bytes:
    """Build and MIC an FT Reassociation Request IE block."""
    rsnie = build_ft_sae_rsn_ie(
        pmkid=pmk_r1_name, capabilities=capabilities,
        akm=akm,
        mgmt_group_cipher=mgmt_group_cipher)
    mdie = build_mdie(mobility_domain)
    ftie = _build_ftie(snonce=snonce, anonce=anonce, r0kh_id=r0kh_id,
                       r1kh_id=r1kh_id, element_count=3 + bool(rsnxe),
                       mic_len=len(kck))
    mic = ft_mic(kck, b"\x00" * 6, b"\x00" * 6, 5, mdie, ftie, rsnie,
                 rsnxe=rsnxe, ext_key=akm == 25)
    # The caller must bind the MIC to its actual addresses. Rebuild through
    # the address-aware helper below rather than exposing a mutable template.
    return rsnie + mdie + ftie[:4] + mic + ftie[4 + len(kck):]


def build_ft_reassoc_ies_for_addresses(pmk_r1_name: bytes,
                                       mobility_domain: bytes,
                                       r0kh_id: bytes, r1kh_id: bytes,
                                       snonce: bytes, anonce: bytes,
                                       kck: bytes, sta_mac: bytes,
                                       ap_mac: bytes, *, capabilities: int = 0,
                                       mgmt_group_cipher: bytes | None =
                                       FT_DEFAULT_MGMT_GROUP_CIPHER,
                                       rsnxe: bytes = b"", akm: int = 9) -> bytes:
    """Address-bound variant used for a real FT OTA frame."""
    rsnie = build_ft_sae_rsn_ie(
        pmkid=pmk_r1_name, capabilities=capabilities,
        akm=akm,
        mgmt_group_cipher=mgmt_group_cipher)
    mdie = build_mdie(mobility_domain)
    ftie = _build_ftie(snonce=snonce, anonce=anonce, r0kh_id=r0kh_id,
                       r1kh_id=r1kh_id, element_count=3 + bool(rsnxe),
                       mic_len=len(kck))
    mic = ft_mic(kck, sta_mac, ap_mac, 5, mdie, ftie, rsnie,
                 rsnxe=rsnxe, ext_key=akm == 25)
    return (rsnie + mdie + ftie[:4] + mic + ftie[4 + len(kck):] +
            rsnxe)


def build_ft_auth_request(bssid: bytes, sta_mac: bytes, ies: bytes) -> bytes:
    """Build an over-the-air FT Authentication Request (transaction 1)."""
    if len(bssid) != 6 or len(sta_mac) != 6:
        raise ValueError("BSSID and station address must be six octets")
    return (mac_header(b"\xb0\x00", bssid, sta_mac, bssid) +
            struct.pack("<HHH", 2, 1, 0) + bytes(ies))


def build_ft_reassoc_request(bssid: bytes, sta_mac: bytes, ssid: str,
                             channel: int, ies: bytes) -> bytes:
    """Build an over-the-air FT Reassociation Request."""
    if len(bssid) != 6 or len(sta_mac) != 6:
        raise ValueError("BSSID and station address must be six octets")
    association = assoc_req(
        bssid, sta_mac, ssid, ies, channel=channel, privacy=True)
    # Association body: capability + listen interval + IEs. Reassociation
    # inserts Current AP immediately before the IEs.
    body = association[24:]
    return (mac_header(b"\x20\x00", bssid, sta_mac, bssid) +
            body[:4] + bssid + body[4:])


@dataclass(frozen=True, slots=True)
class ParsedFtIes:
    rsn: bytes | None
    mdie: bytes
    ftie: bytes
    pmkid: bytes | None
    r0kh_id: bytes | None
    r1kh_id: bytes | None
    mic: bytes
    anonce: bytes
    snonce: bytes
    element_count: int


def parse_ft_ies(ies: bytes, *, mic_len: int = 16) -> ParsedFtIes:
    """Parse the subset of FT IEs required by the OTA client."""
    found = {tag: raw for tag, _body, raw in iter_information_elements(ies)}
    rsn = found.get(48)
    mdie = found.get(WLAN_EID_MOBILITY_DOMAIN)
    ftie = found.get(WLAN_EID_FAST_BSS_TRANSITION)
    if not mdie or not ftie:
        raise ValueError("FT response is missing MDIE or FTIE")
    pmkid = None
    if rsn:
        body = rsn[2:]
        # RSN: version, group, pairwise list, AKM list, capabilities,
        # PMKID list. Initial FT-SAE Association Responses omit the RSNE;
        # Reassociation Responses include it.
        pos = 2 + 4
        pairwise_count = int.from_bytes(body[pos:pos + 2], "little")
        pos += 2 + 4 * pairwise_count
        akm_count = int.from_bytes(body[pos:pos + 2], "little")
        pos += 2 + 4 * akm_count
        pos += 2
        pmkid_count = int.from_bytes(body[pos:pos + 2], "little")
        pos += 2
        pmkid = body[pos:pos + 16] if pmkid_count == 1 else None
    fbody = ftie[2:]
    if len(fbody) < 2 + mic_len + 64:
        raise ValueError("FTIE is too short")
    mic = fbody[2:2 + mic_len]
    anonce = fbody[2 + mic_len:34 + mic_len]
    snonce = fbody[34 + mic_len:66 + mic_len]
    r0kh_id = r1kh_id = None
    pos = 66 + mic_len
    while pos + 2 <= len(fbody):
        sub_id, sub_len = fbody[pos], fbody[pos + 1]
        pos += 2
        value = fbody[pos:pos + sub_len]
        if len(value) != sub_len:
            raise ValueError("truncated FTIE subelement")
        if sub_id == FTIE_SUBELEM_R0KH_ID:
            r0kh_id = bytes(value)
        elif sub_id == FTIE_SUBELEM_R1KH_ID:
            r1kh_id = bytes(value)
        pos += sub_len
    return ParsedFtIes(
        rsn=rsn, mdie=mdie, ftie=ftie, pmkid=pmkid,
        r0kh_id=r0kh_id, r1kh_id=r1kh_id, mic=mic,
        anonce=anonce, snonce=snonce, element_count=fbody[1],
    )
