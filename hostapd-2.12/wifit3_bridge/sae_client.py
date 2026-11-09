"""Minimal WPA3-SAE password client for the explicit wifit3 OTA lab path.

This module implements SAE finite cyclic ECC groups 19, 20, and 21 with both
the legacy hunting-and-pecking and the SSID-bound hash-to-element (H2E) PWE
derivations, including the SAE-PK confirmation elements used by hostapd.
It is used to exercise hostapd's authenticator over raw 802.11 Authentication
frames; it is not a general supplicant and does not claim FFC groups or
transition-mode policy handling.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from wifit3.dot11.auth_assoc import assoc_req
from wifit3.dot11.mac import mac_header


@dataclass(frozen=True, slots=True)
class SaeCurve:
    group: int
    prime: int
    order: int
    curve_a: int
    curve_b: int
    sswu_z: int
    hash_len: int

    @property
    def prime_len(self) -> int:
        return (self.prime.bit_length() + 7) // 8

    @property
    def prime_bits(self) -> int:
        return self.prime.bit_length()

    @property
    def order_len(self) -> int:
        return (self.order.bit_length() + 7) // 8


GROUP_19 = 19
GROUP_20 = 20
GROUP_21 = 21
PRIME_19 = int(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
ORDER_19 = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
CURVE_A_19 = PRIME_19 - 3
CURVE_B_19 = int(
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

PRIME_20 = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "FFFFFFFF0000000000000000FFFFFFFF", 16)
ORDER_20 = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
    "581A0DB248B0A77AECEC196ACCC52973", 16)
CURVE_A_20 = PRIME_20 - 3
CURVE_B_20 = int(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
    "C656398D8A2ED19D2A85C8EDD3EC2AEF", 16)

PRIME_21 = (1 << 521) - 1
ORDER_21 = int(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    16,
)
CURVE_A_21 = PRIME_21 - 3
CURVE_B_21 = int(
    "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109"
    "E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    16,
)

SAE_CURVES = {
    GROUP_19: SaeCurve(GROUP_19, PRIME_19, ORDER_19, CURVE_A_19,
                       CURVE_B_19, -10, 32),
    GROUP_20: SaeCurve(GROUP_20, PRIME_20, ORDER_20, CURVE_A_20,
                       CURVE_B_20, -12, 48),
    GROUP_21: SaeCurve(GROUP_21, PRIME_21, ORDER_21, CURVE_A_21,
                       CURVE_B_21, -4, 64),
}
PRF_LABEL = b"SAE Hunting and Pecking"
KCK_PMK_LABEL = b"SAE KCK and PMK"
SAE_H2E_RSNX_IE = b"\xf4\x01\x20"  # RSNXE: SAE Hash-to-Element capability
SAE_PK_RSNX_IE = b"\xf4\x01\x60"  # RSNXE: H2E plus SAE-PK capability
SAE_EXT_KEY_AKM_IE = b"\xff\x05\x72\x00\x0f\xac\x18"  # AKM 24 selector
_SAE_H2E_STATUS = 126
_SAE_PK_STATUS = 127
_SAE_ASSOC_RETRY_STATUSES = {17, 30}
_SAE_PK_VENDOR = bytes.fromhex("506f9a1f")


class SaeError(ValueError):
    """Malformed, unauthenticated, or unsupported SAE data."""


Point = tuple[int, int] | None


def _curve_for_group(group: int) -> SaeCurve:
    try:
        return SAE_CURVES[group]
    except KeyError as error:
        raise SaeError(f"unsupported SAE group {group}") from error


def _inv(value: int, curve: SaeCurve = SAE_CURVES[GROUP_19]) -> int:
    return pow(value, curve.prime - 2, curve.prime)


def _point_add(left: Point, right: Point,
               curve: SaeCurve = SAE_CURVES[GROUP_19]) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % curve.prime == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = ((3 * x1 * x1 + curve.curve_a) *
                 _inv(2 * y1, curve)) % curve.prime
    else:
        slope = ((y2 - y1) * _inv(x2 - x1, curve)) % curve.prime
    x3 = (slope * slope - x1 - x2) % curve.prime
    y3 = (slope * (x1 - x3) - y1) % curve.prime
    return x3, y3


def _point_mul(point: Point, scalar: int,
               curve: SaeCurve = SAE_CURVES[GROUP_19]) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend, curve)
        addend = _point_add(addend, addend, curve)
        scalar >>= 1
    return result


def _point_encode(point: Point,
                  curve: SaeCurve = SAE_CURVES[GROUP_19]) -> bytes:
    if point is None:
        raise SaeError("SAE point at infinity")
    return (point[0].to_bytes(curve.prime_len, "big") +
            point[1].to_bytes(curve.prime_len, "big"))


def _point_decode(data: bytes,
                  curve: SaeCurve = SAE_CURVES[GROUP_19]) -> Point:
    expected_len = 2 * curve.prime_len
    if len(data) != expected_len:
        raise SaeError(
            f"SAE commit element must be {expected_len} octets")
    point = (int.from_bytes(data[:curve.prime_len], "big"),
             int.from_bytes(data[curve.prime_len:], "big"))
    x, y = point
    if x >= curve.prime or y >= curve.prime:
        raise SaeError("SAE point coordinate is outside the field")
    if ((y * y - (x * x * x + curve.curve_a * x + curve.curve_b)) %
            curve.prime):
        raise SaeError(f"SAE commit element is not on group {curve.group}")
    return point


def _prf_bits(key: bytes, label: bytes, data: bytes, bit_length: int,
              digestmod) -> bytes:
    """hostapd's little-endian IEEE 802.11 hash-PRF variant."""
    result = bytearray()
    counter = 1
    output_length = (bit_length + 7) // 8
    while len(result) < output_length:
        block = hmac.new(
            key,
            counter.to_bytes(2, "little") + label + data +
            bit_length.to_bytes(2, "little"),
            digestmod,
        ).digest()
        result.extend(block[:output_length - len(result)])
        counter += 1
    if bit_length % 8:
        result[-1] &= 0xff << (8 - bit_length % 8)
    return bytes(result)


def _sha256_prf_bits(key: bytes, label: bytes, data: bytes,
                     bit_length: int) -> bytes:
    return _prf_bits(key, label, data, bit_length, hashlib.sha256)


def _hash_for_curve(curve: SaeCurve, h2e: bool):
    if not h2e:
        return hashlib.sha256
    return {32: hashlib.sha256, 48: hashlib.sha384,
            64: hashlib.sha512}[curve.hash_len]


def _derive_pwe(own_mac: bytes, peer_mac: bytes, password: bytes,
                group: int = GROUP_19) -> Point:
    curve = _curve_for_group(group)
    if len(own_mac) != 6 or len(peer_mac) != 6:
        raise SaeError("SAE MAC addresses must be six octets")
    if own_mac == peer_mac:
        raise SaeError("SAE MAC addresses must differ")
    addr_key = max(own_mac, peer_mac) + min(own_mac, peer_mac)
    prime = curve.prime.to_bytes(curve.prime_len, "big")
    for counter in range(1, 201):
        pwd_seed = hmac.new(
            addr_key, password + bytes((counter,)), hashlib.sha256).digest()
        pwd_value = _sha256_prf_bits(
            pwd_seed, PRF_LABEL, prime, curve.prime_bits)
        if curve.prime_bits % 8:
            pwd_value = (int.from_bytes(pwd_value, "big") >>
                         (8 - curve.prime_bits % 8)).to_bytes(
                             curve.prime_len, "big")
        x = int.from_bytes(pwd_value, "big")
        if x >= curve.prime:
            continue
        y_squared = (pow(x, 3, curve.prime) + curve.curve_a * x +
                     curve.curve_b) % curve.prime
        if pow(y_squared, (curve.prime - 1) // 2, curve.prime) != 1:
            continue
        y = pow(y_squared, (curve.prime + 1) // 4, curve.prime)
        if (pwd_seed[-1] & 1) != (y & 1):
            y = curve.prime - y
        return x, y
    raise SaeError(f"SAE PWE derivation failed for group {group}")


def _hkdf_extract(salt: bytes, ikm: bytes,
                  digestmod=hashlib.sha256) -> bytes:
    return hmac.new(salt, ikm, digestmod).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int,
                 digestmod=hashlib.sha256) -> bytes:
    """HKDF-Expand for the SAE H2E PT labels."""
    digest_size = digestmod().digest_size
    if not 0 <= length <= 255 * digest_size:
        raise SaeError("invalid HKDF output length")
    result = bytearray()
    previous = b""
    for counter in range(1, (length + digest_size - 1) // digest_size + 1):
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), digestmod
        ).digest()
        result.extend(previous)
    return bytes(result[:length])


def _sswu(u: int, curve: SaeCurve) -> Point:
    """Simplified SWU map used by hostapd for SAE H2E ECC groups."""
    p = curve.prime
    a = curve.curve_a
    b = curve.curve_b
    z = curve.sswu_z % p
    u %= p

    u2 = (u * u) % p
    t1 = (z * u2) % p
    t2 = (t1 * t1) % p
    m = (t1 + t2) % p
    t = pow(m, p - 2, p)

    x1a = (b * pow((z * a) % p, p - 2, p)) % p
    x1b = ((-b * pow(a, p - 2, p)) * (1 + t)) % p
    x1 = x1a if m == 0 else x1b
    gx1 = (pow(x1, 3, p) + a * x1 + b) % p
    x2 = (z * u2 * x1) % p
    gx2 = (pow(x2, 3, p) + a * x2 + b) % p

    legendre = pow(gx1, (p - 1) // 2, p)
    gx1_is_square = legendre in (0, 1)
    x = x1 if gx1_is_square else x2
    value = gx1 if gx1_is_square else gx2
    y = pow(value, (p + 1) // 4, p)
    if (y * y) % p != value:
        raise SaeError("SAE H2E SSWU map produced a non-residue")
    if (u & 1) != (y & 1):
        y = (-y) % p
    return x, y


def _sswu_group19(u: int) -> Point:
    return _sswu(u, SAE_CURVES[GROUP_19])


def _derive_pwe_h2e(own_mac: bytes, peer_mac: bytes, ssid: bytes,
                    password: bytes, password_identifier: bytes = b"",
                    group: int = GROUP_19) -> Point:
    """Derive the SAE H2E PT/PWE for an ECC group."""
    curve = _curve_for_group(group)
    if len(own_mac) != 6 or len(peer_mac) != 6 or own_mac == peer_mac:
        raise SaeError("SAE MAC addresses must be six distinct octets")
    if len(ssid) > 32:
        raise SaeError("SAE H2E SSID must be at most 32 octets")
    # PT = HashToElement(SSID, password[, password identifier]).
    digestmod = _hash_for_curve(curve, True)
    pwd_seed = _hkdf_extract(ssid, password + password_identifier, digestmod)
    pwd_value_len = curve.prime_len + (curve.prime_len + 1) // 2
    u1 = int.from_bytes(
        _hkdf_expand(pwd_seed, b"SAE Hash to Element u1 P1", pwd_value_len,
                     digestmod),
        "big",
    ) % curve.prime
    u2 = int.from_bytes(
        _hkdf_expand(pwd_seed, b"SAE Hash to Element u2 P2", pwd_value_len,
                     digestmod),
        "big",
    ) % curve.prime
    pt = _point_add(_sswu(u1, curve), _sswu(u2, curve), curve)
    if pt is None:
        raise SaeError("SAE H2E PT is at infinity")
    # PWE = scalar-op(val, PT), where val is derived from the ordered MACs.
    addr_key = max(own_mac, peer_mac) + min(own_mac, peer_mac)
    val = int.from_bytes(
        _hkdf_extract(bytes(curve.hash_len), addr_key, digestmod), "big")
    val = val % (curve.order - 1) + 1
    pwe = _point_mul(pt, val, curve)
    if pwe is None:
        raise SaeError("SAE H2E PWE is at infinity")
    return pwe


def _sae_pk_password_bytes(password: bytes) -> tuple[bytearray, int, int]:
    """Decode an SAE-PK password and return PasswordBase, Sec, bit length."""
    compact = password.replace(b"-", b"")
    if not compact:
        raise SaeError("SAE-PK password is empty")
    padded = compact.upper() + b"=" * ((8 - len(compact) % 8) % 8)
    try:
        password_base = bytearray(base64.b32decode(padded, casefold=True))
    except (ValueError, base64.binascii.Error) as error:
        raise SaeError("SAE-PK password is not valid base32") from error
    sec = 3 if password_base[0] & 0x80 else 5
    password_len = len(password)
    lambda_value = password_len - password_len // 5
    fingerprint_bits = 8 * sec + 19 * lambda_value // 4 - 5
    if fingerprint_bits <= 8 * sec:
        raise SaeError("SAE-PK password has insufficient fingerprint bits")
    return password_base, sec, fingerprint_bits


def _shift_left_1(data: bytearray) -> None:
    for index in range(len(data) - 1):
        data[index] = ((data[index] << 1) & 0xff) | (data[index + 1] >> 7)
    data[-1] = (data[-1] << 1) & 0xff


def _shift_left_19(data: bytearray) -> None:
    shifted = bytearray(len(data))
    source = 2
    destination = 0
    while source + 1 < len(data):
        shifted[destination] = ((data[source] << 3) |
                                (data[source + 1] >> 5)) & 0xff
        source += 1
        destination += 1
    shifted[destination] = (data[source] << 3) & 0xff
    shifted[destination + 1:] = b"\x00" * (len(data) - destination - 1)
    data[:] = shifted


def _sae_pk_fingerprint(password: bytes) -> tuple[bytes, int]:
    """Recreate hostapd's Fingerprint extraction from PasswordBase."""
    password_base, sec, fingerprint_bits = _sae_pk_password_bytes(password)
    fingerprint = bytearray(32)
    position = sec
    bits = fingerprint_bits - 8 * sec
    value = 0
    value_bits = 0
    while bits > 0:
        if value_bits < 8:
            _shift_left_1(password_base)  # skip Sec_1b
            value_19 = ((password_base[0] << 11) |
                        (password_base[1] << 3) |
                        (password_base[2] >> 5))
            _shift_left_19(password_base)
            value = (value << 19) | value_19
            value_bits += 19
        if value_bits >= 8:
            if bits < 8:
                break
            fingerprint[position] = (value >> (value_bits - 8)) & 0xff
            position += 1
            value_bits -= 8
            bits -= 8
    if bits > 0:
        value >>= value_bits - bits
        fingerprint[position] = (value << (8 - bits)) & 0xff
        position += 1
    return bytes(fingerprint[:position]), fingerprint_bits


def _parse_sae_pk_ies(data: bytes) -> tuple[bytes, bytes, bytes] | None:
    fils_public_key = fils_key_confirm = encrypted_modifier = None
    position = 0
    while position + 2 <= len(data):
        element_id = data[position]
        element_len = data[position + 1]
        position += 2
        if position + element_len > len(data):
            return None
        body = data[position:position + element_len]
        position += element_len
        if element_id == 255 and body:
            if body[0] == 12:
                fils_public_key = body[1:]
            elif body[0] == 3:
                fils_key_confirm = body[1:]
        elif (element_id == 221 and len(body) >= 4 and
              body[:4] == _SAE_PK_VENDOR):
            encrypted_modifier = body[4:]
    if (fils_public_key is None or fils_key_confirm is None or
            encrypted_modifier is None):
        return None
    return fils_public_key, fils_key_confirm, encrypted_modifier


class SaePasswordClient:
    """One ECC-group SAE password exchange, without radio I/O."""

    def __init__(self, own_mac: bytes, peer_mac: bytes, password: bytes | str,
                 *, rand: int | None = None, mask: int | None = None,
                 group: int = GROUP_19,
                 h2e: bool = False, ssid: bytes | str | None = None,
                 password_identifier: bytes | str | None = None,
                 sae_pk: bool = False, sae_ext_key: bool = False):
        if isinstance(password, str):
            password = password.encode()
        if not isinstance(password, bytes) or not password:
            raise ValueError("SAE password must be non-empty bytes")
        self.own_mac = bytes(own_mac)
        self.peer_mac = bytes(peer_mac)
        self.password = bytes(password)
        self.group = group
        self.curve = _curve_for_group(group)
        self.h2e = h2e
        if sae_pk and not h2e:
            raise ValueError("SAE-PK requires H2E")
        if sae_ext_key and not h2e:
            raise ValueError("SAE-EXT-KEY requires H2E")
        if sae_pk and sae_ext_key:
            raise ValueError("SAE-PK and SAE-EXT-KEY are separate AKMs")
        self.sae_pk = sae_pk
        self.sae_ext_key = sae_ext_key
        self.ssid = b""
        if password_identifier is not None and not h2e:
            raise ValueError("SAE password identifier requires H2E")
        if h2e:
            if ssid is None:
                raise ValueError("SAE H2E requires the SSID")
            if isinstance(ssid, str):
                ssid = ssid.encode()
            if not isinstance(ssid, bytes):
                raise ValueError("SAE H2E SSID must be bytes or text")
            self.ssid = bytes(ssid)
            if password_identifier is None:
                password_identifier = b""
            elif isinstance(password_identifier, str):
                password_identifier = password_identifier.encode()
            if not isinstance(password_identifier, bytes):
                raise ValueError("SAE password identifier must be bytes or text")
            if len(password_identifier) > 254:
                raise ValueError("SAE password identifier must be at most 254 octets")
            self.password_identifier = bytes(password_identifier)
            self.pwe = _derive_pwe_h2e(
                self.own_mac, self.peer_mac, ssid, self.password,
                password_identifier, group)
        else:
            self.password_identifier = b""
            self.pwe = _derive_pwe(
                self.own_mac, self.peer_mac, self.password, group)
        self.rand = self._secret(rand)
        self.mask = self._secret(mask)
        self.scalar = (self.rand + self.mask) % self.curve.order
        if self.scalar in (0, 1):
            raise ValueError("SAE scalar is invalid")
        element = _point_mul(self.pwe, self.mask, self.curve)
        if element is None:
            raise ValueError("SAE commit element is invalid")
        self.element = element[0], (-element[1]) % self.curve.prime
        self.send_confirm = 0
        self.pmk: bytes | None = None
        self.pmkid: bytes | None = None
        self.kck: bytes | None = None
        self.kek: bytes | None = None
        self.peer_scalar: int | None = None
        self.peer_element: Point = None
        self._confirmed = False

    @staticmethod
    def _secret_for_order(value: int | None, order: int) -> int:
        if value is None:
            return secrets.randbelow(order - 2) + 2
        if not 2 <= value < order:
            raise ValueError("SAE rand/mask must be in [2, order-1]")
        return value

    def _secret(self, value: int | None) -> int:
        return self._secret_for_order(value, self.curve.order)

    def start(self) -> bytes:
        """Return the group/scalar/element portion of an SAE Commit frame."""
        commit = (self.group.to_bytes(2, "little") +
                  self.scalar.to_bytes(self.curve.order_len, "big") +
                  _point_encode(self.element, self.curve))
        if self.password_identifier:
            # IEEE 802.11 SAE Password Identifier extension element:
            # Element ID 255, length 1+identifier, extension ID 33.
            commit += (b"\xff" + bytes((1 + len(self.password_identifier), 33)) +
                       self.password_identifier)
        if self.sae_ext_key:
            commit += SAE_EXT_KEY_AKM_IE
        return commit

    def process_commit(self, payload: bytes) -> bytes:
        """Process a peer commit and return the SAE Confirm payload."""
        commit_len = 2 + self.curve.order_len + 2 * self.curve.prime_len
        if len(payload) < commit_len:
            raise SaeError("SAE commit payload is too short")
        group = int.from_bytes(payload[:2], "little")
        if group != self.group:
            raise SaeError(f"unsupported SAE group {group}")
        scalar_end = 2 + self.curve.order_len
        element_end = scalar_end + 2 * self.curve.prime_len
        self.peer_scalar = int.from_bytes(payload[2:scalar_end], "big")
        if not 2 <= self.peer_scalar < self.curve.order:
            raise SaeError("SAE peer scalar is invalid")
        self.peer_element = _point_decode(
            payload[scalar_end:element_end], self.curve)
        inner = _point_add(
            _point_mul(self.pwe, self.peer_scalar, self.curve),
            self.peer_element, self.curve)
        shared = _point_mul(inner, self.rand, self.curve)
        if shared is None:
            raise SaeError("SAE shared point is at infinity")
        k = shared[0].to_bytes(self.curve.prime_len, "big")
        scalar_sum = ((self.scalar + self.peer_scalar) % self.curve.order).to_bytes(
            self.curve.order_len, "big")
        hashmod = _hash_for_curve(self.curve, self.h2e)
        hash_len = self.curve.hash_len if self.h2e else 32
        keyseed = _hkdf_extract(bytes(hash_len), k, hashmod)
        label = b"SAE-PK keys" if self.sae_pk else KCK_PMK_LABEL
        pmk_len = hash_len if self.sae_ext_key else 32
        output_len = (2 * hash_len + pmk_len if self.sae_pk else
                      hash_len + pmk_len)
        keys = _prf_bits(keyseed, label, scalar_sum, output_len * 8, hashmod)
        self.kck = keys[:hash_len]
        self.pmk = keys[hash_len:hash_len + pmk_len]
        self.kek = (keys[hash_len + 32:hash_len + 32 + hash_len]
                    if self.sae_pk else None)
        self.pmkid = scalar_sum[:16]
        self.send_confirm = 1
        confirm_data = (
            self.send_confirm.to_bytes(2, "little") +
            self.scalar.to_bytes(self.curve.order_len, "big") +
            _point_encode(self.element, self.curve) +
            self.peer_scalar.to_bytes(self.curve.order_len, "big") +
            _point_encode(self.peer_element, self.curve))
        confirm = _hkdf_extract(self.kck, confirm_data, hashmod)
        return self.send_confirm.to_bytes(2, "little") + confirm

    def verify_confirm(self, payload: bytes) -> bool:
        if self.kck is None or self.peer_scalar is None or self.peer_element is None:
            raise SaeError("SAE confirm received before commit processing")
        hash_len = len(self.kck)
        if len(payload) < 2 + hash_len:
            return False
        counter = payload[:2]
        confirm_data = (
            counter + self.peer_scalar.to_bytes(self.curve.order_len, "big") +
            _point_encode(self.peer_element, self.curve) +
            self.scalar.to_bytes(self.curve.order_len, "big") +
            _point_encode(self.element, self.curve))
        expected = _hkdf_extract(
            self.kck, confirm_data, _hash_for_curve(self.curve, self.h2e))
        self._confirmed = hmac.compare_digest(payload[2:2 + hash_len], expected)
        if self._confirmed and self.sae_pk:
            self._confirmed = self._verify_pk_confirm(payload[2 + hash_len:])
        return self._confirmed

    def _verify_pk_confirm(self, data: bytes) -> bool:
        if self.kek is None or self.peer_element is None:
            return False
        parsed = _parse_sae_pk_ies(data)
        if parsed is None:
            return False
        fils_public_key, key_auth, encrypted_modifier = parsed
        if len(fils_public_key) < 2 or fils_public_key[0] != 2:
            return False
        try:
            modifier = AESSIV(self.kek).decrypt(encrypted_modifier, [])
            if len(modifier) != 16:
                return False
            public_key_der = fils_public_key[1:]
            fingerprint, fingerprint_bits = _sae_pk_fingerprint(self.password)
            fingerprint_data = self.ssid + modifier + public_key_der
            expected = bytearray(hashlib.sha256(fingerprint_data).digest())
            if fingerprint_bits % 8:
                expected[fingerprint_bits // 8] &= (
                    0xff << (8 - fingerprint_bits % 8)) & 0xff
            if not hmac.compare_digest(expected[:len(fingerprint)], fingerprint):
                return False
            signed = (
                _point_encode(self.peer_element, self.curve) +
                _point_encode(self.element, self.curve) +
                self.peer_scalar.to_bytes(self.curve.order_len, "big") +
                self.scalar.to_bytes(self.curve.order_len, "big") +
                modifier + public_key_der +
                self.peer_mac + self.own_mac)
            digest = hashlib.sha256(signed).digest()
            public_key = serialization.load_der_public_key(public_key_der)
            public_key.verify(key_auth, digest,
                              ec.ECDSA(Prehashed(hashes.SHA256())))
        except (ValueError, TypeError, InvalidSignature):
            return False
        return True


def sae_auth_frame(bssid: bytes, sta: bytes, sequence: int,
                   payload: bytes = b"", status: int = 0) -> bytes:
    """Build an SAE Authentication frame for any supported ECC group."""
    if sequence not in (1, 2):
        raise ValueError("SAE authentication sequence must be 1 or 2")
    return (mac_header(b"\xb0\x00", bssid, sta, bssid) +
            struct.pack("<HHH", 3, sequence, status) + bytes(payload))


@dataclass(slots=True)
class SaeAssociationResult:
    associated: bool
    auth_status: int | None
    assoc_status: int | None
    fail_reason: str | None
    client: SaePasswordClient
    assoc_response: bytes | None = None


async def sae_associate(iface, bssid: bytes, sta: bytes, ssid: str,
                        password: bytes | str, channel: int, rsn_ie: bytes,
                        *, timeout: float = 2.0, attempts: int = 2,
                        group: int = GROUP_19,
                        on_confirmed: Callable[[SaePasswordClient], None] | None = None,
                        h2e: bool = False,
                        password_identifier: bytes | str | None = None,
                        sae_pk: bool = False, sae_ext_key: bool = False,
                        assoc_extra_ies: bytes = b"",
                        ) -> SaeAssociationResult:
    """Run ECC-group SAE authentication and association over raw frames."""
    client = SaePasswordClient(
        sta, bssid, password, group=group, h2e=h2e, ssid=ssid if h2e else None,
        password_identifier=password_identifier, sae_pk=sae_pk,
        sae_ext_key=sae_ext_key)
    queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=32)
    loop = asyncio.get_running_loop()
    auth_status = None
    assoc_status = None
    fail_reason = None

    def on_packet(pkt) -> None:
        raw = bytes(getattr(pkt, "raw", b""))
        if len(raw) < 24 or raw[4:10] != sta or raw[10:16] != bssid:
            return
        if ((int.from_bytes(raw[:2], "little") >> 2) & 3) != 0:
            return
        def enqueue() -> None:
            try:
                queue.put_nowait(raw)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                queue.put_nowait(raw)
        loop.call_soon_threadsafe(enqueue)

    if iface.current_channel != channel and not await iface.set_channel(channel):
        return SaeAssociationResult(False, None, None,
                                    "SAE channel selection failed", client)
    iface.register_rx_callback(on_packet)
    try:
        for _ in range(attempts):
            queue = asyncio.Queue(maxsize=32)
            # SAE H2E is selected in the Authentication frame by the
            # SAE-Hash-to-Element status code (126). hostapd configured with
            # sae_pwe=1 rejects a legacy success status here.
            commit_status = (_SAE_PK_STATUS if sae_pk else
                             (_SAE_H2E_STATUS if h2e else 0))
            commit = sae_auth_frame(
                bssid, sta, 1, client.start(), status=commit_status)
            await iface.send_no_wait(commit)
            deadline = asyncio.get_running_loop().time() + timeout
            confirmed = False
            while asyncio.get_running_loop().time() < deadline:
                try:
                    frame = await asyncio.wait_for(
                        queue.get(), max(0.05, deadline - asyncio.get_running_loop().time()))
                except asyncio.TimeoutError:
                    break
                if len(frame) < 30:
                    continue
                subtype = (int.from_bytes(frame[:2], "little") >> 4) & 0x0f
                if subtype == 11:
                    algorithm, sequence, status = struct.unpack_from("<HHH", frame, 24)
                    if algorithm != 3:
                        continue
                    auth_status = status
                    # The peer's commit uses status 126 for H2E and status 0
                    # for legacy hunting-and-pecking. Confirm is always 0.
                    expected_status = (
                        _SAE_PK_STATUS if sae_pk and sequence == 1 else
                        (_SAE_H2E_STATUS if h2e and sequence == 1 else 0))
                    if status != expected_status:
                        fail_reason = f"SAE auth rejected (status {status})"
                        return SaeAssociationResult(False, auth_status, None,
                                                    fail_reason, client)
                    if sequence == 1:
                        try:
                            confirm = client.process_commit(frame[30:])
                        except SaeError as error:
                            fail_reason = str(error)
                            return SaeAssociationResult(False, auth_status, None,
                                                        fail_reason, client)
                        await iface.send_no_wait(
                             sae_auth_frame(bssid, sta, 2, confirm))
                    elif sequence == 2:
                        if not client.verify_confirm(frame[30:]):
                            fail_reason = "SAE confirm verification failed"
                            return SaeAssociationResult(False, auth_status, None,
                                                        fail_reason, client)
                        if on_confirmed is not None:
                            on_confirmed(client)
                        confirmed = True
                        break
                elif subtype == 1 and len(frame) >= 28:
                    assoc_status = int.from_bytes(frame[26:28], "little")
                    if assoc_status == 0:
                        return SaeAssociationResult(True, auth_status, assoc_status,
                                                    None, client, frame)
                    fail_reason = f"SAE association rejected (status {assoc_status})"
                    return SaeAssociationResult(False, auth_status, assoc_status,
                                                fail_reason, client)
            if not confirmed:
                continue
            # hostapd may process the confirm frame from its SAE queue just
            # after replying. Give that state transition a short head start
            # before sending the association request.
            await asyncio.sleep(0.2)
            request = assoc_req(
                bssid, sta, ssid,
                rsn_ie + (SAE_PK_RSNX_IE if sae_pk else
                          (SAE_H2E_RSNX_IE if h2e else b"")) +
                assoc_extra_ies,
                channel=channel, privacy=True)
            deadline = asyncio.get_running_loop().time() + timeout
            while asyncio.get_running_loop().time() < deadline:
                await iface.send_no_wait(request)
                try:
                    frame = await asyncio.wait_for(
                        queue.get(), max(0.05, deadline - asyncio.get_running_loop().time()))
                except asyncio.TimeoutError:
                    break
                if len(frame) < 28:
                    continue
                subtype = (int.from_bytes(frame[:2], "little") >> 4) & 0x0f
                if subtype != 1:
                    continue
                assoc_status = int.from_bytes(frame[26:28], "little")
                if assoc_status == 0:
                    return SaeAssociationResult(True, auth_status, assoc_status,
                                                None, client, frame)
                if assoc_status in _SAE_ASSOC_RETRY_STATUSES:
                    # Status 17/30 can be emitted while hostapd is completing
                    # the queued SAE-confirm state transition. Retry within
                    # the bounded association deadline; hard failures remain
                    # terminal.
                    await asyncio.sleep(0.15)
                    continue
                fail_reason = f"SAE association rejected (status {assoc_status})"
                return SaeAssociationResult(False, auth_status, assoc_status,
                                            fail_reason, client)
        fail_reason = fail_reason or "no SAE authentication/association response"
        return SaeAssociationResult(False, auth_status, assoc_status,
                                    fail_reason, client)
    finally:
        iface.unregister_rx_callback(on_packet)
