import pytest

from wifit3_bridge.tkip import (
    WPA_ALG_TKIP,
    TkipError,
    TkipKeyStore,
    michael_mic,
    michael_mic_core,
    tkip_decrypt_mpdu,
    tkip_encrypt_mpdu,
)


AP = bytes.fromhex("020000000001")
STA = bytes.fromhex("020000000002")
KEY = bytes(range(32))


def _data_frame(payload=b"tkip-test"):
    # client -> AP, ToDS; DA is addr3 and SA is addr2 for Michael.
    return (b"\x08\x01\x00\x00" + AP + STA + AP + b"\x00\x00" + payload)


def test_michael_annex_h_core_vectors():
    assert michael_mic_core(bytes(8), b"").hex() == "82925c1ca1d130b8"
    key = bytes.fromhex("82925c1ca1d130b8")
    assert michael_mic_core(key, b"M").hex() == "434721ca40639b3f"


def test_michael_pseudoheader_and_tkip_roundtrip():
    frame = _data_frame(b"hello-eapol")
    mic = michael_mic(KEY[16:24], frame)
    assert len(mic) == 8
    protected = tkip_encrypt_mpdu(frame, KEY, 0x000100000001, key_id=2)
    assert int.from_bytes(protected[:2], "little") & 0x4000
    assert len(protected) == len(frame) + 8 + 12
    tsc, decoded = tkip_decrypt_mpdu(protected, KEY, source=STA)
    assert tsc == 0x000100000001
    assert decoded == frame


def test_tkip_tamper_and_replay_rejected():
    frame = _data_frame(b"protected")
    protected = tkip_encrypt_mpdu(frame, KEY, 7)
    tampered = bytearray(protected)
    tampered[-7] ^= 1
    with pytest.raises(TkipError):
        tkip_decrypt_mpdu(bytes(tampered), KEY, source=STA)
    assert tkip_decrypt_mpdu(protected, KEY, source=STA)[1] == frame
    with pytest.raises(TkipError):
        tkip_decrypt_mpdu(protected, KEY, source=STA, minimum_tsc=7)


def test_tkip_keystore_lifecycle():
    store = TkipKeyStore()
    assert store.install(WPA_ALG_TKIP, 0, STA, 0, b"", KEY)
    assert store.last_tx_tsc(STA, 0) == 0
    protected = store.encrypt(_data_frame(b"store"), STA)
    assert store.last_tx_tsc(STA, 0) == 1
    assert store.decrypt(protected, STA)[1] == _data_frame(b"store")
    assert store.snapshot()[f"{STA.hex(':')}/0"]["alg"] == WPA_ALG_TKIP
    with pytest.raises(TkipError):
        store.decrypt(protected, STA)
