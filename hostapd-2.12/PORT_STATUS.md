# hostapd 2.12 / wifit3 Windows Capability Status

Author: DensenDeluxe  
Revision date: 9 November 2026  
System: Windows 11 x64  
Scope: native hostapd AP operation over six wifit3 USB radios

## Executive assessment

The modified hostapd 2.12 build operates on the specified Windows 11 system
through the wifit3 raw-radio bridge. The experimentally verified scope includes
beacon transmission, raw management exchange, station lifecycle management,
software key lifecycle, WPA2-Personal, WPA3-SAE, IEEE 802.11w PMF, selected
802.11r FT-SAE paths, RADIUS/EAP startup, EAP-TLS, EAP-MSCHAPv2,
EAP-PSK, EAP-SAKE, EAP-PAX, EAP-GPSK, EAP-GPSK-SHA256, EAP-PWD, PEAPv1/MSCHAPv2,
EAP-TTLS/MSCHAPv2, EAP-SIM, EAP-AKA, EAP-AKA', EAP-FAST/MSCHAPv2, and
EAP-TEAP/MSCHAPv2, EAP-EKE, and EAP-IKEv2.

The result is a laboratory interoperability port. It is not evidence of full
production hostapd parity. Ethernet bridging, VLAN integration, hardware key
offload, hardware station-table offload, FT-over-DS/RRB, and production-grade
radio timing remain outside the verified scope. Ethernet and VLAN are
intentionally excluded from this project.

The integrated Windows 11 WLAN client completed one diagnostic WPA2 association
when using an SSID already present in the Windows scan cache. A six-radio fresh-
SSID acceptance matrix produced 0/6 Windows discoveries and 0/6 standard-client
associations. Standard-client interoperability is therefore conditional and is
not classified as a verified repeatable capability.

## Build status

| Component | Status | Evidence |
|---|---|---|
| Native `hostapd.exe` | Verified | MSYS2 UCRT64 build, hostapd 2.12 |
| Native `hostapd_cli.exe` | Verified | Same build profile and toolchain |
| wifit3 driver bridge | Verified experimentally | Authenticated local TCP IPC and six-radio matrix |
| UDP control interface | Verified | Control smoke and `hostapd_cli` responses |
| Windows idle event loop | Verified | Timer-only and control-socket tests |
| Python bridge regression | Verified | 164 tests passed |
| Python bytecode compilation | Verified | `compileall` completed without errors |

## Native EAP build profile

The Windows profile now links the following hostapd EAP server modules:

`EAP-TLS`, `EAP-TTLS`, `EAP-PEAP`, `EAP-MSCHAPv2`, `EAP-MD5`, `EAP-GTC`,
`EAP-SIM`, `EAP-AKA`, `EAP-AKA'`, `EAP-PAX`, `EAP-PSK`, `EAP-PWD`, `EAP-SAKE`,
`EAP-GPSK`, `EAP-GPSK-SHA256`, `EAP-FAST`, `EAP-TEAP`, `EAP-EKE`, and
`EAP-IKEv2`.

Compilation of a module is not classified as interoperability verification.
The OTA status below distinguishes source inclusion, local protocol tests, and
real-radio end-to-end verification.

## Capability matrix

| Capability | Implementation state | OTA evidence | Classification |
|---|---|---|---|
| Open AP and beacon submission | Software beacon path over wifit3 TX | Six-radio AP startup matrix | Experimental laboratory path |
| Active monitor and link ACK | Opt-in `set_fake_mac`, `enable_rx_acks`, and `send_until_ack` path | Open-system association on 6/6 radios | Experimental laboratory path |
| Station add, update, authorization, and removal | Software station store plus hostapd callbacks | Unit, bridge, and OTA management tests | Experimental laboratory path |
| Deauthentication and disassociation | Native MLME callbacks with bounded retry | Broadcast and unicast tests, 6/6 per operation | Experimental laboratory path |
| WPA2-Personal / CCMP | Software CCMP, PTK/GTK lifecycle | Complete M1–M4 OTA verification | Experimental laboratory path |
| Windows 11 standard WLAN client | Temporary `netsh wlan` WPA2 profile path | Cached-SSID diagnostic 1/1; fresh-SSID matrix 0/6 | Conditional; repeatable discovery not verified |
| WPA2-Personal / TKIP | Software TKIP, Michael, RC4, ICV, and replay protection | Complete controlled OTA matrix, 6/6 | Experimental laboratory path |
| WPA2-Personal / GCMP-128 | Software AES-GCM and key lifecycle | Complete controlled OTA matrix, 6/6 | Experimental laboratory path |
| WPA2-Personal / GCMP-256 | Software AES-256-GCM and key lifecycle | Complete controlled OTA matrix, 6/6 | Experimental laboratory path |
| WPA2-Personal / CCMP-256 | Software AES-256-CCM and key lifecycle | Complete controlled OTA matrix, 6/6 | Experimental laboratory path |
| WPA3-SAE legacy groups 19/20/21 | ECC Commit/Confirm, PTK derivation, CCMP, PMF/BIP | 6/6 OTA per group | Experimental laboratory path |
| WPA3-SAE H2E groups 19/20/21 | RSNXE, status 126/127, H2E, PMK/KCK/PMKID | 6/6 OTA per group | Experimental laboratory path |
| SAE-PK groups 19/20/21 | SAE-PK KDF, AES-SIV, ECDSA KeyAuth | 6/6 OTA per group | Experimental laboratory path |
| SAE-EXT-KEY groups 19/20/21 | AKM 24 and variable SHA-256/384/512 key layouts | 6/6 OTA per group | Experimental laboratory path |
| FT-SAE | PMK-R0/R1, FT-PTK, MDIE/FTIE, FT MIC, OTA Auth/Reassoc | 6/6 OTA | Experimental laboratory path |
| FT-SAE-EXT-KEY | AKM 25 and variable FT MIC lengths | 6/6 per group 19/20/21 | Experimental laboratory path |
| PMF / BIP-CMAC-128 | Software IGTK/MMIE and replay protection | 6/6 OTA action-frame verification | Experimental laboratory path |
| PMF / BIP-GMAC-128, BIP-GMAC-256, BIP-CMAC-256 | Software IGTK/MMIE implementations | 6/6 per cipher for PSK and Enterprise | Experimental laboratory path |
| WPA-Enterprise / EAP-TLS | TLS 1.2 client, RADIUS/EAP, MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-MSCHAPv2 | RFC 2759/3079 client and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-PSK | RFC 4764 client, EAX protected channel, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-SAKE | RFC 4763 client, HMAC-SHA1 MIC exchange, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-PAX | RFC 4746 PAX-STD client, ICV/MAC validation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-GPSK | RFC 5433 AES ciphersuite client, AES-GKDF, CMAC MIC validation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-GPSK-SHA256 | RFC 5433 SHA256 ciphersuite client, HMAC-SHA256-GKDF, HMAC MIC validation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-SIM | RFC 4186 Start/Challenge client, GSM triplets, HMAC-SHA1-128 MIC validation, FIPS 186-2 key derivation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port using the Windows loopback UDP SIM-DB transport | Experimental laboratory path |
| WPA-Enterprise / EAP-AKA | RFC 4187 Identity/Challenge client, UMTS authentication data, HMAC-SHA1-128 MIC validation, FIPS 186-2 key derivation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port using the Windows loopback UDP SIM-DB transport | Experimental laboratory path |
| WPA-Enterprise / EAP-AKA' | RFC 5448 network-name-bound CK'/IK' derivation, KDF selection, HMAC-SHA256-128 MIC validation, and MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port using the Windows loopback UDP SIM-DB transport | Experimental laboratory path |
| WPA-Enterprise / EAP-PWD | RFC 5931 groups 19/20/21 client and MSK-to-PMK handoff | 6/6 OTA per group to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / PEAPv1/MSCHAPv2 | TLS 1.2 tunnel and inner EAP-MSCHAPv2 | 6/6 OTA to inner success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-TTLS/MSCHAPv2 | TLS 1.2 tunnel, RADIUS AVPs, MSK-to-PMK handoff | 6/6 OTA to inner success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-FAST/MSCHAPv2 | TLS 1.2 authenticated FAST tunnel, RFC 4851 T-PRF, compound-key derivation, Crypto-Binding, and MSK-to-PMK handoff | 6/6 OTA to inner success, Crypto-Binding success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-TEAP/MSCHAPv2 | TLS 1.2 TEAP exporter, RFC 7170 compound-key derivation, Result/Intermediate-Result handling, Crypto-Binding, and MSK-to-PMK handoff | 6/6 OTA to inner success, Crypto-Binding success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-EKE | RFC 6124 EKE group 14, AES-128-CBC, HMAC-SHA1 PRF/MAC, MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| WPA-Enterprise / EAP-IKEv2 | IKEv2 SA_INIT, DH group 2, AES-CBC, HMAC-SHA1-96, IKE_AUTH, MSK-to-PMK handoff | 6/6 OTA to EAP-Success, M4, and authorized port | Experimental laboratory path |
| RADIUS authentication transport | Integrated UDP listener and request handling | Six-radio RADIUS smoke matrix | Experimental laboratory path |
| RADIUS accounting | UDP accounting listener and asynchronous event drain | Observed station accounting, 6/6 | Laboratory observation path |
| Station counters and inactivity | Software metadata path and hostapd callbacks | Positive counters and inactivity on six radios | Laboratory observation path |
| Dynamic VLAN and Windows network bridge | Not implemented | Explicitly excluded | Out of scope |
| Ethernet data plane | Not implemented | Explicitly excluded | Out of scope |
| 802.11r FT-over-DS/RRB | Not implemented in the wifit3 path | No OTA evidence | Not verified |
| Hardware station and key offload | Not claimed | No hardware offload evidence | Not verified |

## Six-radio test inventory

| Index | Radio | USB identifier | MAC address | Observer assignment |
|---:|---|---|---|---|
| 0 | MT7925AU / Netgear A9000 | `0846:9072` | `28:94:01:d1:85:5d` | MT7610U |
| 1 | RTL8821CU / Auscoumer 600 | `0bda:c820` | `fc:22:1c:50:65:ce` | MT7610U |
| 2 | MT7601U | `148f:7601` | `90:de:80:55:0d:87` | MT7610U |
| 3 | MT7610U / AWUS036ACHM | `0e8d:7610` | `00:c0:ca:bd:0a:31` | MT7601U |
| 4 | RTL8922AU / ASUS USB-BE93 | `0b05:1d84` | `b0:82:e2:2a:25:96` | MT7610U |
| 5 | RTL8814AU / AWUS1900 | `0bda:8813` | `00:c0:ca:ae:5e:a8` | MT7601U |

Two devices initially enumerated in USB CD-ROM mode. They were not admitted to
the test matrix until their wifit3 radio interfaces were available. All six
interfaces listed above were subsequently used for the controlled tests.

## Verification criteria

An OTA run is classified as successful only when all method-specific criteria
are satisfied: raw association, status-zero authentication and association,
successful method completion, WPA four-way completion, authorized port state,
absence of a client error, absence of a fatal hostapd failure, and a zero
process return code. For PMF runs, the protected action frame must additionally
pass the BIP verification path.

## Corrections after the OTA matrix

The six-radio OTA matrix was not repeated. These source corrections change
the laboratory path that matrix exercised:

- CCMP and GCMP additional authentication data follows IEEE 802.11. Subtype bits 4–6, Retry, PwrMgt and MoreData are cleared, Protected is forced to 1, and QoS data clears Order. The previous mask produced a different MIC. A client that shares this implementation could not detect that.
- Infrastructure beacons insert a software TIM and DTIM count between the hostapd beacon head and tail. The timestamp remains a monotonic microsecond clock. Transmission is not locked to a hardware TBTT.
- Beacon, management and EAPOL frames share one 12-bit sequence counter for the AP transmitter. The fragment number is preserved.
- `get_seqnum` returns the last used PN, TSC or IPN as 6 little-endian octets. An unused key reports 0. Key-install sequences are read little-endian.
- A management frame marked noack, including a probe response to a wildcard broadcast probe, is submitted without waiting for a link ACK. An armed link-ACK wait that sees no ACK is reported with TX status ack=0. Successful submission without an ACK tally is still reported as ack=1, because hostapd otherwise does not complete association.
- The Windows driver drains queued receive frames and reads each command until its acknowledgement. Receive delivery does not block the radio asyncio thread.

## Reproducibility and evidence

The native executable currently installed in the workspace was built with the
local MSYS2 UCRT64 toolchain from the expanded Windows profile. It includes
the driver corrections in the previous section. The six-radio OTA matrix and
the Windows fresh-SSID run were produced by the previous executable, SHA-256
`FCEEA5E8484C8CB18DDC53EF30CFA222F617BA9C714B5AC4249B3EA43B93FCBE`, 7,466,243
bytes, and were not repeated.

| Artifact | Value |
|---|---|
| Version | hostapd 2.12 |
| Executable | `hostapd-2.12/hostapd/hostapd.exe` |
| Executable size | 7,486,834 bytes |
| SHA-256 | `2D7A610D36ADC956B2F31686AFBFC6589D6EA4D9974851FDC2BCB52B1D6A8A34` |
| Python regression | 164 passed |
| Python compilation | Passed |

## References

- `README-WIFIT3.md`
- `../TESTREPORT-WIN11-WIFIT3-HOSTAPD.md`
- `wifit3_bridge/examples/windows_wpa_smoke.py`
