# Scientific Test Report: hostapd 2.12 over wifit3 on Windows 11

Author: DensenDeluxe  
Test date: 9 November 2026  
System: Acer Predator PHN18-72, Windows 11 Home x64, build 26300  
hostapd: 2.12, native Windows executable  
wifit3: local laboratory revision, commit `99189c4d`  
Test mode: controlled raw-802.11 loopback bridge with six USB radios

## Abstract

This report evaluates a modified hostapd 2.12 build using the wifit3 raw-radio
backend on the specified Windows 11 system. The evaluation covers native build
integrity, bridge operation, AP startup, station management, WPA key lifecycle,
RADIUS/EAP control paths, and OTA client interoperability.

The build is functional for the experimentally verified laboratory scope. The
most recent local regression contains 166 passing tests. Controlled OTA tests
verified WPA2-Personal, WPA3-SAE, PMF/BIP, FT-SAE, FT-SAE-EXT-KEY, EAP-TLS,
EAP-MSCHAPv2, EAP-PSK, EAP-SAKE, EAP-PAX, EAP-GPSK, EAP-GPSK-SHA256, EAP-PWD,
EAP-SIM, EAP-AKA, EAP-AKA', PEAPv1/MSCHAPv2,
EAP-TTLS/MSCHAPv2, EAP-FAST/MSCHAPv2, EAP-TEAP/MSCHAPv2, EAP-EKE, and
EAP-IKEv2. The result does not
establish complete production hostapd parity. Ethernet, VLAN, FT-over-DS/RRB,
hardware station offload, hardware key offload, and production radio timing
are not included in the acceptance claim.

An external Ubuntu 26.04.1 LTS client using an AWUS036ACHM completed OTA
interoperability runs for WPA2-Personal/CCMP, WPA2-Personal with required
PMF/BIP-CMAC-128, and WPA3-SAE/H2E group 19. The three runs completed 6, 4,
and 4 client connections respectively, including 5, 3, and 3 controlled
reconnects. The WPA2 baseline remained connected for 183.8 seconds after its
final reconnect. All six WPA3-SAE/H2E stability samples remained connected
over a 50-second observation window. The AP smoke runner automatically armed
active-monitor link acknowledgements in each run.

The integrated Windows WLAN client completed one cached-SSID diagnostic
association. A separate six-radio fresh-SSID matrix produced 0/6 discoveries
and 0/6 associations. Linux-client interoperability is verified for the tested
adapter and configuration; repeatable Windows-client discovery remains
unverified.

## 1. Objective and scope

The objective was to determine whether the modified hostapd build can execute
its AP state machine on Windows 11 while using wifit3 for raw radio I/O. The
test scope was restricted to the six available wifit3-compatible USB dongles.

The following were in scope:

- native Windows compilation and process startup;
- authenticated bridge IPC and UDP control;
- beacon and raw management transmission;
- station add, update, authorization, removal, and management frames;
- software WPA key installation and protected EAPOL handling;
- WPA2-Personal, WPA3-SAE, PMF/BIP, and selected 802.11r paths;
- RADIUS/EAP authentication and accounting transport;
- controlled OTA client tests using a second wifit3 observer radio;
- standard-client interoperability using a native Linux WLAN stack.

Ethernet data-plane bridging and VLAN integration were deliberately excluded.

## 2. Test system and radio inventory

| Index | Radio | USB VID:PID | MAC address | Observer |
|---:|---|---|---|---|
| 0 | MT7925AU / Netgear A9000 | `0846:9072` | `28:94:01:d1:85:5d` | MT7610U |
| 1 | RTL8821CU / Auscoumer 600 | `0bda:c820` | `fc:22:1c:50:65:ce` | MT7610U |
| 2 | MT7601U | `148f:7601` | `90:de:80:55:0d:87` | MT7610U |
| 3 | MT7610U / AWUS036ACHM | `0e8d:7610` | `00:c0:ca:bd:0a:31` | MT7601U |
| 4 | RTL8922AU / ASUS USB-BE93 | `0b05:1d84` | `b0:82:e2:2a:25:96` | MT7610U |
| 5 | RTL8814AU / AWUS1900 | `0bda:8813` | `00:c0:ca:ae:5e:a8` | MT7601U |

Two devices initially enumerated in USB CD-ROM mode. They were excluded until
their wifit3 radio interfaces were available. The six interfaces in the table
were then used in the controlled test matrix.

## 3. Methodology

Each test used a single AP radio and, where required, a separately assigned
observer radio. USB ownership was serialized. The harness collected hostapd
control responses, raw authentication and association status, EAP state,
WPA state, protected-frame observations, process return code, and fatal-error
state.

An OTA test was accepted only if it reached raw association, status-zero
authentication and association, method success, complete WPA four-way
handshake, authorized port state, no client error, no fatal hostapd error, and
return code zero. PMF tests additionally required successful BIP verification
of a protected action frame.

No WPA keys, EAP credentials, or private key material are included in this
report.

## 4. Native build verification

The Windows profile was rebuilt with the local MSYS2 UCRT64 toolchain. The
profile links the existing hostapd AP/WPA/RADIUS stack and additionally enables
the native EAP server modules for EAP-SIM, EAP-AKA, EAP-AKA', EAP-PAX, EAP-PSK,
EAP-PWD, EAP-SAKE, EAP-GPSK, EAP-GPSK-SHA256, EAP-FAST, EAP-TEAP, EAP-EKE, and
EAP-IKEv2.

The native Windows build required a portability correction for the EAP-SIM/AKA
database path. AF_UNIX is unavailable in the Python 3.11/Winsock environment
(`WinError 10047` for an AF_UNIX datagram socket), while hostapd's native
Windows build also retains a POSIX-domain implementation. The source therefore
adds a connected IPv4 UDP database transport using the configuration form
`eap_sim_db=udp:127.0.0.1:<port>` and registers that socket with the Windows
event loop. The existing UNIX-domain path remains available on platforms that
provide it.

The build completed successfully, including `hostapd.exe` and
`hostapd_cli.exe`. The resulting executable has the following identity:

| Property | Value |
|---|---|
| Version | hostapd 2.12 |
| Path | `hostapd-2.12/hostapd/hostapd.exe` |
| Size | 7,486,834 bytes |
| SHA-256 | `2D7A610D36ADC956B2F31686AFBFC6589D6EA4D9974851FDC2BCB52B1D6A8A34` |

This identity is the rebuild that contains the driver corrections for command
acknowledgement, `get_seqnum`, and management TX status. The OTA results in
the following sections were produced by the previous executable, SHA-256
`FCEEA5E8484C8CB18DDC53EF30CFA222F617BA9C714B5AC4249B3EA43B93FCBE`, 7,466,243
bytes. That matrix and the Windows fresh-SSID run were not repeated.

Compilation of an EAP server module is recorded as build evidence only. It is
not classified as OTA interoperability evidence without a completed client
exchange.

## 5. Local regression verification

The local Python regression and syntax check were executed after installation
of the expanded native binary.

| Check | Result |
|---|---:|
| `pytest -q` | 166 passed |
| `python -m compileall -q wifit3_bridge` | Passed |
| Native hostapd build | Passed |
| `hostapd.exe -v` | hostapd 2.12 |

## 6. Native-binary OTA regression

This run used the previous executable named above. It was tested on the MT7925AU AP path with the
MT7610U observer. The executable identified in section 4 was not part of this run. The native-binary methods reached raw association, EAP success, complete
WPA four-way handshake, and an authorized port.

| Method | Raw association | Authentication | WPA state | WPA complete | EAP result | Process |
|---|---:|---:|---|---:|---|---:|
| PEAPv1/MSCHAPv2 | True | 0 | WPA | True | Outer and inner success | 0 |
| EAP-TLS | True | 0 | WPA | True | Success | 0 |
| EAP-TTLS/MSCHAPv2 | True | 0 | WPA | True | Outer and inner success | 0 |
| EAP-SIM | True | 0 | WPA | True | Success | 0 |
| EAP-AKA | True | 0 | WPA | True | Success | 0 |
| EAP-AKA' | True | 0 | WPA | True | Success | 0 |
| EAP-PWD | True | 0 | WPA | True | Success | 0 |
| EAP-FAST/MSCHAPv2 | True | 0 | WPA | True | Inner success and Crypto-Binding success | 0 |
| EAP-TEAP/MSCHAPv2 | True | 0 | WPA | True | Inner success and Crypto-Binding success | 0 |
| EAP-EKE | True | 0 | WPA | True | Success | 0 |
| EAP-IKEv2 | True | 0 | WPA | True | Success | 0 |

The successful native-binary regression demonstrates that the expanded EAP
link set did not regress the previously verified Enterprise paths. A final
single-radio EAP-IKEv2 sanity run against the current executable reached
EAP-Success, WPA four-way completion, and an authorized port with no fatal
hostapd state. The full six-radio matrix remains associated with the previous
executable revision identified in section 4.

## 7. Six-radio OTA verification summary

The following controlled matrices were completed before and during the current
build revision.

| Protocol or cipher | Matrix result |
|---|---:|
| WPA2-Personal / CCMP | 6/6 |
| WPA2-Personal / TKIP | 6/6 |
| WPA2-Personal / GCMP-128 | 6/6 |
| WPA2-Personal / GCMP-256 | 6/6 |
| WPA2-Personal / CCMP-256 | 6/6 |
| WPA3-SAE legacy, groups 19, 20, and 21 | 6/6 per group |
| WPA3-SAE H2E, groups 19, 20, and 21 | 6/6 per group |
| SAE-PK, groups 19, 20, and 21 | 6/6 per group |
| SAE-EXT-KEY, groups 19, 20, and 21 | 6/6 per group |
| FT-SAE | 6/6 |
| FT-SAE-EXT-KEY, groups 19, 20, and 21 | 6/6 per group |
| PMF / BIP-CMAC-128 | 6/6 |
| PMF / BIP-GMAC-128 | 6/6 |
| PMF / BIP-GMAC-256 | 6/6 |
| PMF / BIP-CMAC-256 | 6/6 |
| EAP-TLS / WPA-EAP | 6/6 |
| EAP-MSCHAPv2 / WPA-EAP | 6/6 |
| EAP-PSK / WPA-EAP | 6/6 |
| EAP-SAKE / WPA-EAP | 6/6 |
| EAP-PAX / WPA-EAP | 6/6 |
| EAP-GPSK / WPA-EAP | 6/6 |
| EAP-GPSK-SHA256 / WPA-EAP | 6/6 |
| EAP-SIM / WPA-EAP | 6/6 |
| EAP-AKA / WPA-EAP | 6/6 |
| EAP-AKA' / WPA-EAP | 6/6 |
| PEAPv1/MSCHAPv2 / WPA-EAP | 6/6 |
| EAP-TTLS/MSCHAPv2 / WPA-EAP | 6/6 |
| EAP-FAST/MSCHAPv2 / WPA-EAP | 6/6 |
| EAP-TEAP/MSCHAPv2 / WPA-EAP | 6/6 |
| EAP-EKE / WPA-EAP | 6/6 |
| EAP-IKEv2 / WPA-EAP | 6/6 |
| EAP-PWD group 19 / WPA-EAP | 6/6 |
| EAP-PWD group 20 / WPA-EAP | 6/6 |
| EAP-PWD group 21 / WPA-EAP | 6/6 |

The Enterprise matrices reached EAP success and the WPA four-way handshake.
The PEAP and TTLS matrices additionally verified inner MSCHAPv2 completion.
EAP-PWD completed RFC 5931 identity, Commit, Confirm, MSK derivation, and the
WPA-EAP four-way path for groups 19/P-256, 20/P-384, and 21/P-521. The P-521
implementation was corrected after comparison with hostapd's non-byte-aligned
KDF operation, which right-shifts the 528-bit intermediate by seven bits.
EAP-PSK completed the four-message RFC 4764 exchange, EAX-protected channel
validation, MSK derivation, EAP-Success processing, and the WPA-EAP four-way
path on every AP radio. Its native client regression covers independent key
derivation and deterministic protected-channel vectors.
EAP-SAKE completed the identity, challenge, confirm, HMAC-SHA1 MIC validation,
MSK derivation, EAP-Success processing, and WPA-EAP four-way path on every AP
radio. Its regression covers the RFC 4763 key schedule and deterministic
challenge/confirm vectors; the OTA path uses hostapd's default server identity.
EAP-PAX completed the PAX-STD-1, PAX-STD-2, PAX-STD-3 and ACK exchange,
ICV/MAC validation, MSK derivation, EAP-Success processing, and WPA-EAP
four-way path on every AP radio. The implementation also retransmits the last
valid STD-2 or ACK for identical server retries; this behavior was required by
one observed USB timing run and is covered by regression evidence.
EAP-GPSK and EAP-GPSK-SHA256 completed the GPSK-1, GPSK-2, GPSK-3 and GPSK-4
exchange on every AP radio. The AES path uses AES-GKDF and CMAC MIC validation;
the SHA256 path uses HMAC-SHA256-GKDF, 32-byte session keys and HMAC-SHA256
MIC validation. Both paths completed EAP-Success processing and the WPA-EAP
four-way exchange. The regression covers both key schedules and deterministic
GPSK frame vectors.
EAP-EKE completed the RFC 6124 identity, proposal, commit, confirm, protected
nonce, authentication, MSK derivation, EAP-Success, and WPA-EAP four-way
exchange on all six AP radios. The OTA client uses DH group 14, AES-128-CBC,
HMAC-SHA1 PRF/MAC, the hostapd server identity, and a station identity of
`wifit3-eke`. The regression covers the hostapd PRF+ counter convention,
DHComponent/shared-secret symmetry, key export, protected-payload integrity,
and the WPA-EAP PMK handoff.
EAP-IKEv2 completed the hostapd-compatible IKEv2 SA_INIT and IKE_AUTH
exchanges with DH group 2, AES-128-CBC encryption, HMAC-SHA1-96 integrity,
shared-key authentication, MSK/EMSK export, EAP-Success processing, and the
WPA-EAP four-way exchange on all six AP radios. The regression covers the
RFC 4306 PRF+ counter convention, IKEv2 key-schedule lengths, proposal
encoding, encrypted-payload integrity, retransmission handling, and the
MSK-to-PMK handoff. The six-radio run reached the acceptance criteria on every
radio; the first observation window on indices 0 and 4 required additional
radio retries before the same run completed successfully.

| AP index | AP radio | Observer | Final result |
|---:|---|---|---|
| 0 | MT7925AU / Netgear A9000 | MT7610U | PASS |
| 1 | RTL8821CU / Auscoumer 600 | MT7610U | PASS |
| 2 | MT7601U | MT7610U | PASS |
| 3 | MT7610U / AWUS036ACHM | MT7601U | PASS |
| 4 | RTL8922AU / ASUS USB-BE93 | MT7610U | PASS |
| 5 | RTL8814AU / AWUS1900 | MT7610U | PASS |
EAP-SIM completed the Start and Challenge exchange, external GSM-triplet
retrieval over the Windows loopback UDP database transport, HMAC-SHA1-128 MIC
verification, FIPS 186-2 key derivation, EAP-Success processing, and the
WPA-EAP four-way exchange on every AP radio. The regression covers the NIST
FIPS 186-2 PRF vector, deterministic EAP-SIM frame vectors, key derivation,
and the loopback database transport.
EAP-AKA completed the RFC 4187 Identity and Challenge exchange, external UMTS
authentication-data retrieval, HMAC-SHA1-128 verification, AT_CHECKCODE
validation, FIPS 186-2 key derivation, EAP-Success processing, and the WPA-EAP
four-way exchange on every AP radio. EAP-AKA' completed the RFC 5448 KDF
selection and network-name binding, CK'/IK' derivation, HMAC-SHA256-128
verification, AT_CHECKCODE validation, MSK derivation, EAP-Success processing,
and the WPA-EAP four-way exchange on every AP radio. Both methods use the
Windows-compatible loopback UDP SIM database transport.
Some USB pairings required a longer observation window; repeated runs passed
without a protocol error. Such timing retries are recorded as harness timing
conditions, not as protocol corrections.

EAP-FAST used an authenticated TLS 1.2 phase with hostapd server certificates,
disabled PAC provisioning, and an inner EAP-MSCHAPv2 method. The client derived
the RFC 4851 session-key seed from the TLS key expansion, applied the
EAP-FAST-specific MSK ordering for MSCHAPv2, derived the inner-method compound
key with SHA-1 T-PRF, and verified the server Crypto-Binding request with the
incremented nonce and HMAC-SHA1 compound MAC. All six runs reached inner method
success, valid Crypto-Binding, EAP-Success, WPA four-way completion, authorized
port state, zero client transmission failures, and return code zero.

| AP index | AP radio | Observer | Final result |
|---:|---|---|---|
| 0 | MT7925AU / Netgear A9000 | MT7610U | PASS |
| 1 | RTL8821CU / Auscoumer 600 | MT7610U | PASS |
| 2 | MT7601U | MT7610U | PASS |
| 3 | MT7610U / AWUS036ACHM | MT7601U | PASS |
| 4 | RTL8922AU / ASUS USB-BE93 | MT7610U | PASS |
| 5 | RTL8814AU / AWUS1900 | MT7601U | PASS |

EAP-TEAP used an authenticated TLS 1.2 phase with the RFC 7170 session-key
exporter label, the inner EAP-MSCHAPv2 method, and the TEAP Result,
Intermediate-Result, and Crypto-Binding TLVs. For the negotiated AES128-SHA
TLS suite, the client used the TLS 1.2 SHA-256 PRF for the session-key seed,
inner-method compound-key derivation, and final MSK derivation, and HMAC-SHA1
for the compound MAC specified by the TLS record-protection suite. The
EAP-FAST-specific MSCHAPv2 key ordering was retained because hostapd marks the
TEAP inner method accordingly. The implementation also records the server's
first-message Authority-ID outer TLV and tolerates repeated TLS fragments from
the raw-radio receive path by serializing and caching identical EAP requests.
All six runs reached inner MSCHAPv2 success, valid Crypto-Binding, EAP-Success,
WPA four-way completion, authorized port state, zero client transmission
failures, and return code zero.

| AP index | AP radio | Observer | Final result |
|---:|---|---|---|
| 0 | MT7925AU / Netgear A9000 | MT7610U | PASS |
| 1 | RTL8821CU / Auscoumer 600 | MT7610U | PASS |
| 2 | MT7601U | MT7610U | PASS |
| 3 | MT7610U / AWUS036ACHM | MT7601U | PASS |
| 4 | RTL8922AU / ASUS USB-BE93 | MT7610U | PASS |
| 5 | RTL8814AU / AWUS1900 | MT7601U | PASS |

## 8. Standard Windows client interoperability and stability

The integrated Windows 11 WLAN client was identified as a Killer(R) Wi-Fi 6E
AX1675i 160MHz Wireless Network Adapter (211NGW), interface `WLAN`, MAC
`80:e4:ba:60:f5:b3`. The standard-client test used a temporary WPA2-Personal
CCMP profile, the native `netsh wlan` control path, a fresh SSID for every
radio, channel 1, and no observer radio. Ethernet and IP data-plane behavior
were not evaluated.

| Test criterion | Result |
|---|---:|
| Hostapd AP startup, six fresh-SSID runs | 6/6 |
| Fatal hostapd failure | 0/6 |
| Windows scan discovery of fresh SSID | 0/6 |
| Windows `netsh wlan connect` completion | 0/6 |
| Standard-client WPA2 association acceptance | 0/6 in fresh-SSID acceptance runs |

The six fresh-SSID runs used the following mapping: MT7925AU, RTL8821CU,
MT7601U, MT7610U, RTL8922AU, and RTL8814AU. In all cases hostapd remained
enabled and continued beacon transmission, but the Windows scan did not expose
the newly generated SSID and no standard-client association was completed.
The harness recorded repeated `handle_probe_req: send failed` messages on the
AP path during these discovery attempts.

A separate diagnostic run with an SSID already present in the Windows WLAN
cache reached standard-client authentication, association, WPA2 four-way
completion, and hostapd key installation (`num_sta=1`, three key slots). This
single cached-SSID observation demonstrates that the Windows profile format
and WPA2 state machine can interoperate after discovery, but it is not a
repeatable acceptance result and does not override the fresh-SSID matrix.

The conclusion for standard-client interoperability is therefore conditional:
cached-SSID WPA2 association is demonstrated once, while fresh-SSID discovery
and repeatable Windows-client association are not verified on this system.
The result is classified as a management/discovery interoperability limitation,
not as a failure of the previously verified raw-observer WPA and EAP matrices.

## 9. Native Linux client interoperability

The external Ubuntu host provided wired control access. The WLAN station was
an Alfa AWUS036ACHM using the MediaTek MT7610U chipset, USB identifier
`0e8d:7610`, and the native Linux `mt76x0u` driver. The client environment was
Ubuntu 26.04.1 LTS, kernel `7.0.0-43-generic`, with `wpa_supplicant v2.11`.
The Windows AP used radio index 0 (MT7925AU / Netgear A9000), BSSID
`28:94:01:d1:85:5d`, and channel 1 (2412 MHz). The wired Ethernet connection
carried SSH control only. Ethernet bridging, VLAN, and IP data-plane behavior
were excluded.

Each security mode used a fresh SSID and an ephemeral test credential. The
Ubuntu station used a dedicated direct `wpa_supplicant` process. The Windows
AP runner omitted the explicit `--hardware-ack` option; it detected the
selected adapter's public ACK API and armed active-monitor link
acknowledgements automatically. All three runs reported
`hardware_ack_armed=True`, `ap_enabled=True`, and `fatal_failure=False`.
All client profiles selected RSN and CCMP. WPA2 used `key_mgmt=WPA-PSK`; the
PMF run additionally required `ieee80211w=2` and BIP-CMAC-128. WPA3 used
`key_mgmt=SAE`, required PMF, H2E-only password-element derivation
(`sae_pwe=1`), and SAE group 19. Controlled reconnects used
`wpa_cli disconnect` followed by `wpa_cli reconnect`; each was accepted only
after the client returned to `wpa_state=COMPLETED`. Ephemeral credentials
and client profiles were removed from the Ubuntu host after the campaign.

| Security mode | AP duration | Client result | AP-side result |
|---|---:|---|---|
| WPA2-Personal, CCMP | 240 s | 6 completed connections: initial association plus 5/5 controlled reconnects. After the fifth reconnect, `wpa_state=COMPLETED` persisted for 183.806 s until AP shutdown. Ten of twelve 15-second samples were completed; the final two were taken after AP shutdown. | M1–M4 completed; 3 key slots; active-monitor ACK count 12; no fatal process failure. |
| WPA2-Personal, required PMF, BIP-CMAC-128 | 90 s | 4 completed connections: initial association plus 3/3 controlled reconnects. `wpa_state=COMPLETED`, `key_mgmt=WPA2-PSK`, and CCMP were reported. | M1–M4 completed; 5 key slots including IGTK state; active-monitor ACK count 26; no fatal process failure. One SA Query timeout was logged during the controlled reconnect sequence; the subsequent association and key exchange completed. |
| WPA3-Personal, SAE/H2E, group 19, required PMF | 120 s | 4 completed connections: initial association plus 3/3 controlled reconnects. Six samples at 10-second intervals all reported `wpa_state=COMPLETED`; measured signal was −14 to −15 dBm. | H2E derivation and SAE confirm succeeded; M1–M4 completed; 5 key slots including IGTK state; active-monitor ACK count 27; no fatal process failure. One non-fatal beacon-task warning appeared at shutdown. |

The initial WPA2 run without active-monitor link acknowledgements had stalled
after AP-side M1 transmission. With automatic link acknowledgements enabled,
the Ubuntu client completed the WPA2 exchange. The expanded WPA2 baseline
recorded six completed client sessions, and the connection remained completed
for 183.806 seconds after the final controlled reconnect. Samples 11 and 12
were collected after the time-limited AP had stopped and the station returned
to scanning; they are not counted as connected-state samples.

For WPA2 with PMF required, the AP installed IGTK state and the Ubuntu
supplicant completed the WPA handshake after each of three controlled
reconnects. The AP logged an SA Query timeout during this sequence, followed
by a successful reassociation and completed key exchange. This event is
reported as an observed reconnect-path limitation; it did not prevent the
client from reaching `COMPLETED`.

For WPA3-SAE/H2E, the AP log recorded H2E key derivation, successful SAE
confirmation, and completion of the four-way handshake. Three controlled
reconnects completed, followed by six successful samples collected 10 seconds
apart. No client disconnect event occurred between the final reconnect and
the timed AP shutdown. The six samples establish a 50-second connected-state
observation window, not production-duration stability.

The SAE runner also emitted `software beacon transmission failed; stopping`
during final shutdown. The process returned exit status zero with
`fatal_failure=False`. Source-path analysis indicates a teardown race: the
test lease is revoked before the asynchronous beacon task is cancelled, so a
beacon already scheduled at shutdown can be reported as a failed send. No
beacon-loss evidence was recorded during the connected-state observation
window; the shutdown warning remains a cleanup-path observation.

These outcomes apply to the tested Ubuntu supplicant, AWUS036ACHM adapter,
Windows AP radio, channel, and security profiles. The wired connection was
used only for remote control. No IP connectivity, Ethernet bridging, VLAN,
throughput, roaming, power-save, or multi-client behavior was tested.

## 10. Management, accounting, and RADIUS evidence

The bridge regression covers station creation, flag updates, authorization,
removal, management TX, deauthentication, disassociation, station counters,
inactivity reporting, and control-interface status queries. Real-radio tests
verified broadcast and unicast deauthentication and disassociation on all six
AP radios.

The RADIUS UDP smoke matrix completed on all six radios. Accounting events were
observed through the asynchronous Windows event-loop drain and returned
positive station counters and inactivity data. This is a software observation
path; it is not hardware counter or Ethernet accounting evidence.

## 11. Capability classification

The verified result is divided into three categories:

1. **OTA-verified laboratory path:** functionality that completed the stated
raw-radio, authentication, key, and management criteria.
2. **Build-enabled but not OTA-verified:** native modules or functions that
   compile and link without a completed client exchange. No EAP method listed
   in the current Enterprise matrix remains in this category.
3. **Out of scope or not verified:** Ethernet, VLAN, hardware offload,
   FT-over-DS/RRB, multi-client behavior, and production-duration stability.

The full list is maintained in `hostapd-2.12/PORT_STATUS.md`.

## 12. Limitations

The wifit3 API provides raw TX/RX and control callbacks but does not provide a
complete Windows AP hardware abstraction for TBTT scheduling, station
tables, key offload, hardware counters, Ethernet bridging, or VLAN binding.
The bridge inserts a software TIM and DTIM count between the hostapd beacon
head and tail. The beacon timestamp remains a monotonic microsecond clock,
and transmission is not locked to a hardware TBTT.
Accordingly, hostapd source availability and successful compilation are not
converted into runtime capability claims.

After that matrix, the bridge source was corrected for the CCMP/GCMP
additional authentication data, software TIM insertion, per-transmitter
sequence numbers, `get_seqnum`, noack probe responses, and receive
backpressure. Those corrections were checked with the local regression.
The EAPOL receive parser also accounts for bounded DMA alignment padding
before LLC/SNAP. The smoke runner now automatically enables the public
active-monitor link-ACK API when supported by the selected radio. The expanded
Ubuntu client campaign is documented in section 9 and covers WPA2-Personal,
WPA2 with required PMF, and WPA3-SAE/H2E on the current native executable.
The native executable was then rebuilt, as identified in section 4, so the
driver acknowledgement, `get_seqnum`, and TX-status changes are in
`hostapd.exe`. The six-radio OTA matrix and the Windows fresh-SSID run were
not repeated against that binary.

The observations were made on one Windows 11 system, one controlled channel,
the listed six radios, and a serialized laboratory harness. They do not
establish arbitrary adapter pairing stability, regulatory-domain coverage,
throughput, power-save behavior, DFS, EHT, production service lifetime, or
interoperability with every external client implementation.

## 13. Conclusion

The modified hostapd 2.12 build functions on the specified Windows 11 system
over wifit3 for the experimentally verified AP, station, WPA, PMF, RADIUS, and
Enterprise OTA paths listed in this report. The expanded native build is
reproducible and passes the 166-test local regression. EAP-FAST/MSCHAPv2,
EAP-TEAP/MSCHAPv2, EAP-EKE, and EAP-IKEv2 are verified on all six radios.

Full hostapd functionality under Windows cannot be claimed because
Ethernet/VLAN, hardware offload, FT-over-DS/RRB, and production radio behavior
remain outside the demonstrated scope. Standard Windows-client discovery
remains conditional: one cached-SSID diagnostic association succeeded, while
the fresh-SSID matrix remained 0/6. The external Ubuntu AWUS036ACHM completed
WPA2, required-PMF WPA2, and WPA3-SAE/H2E client runs with automatically
enabled link acknowledgements. Five WPA2 reconnects, three PMF reconnects,
and three SAE/H2E reconnects completed. A PMF SA Query timeout was observed
during controlled reconnection, followed by successful association and key
installation. These results verify interoperability for the tested Linux
client and radio configuration; they do not establish universal compatibility
or production-duration stability.
