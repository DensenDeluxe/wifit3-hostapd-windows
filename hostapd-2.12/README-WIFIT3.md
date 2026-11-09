# hostapd 2.12 with the wifit3 raw-radio backend

Author: DensenDeluxe  
Revision date: 9 November 2026  
Status: experimental Windows 11 laboratory port

## Architecture

This directory contains hostapd 2.12 with a wifit3 AP driver, a local TCP
bridge, and a Python test harness. The hostapd AP, WPA, EAP, RADIUS, station,
and control state machines remain in hostapd. The wifit3 driver supplies the
raw-radio transport through a versioned local IPC path.

The Windows profile does not require `nl80211`, the Linux wireless API, or
`libnl`. The bridge uses the available wifit3 raw TX/RX and control interfaces.

## Current result

The native Windows build starts and operates with six wifit3-compatible USB
radios. The latest recorded local regression contains 166 passing tests.
OTA verification
includes WPA2-Personal, WPA3-SAE groups 19/20/21, SAE-PK, SAE-EXT-KEY,
FT-SAE, FT-SAE-EXT-KEY, PMF/BIP, EAP-TLS, EAP-MSCHAPv2, EAP-PSK, EAP-SAKE,
EAP-PAX, EAP-GPSK, EAP-GPSK-SHA256, EAP-SIM, EAP-AKA, EAP-AKA', EAP-PWD groups 19/20/21,
PEAPv1/MSCHAPv2, and EAP-TTLS/MSCHAPv2.
EAP-FAST/MSCHAPv2 is additionally verified on all six radios through the
authenticated TLS tunnel, inner method, Crypto-Binding, EAP-Success, and WPA
four-way exchange.
EAP-TEAP/MSCHAPv2 is additionally verified on all six radios through the
TLS exporter, inner method, Result and Crypto-Binding exchange, EAP-Success,
and WPA four-way exchange.
EAP-EKE is additionally verified on all six radios for the RFC 6124 group-14,
AES-128-CBC, HMAC-SHA1 profile through EAP-Success and the WPA four-way
exchange. EAP-IKEv2 is verified on all six radios for the hostapd-compatible
DH group-2, AES-CBC, HMAC-SHA1-96, IKE_AUTH, EAP-Success, and WPA four-way
profile.

These broad OTA matrices are historical results from earlier executable
revisions. They were not repeated on the v0.1 release binary; its Ubuntu client
evidence is limited to the three single-association smoke profiles below.

Ethernet, VLAN, FT-over-DS/RRB, hardware key offload, hardware station-table
offload, and production radio stability are not claimed. Ethernet and VLAN are
intentionally outside the project scope.

The integrated Windows 11 WLAN client completed one diagnostic WPA2 association
with a cached SSID. A fresh-SSID matrix across all six AP radios produced 0/6
Windows discoveries and 0/6 repeatable standard-client associations. Raw
observer-based WPA and EAP results remain independent of this client-discovery
limitation.

## Native Windows build

The reproducible toolchain is the local MSYS2 UCRT64 installation. The native
profile is stored in `hostapd/.config.wifit3`.

The profile links the hostapd EAP server modules for EAP-TLS, EAP-TTLS,
EAP-PEAP, EAP-MSCHAPv2, EAP-MD5, EAP-GTC, EAP-SIM, EAP-AKA, EAP-AKA', EAP-PAX,
EAP-PSK, EAP-PWD, EAP-SAKE, EAP-GPSK, EAP-GPSK-SHA256, EAP-FAST, EAP-TEAP,
EAP-EKE, and EAP-IKEv2.

Build from an MSYS2 UCRT64 shell:

```text
cd /c/wifit3build/hostapd-2.12/hostapd
cp .config.wifit3 .config
make -j2 hostapd hostapd_cli
```

The v0.1 release executable was rebuilt with GCC 16.2.0 and OpenSSL 3.6.4. Its
single-association Ubuntu smoke tests covered WPA2-Personal/CCMP, required-PMF
WPA2/BIP-CMAC-128, and WPA3-SAE/H2E group 19. Each run reached
`wpa_state=COMPLETED`; the test report distinguishes these checks from the
longer reconnect campaign performed with the prior binary.

The release executable is:

```text
hostapd-2.12/hostapd/hostapd.exe
```

| Artifact | Size | SHA-256 |
|---|---:|---|
| `hostapd.exe` | 7,475,058 bytes | `B02A0965C3DDE865E7E0501E7AF1BE8C06B4DB06CC426B5A494D8F978C01B39F` |
| `hostapd_cli.exe` | 364,323 bytes | `414A01F98F15066701126E569EEA13943E563038709821935ACCE8677A6B98B5` |
| `libcrypto-3-x64.dll` | 5,495,100 bytes | `7D25614B72D98B1A280D50DE253F395F4062058AF8E22D2DC1EC44FB648F0028` |
| `libssl-3-x64.dll` | 992,847 bytes | `A587A71129263D8114CB7F45F5DCBD2260FD37659286EA6174046491A458F914` |

`hostapd.exe` dynamically loads both OpenSSL DLLs. The release package
includes them beside the executable. The rebuild succeeded with non-fatal
compiler warnings involving format specifiers, integer widths, pointer-width
casts, and Winsock signedness; see the test report.

The extended Ubuntu reconnect and stability campaign used the preceding
executable, SHA-256
`2D7A610D36ADC956B2F31686AFBFC6589D6EA4D9974851FDC2BCB52B1D6A8A34`,
7,486,834 bytes. The six-radio OTA matrices and Windows fresh-SSID matrix used
an earlier executable, SHA-256
`FCEEA5E8484C8CB18DDC53EF30CFA222F617BA9C714B5AC4249B3EA43B93FCBE`,
7,466,243 bytes. Neither historical matrix was repeated on the v0.1 binary.

## Local validation

From `hostapd-2.12`:

```text
set PYTHONPATH=.
pytest -q
python -m compileall -q wifit3_bridge
```

Expected result:

```text
164 passed
```

## OTA smoke harness

The primary controlled harness is:

```text
wifit3_bridge/examples/windows_wpa_smoke.py
```

It supports AP startup, control validation, raw association, WPA2-PSK,
WPA3-SAE, PMF, FT-SAE, EAP-TLS, EAP-MSCHAPv2, EAP-PSK, EAP-SAKE, EAP-PAX,
EAP-GPSK, EAP-GPSK-SHA256, EAP-PWD, EAP-SIM, EAP-AKA, EAP-AKA', PEAP, TTLS,
and EAP-FAST/MSCHAPv2, EAP-TEAP/MSCHAPv2, EAP-EKE, and EAP-IKEv2 client paths. EAP-SIM, EAP-AKA, and EAP-AKA' use the Windows-compatible
loopback UDP SIM database transport (`eap_sim_db=udp:127.0.0.1:<port>`); the
POSIX UNIX-domain transport is retained for platforms that provide AF_UNIX.
Each method must be evaluated with the observer mapping documented in
`PORT_STATUS.md`.

## Capability policy

The bridge reports a capability only when the corresponding software path and
its independent test evidence are present. A hostapd callback, a linked object
file, or a successful AP startup is not sufficient to classify a capability as
OTA verified.

The native build includes EAP-IKEv2 and the bridge provides a corresponding
raw-station client. The implementation is classified as an experimental
laboratory capability after a completed six-radio OTA matrix; it is not a
claim of production-grade hostapd parity.

## Documentation

- `PORT_STATUS.md` contains the capability matrix and evidence classification.
- `../TESTREPORT-WIN11-WIFIT3-HOSTAPD.md` contains the scientific test report.
- `wifit3_bridge/examples/windows_wpa_smoke.py` contains the controlled OTA
  test entry point.
