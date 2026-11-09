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
radios. The local regression contains 164 passing tests. OTA verification
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

The current workspace executable is:

```text
hostapd-2.12/hostapd/hostapd.exe
```

SHA-256:

```text
2D7A610D36ADC956B2F31686AFBFC6589D6EA4D9974851FDC2BCB52B1D6A8A34
```

Size: 7,486,834 bytes. This executable contains the driver corrections for command acknowledgement, `get_seqnum`, and management TX status. The six-radio OTA matrix and the Windows fresh-SSID run were produced by the previous executable, SHA-256 `FCEEA5E8484C8CB18DDC53EF30CFA222F617BA9C714B5AC4249B3EA43B93FCBE`, 7,466,243 bytes, and were not repeated.

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
