# wifit3 hostapd Windows Integration

Author: DensenDeluxe

This repository combines the wifit3 raw USB 802.11 radio backend with a
Windows port of hostapd 2.12. It provides a software access point, station
management, WPA/WPA3 key handling, IEEE 802.1X and EAP authentication, PMF,
RADIUS transport, accounting, and controlled over-the-air validation on
Windows 11.

## Project components

- `wifit3/` contains the cross-platform raw USB radio application and driver
  stack.
- `hostapd-2.12/` contains the hostapd integration, native Windows build
  profile, wifit3 bridge, client implementations, and test harness.
- `TESTREPORT-WIN11-WIFIT3-HOSTAPD.md` contains the scientific Windows 11 test
  report.

## Verified scope

The controlled laboratory scope covers AP startup, beacon and management
frames, station lifecycle operations, WPA2-Personal, WPA3-SAE, PMF/BIP,
selected 802.11r paths, RADIUS and accounting transport, and the documented
Enterprise EAP methods. The six-radio OTA matrix is documented with its
executable revision and evidence boundaries in the test report.

Ethernet bridging, VLAN integration, FT-over-DS/RRB, hardware station-table
offload, hardware key offload, and production-duration radio stability are
outside the project scope.

The integrated Windows WLAN client completed one cached-SSID WPA2 diagnostic
association. The fresh-SSID standard-client matrix produced no repeatable
discoveries or associations on the six AP radios. Raw observer-based WPA and
EAP results are reported independently from this discovery limitation.

## Build and test

### wifit3

```text
cd wifit3
uv sync --group dev
uv run pytest
uv run ruff check src/ tests/
```

### hostapd bridge

Use an MSYS2 UCRT64 shell with the required C toolchain and OpenSSL headers:

```text
cd hostapd-2.12/hostapd
cp .config.wifit3 .config
make -j2 hostapd hostapd_cli
```

Run the bridge regression from `hostapd-2.12`:

```text
set PYTHONPATH=.
pytest -q wifit3_bridge/tests
python -m compileall -q wifit3_bridge
```

The controlled OTA entry point is:

```text
wifit3_bridge/examples/windows_wpa_smoke.py
```

The observer assignments and acceptance criteria are maintained in
`hostapd-2.12/PORT_STATUS.md`.

## Documentation

- [Hostapd integration guide](hostapd-2.12/README-WIFIT3.md)
- [Capability status](hostapd-2.12/PORT_STATUS.md)
- [Scientific test report](TESTREPORT-WIN11-WIFIT3-HOSTAPD.md)
- [wifit3 application documentation](wifit3/README.md)

## Licensing

wifit3 is distributed under the GNU General Public License v2.0 as documented
in `wifit3/LICENSE`. hostapd retains its upstream modified BSD license and
copyright notices in `hostapd-2.12/README` and the affected source files.
Both license boundaries must be preserved when redistributing the combined
project.
