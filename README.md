# Wi-Fi 6 (802.11ax / HE) for Intel Wi-Fi on macOS

This branch of [ReAWDL-Sonoma](https://github.com/maddog860/ReAWDL-Sonoma/tree/wifi6-he-fix) adds Wi-Fi 6 (802.11ax / High Efficiency) capability handling and firmware-based transmit-rate reporting to the [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm) driver.

**This is the Wi-Fi 6-only branch.** It does not include the experimental ReAWDL/AWDL implementation or the separately developed Sonoma virtual-interface infrastructure.

## Features

- HE capability advertisement, including supported 5 GHz 40/80 MHz and 160 MHz channel widths.
- HT/VHT/HE association compatibility.
- Corrected Wi-Fi 6 MCS and rate-control handling.
- Improved HE information-element validation and parsing.
- Firmware-selected transmit-rate reporting through the macOS Wi-Fi interfaces.
- Independent operation without experimental AWDL modifications.

**Source history:** Original focused HE changes retained; the HE-PR1066 reporting follow-up is a separate patch and commit.

## HE-PR1066 — Wi-Fi 6 reporting follow-up (November 22, 2026)

A focused update on the existing Wi-Fi 6-only branch. It does **not** import ReAWDL/AWDL-specific source or require its diagnostic infrastructure.

- **Freshness-aware HE PHY rate enabled by default** in Debug and Release builds for AX210 infrastructure Wi-Fi 6. A valid recent, successful single-frame firmware TX completion can replace the older firmware TLC initial-rate report for up to three seconds.
- **Consistent MCS reporting:** legacy and Skywalk `getMCS`/`getMCS_VHT` use the same HE rate-source selection as the transmit-rate API, without altering the `ni_txmcs` value used by the driver.
- **Connection/reset fences:** rate witnesses are invalidated on disconnect, stop, and initialization; the selection also checks firmware generation, connection epoch, validity, and negotiated bandwidth.
- **Safe fallback:** if no recent eligible completion exists, the original TLC-selected HE rate is reported. The code does not change Intel firmware rate-control decisions or select TX queues.
- **Optional Debug telemetry:** `-itlwm-herate` enables HE-PR1063/1064 IORegistry counters on the Intel PCI provider; there is no AWDL trace dependency. Aggregated Block ACK rate evidence is diagnostic-only, not used for the display.
- **Opt-out:** `-itlwm-hefreshoff` restores TLC-only reporting; `-itlwm-hefresh` is unnecessary in this version.

The developer observed 1,200 Mbps / MCS 11 (80 MHz, two spatial streams) after router channel changes, without resetting Wi-Fi. One transient MCS/rate mismatch also recovered spontaneously. These are **PHY reporting observations**, not proof of sustained user-data throughput or continuously exact instantaneous rate tracking.

**Verification note:** The complete HE-PR1066 ReAWDL Debug source passed a Sonoma Xcode build and runtime observations. This standalone branch follow-up requires its own independent macOS build and runtime validation before it is distributed as a tested binary.

## Tested configuration

| Component | Result |
|---|---|
| Wireless adapter | Intel AX210 |
| Operating system | macOS Sonoma |
| Driver target | AirportItlwm-Sonoma14.4 |
| Wi-Fi standard | 802.11ax |
| Channel width | 160 MHz |
| Maximum reported PHY rate | 2,401 Mbps |
| Debug build | Compiled and runtime-tested |
| Release build | Compiled and packaged; runtime test pending |

The Wi-Fi 6-only Debug build demonstrated connection statistics comparable to the full ReAWDL PR1062 driver. Speedtest performance also exceeded the BCM94360NG setup under the tested conditions.

The 2,401 Mbps figure represents the reported PHY link rate, not actual Internet or file-transfer throughput.

## Operating-system compatibility

| Operating system | Status |
|---|---|
| macOS Sonoma 14.4+ | Tested on AX210 |
| macOS Sonoma 14.0–14.3 | Untested; requires separate Sonoma 14.0 build |
| macOS Ventura 13 | Potentially compatible; untested |
| macOS Monterey 12 | Potentially compatible; untested |
| Earlier supported macOS versions | Require version-specific builds and testing |
| macOS Sequoia 15 / Tahoe 26 | Untested; additional compatibility work may be necessary |
| Windows / Linux | Not applicable — macOS kernel extension |

The shared HE source changes may benefit other macOS versions, but the supplied Sonoma kext should not be treated as a universal driver.

## Hardware compatibility

The modifications target HE-capable Intel wireless adapters handled by the `iwx` driver.

The **Intel AX210 is the only adapter verified in runtime testing**. Other supported Intel Wi-Fi 6 devices, including AX200, AX201, AX211, AX411 and compatible Killer AX variants, are candidates for further testing.

See the [upstream hardware compatibility list](https://openintelwireless.github.io/itlwm/Compat.html).

## Building from source

Source branch: `wifi6-he-fix`

Original Wi-Fi 6 implementation: `1935cc3`

Base of this update: `c23f4ac`

```bash
git clone --branch wifi6-he-fix --single-branch \
  https://github.com/maddog860/ReAWDL-Sonoma.git itlwm-WiFi6

cd itlwm-WiFi6
```

Provide a compatible [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK) in the `MacKernelSDK` directory.

Build for macOS Sonoma 14.4+:

```bash
xcodebuild -project itlwm.xcodeproj \
  -target AirportItlwm-Sonoma14.4 \
  -configuration Release \
  -sdk macosx \
  ARCHS=x86_64 \
  CODE_SIGNING_ALLOWED=NO \
  build
```

The source was successfully built using Xcode 15.2 with compatible MacKernelSDK headers.

For installation, consult the [OpenIntelWireless installation guide](https://openintelwireless.github.io/itlwm/Installation.html). Do not load `itlwm.kext` and `AirportItlwm.kext` simultaneously.

## Limitations

This branch does not add experimental AWDL, AirDrop, or peer-to-peer functionality. It also does not establish Wi-Fi 6E / 6 GHz support.

Additional testing across supported Intel adapters, routers, macOS releases, and sleep/wake scenarios is encouraged.

## Credits

Based on the original [OpenIntelWireless/itlwm](https://github.com/OpenIntelWireless/itlwm) project.

HE capability advertisement and parsing improvements build upon [DurkaEbanaya's PR #1060](https://github.com/OpenIntelWireless/itlwm/pull/1060), with additional HE rate handling and firmware-rate-reporting changes.

The complete experimental project remains available separately on the [ReAWDL full-source branch](https://github.com/maddog860/ReAWDL-Sonoma/tree/reawdl-pr1062-full).

## License

This fork retains the original itlwm project's license and applicable firmware licensing requirements.
