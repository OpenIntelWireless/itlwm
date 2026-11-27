# itlwm / iwx Driver Patch (v4-Alpha) Build Instructions

## Overview
This document contains the build instructions for compiling the `v4-alpha` driver binary (`itlwm` and `AirportItlwm`) for macOS Tahoe / Sequoia / Sonoma.

## Prerequisites
1. **Host Environment:** macOS with Xcode 13 or newer installed (`xcode-select --install`).
2. **MacKernelSDK:** MacKernelSDK cloned into the root directory of the repository:
   ```bash
   git clone https://github.com/acidanthera/MacKernelSDK.git MacKernelSDK
   ```

## Build Steps

### 1. Build `itlwm.kext` (v4-alpha Primary Target)
Run the following command from the repository root:
```bash
xcodebuild -project itlwm.xcodeproj -scheme itlwm -configuration Release
```
The compiled kext bundle will be located at:
`build/Release/itlwm.kext`

### 2. Build `AirportItlwm.kext` (Optional Target)
To build `AirportItlwm` for macOS Sonoma or other supported versions:
```bash
# For Sonoma (macOS 14+)
xcodebuild -project itlwm.xcodeproj -scheme "AirportItlwm (Sonoma)" -configuration Release

# For Monterey / Ventura / Tahoe
xcodebuild -project itlwm.xcodeproj -scheme "AirportItlwm (Monterey)" -configuration Release
```
The compiled bundle will be located at:
`build/Release/AirportItlwm.kext`

## Key v4-Alpha Features Included
- **Loader Gate Fix:** Injected `<key>IOPCITunnelCompatible</key><true/>` into all `IOKitPersonalities` across all `Info.plist` files to bypass macOS 15/16 `IOPCIFamily` loader restrictions.
- **PCIe Link-Down Safety:** Register read and polling loops (`iwx_poll_bit`, `iwx_prepare_card_hw`, `iwx_disable_rx_dma`) break immediately upon encountering `0xFFFFFFFF` read failures.
- **AppleVTD DMA Safeguards:** DMA memory allocations (`allocDmaMemory2`) cleanly release descriptors and handle quarantine faults without triggering kernel panics.
