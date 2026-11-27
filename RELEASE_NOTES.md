# Release Notes: itlwm & AirportItlwm Experimental Release (AppleVTD / AX210 Tahoe Fixes)

## Overview

This experimental release provides enhanced support for **Intel Wi-Fi 6E AX210** wireless network adapters under **AppleVTD / IOMMU** environments on **macOS Sonoma** and **macOS Tahoe**.

It resolves critical memory leaks, race conditions, and transmit pool exhaustion bugs present in previous AppleVTD DMA implementations.

---

## What's New & Key Improvements

### 1. Thread Safety & Race Condition Protection
- Introduced kernel synchronization (`IOLock`) for the AX210 transmit (TX) DMA buffer pool (`fAppleVTDTxLock`).
- Protected buffer slot selection, in-flight state mutation (`AppleVTDTxFree`, `AppleVTDTxCopying`, `AppleVTDTxInflight`, `AppleVTDTxQuarantined`), and retirement procedures under lock protection. Prevents kernel panics and packet corruption under concurrent transmit operations.

### 2. Automatic Quarantine Buffer Recovery
- Added `applevtdTxResetQuarantine()` to automatically recycle quarantined DMA buffers back into the free pool when transmit rings reset (`iwx_reset_tx_ring`) or the device stops (`iwx_stop_device`).
- Prevents TX pool starvation and transmit stalls after Wi-Fi re-associations, sleep/wake cycles, or heavy RF interference.

### 3. Complete Resource Cleanup on Driver Unload
- Rewrote `applevtdTxFree()` to unconditionally deallocate all pre-allocated contiguous DMA descriptors (`fAppleVTDTx[i].dma`) regardless of state.
- Ensures `IOLock` resources are safely freed (`IOLockFree`), eliminating kernel memory leaks upon kext unload.

### 4. Automated GitHub Actions CI Workflow
- Added `.github/workflows/build.yml` to automatically compile `itlwm.kext` and `AirportItlwm.kext` binaries using Xcode 15.4 and MacKernelSDK, producing ready-to-use release artifacts.

### 5. Updated Documentation & Patch
- Updated `ANALYSIS.md` (complete architectural and DMA quality analysis).
- Added `RECOMMENDATIONS.md` (OpenCore deployment guidelines, BIOS/Quirks configuration, and safety assessment).
- Regenerated `itlwm-applevtd-ax210-v3.patch` with all applied source fixes.

---

## Intended Test Configuration

- **Hardware:** Intel AX210 Wi-Fi card (PCI ID: `8086:2725`) or compatible IWX Gen3 devices.
- **Operating System:** macOS Sonoma (14.x) / macOS Tahoe (15.x/16.x).
- **BIOS Settings:** `VT-d` enabled.
- **OpenCore Quirks:**
  - `Kernel -> Quirks -> DisableIoMapper` = `false`
  - `Kernel -> Quirks -> DisableIoMapperMapping` = `false`

---

## Feedback & Debugging

If you encounter any issues or kernel panics, please collect kernel logs using the following terminal commands:

```bash
# Capture itlwm logs from the last 10 minutes
sudo log show --predicate 'process == "kernel" AND message CONTAINS[c] "itlwm"' --last 10m > itlwm_debug.log

# Capture iwx HAL logs
sudo log show --predicate 'process == "kernel" AND message CONTAINS[c] "iwx"' --last 10m > iwx_debug.log
```
