# itlwm AppleVTD / AX210 Tahoe v3

This patch is a new AX210/iww-only transplant into the original `itlwm-master.zip` source. It does **not** build on the previous v2 patch.

## Source basis

The DMA architecture is derived from the current `kgp-macPro/AirportItlwm-Tahoe` source and its documented 2H/2I/2K lineage:

- prepared `IOBufferMemoryDescriptor` + `IODMACommand::kMapped` backing
- hardware receives the generated IOVM address (`fIOVMAddr`)
- RX hardware backing is independent of the delivered mbuf
- ordinary TX copies the complete mbuf chain into prepared backing and retains it through TX completion
- reset/uncertain TX mappings are quarantined rather than immediately recycled
- large command payloads use prepared per-command backing instead of an mbuf physical address

The Tahoe project reports physical AX210 qualification on Tahoe 26.6.2 with AppleVTD and `DisableIoMapper=false`. This patch is a source transplant into the original `itlwm` target, not the qualified AirportItlwm-Tahoe binary.

## Files changed

- `itlwm/hal_iwx/ItlIwx.cpp`
- `itlwm/hal_iwx/ItlIwx.hpp`
- `itlwm/hal_iwx/if_iwxvar.h`

No `itl80211/compat.*` rewrite is made in v3. The old cursor implementation remains for non-AX210 devices and is no longer used for the AX210 RX/ordinary-TX/large-command DMA paths changed here.

## AX210 paths changed

1. RX: one prepared 4096-byte DMA buffer per RX slot. The AX210 descriptor receives its IOVA; the completed buffer is synchronized and copied into the mbuf before normal RX parsing.
2. Ordinary TX: a 1024-entry pool of prepared 8192-byte DMA buffers. Packets are copied into a backing buffer, synchronized for device output, split into <=4092-byte/page-safe segments, and the backing remains associated with the TX descriptor until completion. Reset retirement quarantines the backing instead of reusing it.
3. Large firmware commands: the command queue gets a prepared 4096-byte DMA backing per descriptor. AX210 uses its IOVA directly; the existing mbuf/cursor path remains for older families.

## Important limitations

- This is **source-level experimental code**. It has not been compiled against the exact macOS 26.6.2 KDK or boot-tested on the user's AX210.
- The Tahoe reference project contains additional PC1/2Q reset fencing, deferred queue-drain handling, diagnostics, and command-lifetime state machines. Those were intentionally not imported wholesale here because the goal is the minimum AppleVTD DMA transplant into `itlwm`.
- Quarantined ordinary-TX backing is retained rather than reclaimed until a proven safe boundary. Repeated resets can therefore consume the finite 1024-entry pool; that is deliberately fail-closed rather than risking DMA-after-free.
- The patch does not add `pci-aspm-default`, change OpenCore quirks, modify DMAR/ACPI, or alter HeliPort.

## Intended test configuration

- Intel AX210 PCI ID: `8086:2725`
- BIOS VT-d: enabled
- OpenCore `DisableIoMapper`: `false`
- OpenCore `DisableIoMapperMapping`: `false`
- No `pci-aspm-default` property initially
- itlwm: patched build

A clean comparison against unmodified itlwm with `DisableIoMapper=true` should be retained as the fallback baseline.
