# itlwm

**Patches to the original itlwm Kernel Extension to allow it loading in macOS 26 with AppleVTD enabled and supporting Airdrop when loading AirportItlwm kext in Sequoia and Tahoe**

This fork enables itlwm loading with AppleVTD enabled in macOS Tahoe and Airportitlwm kexts loading in Tahoe and Sequoia without root patches and with AppleVTD enabled. The fork kext binaries also allow bi-directional Airdrop support in Tahoe and Sequoia. Patching and testing is based on and being done using a AX201 wifi chip and the AX210 wifi chip below:

https://a.co/d/0hY4N3fQ EDUP PCIE WiFi 6E Card AX210 Bluetooth 5.2 AX5400M 802.11ax Tri-Band 6G/5.8G/2.4GHz Heat Sink 6dBi Antenna PCI-E Wireless Network Cards for Desktop PC Support Windows 11/10 64-bit.

A lot of credits to [laobamac](https://github.com/laobamac) who enhanced Aiportitlwm to support loading in macOS Tahoe and Sequoia with AppleVTD enabled. I leveraged his implementation of IOMMU / DMA enabling AppleVTD in Airportitlwm to enhance my initial implementation of itlwm with AppleVTD enabled, and to YBronst for creating the first iteration of this downstream repository, generating the initial patches and builds attempting to allow AppleVTD enabling with this kext and sharing it with me to continue the development. 

Kudos to [retropineaple](https://github.com/retropineaple) for enabling Airdrop in Intel wifi+bluetooth cards. I integrated the code from [ForbiddenItlwm](https://github.com/retropineaple/ForbiddenItlwm) into this fork to build and release from this fork the necessary Airportitlwm and IntelBTPatcher (BTLEAdvFixup in ForbiddenItlwm repo) kexts for Sequoia and Tahoe for the benefit of all community users. I tested Airdrop in my AX210 transferring a file from my iPhone to my hackintosh and viceversa, and it worked. The code to enable Airdrop is published in the Airdrop-test branch.

**In my fork, an iteration of `IntelBTPatcher.kext` is generated to enable Airdrop.** BTLEAdvFixup implementation is under the hood, but the kext binary is bundled as IntelBTPatcher.

**What you need to enable Airdrop under latest release**

| Kext | Where from | Notes |
| --- | --- | --- |
| `AirportItlwm.kext` | This repository, Tahoe, Sequoia or Sonoma build | 
| `IntelBTPatcher.kext` | This repository, Tahoe, Sequoia or Sonoma build | Lets macOS start Bluetooth LE advertising on an Intel controller |
| `Lilu.kext` | [acidanthera/Lilu](https://github.com/acidanthera/Lilu) | Tested with 1.7.2 |
| `IntelBluetoothFirmware.kext` | [OpenIntelWireless/IntelBluetoothFirmware](https://github.com/OpenIntelWireless/IntelBluetoothFirmware) | Tested with 2.5.1 |
| `BlueToolFixup.kext` | [acidanthera/BrcmPatchRAM](https://github.com/acidanthera/BrcmPatchRAM) | Tested with 2.7.3 |

For more details about AirDrop support you can refer to the original fork, [ForbiddenItlwm](https://github.com/retropineaple/ForbiddenItlwm) 

## OpenCore setup

All of this goes on the EFI.

1. **Kexts:** in `EFI/OC/Kexts`, add `AirportItlwm.kext` and `IntelBTPatcher.kext` from latest release.

2. **`Kernel` → `Add`:** keep this order, so each kext comes after what it depends on.

   | Order | BundlePath | ExecutablePath | Notes |
   | --- | --- | --- | --- |
   | 1 | `Lilu.kext` | `Contents/MacOS/Lilu` | |
   | 2 | `IntelBluetoothFirmware.kext` | `Contents/MacOS/IntelBluetoothFirmware` | |
   | 3 | `BlueToolFixup.kext` | `Contents/MacOS/BlueToolFixup` | `MinKernel` 21.0.0 |
   | 4 | `IntelBTPatcher.kext` | `Contents/MacOS/IntelBTPatcher` | `MinKernel` 21.0.0. After BlueToolFixup, so it can undo BlueToolFixup's patches for APFS's check too (#62) |
   | 5 | `AirportItlwm.kext` | `Contents/MacOS/AirportItlwm` |

   **Recommended:** limit `AirportItlwm.kext` and `IntelBTPatcher.kext` to their macOS version with `MinKernel` and `MaxKernel`, so a stick moved to another macOS doesn't load the wrong build:

   | Build | `MinKernel` | `MaxKernel` |
   | --- | --- | --- |
   | Tahoe | 25.0.0 | 25.99.99 |
   | Sequoia | 24.0.0 | 24.99.99 |
   | Sonoma | 23.4.0 | 23.99.99 |

3. **Boot arguments:** add the flags listed below to `boot-args` under `NVRAM` → `Add` → `7C436110-AB2A-4BBB-A880-FE41995C9F82`. Keep your existing arguments. Because OpenCore only writes NVRAM keys listed under `Delete`, check that `boot-args` is listed there for the same GUID.

4. **Validate:** `plutil -lint config.plist`, and `ocvalidate` if you have it.

**Airdrop Support Boot flags**

AirDrop is off unless its flags are set, so with none of them ForbiddenItlwm behaves like AirportItlwm. The beta needs a long list of flags. They are the exact set used for every tested result. The Tahoe, Sequoia and Sonoma builds use the same flags. Simpler defaults are planned.

**The tested boot-args set (introduced with ForbiddenItlwm 0.7.0-alpha.4 related merged commits)**

Add all of these to `boot-args`, on one line, separated by spaces:

```
-btleadv -btleadvnodupfilter itlawdlsched=1 -itlawdlmultipeer -itlawdlamsdurx -itlawdlamsdutx -itlwmwpa3
```

What each one does:

| Flag | Effect |
| --- | --- |
| `-btleadv` | Turns BTLEAdvFixup on, so `bluetoothd` can start Bluetooth LE advertising on the Intel controller. `-btleadvoff` turns it off again |
| `-itlawdlcoexprobe` | Adds a second firmware context, the AWDL listener, beside the normal Wi-Fi station |
| `-itlawdliface` | Tells macOS the card can do AWDL and creates the `awdl0` interface |
| `-itlawdlnativeup` | Accepts the requests that let macOS's AWDL peer manager start |
| `-itlawdlcoexrx` | Hands the AWDL frames the listener hears to macOS |
| `-itlawdlcoextx` | Gives the listener its own firmware station and queue, and sends macOS's AWDL sync frames from it |
| `-itlawdlcoexmulti` | Puts the listener on its own channel (149 at 80 MHz when allowed, else 6). The firmware time-shares the radio between it and the station |
| `-itlawdlcoexdata` | Carries AirDrop's data through the listener, both ways |
| `-itlawdlmitx` | Sends macOS's own AWDL announcement (its name and services) in the sync frames. Only on verified macOS builds: `ItlwmAWDLMiState` says `on`, `off` or `blocked: build not verified` |
| `-itlawdlelicit` | Adds the extra AWDL fields Apple devices expect: election parameters, channel sequence and HT capabilities |
| `-itlawdlcaps` | Reports two spatial streams and VHT to macOS and to peers, so the iPhone uses 80 MHz two-stream rates |
| `-itlawdlsvcmerge` | Merges macOS's service records into the announcement frames, which helps discovery |
| `-itlawdlawsync` | Times idle sync frames to the iPhone's availability windows |
| `itlawdlintcoal=4` | Shorter interrupt coalescing for the listener, for lower latency |
| `-itlawdlcoexbatx` | Outbound Block Ack and firmware aggregation. This is what makes Mac → iPhone fast |
| `-itlawdlcoexpeerpause` | Pauses the iPhone's firmware queue while its schedule has it away, so frames aren't wasted |
| `-itlawdlcoexbatrace` | Records Block Ack events in the I/O Registry for bug reports. Diagnostic only, cheap |
| `itlawdltxqueue=4096` | Size of the driver's own transmit queue for `awdl0` |

**Experimental flags introduced with ForbiddenItlwm 0.7.0-alpha.4 related merged commits**

| Flag | Effect | Try it if |
| --- | --- | --- |
| `itlawdlsched=1` | The scheduler: the driver follows macOS's AirDrop plan like a real Mac. **New**: it now also covers a second 5 GHz AirDrop channel (see below) | Your card is a Wi-Fi 6 or 6E card (AX210, AX211, AX411, AX200, AX201, AX101 or 9560 class) |
| `-btleadvnodupfilter` | The Mac notices the iPhone's Bluetooth changes at once | Everyone. Remove it before a macOS update, like -btleadv |
| `-itlawdlmultipeer` | Each nearby Apple device gets its own fast session | You have two or more Apple devices nearby |
| `-itlawdlamsdurx` | Accepts packed frames (A-MSDU) from Apple devices sending to the Mac | You'd like to compare iPhone → Mac speed with and without it |
| `-itlawdlamsdutx` | **New**: the Mac packs two packets into one frame when it sends to a device that agreed to it | You'd like to compare Mac → iPhone speed with and without it |
| `-itlwmwpa3` | **New**: Joins WPA3 networks (SAE with H2E) | Your network uses WPA3 |

**Optional flags**

| Flag | Effect |
| --- | --- |
| `itlawdltxpool=N` | Size of the `awdl0` transmit packet pool, 896 to 8192. Default 2048. Below that, long Mac → iPhone transfers can stall |
| `-itlawdlanybuild` | Starts AirDrop on a macOS build the driver hasn't verified. **Risk of a kernel panic.** Only for testing a new build, from a USB stick. It doesn't override the check of Apple's AWDL function table |
| `itlawdlbtcoex=1` | Firmware Bluetooth coexistence mode 1. Fixed choppy Bluetooth audio during AirDrop on an older test build. Before 0.5.1 it only took effect in the monitor test mode |
| `-itlawdlsamples` | Publishes raw frame samples in the I/O Registry for debugging. **They can hold device names and addresses.** Never share them publicly, and don't leave the flag on |

**Comparison flags**

These restore earlier behaviour, for A/B testing only. Leave them off.

| Flag | Effect |
| --- | --- |
| `-itlawdlcoexnogate` | Turns off the send gate, which holds frames for the iPhone while its schedule has it away |
| `-itlawdlcoexcalwait` | Waits for a 300-frame calibration of the iPhone's schedule instead of assuming it straight away |
| `-itlawdlsameband` | Test (0.5.2): while the Mac's Wi-Fi is on 2.4 GHz, keep the listener on channel 6 instead of 149, so the radio doesn't time-share across bands. For setups where Wi-Fi keeps dropping with `-itlawdlcoexmulti` (#16) |
| `-itlawdlbaaskshared` | Test (0.5.3, #24): when the Mac's Wi-Fi is on the listener's own channel, send Block Ack requests without waiting for the iPhone's window. `ITLAWDLCoexBaAsksShared` counts them. From 0.5.4 it also works without `-itlawdlcoexmulti` |
| `-itlawdlhideinfra` | Test (0.5.3, #24): leave the Mac's Wi-Fi network and channel out of AirDrop's sync frames. `ItlwmAWDLSyncInfraStripped` counts the frames changed |
| `-itlawdlnosharedba` | Turns off block ack when the listener shares your Wi-Fi's channel (without `-itlawdlcoexmulti`), as before 0.5.4 |
| `itlawdlpooltype=N` | AirDrop packet pool type: 0 (quantum, Tahoe's default) or 1 (packet, the default on Sequoia and Sonoma from 0.5.1). Sequoia doesn't create `awdl0` with 0 |
| `-itlawdlcoexnoorder` | Lets short frames overtake a paused aggregate queue, as older builds did |
| `-itlawdlcoexbarefill`, `-itlawdlcoexawhold`, `-itlawdlcoexbafilterhyst`, `-itlawdlcoexawsync0` | Older experiments. No gain was measured |

**Don't use**

- **`-itlawdlcoexlowlat`** is disabled in this build and ignored. On the AX211 the firmware rejected the low-latency command, and normal Wi-Fi went down with it.
- **The dedicated-mode test flags:** `-itlawdlrx` and the flags that build on it (`-itlawdlqueue`, `-itlawdl6`, `-itlawdloneshot`, `-itlawdlsyncprobe` and the other train and probe flags, `-itlawdlch149`, `itlawdlcc=`). They put the card in monitor mode, so normal Wi-Fi is down. They are kept for development.
- **Country overrides.** Nothing here changes the country's rules, and nothing should. (From 0.5.0 the driver uses channels the firmware marks passive once it has heard a network there, as Linux does; that needs no flag.) `itlwm_cc` only changes the code macOS displays. It doesn't open channel 149.

For more details about boot-args enabling AirDrop support you can refer to the original fork, [ForbiddenItlwm](https://github.com/retropineaple/ForbiddenItlwm)

# An Intel Wi-Fi Adapter Kernel Extension for macOS, based on the OpenBSD Project

## Upstream itlwm Repository Documentation

We highly recommend exploring our documentation before using this Kernel Extension:

- [Intro](https://OpenIntelWireless.github.io/itlwm)
- [Compatibility](https://openintelwireless.github.io/itlwm/Compat)
- [FAQ](https://openintelwireless.github.io/itlwm/FAQ)

## Download

[![Download from https://github.com/OpenIntelWireless/itlwm/releases](https://img.shields.io/github/v/release/OpenIntelWireless/itlwm?label=Download)](https://github.com/OpenIntelWireless/itlwm/releases)

## Questions and Issues

Check out our [FAQ Page](https://openintelwireless.github.io/itlwm/FAQ) for more info.

If you have other questions or feedback, feel free to [![Join the chat at https://gitter.im/OpenIntelWireless/itlwm](https://badges.gitter.im/OpenIntelWireless/itlwm.svg)](https://gitter.im/OpenIntelWireless/itlwm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge).

We only accept bug reports in GitHub Issues, before opening an issue, you're recommended to reconfirm it with us on [Gitter](https://gitter.im/OpenIntelWireless/itlwm); once it's confirmed, please use the provided issue template.

## Credits

- [Acidanthera](https://github.com/acidanthera) for [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK)
- [Apple](https://www.apple.com) for [macOS](https://www.apple.com/macos)
- [AppleIntelWiFi](https://github.com/AppleIntelWiFi) for [Black80211-Catalina](https://github.com/AppleIntelWiFi/Black80211-Catalina)
- [ErrorErrorError](https://github.com/ErrorErrorError) for UserClient bug fixes
- [Intel](https://www.intel.com) for [Wireless Adapter Firmwares](https://www.intel.com/content/www/us/en/support/articles/000005511/network-and-io/wireless.html) and [iwlwifi](https://wireless.wiki.kernel.org/en/users/drivers/iwlwifi)
- [Linux](https://www.kernel.org) for [iwlwifi](https://wireless.wiki.kernel.org/en/users/drivers/iwlwifi)
- [mercurysquad](https://github.com/mercurysquad) for [Voodoo80211](https://github.com/mercurysquad/Voodoo80211)
- [OpenBSD](https://openbsd.org) for [net80211, iwn, iwm, and iwx](https://github.com/openbsd/src)
- [pigworlds](https://github.com/OpenIntelWireless/itlwm/commits?author=pigworlds) for DVM devices support, MIRA bug fixes, and Tx aggregation for MVM Gen 1 devices
- [rpeshkov](https://github.com/rpeshkov) for [black80211](https://github.com/rpeshkov/black80211)
- [usr-sse2](https://github.com/usr-sse2) for implementing the usage of Apple RSN Supplicant and bug fixes
- [zxystd](https://github.com/zxystd) for developing [itlwm](https://github.com/OpenIntelWireless/itlwm)
- [laobamac](https://github.com/laobamac) for improving Aiportitlwm to support loading in macOS Tahoe and Sequoia with AppleVTD enabled [itlwm](https://github.com/laobamac/itlwm)
- [YBronst](https://github.com/YBronst) for creating the first iteration of this downstream repository, generating the initial patches and builds attempting to allow AppleVTD enabling with this kext and sharing it with me to continue the development.
- [kgp](https://github.com/kgp-macPro) for developing a solution to use Airportitlwm kext with AppleVTD enabled supported by YBronst which was studied and leveraged to kickstart this repository
- [deeveedee](https://github.com/deeveedee-git) for contributing to the first release by updating the code to fix a race condition and enabling AX201 kext support.
- [retropineaple](https://github.com/retropineaple) for enabling Airdrop in Intel wifi+bluetooth cards in [ForbiddenItlwm](https://github.com/retropineaple/ForbiddenItlwm)
- OpenAI ChatGPT: research and architecture collaboration, evidence analysis, test strategy, independent source review and technical documentation.
- Anthropic Claude: research and architecture collaboration, evidence analysis, test strategy, and independent source review.

## Acknowledgements

- [@penghubingzhou](https://github.com/startpenghubingzhou)
- [@Bat.bat](https://github.com/williambj1)
- [@iStarForever](https://github.com/XStar-Dev)
- [@stevezhengshiqi](https://github.com/stevezhengshiqi)
- [@DogAndPot](https://github.com/DogAndPot) for providing resources and help for system configuration
- [@Daliansky](https://github.com/Daliansky) for providing Wi-Fi cards
