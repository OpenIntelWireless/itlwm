# itlwm

**Patches to the original itlwm Kernel Extension to allow it loading in macOS 26 with AppleVTD enabled**

Patching and testing is based on and being done using a AX201 wifi chip and the AX210 wifi chip below:

https://a.co/d/0hY4N3fQ EDUP PCIE WiFi 6E Card AX210 Bluetooth 5.2 AX5400M 802.11ax Tri-Band 6G/5.8G/2.4GHz Heat Sink 6dBi Antenna PCI-E Wireless Network Cards for Desktop PC Support Windows 11/10 64-bit.

A lot of credits to [laobamac](https://github.com/laobamac) who enhanced Aiportitlwm to support loading in macOS Tahoe and Sequoia with AppleVTD enabled. I leveraged his implementation of IOMMU / DMA enabling AppleVTD in Airportitlwm to enhance my initial implementation of itlwm with AppleVTD enabled, and to YBronst for creating the first iteration of this downstream repository, generating the initial patches and builds attempting to allow AppleVTD enabling with this kext and sharing it with me to continue the development. 

Kudos to [retropineaple](https://github.com/retropineaple) for enabling Airdrop in Intel wifi+bluetooth cards. I integrated the code from [ForbiddenItlwm](https://github.com/retropineaple/ForbiddenItlwm) into this fork to build and release from this fork the necessary Airportitlwm and BTLEAdvFixup kexts for Sequoia and Tahoe for the benefit of all community users. I tested Airdrop in my AX210 transferring a file from my iPhone to my hackintosh and viceversa, and it worked. The code to enable Airdrop is published in the Airdrop-test branch.

**An Intel Wi-Fi Adapter Kernel Extension for macOS, based on the OpenBSD Project.**

## Documentation

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
