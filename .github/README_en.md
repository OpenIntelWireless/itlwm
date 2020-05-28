# itlwm

[![Join the chat at https://gitter.im/OpenIntelWireless/itlwm](https://badges.gitter.im/OpenIntelWireless/itlwm.svg)](https://gitter.im/OpenIntelWireless/itlwm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**An Intel Wifi Adapter Kernel Extension for macOS, based on the OpenBSD Project.**

## Readme

- [简体中文](../README.md)
- **English**

## Intro

PCBeta Forum: <http://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1848662>

It has been exactly three and a half months since I released the Intel Bluetooth Firmware Uploader Kext, and I truly appreciate everyone who supports me. I begin to use MacOS half a year ago. Without having a solid understanding of IOKit, I tried my best to move forward, and things might be wrong. I did this with full caution and passion for Hackintoshing.

People who watch me should know I have another Intel Wi-Fi Kext Repository [AppleIntelWifiAdapter](https://github.com/zxystd/AppleIntelWifiAdapter) which is based on Linux's iwlwifi code; so far the Kext is able to upload firmware for Intel Wi-Fi cards of `3`, `7`, `8`, `9`, `ax` series and do simple `RX` & `TX` I/O. Because the integrated `80211` ported from OpenBSD in that project has so many things require testing, I came up with an idea of porting the entire iwm driver from OpenBSD, and this repo is the result. Since I ported Linux drivers before, the porting progress is extremely smooth this time. It only took half a day to port the entire code, and then I spent roughly one month to tweak it.

**Now, Intel Wi-Fi Cards are finally able to access the Internet!**

Don't be misled by `Ethernet` shown in System Prefs. The reason is that I didn't use Apple's close source `IO80211Family` but rather spoofed it into Ethernet, just like USB Wi-Fi cards.

I decided to make the source code open. **Anyone can view my code and modify it, but whoever you are, you have to inform me the content you modified and keep the copyright information in the code, thank you very much!**

<https://github.com/zxystd/itlwm>

I will keep updating, and everyone should keep a positive attitude and believe the immense power of the Open Source community, believing the power from China and the World. So far I've taken a big step, and not only my theory has been proved to be correct, but also it works in reality, WE NEED TO BREAK THE STEREOTYPE OF "GIVE UP IN INTEL!"

## Development Status

WPA  Wi-Fi connection  is currently supported. Wi-Fi SSID is hardcoded as `ssdt` password as `zxyssdt112233` and will auto-connect once the Kext is loaded.

Now the slow network speed and firmware random crash should be fix.

## Supported Devices

- 3xxx: 3160, 3165, 3168
- 7xxx: 7260, 7265
- 8xxx: 8260, 8265
- 9xxx: 9260、9560、9462

## Credit

- [mercurysquad/Voodoo80211](https://github.com/mercurysquad/Voodoo80211)
- [openbsd/src](https://github.com/openbsd/src)
- [torvalds/linux](https://github.com/torvalds/linux)
- [rpeshkov/black80211](https://github.com/rpeshkov/black80211)
- [AppleIntelWiFi/Black80211-Catalina](https://github.com/AppleIntelWiFi/Black80211-Catalina)

## Acknowledge

- [@penghubingzhou](https://github.com/startpenghubingzhou)
- [@Bat.bat](https://github.com/williambj1)
- [@iStarForever](https://github.com/XStar-Dev)
- [@stevezhengshiqi](https://github.com/stevezhengshiqi)
- [@DogAndPot](https://github.com/DogAndPot)

For providing resources and help in Hackintoshing.

- [@Daliansky](https://github.com/Daliansky)

For providing Wi-Fi cards.
