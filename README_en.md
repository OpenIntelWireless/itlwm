# itlwm

**An Intel Wifi Adapter Kernel Extension for macOS, based on the OpenBSD Project.**

[PCBeta Forum (Chinese)](http://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1848662) | [简体中文](./README.md)

## Intro

It has been exactly three and a half months since I released the Intel Bluetooth Firmware Uploader Kext. Thank you, everyone, for supporting me. I've started Hackintoshing for only half a year, without having a solid understanding of `IOKit` I tried my best to move forward and things may be wrong. I did this purely with my curiosity and passion for Hackintoshing.

People who watch me should know I have another Intel Wi-Fi Kext Repository [AppleIntelWifiAdapter](https://github.com/zxystd/AppleIntelWifiAdapter) which is based on Linux' iwlwifi code, so far that Kext is able to upload firmware for `3`, `7`, `8`, `9`, `ax` series Intel Wi-Fi cards and do simple `RX` & `TX` I/O. Because the integrated `80211` ported from OpenBSD in that project has so many things required to be verified, I came up with an idea of porting the entire iwm driver from OpenBSD, so this repo is the result.

Since I've ported Linux drivers before, the porting progress this time is going extremely well, it only took my half a day to port the entire code, then I spent roughly one month to tweak it.

**Now, Intel Wi-Fi Cards are finally able to access the Internet!**

Don't be misled by `Ethernet` shown in System Prefs. In fact, I didn't use Apple's `IO80211Family` but rather spoofed it into Ethernet, just like USB Wi-Fi cards.

I decided to make the project open-source, **anyone can view it and modify it, but whoever you are, you have to inform me about what you modified and keep the copyright information in the code, thank you very much!**

I will keep updating, but please keep a positive attitude, it's better to believe the huge power of the Hackintosh community, believe the power from China and the World. So far I've taken a big step forward, not only my theory has been proved to be correct, but it is also already working in reality, WE NEED TO BREAK THE BELIEF OF "GIVE UP IN INTEL!"

## Development Status

Only non-encrypted Wi-Fi connection is currently supported. It's able to connect to mobile shared hotspots, Wi-Fi SSID is hardcoded as `Redmi` and will auto-connect once the Kext is loaded.

Four-time WPA Handshake has completed, but encryption and decryption still have some issues that need to be fixed.

## Supported Devices

- 3xxx: 3160, 3165, 3168
- 7xxx: 7260, 7265
- 8xxx: 8260, 8265

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
