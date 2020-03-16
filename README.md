# itlwm

**基于 OpenBSD 的 macOS 英特尔网卡驱动**

## Readme

- **简体中文**
- [English](./.github/README_en.md)

## 简介

[远景链接](http://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1848662)

距离上次发布 [蓝牙固件上传驱动](http://bbs.pcbeta.com/viewthread-1838959-1-1.html) 刚好过了三月半，很感谢各位的支持，本人接触黑苹果半年，对于 IOKit 也是半知半解，摸索着前进，可能有很多东西是不对的，也是纯粹凭着对黑苹果的求知欲以及编程的爱好来完成这些的。

关注我的朋友应该都知道我还有一个 Wi-Fi 驱动仓库，根据 2019 年十月份的 Linux `iwlwifi` 代码移植开发的 [AppleIntelWiFiAdapter](https://github.com/zxystd/AppleIntelWifiAdapter) 驱动，截止到目前已经完成了 3、7、8、9、ax 系列 Intel 网卡的固件上传以及基本的 `RX` `TX` 输入输出代码，但是由于本人移植自 OpenBSD 的 `80211` 实在有太多东西需要去验证，所以就萌生了把整个 OpenBSD 的 iwm 驱动移植过来的想法。

因为重写过 Linux 驱动的代码的关系，移植过程非常顺利，半天即完成代码移植，断断续续花费了差不多一个月进行调试。

**现在，终于实现了 Intel 无线网卡上网！**

不要看那显示的是个以太网，因为我并没有使用苹果的 `IO80211Family`，而是像 USB 网卡一样，使用以太网接口上网。

关于源代码，本人决定开源，**任何人可以查阅并且修改，但是请务必通知我修改的内容，并且保留本作者信息，非常感谢！**

本人还会继续更新，但是请大家保持积极乐观的态度，要相信这个黑苹果社区的强大，相信咱们国人乃至世界人民的力量，目前我已经算是迈了一大步了，不仅是理论通，实际也已经走通，争取打破 “Intel无解” 的言论。

**注意：现在虽然能够上网，但是还没有到民用的程度，暂时不提供成品 Kext，想折腾的可以自行用 Xcode 编译。**

## 当前进度

目前支持无加密 Wi-Fi 连接，Wi-Fi 名字已经写死，可以手机分享无加密的 Wi-Fi，名字叫 `Redmi`，加载驱动之后会自动连接上。

WPA 四次握手已经完成，但是加解密还有一些问题需要修复。

## 支持设备

- 3 系：3160、3165、3168
- 7 系：7260、7265
- 8 系：8260、8265

## 参考资料

- [mercurysquad/Voodoo80211](https://github.com/mercurysquad/Voodoo80211)
- [openbsd/src](https://github.com/openbsd/src)
- [torvalds/linux](https://github.com/torvalds/linux)
- [rpeshkov/black80211](https://github.com/rpeshkov/black80211)
- [AppleIntelWiFi/Black80211-Catalina](https://github.com/AppleIntelWiFi/Black80211-Catalina)

## 致谢

在这里还要感谢大佬们：

- [@penghubingzhou](https://github.com/startpenghubingzhou)
- [@Bat.bat](https://github.com/williambj1)
- [@iStarForever](https://github.com/XStar-Dev)
- [@stevezhengshiqi](https://github.com/stevezhengshiqi)
- [@DogAndPot](https://github.com/DogAndPot)

给予我黑苹果以及资源帮助

- [@Daliansky](https://github.com/Daliansky)

帮忙提供网卡测试。
