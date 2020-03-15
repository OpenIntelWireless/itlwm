# itlwm

##An Intel Wifi Adapter for Macos from OpenBsd project.

远景链接：http://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1848662

距离上次发布蓝牙固件上传驱动刚好三月半（http://bbs.pcbeta.com/viewthread-1838959-1-1.html），很感谢各位的支持，本人接触黑苹果半年，对于IOKit也是半知半解，摸索着前进，可能有很多东西是不对的，也是纯粹凭着对黑苹果的求知欲以及编程的爱好来完成这些的。关注我的朋友应该都知道我还有一个WIFI驱动仓库，根据2019年十月份的linux iwlwifi代码移植开发的AppleIntelWifiAdapter(https://github.com/zxystd/IntelBluetoothFirmware)驱动，截止到目前已经完成了3、7、8、9、ax系列Intel网卡的固件上传以及基本的RX TX输入输出代码，但是由于本人移植自openbsd的80211实在有太多东西需要去验证，所以就萌生了把整个openbsd的iwm 驱动移植过来的想法。因为重写过linux驱动的代码的关系，移植过程非常顺利，半天即完成代码移植，断断续续花费了差不多一个月进行调试，

现在，终于实现了Intel无线网卡上网





不要看那显示的是个以太网，因为我并没有使用苹果的IO80211Family，而是像usb网卡一样，使用以太网接口上网。

关于源代码，本人决定开源，任何人可以查阅并且修改，但是请务必通知我修改的内容，并且保留本作者信息，非常感谢！

https://github.com/zxystd/itlwm

本人还会继续更新，但是请大家保持积极乐观的态度，要相信这个黑苹果社区的强大，相信咱们国人乃至世界人民的力量，目前我已经算是迈了一大步了，不仅是理论通，实际也已经走通，争取打破“Intel无解”的言论。

代码信息：
目前支持无加密WiFi连接，Wifi名字已经写死，可以手机分享无加密的Wifi，名字叫Redmi，加载驱动之后会自动连接上。
WPA四次握手已经完成，但是加解密还有一些问题需要修复。
支持的设备：
3165
3160
3168
7260
7265
8260
8265

参考资料
https://github.com/mercurysquad/Voodoo80211
https://github.com/openbsd/src
https://github.com/torvalds/linux
https://github.com/rpeshkov/black80211
https://github.com/AppleIntelWifi/Black80211-Catalina

致谢
在这里还要感谢大佬们：@1989～PHBZ  @Bat.bat  @iStar/OC-惠普暗影2Pro-1820A 
@葫芦娃 @大狗子 给予我黑苹果以及资源帮助，感谢黑果小兵兵哥帮忙提供网卡测试。

