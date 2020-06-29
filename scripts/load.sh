sudo kextunload -b com.zxystd.itlwm
sudo chown -R root:wheel ./../Build/Products/Debug/itlwm.kext
sudo kextutil -v 6 ./../Build/Products/Debug/itlwm.kext

