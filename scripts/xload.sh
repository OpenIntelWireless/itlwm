sudo kextunload -b com.zxystd.itlwmx
sudo chown -R root:wheel ./../Build/Products/Debug/itlwmx.kext
sudo kextutil -v 6 ./../Build/Products/Debug/itlwmx.kext

