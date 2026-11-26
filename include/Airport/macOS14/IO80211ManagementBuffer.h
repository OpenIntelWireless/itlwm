// Sonoma 14.8.9 (23J631) ABI views of native-owned objects, the same as Sequoia's except for
// where the management frame pool comes from (see below). Never instantiate or derive
// from these partial declarations.
//
// Unlike Tahoe, Sequoia's IO80211Buffer has no virtual methods beyond OSObject's: returnBuffer,
// getCapacity, setLength and getBytesNoCopy are ordinary exported functions. They are declared
// non-virtual here, so calls link straight to those exports. IO80211BufferPool::getBuffer is
// still virtual, in the same slot as on Tahoe (checked against the KDK).
#pragma once
#include <libkern/c++/OSObject.h>
class IO80211Buffer : public OSObject {
    IO80211Buffer();
public:
    void returnBuffer();                                 // __ZN13IO80211Buffer12returnBufferEv
    size_t getCapacity() const;                          // __ZNK13IO80211Buffer11getCapacityEv
    void setLength(size_t);                              // __ZN13IO80211Buffer9setLengthEm
    void *getBytesNoCopy();                              // __ZN13IO80211Buffer14getBytesNoCopyEv
};
class IO80211BufferPool : public OSObject {
    IO80211BufferPool();
public:
    virtual IO80211Buffer *getBuffer();                  // 0x118
};
class IO80211Controller;
class IO80211VirtualInterface;
// On Sonoma the pool belongs to the virtual interface (its ivars +0x230), not the controller.
extern "C" IO80211BufferPool *itlGetInterfaceMgmtFramePool(IO80211VirtualInterface*)
    __asm__("__ZN23IO80211VirtualInterface16getMgmtFramePoolEv");
// This overload consumes the pool-buffer lease on every path: it returns the
// buffer itself or transfers it to the peer manager. Do not return it twice.
extern "C" void itlSubmitMgmtFrame(IO80211VirtualInterface*, IO80211Buffer*, unsigned int, void*, unsigned long)
    __asm__("__ZN23IO80211VirtualInterface11bpfTapInputEP13IO80211BufferjPvm");
