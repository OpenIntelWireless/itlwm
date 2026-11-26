// Tahoe 25G241 ABI views of native-owned objects. Never instantiate or derive
// from these partial declarations. Only their verified virtual prefixes are used.
#pragma once
#include <libkern/c++/OSObject.h>
class IO80211Buffer : public OSObject {
    IO80211Buffer();
public:
    virtual void returnBuffer();                         // 0x118
    virtual void zero();
    virtual bool isZero() const;
    virtual size_t getLength() const;
    virtual void setLength(size_t);
    virtual size_t getCapacity() const;                  // 0x140
private:
    virtual void _cursor() __asm__("__ZN13IO80211Buffer9getCursorEv");
    virtual void _constCursor() __asm__("__ZNK13IO80211Buffer9getCursorEv");
public:
    virtual void *getBytesNoCopy();                      // 0x158
};
class IO80211BufferPool : public OSObject {
    IO80211BufferPool();
public:
    virtual IO80211Buffer *getBuffer();                  // 0x118
};
class IO80211Controller;
class IO80211VirtualInterface;
extern "C" IO80211BufferPool *itlGetMgmtFramePool(IO80211Controller*)
    __asm__("__ZN17IO80211Controller16getMgmtFramePoolEv");
// This overload consumes the pool-buffer lease on every path: it returns the
// buffer itself or transfers it to the peer manager. Do not return it twice.
extern "C" void itlSubmitMgmtFrame(IO80211VirtualInterface*, IO80211Buffer*, unsigned int, void*, unsigned long)
    __asm__("__ZN23IO80211VirtualInterface11bpfTapInputEP13IO80211BufferjPvm");
