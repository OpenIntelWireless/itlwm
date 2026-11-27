// Sequoia 15.8 (24H23, 24H241) native-owned ABI views. IOSkywalkPacket and IOSkywalkPacketBufferPool
// have the same vtable slots here as on Tahoe (checked against the KDK). Never instantiate or derive from them.
#pragma once
#include <libkern/c++/OSObject.h>
#include <IOKit/IOReturn.h>
class IOSkywalkPacketBufferPool;
class IOSkywalkPacketDescriptor;
class IOSkywalkPacketBuffer;
class IOMemoryDescriptor;
class ItlSkywalkPacketView : public OSObject {
    ItlSkywalkPacketView();
    virtual void _initSlot(); // 0x118, deliberately not callable
public:
    virtual unsigned int getPacketBuffers(IOSkywalkPacketBuffer**, unsigned int) const;
    virtual unsigned int getPacketBufferCount() const;
    virtual IOMemoryDescriptor *getMemoryDescriptor() const;
    virtual IOReturn setDataLength(unsigned int);
    virtual unsigned int getDataLength() const; // 0x140
private:
    virtual void _offset1();
    virtual void _offset2();
    virtual void _offset3();
    virtual void _offset4();
    virtual void _offset5();
    virtual void _offset6();
public:
    virtual uint64_t getDataVirtualAddress() const; // 0x178, CPU address
private:
    virtual void _address2();
public:
    virtual IOReturn prepareWithQueue(void*, unsigned int, unsigned int); // 0x188
private:
    virtual void _prepareSlot();
public:
    virtual IOReturn completeWithQueue(void*, unsigned int, unsigned int); // 0x198
};
// Native exports (present on 25G241 and 24H241). The two setters only touch the packet's kernel handle.
// A successful enqueue consumes the packet: the queue completes, finalizes and
// disposes it, so the caller must not touch or return it afterwards. On error
// nothing has been consumed.
extern "C" IOReturn itlRxEnqueue(void *, ItlSkywalkPacketView *const *, unsigned int, unsigned int)
    __asm__("__ZN26IOSkywalkRxCompletionQueue14enqueuePacketsEPKP15IOSkywalkPacketjj");
extern "C" IOReturn itlPacketSetHeadroom(ItlSkywalkPacketView *, unsigned char)
    __asm__("__ZN22IOSkywalkNetworkPacket11setHeadroomEh");
extern "C" IOReturn itlPacketSetLinkHeaderLength(ItlSkywalkPacketView *, unsigned char)
    __asm__("__ZN22IOSkywalkNetworkPacket19setLinkHeaderLengthEh");
// Where the frame starts: macOS's output packets carry headroom before it.
extern "C" unsigned short itlPacketGetDataOffset(const ItlSkywalkPacketView *)
    __asm__("__ZNK15IOSkywalkPacket13getDataOffsetEv");
// Finishes and frees each packet, and notifies its source queue. Count must be
// below the queue's capacity. On error nothing has been consumed.
extern "C" IOReturn itlTxComplete(void *, void *const *, unsigned int, unsigned int)
    __asm__("__ZN26IOSkywalkTxCompletionQueue14enqueuePacketsEPKP15IOSkywalkPacketjj");
class ItlSkywalkPoolView : public OSObject {
    ItlSkywalkPoolView();
    virtual void _initSlot1(); // 0x118
    virtual void _initSlot2(); // 0x120
public:
    virtual IOReturn allocatePacket(ItlSkywalkPacketView**, unsigned int); // 0x128, native default overload
    virtual IOReturn allocatePacket(unsigned int, ItlSkywalkPacketView**, unsigned int); // 0x130
private:
    virtual void _allocateManySlot(); // 0x138
public:
    virtual void deallocatePacket(ItlSkywalkPacketView*); // 0x140, no status result
};
