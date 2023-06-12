//
//  IOSkywalkNetworkPacket.h
//  itlwm
//
//  Created by qcwap on 2023/6/13.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOSkywalkInterface_h
#define IOSkywalkInterface_h

class IOSkywalkPacketBufferPool;
class IOSkywalkPacketDescriptor;
class IOSkywalkPacketBuffer;
class IOSkywalkPacketQueue;

class IOSkywalkNetworkPacket : public IOService {
    OSDeclareAbstractStructors(IOSkywalkNetworkPacket)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    
    virtual bool initWithPool(IOSkywalkPacketBufferPool *,IOSkywalkPacketDescriptor *,uint);
    virtual void *getPacketBuffers(IOSkywalkPacketBuffer **,uint);
    virtual UInt getPacketBufferCount(void);
    virtual IOSkywalkPacketDescriptor *getMemoryDescriptor(void);
    virtual void setDataLength(uint);
    virtual UInt getDataLength(void);
    virtual void setDataOffset(unsigned short);
    virtual unsigned short getDataOffset(void);
    virtual void setDataOffsetAndLength(unsigned short,uint);
    virtual void setDataOff(long long);
    virtual long long getDataOff(void);
    virtual void setDataOffAndLen(long long,unsigned long);
    virtual void *getDataVirtualAddress(void);
    virtual void *getDataIOVirtualAddress(void);
    virtual bool prepareWithQueue(IOSkywalkPacketQueue *,uint,uint);
    virtual bool prepare(IOSkywalkPacketQueue *,unsigned long long,uint);
    virtual void completeWithQueue(IOSkywalkPacketQueue *,uint,uint);
    virtual void complete(IOSkywalkPacketQueue *,uint);
    virtual UInt getPacketType(void);
    virtual void setWakeFlag(void);
    virtual UInt getTraceID(void);
    virtual void setTraceID(UInt);
    virtual void traceEvent(uint);
    virtual void *generateTraceTag(IOSkywalkPacketQueue *);
    virtual void *acquireWithPacketHandle(unsigned long long,uint);
    virtual void disposePacket(void);
    
public:
    uint8_t filter[0x78];
};

#endif /* IOSkywalkInterface_h */
