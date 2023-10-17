//
//  IOSkywalkPacketBufferPool.h
//  itlwm
//
//  Created by qcwap on 2023/6/15.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOSkywalkPacketBufferPool_h
#define IOSkywalkPacketBufferPool_h

#include <IOKit/IOService.h>

class IOSkywalkMemorySegment;
class IOSkywalkMemorySegmentDescriptor;
class IOSkywalkPacket;
class IOSkywalkPacketBuffer;
class IOSkywalkPacketDescriptor;
class IOSkywalkPacketBufferDescriptor;

class IOSkywalkPacketBufferPool : public OSObject {
    OSDeclareDefaultStructors(IOSkywalkPacketBufferPool)
    
public:
    struct PoolOptions {
        uint32_t packetCount;
        uint32_t bufferCount;
        uint32_t bufferSize;
        uint32_t maxBuffersPerPacket;
        uint32_t memorySegmentSize;
        uint32_t poolFlags;
        uint64_t pad;
    };
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool initWithName(char const*,void *,uint,IOSkywalkPacketBufferPool::PoolOptions const*);
    virtual bool initWithName(char const*,OSObject *,uint,IOSkywalkPacketBufferPool::PoolOptions const*);
    virtual bool allocatePacket(IOSkywalkPacket **,uint);
    virtual bool allocatePacket(uint,IOSkywalkPacket **,uint);
    virtual bool allocatePackets(uint,uint *,IOSkywalkPacket **,uint);
    virtual void deallocatePacket(IOSkywalkPacket *);
    virtual void deallocatePackets(IOSkywalkPacket **,uint);
    virtual void deallocatePacketList(IOSkywalkPacket *);
    virtual void deallocatePacketChain(unsigned long long);
    virtual bool allocatePacketBuffer(IOSkywalkPacketBuffer **,uint);
    virtual bool allocatePacketBuffers(uint *,IOSkywalkPacketBuffer **,uint);
    virtual void deallocatePacketBuffer(IOSkywalkPacketBuffer *);
    virtual void deallocatePacketBuffers(IOSkywalkPacketBuffer **,uint);
    virtual bool newPacket(IOSkywalkPacketDescriptor *,IOSkywalkPacket **);
    virtual bool newPacketBuffer(IOSkywalkPacketBufferDescriptor *,IOSkywalkPacketBuffer **);
    virtual bool newMemorySegment(IOSkywalkMemorySegmentDescriptor *,IOSkywalkMemorySegment **);
    
public:
    static IOSkywalkPacketBufferPool *withName(char const*,OSObject *,uint,IOSkywalkPacketBufferPool::PoolOptions const*);
    
public:
    uint8_t filter[0xB8];
};

#endif /* IOSkywalkPacketBufferPool_h */

