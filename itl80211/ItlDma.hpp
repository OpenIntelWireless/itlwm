//
//  ItlDma.hpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/7.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef ItlDma_hpp
#define ItlDma_hpp

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOLocks.h>
#include <IOKit/pci/IOPCIDevice.h>

class ItlDmaArena;

struct ItlDmaBuffer {
    ItlDmaArena *arena;
    void *vaddr;
    uint64_t address;
    uint32_t size;
    uint16_t block;
    uint16_t page;
    uint16_t pages;
};

class ItlDmaArena {
public:
    static ItlDmaArena *create(IOPCIDevice *device, IOService *owner, uint8_t bits);
    bool allocate(uint32_t size, uint32_t alignment, ItlDmaBuffer &buffer);
    void deallocate(ItlDmaBuffer &buffer);
    void deferRecycling();
    void reclaim();
    void destroy();

private:
    enum : uint32_t {
        PageSize = 4096,
        PagesPerBlock = 256,
        BlockSize = PageSize * PagesPerBlock,
        BlockCount = 32,
        Occupied = 0xffff,
        Retired = 0x8000
    };

    struct Block {
        IOBufferMemoryDescriptor *memory;
        IODMACommand *command;
        void *vaddr;
        uint64_t address;
        uint16_t runs[PagesPerBlock];
        bool prepared;
    };

    bool initialize(IOPCIDevice *device, IOService *owner, uint8_t bits);
    Block blocks[BlockCount];
    IOSimpleLock *lock;
    IOPCIDevice *device;
    IOService *owner;
    IOMapper *mapper;
    uint32_t usedPages;
    uint32_t highWaterPages;
    uint32_t failures;
    bool opened;
    bool recyclingDeferred;
};

#endif
