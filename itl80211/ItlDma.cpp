//
//  ItlDma.cpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/7.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "ItlDma.hpp"
#include <IOKit/IOLib.h>
#include <libkern/c++/OSBoolean.h>

ItlDmaArena *ItlDmaArena::create(IOPCIDevice *device, IOService *owner, uint8_t bits)
{
    auto arena = new ItlDmaArena();
    if (!arena)
        return nullptr;
    if (!arena->initialize(device, owner, bits)) {
        arena->destroy();
        return nullptr;
    }
    return arena;
}

bool ItlDmaArena::initialize(IOPCIDevice *pci, IOService *controller, uint8_t bits)
{
    if (!pci || !controller || (bits != 36 && bits != 64))
        return false;
    device = pci;
    device->retain();
    owner = controller;
    owner->setProperty("IOPCIUseDeviceMapper", kOSBooleanTrue);
    if (!device->open(owner)) {
        IOLog("AirportItlwm: DMA could not open PCI device\n");
        return false;
    }
    opened = true;
    mapper = IOMapper::copyMapperForDevice(device);
    const char *mode = "device";
    if (!mapper) {
        if (device->getProperty("iommu-parent")) {
            IOLog("AirportItlwm: DMA device mapper unavailable\n");
            return false;
        }
        IOMapper::checkForSystemMapper();
        mapper = IOMapper::gSystem;
        if (mapper)
            mapper->retain();
        mode = mapper ? "system" : "direct";
    }
    lock = IOSimpleLockAlloc();
    if (!lock)
        return false;

    const uint64_t mask = (bits == 64 ? UINT64_MAX : ((1ULL << bits) - 1)) & ~(uint64_t(PageSize) - 1);
    for (uint32_t i = 0; i < BlockCount; i++) {
        auto &block = blocks[i];
        block.memory = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
            kIODirectionInOut | kIOMemoryHostPhysicallyContiguous | kIOMemoryMapperNone,
            BlockSize, mask);
        if (!block.memory)
            return false;
        if (block.memory->prepare() != kIOReturnSuccess)
            return false;
        block.prepared = true;
        block.command = IODMACommand::withSpecification(kIODMACommandOutputHost64,
            bits, BlockSize, IODMACommand::kMapped, BlockSize, PageSize, mapper);
        if (!block.command || block.command->setMemoryDescriptor(block.memory) != kIOReturnSuccess)
            return false;
        IODMACommand::Segment64 segment = {};
        uint64_t offset = 0;
        uint32_t count = 1;
        if (block.command->gen64IOVMSegments(&offset, &segment, &count) != kIOReturnSuccess ||
            count != 1 || segment.fLength != BlockSize || offset != BlockSize ||
            (segment.fIOVMAddr & (PageSize - 1)) ||
            segment.fIOVMAddr > UINT64_MAX - (BlockSize - 1) ||
            (bits < 64 && ((segment.fIOVMAddr + BlockSize - 1) >> bits))) {
            IOLog("AirportItlwm: DMA arena segment constraints failed at block %u\n", i);
            return false;
        }
        block.address = segment.fIOVMAddr;
        block.vaddr = block.memory->getBytesNoCopy();
        if (!block.vaddr)
            return false;
    }
#if __IO80211_TARGET == __MAC_15_2
    owner->setProperty("ItlwmDMARevision", "sequoia-vtd-1");
#else
    owner->setProperty("ItlwmDMARevision", "tahoe-vtd-1");
#endif
    owner->setProperty("ItlwmDMAMapper", mode);
    owner->setProperty("ItlwmDMAAddressBits", bits, 32);
    owner->setProperty("ItlwmDMAPoolBytes", BlockCount * BlockSize, 32);
    IOLog("AirportItlwm: DMA mapper=%s bits=%u pool=%u MiB\n", mode, bits, BlockCount);
    return true;
}

bool ItlDmaArena::allocate(uint32_t size, uint32_t alignment, ItlDmaBuffer &buffer)
{
    if (buffer.arena || !size || size > BlockSize)
        return false;
    if (!alignment)
        alignment = 1;
    if ((alignment & (alignment - 1)) || alignment > BlockSize)
        return false;
    const uint32_t pages = (size + PageSize - 1) / PageSize;
    IOSimpleLockLock(lock);
    for (uint32_t b = 0; b < BlockCount; b++) {
        auto &block = blocks[b];
        for (uint32_t p = 0; p + pages <= PagesPerBlock; p++) {
            if (block.runs[p] || ((block.address + uint64_t(p) * PageSize) & (alignment - 1)))
                continue;
            uint32_t n = 1;
            while (n < pages && !block.runs[p + n])
                n++;
            if (n != pages) {
                p += n;
                continue;
            }
            block.runs[p] = pages;
            for (n = 1; n < pages; n++)
                block.runs[p + n] = Occupied;
            usedPages += pages;
            if (usedPages > highWaterPages)
                highWaterPages = usedPages;
            buffer.arena = this;
            buffer.vaddr = static_cast<uint8_t *>(block.vaddr) + p * PageSize;
            buffer.address = block.address + uint64_t(p) * PageSize;
            buffer.size = size;
            buffer.block = b;
            buffer.page = p;
            buffer.pages = pages;
            IOSimpleLockUnlock(lock);
            bzero(buffer.vaddr, pages * PageSize);
            return true;
        }
    }
    uint32_t failure = ++failures;
    uint32_t used = usedPages;
    IOSimpleLockUnlock(lock);
    if (failure == 1 || !(failure & (failure - 1)))
        IOLog("AirportItlwm: DMA pool exhausted size=%u used=%u failures=%u\n", size, used * PageSize, failure);
    return false;
}

void ItlDmaArena::deallocate(ItlDmaBuffer &buffer)
{
    if (!buffer.arena)
        return;
    IOSimpleLockLock(lock);
    if (buffer.arena != this || buffer.block >= BlockCount || !buffer.pages ||
        buffer.page + buffer.pages > PagesPerBlock ||
        blocks[buffer.block].runs[buffer.page] != buffer.pages) {
        IOSimpleLockUnlock(lock);
        panic("AirportItlwm: invalid DMA pool release");
    }
    auto &block = blocks[buffer.block];
    if (recyclingDeferred) {
        block.runs[buffer.page] |= Retired;
    } else {
        for (uint32_t n = 0; n < buffer.pages; n++)
            block.runs[buffer.page + n] = 0;
        usedPages -= buffer.pages;
    }
    IOSimpleLockUnlock(lock);
    bzero(&buffer, sizeof(buffer));
}

void ItlDmaArena::deferRecycling()
{
    IOSimpleLockLock(lock);
    recyclingDeferred = true;
    IOSimpleLockUnlock(lock);
}

void ItlDmaArena::reclaim()
{
    if (device->configRead16(kIOPCIConfigCommand) & kIOPCICommandBusMaster)
        return;
    IOSimpleLockLock(lock);
    for (uint32_t b = 0; b < BlockCount; b++) {
        auto &block = blocks[b];
        for (uint32_t p = 0; p < PagesPerBlock; p++) {
            uint16_t run = block.runs[p];
            if (!(run & Retired) || run == Occupied)
                continue;
            uint32_t count = run & ~Retired;
            for (uint32_t n = 0; n < count; n++)
                block.runs[p + n] = 0;
            usedPages -= count;
            p += count - 1;
        }
    }
    recyclingDeferred = false;
    IOSimpleLockUnlock(lock);
}

void ItlDmaArena::destroy()
{
    IOLog("AirportItlwm: DMA teardown used=%u high-water=%u failures=%u\n",
        usedPages * PageSize, highWaterPages * PageSize, failures);
    if (opened)
        device->setBusMasterEnable(false);
    for (uint32_t i = 0; i < BlockCount; i++) {
        auto &block = blocks[i];
        if (block.command) {
            block.command->clearMemoryDescriptor();
            block.command->release();
        }
        if (block.memory) {
            if (block.prepared)
                block.memory->complete();
            block.memory->release();
        }
    }
    if (mapper)
        mapper->release();
    if (opened)
        device->close(owner);
    if (device)
        device->release();
    if (lock)
        IOSimpleLockFree(lock);
    delete this;
}
