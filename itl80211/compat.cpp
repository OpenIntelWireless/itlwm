/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/
//
//  compat.cpp
//  net80211
//
//  Copyright (c) 2012 Prashant Vaibhav. All rights reserved.
//

#include "compat.h"
#include <sys/random.h>
#include <sys/param.h>
#include <sys/proc.h>

#include <IOKit/IOCommandGate.h>
#include <IOKit/IODMACommand.h>

OSDefineMetaClassAndStructors(pci_intr_handle, OSObject)

extern IOCommandGate *_fCommandGate;

IOReturn tsleepHandler(OSObject *owner, void *arg0, void *arg1, void *arg2, void *arg3) {
    if (arg1 == 0)
        return _fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED ? kIOReturnSuccess : kIOReturnTimeout;
    else {
        AbsoluteTime deadline;
        clock_interval_to_deadline(((int)(uint64_t)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        return _fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED ? kIOReturnSuccess : kIOReturnTimeout;
    }
}

int
tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
    if (!_fCommandGate) {
        IOLog("%s No command gate for sleep\n", __FUNCTION__);
        return 0;
    }
    return _fCommandGate->runAction(tsleepHandler, ident, (void *)(uint64_t)timo);
}

void
wakeupOn(void *ident)
{
    if (!_fCommandGate) {
        IOLog("%s No command gate for wakeup\n", __FUNCTION__);
        return;
    }
    _fCommandGate->commandWakeup(ident);
}

void
wakeup_oneOn(void *ident)
{
    if (!_fCommandGate) {
        IOLog("%s No command gate for wakeup one thread\n", __FUNCTION__);
        return;
    }
    _fCommandGate->commandWakeup(ident, true);
}

int pci_get_capability(pci_chipset_tag_t chipsettag, pcitag_t pcitag, int capid, int *offsetp, pcireg_t *valuep) {
	uint8_t offset;
	UInt32 value = pcitag->findPCICapability(capid, &offset);
	if (valuep)
		*valuep = (pcireg_t)value;
	if (offsetp)
		*offsetp = offset;
	if (value == 0)
		return 0;
	else
		return 1;
}

pcireg_t pci_conf_read(pci_chipset_tag_t pc, pcitag_t tag, int reg) {
	return tag->configRead32(reg);
}

void pci_conf_write(pci_chipset_tag_t pc, pcitag_t tag, int reg, pcireg_t val) {
	tag->configWrite32(reg, val);
}

pcireg_t pci_mapreg_type(pci_chipset_tag_t pc, pcitag_t tag, int reg) {
	return 0; // XXX this is not needed on OS X, will always be memorymap
}

int pci_mapreg_map(const struct pci_attach_args *pa, int reg, pcireg_t type, int busflags, bus_space_tag_t *tagp,
		   bus_space_handle_t *handlep, bus_addr_t *basep, bus_size_t *sizep, bus_size_t maxsize)
{	
	IOMemoryMap* map = pa->pa_tag->mapDeviceMemoryWithRegister(reg);
	if (map == 0)
		return kIOReturnError;
	
	*handlep = reinterpret_cast<caddr_t>(map->getVirtualAddress());
	
	if (tagp)
		*tagp = map;
	if (basep)
		*basep = map->getVirtualAddress();
	if (sizep)
		*sizep = map->getSize();
	
	return 0;
}

int bus_space_unmap(bus_space_tag_t tag, bus_space_handle_t handle, bus_size_t size)
{
    return 0;
}

int
pci_intr_map_msix(struct pci_attach_args *pa, int vec, pci_intr_handle_t *ihp)
{
    pci_chipset_tag_t pc = pa->pa_pc;
    pcitag_t tag = pa->pa_tag;
    pcireg_t reg;

    KASSERT(PCI_MSIX_VEC(vec) == vec, "PCI_MSIX_VEC(vec) == vec");

    if (pci_get_capability(pc, tag, PCI_CAP_MSIX, NULL, &reg) == 0)
        return 1;

    if (vec > PCI_MSIX_MC_TBLSZ(reg))
        return 1;
    
    return pci_intr_map_msi(pa, ihp);
}

#define  PCI_MSI_FLAGS        2    /* Message Control */
#define  PCI_CAP_ID_MSI        0x05    /* Message Signalled Interrupts */
#define  PCI_MSIX_FLAGS        2    /* Message Control */
#define  PCI_CAP_ID_MSIX    0x11    /* MSI-X */
#define  PCI_MSIX_FLAGS_ENABLE    0x8000    /* MSI-X enable */
#define  PCI_MSI_FLAGS_ENABLE    0x0001    /* MSI feature enabled */

static void pciMsiSetEnable(IOPCIDevice *device, UInt8 msiCap, int enable)
{
    u16 control;
    
    control = device->configRead16(msiCap + PCI_MSI_FLAGS);
    control &= ~PCI_MSI_FLAGS_ENABLE;
    if (enable)
        control |= PCI_MSI_FLAGS_ENABLE;
    device->configWrite16(msiCap + PCI_MSI_FLAGS, control);
}

static void pciMsiXClearAndSet(IOPCIDevice *device, UInt8 msixCap, UInt16 clear, UInt16 set)
{
    u16 ctrl;
    
    ctrl = device->configRead16(msixCap + PCI_MSIX_FLAGS);
    ctrl &= ~clear;
    ctrl |= set;
    device->configWrite16(msixCap + PCI_MSIX_FLAGS, ctrl);
}

int pci_intr_map_msi(struct pci_attach_args *paa, pci_intr_handle_t *ih)
{
    UInt8 msiCap;
    UInt8 msixCap;

	if (paa == 0 || ih == 0)
		return 1;
	
	*ih = new pci_intr_handle();
	
	if (*ih == 0)
		return 1;
	
	(*ih)->dev = paa->pa_tag;  // pci device reference
	
	(*ih)->workloop = paa->workloop;
    
    (*ih)->msi = true;
    
    paa->pa_tag->findPCICapability(PCI_CAP_ID_MSIX, &msixCap);
    if (msixCap) {
        pciMsiXClearAndSet(paa->pa_tag, msixCap, PCI_MSIX_FLAGS_ENABLE, 0);
    }
    paa->pa_tag->findPCICapability(PCI_CAP_ID_MSI, &msiCap);
    if (msiCap) {
        pciMsiSetEnable(paa->pa_tag, msiCap, 1);
    }
	
	return 0; // XXX not required on OS X
}

int pci_intr_map(struct pci_attach_args *paa, pci_intr_handle_t *ih)
{
    UInt8 msiCap;
    UInt8 msixCap;

    if (paa == 0 || ih == 0)
        return 1;
    
    *ih = new pci_intr_handle();
    
    if (*ih == 0)
        return 1;
    
    (*ih)->dev = paa->pa_tag;  // pci device reference
    
    (*ih)->workloop = paa->workloop;
    
    (*ih)->msi = false;
    
    paa->pa_tag->findPCICapability(PCI_CAP_ID_MSIX, &msixCap);
    if (msixCap) {
        pciMsiXClearAndSet(paa->pa_tag, msixCap, PCI_MSIX_FLAGS_ENABLE, 0);
    }
    paa->pa_tag->findPCICapability(PCI_CAP_ID_MSI, &msiCap);
    if (msiCap) {
        pciMsiSetEnable(paa->pa_tag, msiCap, 0);
    }

	return 0;
}

static void interruptTrampoline(OSObject *object, IOInterruptEventSource *sender, int count)
{
    pci_intr_handle *ih = OSDynamicCast(pci_intr_handle, object);
    if (!ih || !ih->func)
        return;
    ih->func(ih->arg);
}

void* pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*handler)(void *), void *arg, const char *name)
{
    int intrIndex = 0;

    if (ih->msi) {
        for (int index = 0; ; index++)
        {
            int interruptType;
            int ret = ih->dev->getInterruptType(index, &interruptType);
            if (ret != kIOReturnSuccess)
                break;
            if (interruptType & kIOInterruptTypePCIMessaged)
            {
                intrIndex = index;
                break;
            }
        }
    }
	ih->arg = arg;
    ih->func = handler;
	ih->intr = IOInterruptEventSource::interruptEventSource(ih, &interruptTrampoline, ih->dev, intrIndex);
	
	if (ih->intr == NULL)
		return NULL;
	if (ih->workloop->addEventSource(ih->intr) != kIOReturnSuccess)
		return NULL;
	
	ih->intr->enable();
	return ih;
}

void pci_intr_disestablish(pci_chipset_tag_t pc, void *ih)
{
	pci_intr_handle_t intr = (pci_intr_handle_t) ih;
    
	if (intr->workloop)
        intr->workloop->removeEventSource(intr->intr);
	
    if (intr->intr) {
        intr->intr->release();
        intr->intr = NULL;
    }
	intr->dev = NULL;
	intr->workloop = NULL;
	
	intr->arg = NULL;
	intr->release();
	intr = 0;
	ih = 0;
}

uint64_t bus_space_read_8(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset) {
    return *((uint64_t*)(handle + offset));
}

void bus_space_write_8(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint64_t value) {
    *((uint64_t*)(handle + offset)) = value;
}

uint32_t bus_space_read_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset) {
	return *((uint32_t*)(handle + offset));
}

void bus_space_write_1(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint8_t value) {
    *((uint8_t*)(handle + offset)) = value;
}

void bus_space_write_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint32_t value) {
	*((uint32_t*)(handle + offset)) = value;
}

void bus_space_barrier(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, bus_size_t length, int flags) {
	return; // In OSX device memory access is always uncached and serialized (afaik!)
}

int bus_dmamap_create(bus_dma_tag_t tag, bus_size_t size, int nsegments, bus_size_t maxsegsz, bus_size_t boundary, int flags, bus_dmamap_t *dmamp) {
	if (dmamp == 0)
		return -EINVAL;
	*dmamp = new bus_dmamap;
	(*dmamp)->cursor = IOMbufNaturalMemoryCursor::withSpecification(maxsegsz, nsegments);
    (*dmamp)->dm_maxsegs = nsegments;
    (*dmamp)->dm_mapsize = size;
    return (*dmamp)->cursor == NULL;
}

int bus_dmamem_alloc(bus_dma_tag_t tag, bus_size_t size, bus_size_t alignment, bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs, int flags)
{
    UInt64 ofs = 0;
    UInt32 numSegs = 1;
    IODMACommand::Segment64 seg;

    segs->bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache, size, DMA_BIT_MASK(36));
    if (segs->bmd == NULL) {
        XYLog("%s alloc DMA memory failed.\n", __FUNCTION__);
        return -ENOMEM;
    }
    segs->bmd->prepare();
    segs->cmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, alignment);
    if (segs->cmd == NULL) {
        XYLog("%s alloc IODMACommand memory failed.\n", __FUNCTION__);
        segs->bmd->complete();
        segs->bmd->release();
        segs->bmd = NULL;
        return -ENOMEM;
    }
    segs->cmd->setMemoryDescriptor(segs->bmd);
    if (segs->cmd->gen64IOVMSegments(&ofs, &seg, &numSegs) != kIOReturnSuccess) {
        segs->cmd->release();
        segs->cmd = NULL;
        segs->bmd->complete();
        segs->bmd->release();
        segs->bmd = NULL;
        return -ENOMEM;
    }
    segs->paddr = seg.fIOVMAddr;
    segs->vaddr = segs->bmd->getBytesNoCopy();
    segs->size = size;
    memset(segs->vaddr, 0, segs->size);
    *rsegs = numSegs;
    return 0;
}

int bus_dmamem_map(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs, size_t size, caddr_t *kvap, int flags)
{
    if (!kvap)
        return -EINVAL;
    memset(segs->vaddr, 0, segs->size);
    *kvap = (caddr_t)segs->vaddr;
	return 0;
}

void bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t dmam, bus_addr_t offset, bus_size_t len, int ops)
{
}

int bus_dmamap_unload(bus_dma_tag_t tag, bus_dmamap_t dmam)
{
    if (dmam->_loadCmd)
        dmam->_loadCmd->clearMemoryDescriptor();
    if (dmam->_loadDesc) {
        dmam->_loadDesc->complete();
        dmam->_loadDesc->release();
        dmam->_loadDesc = NULL;
    }
    return 0;
}

int bus_dmamem_unmap(bus_dma_tag_t tag, void *addr, int length)
{
    return 0;
}

void bus_dmamem_unmap(bus_dma_segment_t seg)
{
}

void bus_dmamem_free(bus_dma_tag_t tag, bus_dma_segment_t *dma, int nsegs)
{
	if (dma == NULL)
        return;
    if (dma->vaddr == NULL)
        return;
    if (dma->cmd) {
        dma->cmd->clearMemoryDescriptor();
        dma->cmd->release();
        dma->cmd = NULL;
    }
    if (dma->bmd) {
        dma->bmd->complete();
        dma->bmd->release();
        dma->bmd = NULL;
    }
    dma->vaddr = NULL;
}

void bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t dmam) {
	if (dmam == NULL)
		return;
    if (dmam->_loadCmd) {
        dmam->_loadCmd->release();
        dmam->_loadCmd = NULL;
    }
    if (dmam->_loadDesc) {
        dmam->_loadDesc->release();
        dmam->_loadDesc = NULL;
    }
	if (dmam->cursor == NULL)
		return;
	dmam->cursor->release();
	dmam->cursor = NULL;
	delete dmam;
}

int bus_dmamap_load_mbuf(bus_dma_tag_t tag, bus_dmamap_t dmam, mbuf_t m, int ops)
{
    if (dmam == NULL || m == NULL)
        return -EINVAL;
    if (ops & BUS_DMA_WRITE)
        dmam->dm_nsegs = dmam->cursor->getPhysicalSegmentsWithCoalesce(m, &dmam->dm_segs[0], dmam->dm_maxsegs);
    else
        dmam->dm_nsegs = dmam->cursor->getPhysicalSegments(m, &dmam->dm_segs[0], 1);
    return dmam->dm_nsegs == 0;
}

int bus_dmamap_load_raw(bus_dma_tag_t t, bus_dmamap_t map, bus_dma_segment_t *segs, int nsegs, bus_size_t size, int flags)
{
    if (map == NULL)
        return -EINVAL;
    map->dm_segs[0].location = segs->paddr;
    map->dm_segs[0].length = segs->size;
    return 0;
}

int bus_dmamap_load(bus_dma_tag_t tag, bus_dmamap_t dmam, void *addr, int size, struct proc *p, int ops)
{
    UInt64 ofs = 0;
    UInt32 numSegs = 1;
    if (dmam == NULL)
        return -EINVAL;
    dmam->_loadDesc = IOBufferMemoryDescriptor::withAddress(addr, size, kIODirectionInOut);
    if (dmam->_loadDesc == NULL) {
        XYLog("%s alloc DMA memory failed.\n", __FUNCTION__);
        return -ENOMEM;
    }
    dmam->_loadDesc->prepare();
    dmam->_loadCmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, 1);
    if (dmam->_loadCmd == NULL) {
        XYLog("%s alloc IODMACommand memory failed.\n", __FUNCTION__);
        dmam->_loadDesc->complete();
        dmam->_loadDesc->release();
        dmam->_loadDesc = NULL;
        return -ENOMEM;
    }
    dmam->_loadCmd->setMemoryDescriptor(dmam->_loadDesc);
    if (dmam->_loadCmd->genIOVMSegments(&ofs, &dmam->dm_segs[0], &numSegs) != kIOReturnSuccess) {
        dmam->_loadCmd->release();
        dmam->_loadCmd = NULL;
        dmam->_loadDesc->complete();
        dmam->_loadDesc->release();
        dmam->_loadDesc = NULL;
        return -ENOMEM;
    }
    dmam->dm_nsegs = numSegs;
    return 0;
}
