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

OSDefineMetaClassAndStructors(pci_intr_handle, OSObject)

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

int pci_intr_map_msi(struct pci_attach_args *paa, pci_intr_handle_t *ih) {
	if (paa == 0 || ih == 0)
		return 1;
	
	*ih = new pci_intr_handle();
	
	if (*ih == 0)
		return 1;
	
	(*ih)->dev = paa->pa_tag;  // pci device reference
	
	(*ih)->workloop = paa->workloop;
	
	return 0; // XXX not required on OS X
}

int pci_intr_map(struct pci_attach_args *paa, pci_intr_handle_t *ih) {
	return pci_intr_map_msi(paa, ih);
}

void interruptTrampoline(OSObject *ih, IOInterruptEventSource *, int count);
void interruptTrampoline(OSObject *ih, IOInterruptEventSource *, int count) {
	pci_intr_handle* _ih = OSDynamicCast(pci_intr_handle, ih);
	if (_ih == 0)
		return;
	_ih->func(_ih->arg); // jump to actual interrupt handler
}

void* pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*handler)(void *), void *arg) {
	ih->arg = arg;
	ih->intr = IOInterruptEventSource::interruptEventSource(ih, &interruptTrampoline, ih->dev);
	
	if (ih->intr == 0)
		return 0;
	if (ih->workloop->addEventSource(ih->intr) != kIOReturnSuccess)
		return 0;
	
	ih->intr->enable();
	return ih;
}

void pci_intr_disestablish(pci_chipset_tag_t pc, void *ih) {
	pci_intr_handle_t intr = (pci_intr_handle_t) ih;
	
	intr->workloop->removeEventSource(intr->intr);
	
	intr->intr->release();
	intr->intr = 0;
	
	intr->dev->release();
	intr->dev = 0;
	
	intr->workloop->release();
	intr->workloop = 0;
	
	intr->arg = 0;
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
		return 1;
	*dmamp = new bus_dmamap;
	(*dmamp)->cursor = IOMbufNaturalMemoryCursor::withSpecification(maxsegsz, nsegments);
	if ((*dmamp)->cursor == 0)
		return 1;
	else
		return 0;
}

IOBufferMemoryDescriptor* alloc_dma_memory(size_t size, mach_vm_address_t alignment,/* void** vaddr, mach_vm_address_t* paddr, */IOOptionBits opts);
IOBufferMemoryDescriptor* alloc_dma_memory(size_t size, mach_vm_address_t alignment,/* void** vaddr, mach_vm_address_t* paddr, */IOOptionBits opts = kIOMemoryPhysicallyContiguous | kIOMapInhibitCache)
{
	size_t		reqsize;
	uint64_t	phymask;
	int		i;
	/*
	if (alignment <= PAGE_SIZE) {
		reqsize = size;
		phymask = 0x00000000ffffffffull & (~(alignment - 1));
	} else {
		reqsize = size + alignment;
		phymask = 0x00000000fffff000ull; /* page-aligned 
	}*/
	
	phymask = 0x00000000ffffffffull & (~(alignment - 1));
	reqsize = size;
	
	IOBufferMemoryDescriptor* mem = 0;
	mem = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, opts, reqsize, phymask);
	if (!mem)
		return 0;

	mem->prepare();
	/*
	if (paddr)
		*paddr = mem->getPhysicalAddress();
	if (vaddr)
		*vaddr = mem->getBytesNoCopy();
	
	/*
	 * Check the alignment and increment by 4096 until we get the
	 * requested alignment. Fail if can't obtain the alignment
	 * we requested.
	 
	if ((*paddr & (alignment - 1)) != 0) {
		for (i = 0; i < alignment / 4096; i++) {
			if ((*paddr & (alignment - 1 )) == 0)
				break;
			*paddr += 4096;
			*vaddr = ((uint8_t*) *vaddr) + 4096;
		}
		if (i == alignment / 4096) {
			mem->complete();
			mem->release();
			return 0;
		}
	}*/
	return mem;
}


int bus_dmamem_alloc(bus_dma_tag_t tag, bus_size_t size, bus_size_t alignment, bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs, int flags) {
	// Ignore flags and don't pass in the number of segments, it's not used in the driver (always 1 anyway)
	if (segs == 0)
		return 1;
	*segs = alloc_dma_memory(size, alignment);
	if (*segs == 0)
		return 1;
	else
		return 0;
}

int bus_dmamem_map(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs, size_t size, void **kvap, int flags) {
	// ignore flags, the memory is already mapped as one segment by the call to bus_dmamem_alloc so just return the virtual address
	if (*segs == 0 || kvap == 0)
		return 1;
	*kvap = (*segs)->getBytesNoCopy();
	return 0;
}

bus_addr_t bus_dmamap_get_paddr(bus_dma_segment_t seg) {
	if (seg == 0)
		return 0;
	else
		return seg->getPhysicalAddress();
}

void bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t dmam, bus_addr_t offset, bus_size_t len, int ops) {
	return; // no syncing, we mapped the memory with cache inhibition so pray it works
}

void bus_dmamem_unmap(bus_dma_segment_t seg) {
	if (seg == 0)
		return;
	seg->complete();
}

void bus_dmamem_free(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs) {
	if (segs == 0)
		return;
	if (*segs == 0)
		return;
	(*segs)->release();
	*segs = 0;
}

void bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t dmam) {
	if (dmam == 0)
		return;
	if (dmam->cursor == 0)
		return;
	dmam->cursor->release();
	dmam->cursor = 0;
	delete dmam;
}

int bus_dmamap_load(bus_dmamap_t map, mbuf_t mb) {
	if (map == 0 || mb == 0)
		return 1;
	map->dm_nsegs = map->cursor->getPhysicalSegmentsWithCoalesce(mb, map->dm_segs, 1);
	if (map->dm_nsegs == 0)
		return 1;
	else
		return 0;
}
