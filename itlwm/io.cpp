//
//  io.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

uint32_t itlwm::
iwm_read_prph(struct iwm_softc *sc, uint32_t addr)
{
    iwm_nic_assert_locked(sc);
    IWM_WRITE(sc,
        IWM_HBUS_TARG_PRPH_RADDR, ((addr & 0x000fffff) | (3 << 24)));
    IWM_BARRIER_READ_WRITE(sc);
    return IWM_READ(sc, IWM_HBUS_TARG_PRPH_RDAT);
}

void itlwm::
iwm_write_prph(struct iwm_softc *sc, uint32_t addr, uint32_t val)
{
    iwm_nic_assert_locked(sc);
    IWM_WRITE(sc,
        IWM_HBUS_TARG_PRPH_WADDR, ((addr & 0x000fffff) | (3 << 24)));
    IWM_BARRIER_WRITE(sc);
    IWM_WRITE(sc, IWM_HBUS_TARG_PRPH_WDAT, val);
}

int itlwm::
iwm_read_mem(struct iwm_softc *sc, uint32_t addr, void *buf, int dwords)
{
    int offs, err = 0;
    uint32_t *vals = (uint32_t*)buf;

    if (iwm_nic_lock(sc)) {
        IWM_WRITE(sc, IWM_HBUS_TARG_MEM_RADDR, addr);
        for (offs = 0; offs < dwords; offs++)
            vals[offs] = IWM_READ(sc, IWM_HBUS_TARG_MEM_RDAT);
        iwm_nic_unlock(sc);
    } else {
        err = EBUSY;
    }
    return err;
}

int itlwm::
iwm_write_mem(struct iwm_softc *sc, uint32_t addr, const void *buf, int dwords)
{
    int offs;
    const uint32_t *vals = (const uint32_t*)buf;

    if (iwm_nic_lock(sc)) {
        IWM_WRITE(sc, IWM_HBUS_TARG_MEM_WADDR, addr);
        /* WADDR auto-increments */
        for (offs = 0; offs < dwords; offs++) {
            uint32_t val = vals ? vals[offs] : 0;
            IWM_WRITE(sc, IWM_HBUS_TARG_MEM_WDAT, val);
        }
        iwm_nic_unlock(sc);
    } else {
        return EBUSY;
    }
    return 0;
}

int itlwm::
iwm_write_mem32(struct iwm_softc *sc, uint32_t addr, uint32_t val)
{
    return iwm_write_mem(sc, addr, &val, 1);
}

int itlwm::
iwm_poll_bit(struct iwm_softc *sc, int reg, uint32_t bits, uint32_t mask,
    int timo)
{
    for (;;) {
        if ((IWM_READ(sc, reg) & mask) == (bits & mask)) {
            return 1;
        }
        if (timo < 10) {
            return 0;
        }
        timo -= 10;
        DELAY(10);
    }
}

int itlwm::
iwm_nic_lock(struct iwm_softc *sc)
{
    if (sc->sc_nic_locks > 0) {
        iwm_nic_assert_locked(sc);
        sc->sc_nic_locks++;
        return 1; /* already locked */
    }

    IWM_SETBITS(sc, IWM_CSR_GP_CNTRL,
        IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000)
        DELAY(2);

    if (iwm_poll_bit(sc, IWM_CSR_GP_CNTRL,
        IWM_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
        IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY
         | IWM_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP, 150000)) {
        sc->sc_nic_locks++;
        return 1;
    }

    printf("%s: acquiring device failed\n", DEVNAME(sc));
    return 0;
}

void itlwm::
iwm_nic_assert_locked(struct iwm_softc *sc)
{
    uint32_t reg = IWM_READ(sc, IWM_CSR_GP_CNTRL);
    if ((reg & IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) == 0)
        panic("%s: mac clock not ready", DEVNAME(sc));
    if (reg & IWM_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP)
        panic("%s: mac gone to sleep", DEVNAME(sc));
    if (sc->sc_nic_locks <= 0)
        panic("%s: nic locks counter %d", DEVNAME(sc), sc->sc_nic_locks);
}

void itlwm::
iwm_nic_unlock(struct iwm_softc *sc)
{
    if (sc->sc_nic_locks > 0) {
        if (--sc->sc_nic_locks == 0)
            IWM_CLRBITS(sc, IWM_CSR_GP_CNTRL,
                IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    } else
        printf("%s: NIC already unlocked\n", DEVNAME(sc));
}

void itlwm::
iwm_set_bits_mask_prph(struct iwm_softc *sc, uint32_t reg, uint32_t bits,
    uint32_t mask)
{
    uint32_t val;

    /* XXX: no error path? */
    if (iwm_nic_lock(sc)) {
        val = iwm_read_prph(sc, reg) & mask;
        val |= bits;
        iwm_write_prph(sc, reg, val);
        iwm_nic_unlock(sc);
    }
}

void itlwm::
iwm_set_bits_prph(struct iwm_softc *sc, uint32_t reg, uint32_t bits)
{
    iwm_set_bits_mask_prph(sc, reg, bits, ~0);
}

void itlwm::
iwm_clear_bits_prph(struct iwm_softc *sc, uint32_t reg, uint32_t bits)
{
    iwm_set_bits_mask_prph(sc, reg, 0, ~bits);
}

IOBufferMemoryDescriptor* allocDmaMemory
( size_t size, int alignment, void** vaddr, uint32_t* paddr )
{
    size_t        reqsize;
    uint64_t    phymask;
    int        i;
    
    XYLog("Asked to allocate %u bytes with align=%u\n", size, alignment);
    
    if (alignment <= PAGE_SIZE) {
        reqsize = size;
        phymask = 0x00000000ffffffffull & (~(alignment - 1));
    } else {
        reqsize = size + alignment;
        phymask = 0x00000000fffff000ull; /* page-aligned */
    }
    
    IOBufferMemoryDescriptor* mem = 0;
    mem = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, kIOMemoryPhysicallyContiguous | kIODirectionInOut,
                                   reqsize, phymask);
    if (!mem) {
        IOLog("Could not allocate DMA memory\n");
        return 0;
    }
    mem->prepare();
    *paddr = mem->getPhysicalAddress();
    *vaddr = mem->getBytesNoCopy();
    
    XYLog("Got allocated at paddr=0x%x, vaddr=0x%x\n", *paddr, *vaddr);
    
    /*
     * Check the alignment and increment by 4096 until we get the
     * requested alignment. Fail if can't obtain the alignment
     * we requested.
     */
    if ((*paddr & (alignment - 1)) != 0) {
        for (i = 0; i < alignment / 4096; i++) {
            if ((*paddr & (alignment - 1 )) == 0)
                break;
            *paddr += 4096;
            *vaddr = ((uint8_t*) *vaddr) + 4096;
        }
        if (i == alignment / 4096) {
            XYLog("Memory alloc alignment requirement %d was not satisfied\n", alignment);
            mem->complete();
            mem->release();
            return 0;
        }
    }
    XYLog("Re-aligned DMA memory to paddr=0x%x, vaddr=0x%x\n", *paddr, *vaddr);
    return mem;
}

void itlwm::
iwm_dma_contig_free(struct iwm_dma_info *dma)
{
    if (dma == NULL)
        return;
    if (dma->vaddr == NULL)
        return;
    dma->buffer->complete();
    dma->buffer->release();
    dma->buffer = 0;
    dma->vaddr = 0;
    dma->paddr = 0;
    return;
}

int itlwm::
iwm_dma_contig_alloc(bus_dma_tag_t tag, struct iwm_dma_info *dma, void **kvap,
             bus_size_t size, bus_size_t alignment)
{
    dma->buffer = allocDmaMemory((size_t)size, (int)alignment, (void**)&dma->vaddr, (uint32_t*)&dma->paddr);
    if (dma->buffer == NULL)
        return 1;
    
    dma->size = size;
    if (kvap != NULL)
        *kvap = dma->vaddr;
    
    return 0;
}
