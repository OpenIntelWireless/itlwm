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
//  compat.h
//  net80211
//
//  Copyright (c) 2012 Prashant Vaibhav. All rights reserved.
//

#ifndef net80211_compat_h
#define net80211_compat_h

// BSD compatibility definitions

#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/kpi_mbuf.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_mira.h>
#include <net80211/ieee80211_amrr.h>
#include <sys/pcireg.h>

// the following isn't actually used
#define BUS_SPACE_BARRIER_READ	0
#define BUS_SPACE_BARRIER_WRITE	0
#define BUS_DMA_NOWAIT		0
#define BUS_DMA_ZERO		0
#define BUS_DMA_COHERENT	0
#define BUS_DMA_READ		0

static inline void
USEC_TO_TIMEVAL(uint64_t us, struct timeval *tv)
{
    tv->tv_sec = us / 1000000;
    tv->tv_usec = us % 1000000;
}

static inline void
NSEC_TO_TIMEVAL(uint64_t ns, struct timeval *tv)
{
    tv->tv_sec = ns / 1000000000L;
    tv->tv_usec = (ns % 1000000000L) / 1000;
}

static inline uint64_t
TIMEVAL_TO_NSEC(const struct timeval *tv)
{
    uint64_t nsecs;

    if (tv->tv_sec > UINT64_MAX / 1000000000ULL)
        return UINT64_MAX;
    nsecs = tv->tv_sec * 1000000000ULL;
    if (tv->tv_usec * 1000ULL > UINT64_MAX - nsecs)
        return UINT64_MAX;
    return nsecs + tv->tv_usec * 1000ULL;
}

static inline void
NSEC_TO_TIMESPEC(uint64_t ns, struct timespec *ts)
{
    ts->tv_sec = ns / 1000000000L;
    ts->tv_nsec = ns % 1000000000L;
}

static inline uint64_t
SEC_TO_NSEC(uint64_t seconds)
{
    if (seconds > UINT64_MAX / 1000000000ULL)
        return UINT64_MAX;
    return seconds * 1000000000ULL;
}

static inline uint64_t
MSEC_TO_NSEC(uint64_t milliseconds)
{
    if (milliseconds > UINT64_MAX / 1000000ULL)
        return UINT64_MAX;
    return milliseconds * 1000000ULL;
}

static inline uint64_t
USEC_TO_NSEC(uint64_t microseconds)
{
    if (microseconds > UINT64_MAX / 1000ULL)
        return UINT64_MAX;
    return microseconds * 1000ULL;
}

static inline uint64_t
TIMESPEC_TO_NSEC(const struct timespec *ts)
{
    if (ts->tv_sec > (UINT64_MAX - ts->tv_nsec) / 1000000000ULL)
        return UINT64_MAX;
    return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

#define MHLEN mbuf_get_mhlen()
#define M_DONTWAIT MBUF_DONTWAIT
#define M_EXT MBUF_EXT
#define m_freem mbuf_freem
#define m_free mbuf_free
#define m_copydata mbuf_copydata

static inline int
flsl(long mask)
{
    int bit;

    if (mask == 0)
        return (0);
    for (bit = 1; mask != 1; bit++)
        mask = (unsigned long)mask >> 1;
    return (bit);
}

/*
 * Find Last Set bit
 */
static inline int
_fls(int mask)
{
    int bit;

    if (mask == 0)
        return (0);
    for (bit = 1; mask != 1; bit++)
        mask = (unsigned int)mask >> 1;
    return (bit);
}

enum {
	BUS_DMASYNC_PREREAD,
	BUS_DMASYNC_PREWRITE,
	BUS_DMASYNC_POSTREAD,
	BUS_DMASYNC_POSTWRITE
};

typedef int				bus_dma_tag_t;
typedef IOBufferMemoryDescriptor*	bus_dma_segment_t;
typedef caddr_t				bus_space_handle_t; // pointer to device memory
typedef int				pci_chipset_tag_t;
typedef mach_vm_address_t		bus_addr_t;
typedef u_int32_t			bus_size_t;
typedef IOMemoryMap*			bus_space_tag_t;
typedef IOPCIDevice*			pcitag_t;
typedef uint32_t			pcireg_t;

class pci_intr_handle : public OSObject {
	OSDeclareDefaultStructors(pci_intr_handle)
public:
	IOWorkLoop*		workloop;
	IOInterruptEventSource*	intr;
	IOPCIDevice*		dev;
	void (*func)(void* arg);
	void* arg;
};
typedef pci_intr_handle* pci_intr_handle_t;

/*
 * Actions for ca_activate.
 */
#define    DVACT_DEACTIVATE    1    /* deactivate the device */
#define    DVACT_QUIESCE        2    /* warn the device about suspend */
#define    DVACT_SUSPEND        3    /* suspend the device */
#define    DVACT_RESUME        4    /* resume the device */
#define    DVACT_WAKEUP        5    /* tell device to recover after resume */
#define    DVACT_POWERDOWN        6    /* power device down */

struct device {
    IOService *provider;
    void *_data;
	char dv_xname[16];
};

struct workq_task {
	int blah;
};

struct pci_attach_args {
	IOWorkLoop*		workloop;
	pci_chipset_tag_t	pa_pc;
	pcitag_t		pa_tag;
	bus_dma_tag_t		pa_dmat;
};

struct bus_dmamap {
	IOMbufNaturalMemoryCursor*	cursor;
	int				dm_nsegs;
	IOPhysicalSegment		dm_segs[23]; // reserve space for 8 segments
};
typedef struct bus_dmamap* bus_dmamap_t;

/* max bufs per tfd the driver will use */
#define IWM_MAX_CMD_TBS_PER_TFD 2

#define IWM_TX_RING_COUNT    256
#define IWM_TX_RING_LOMARK    192
#define IWM_TX_RING_HIMARK    224

struct pci_matchid {
    int     pm_vid;
    int     pm_pid;
    int     pm_sub_dev;
    int     pm_sub_vid;
    void    *drv_data;
};

#define PCI_ANY_ID 0xffff

static inline int
pci_matchbyid(int vid, int pid, const struct pci_matchid *ids, int nent)
{
    const struct pci_matchid *pm;
    int i;

    for (i = 0, pm = ids; i < nent; i++, pm++)
        if (vid == pm->pm_vid &&
            pid == pm->pm_pid)
            return (1);
    return (0);
}

static inline int
pci_match(int vid, int pid, int sub_vid, int sub_dev, const struct pci_matchid *ids, int nent, void **drv_data)
{
    const struct pci_matchid *pm;
    int i;

    for (i = 0, pm = ids; i < nent; i++, pm++) {
        if (vid == pm->pm_vid && pid == pm->pm_pid) {
            if (pm->pm_sub_dev != PCI_ANY_ID && sub_dev != pm->pm_sub_dev) {
                return 0;
            }
            if (pm->pm_sub_vid != PCI_ANY_ID && sub_vid != pm->pm_sub_vid) {
                return 0;
            }
            if (drv_data) {
                *drv_data = pm->drv_data;
            }
            return 1;
        }
    }
    return 0;
}

/*
 * DMA glue is from iwn
 */

char*		ether_sprintf(const u_char *ap);
int		pci_get_capability(pci_chipset_tag_t chipsettag, pcitag_t pcitag, int capid, int *offsetp, pcireg_t *valuep);
pcireg_t	pci_conf_read(pci_chipset_tag_t pc, pcitag_t tag, int reg);
void		pci_conf_write(pci_chipset_tag_t pc, pcitag_t tag, int reg, pcireg_t val);
pcireg_t	pci_mapreg_type(pci_chipset_tag_t pc, pcitag_t tag, int reg);
int		pci_mapreg_map(const struct pci_attach_args *pa, int reg, pcireg_t type, int busflags, bus_space_tag_t *tagp,
			       bus_space_handle_t *handlep, bus_addr_t *basep, bus_size_t *sizep, bus_size_t maxsize);
int     pci_intr_map_msix(struct pci_attach_args *pa, int vec, pci_intr_handle_t *ihp);
int		pci_intr_map_msi(struct pci_attach_args *paa, pci_intr_handle_t *ih);
int		pci_intr_map(struct pci_attach_args *paa, pci_intr_handle_t *ih);
void*		pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*handler)(void *), void *arg);
void		pci_intr_disestablish(pci_chipset_tag_t pc, void *ih);

uint64_t    bus_space_read_8(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset);
void        bus_space_write_8(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint64_t value);
uint32_t	bus_space_read_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset);
void		bus_space_write_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint32_t value);
void bus_space_write_1(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint8_t value);
void		bus_space_barrier(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, bus_size_t length, int flags);

int		bus_dmamap_create(bus_dma_tag_t tag, bus_size_t size, int nsegments, bus_size_t maxsegsz, bus_size_t boundary, int flags, bus_dmamap_t *dmamp);
int		bus_dmamem_alloc(bus_dma_tag_t tag, bus_size_t size, bus_size_t alignment, bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs, int flags);
int		bus_dmamem_map(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs, size_t size, void **kvap, int flags);
bus_addr_t	bus_dmamap_get_paddr(bus_dma_segment_t seg); // XXX new
void		bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t dmam, bus_addr_t offset, bus_size_t len, int ops);
void		bus_dmamem_unmap(bus_dma_segment_t seg); // XXX changed args
void		bus_dmamem_free(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs);
void		bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t dmam);
int		bus_dmamap_load(bus_dmamap_t map, mbuf_t m);
#define bus_dmamap_load_mbuf bus_dmamap_load

#endif
