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
#define BUS_DMA_NOWAIT		1
#define BUS_DMA_ZERO		2
#define BUS_DMA_COHERENT	4
#define BUS_DMA_READ		8
#define BUS_DMA_WRITE       10
#define BUS_DMA_ALLOCNOW    20

#define M_DEVBUF    0

#define pci_intr_string(x, y)   "MSI"

#define SIMPLEQ_ENTRY   STAILQ_ENTRY
#define SIMPLEQ_HEAD    STAILQ_HEAD
#define SIMPLEQ_FIRST   STAILQ_FIRST
#define SIMPLEQ_REMOVE_HEAD STAILQ_REMOVE_HEAD
#define SIMPLEQ_INSERT_TAIL STAILQ_INSERT_TAIL
#define SIMPLEQ_INIT    STAILQ_INIT
#define SIMPLEQ_EMPTY   STAILQ_EMPTY
#define SIMPLEQ_NEXT    STAILQ_NEXT

#ifdef DELAY
#undef DELAY
#define DELAY(x) IODelay(x)
#endif

#define __predict_false(x)  (x)
#define __predict_true(x)   (x)

#define MUL_NO_OVERFLOW    (1UL << (sizeof(size_t) * 4))

#define    M_CANFAIL    0x0004
static inline void *
mallocarray(size_t nmemb, size_t size, int type, int flags)
{
    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        nmemb > 0 && SIZE_MAX / nmemb < size) {
        if (flags & M_CANFAIL)
            return (NULL);
        panic("mallocarray: overflow %zu * %zu", nmemb, size);
    }
    return (malloc(size * nmemb, type, flags));
}

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

extern int tsleep_nsec(void *ident, int priority, const char *wmesg, int timo);

extern void wakeupOn(void *chan);

extern void wakeup_oneOn(void *chan);

#define wakeup(x) wakeupOn(x)
#define wakeup_one(x) wakeup_oneOn(x)

#define MHLEN mbuf_get_mhlen()
#define M_DONTWAIT MBUF_DONTWAIT
#define M_EXT MBUF_EXT
#define m_freem mbuf_freem
#define m_free mbuf_free
#define m_copydata mbuf_copydata
#define m_adj   mbuf_adj
#define MGETHDR(m, how, type)   mbuf_gethdr((how), (type), &(m))
#define MCLGET(m, how)          mbuf_mclget((how), MBUF_TYPE_DATA, &(m))
#define MCLGETL(m, how, len)    mcl_get((m), (how), (len))

static inline mbuf_t
m_makespace(mbuf_t m0, int skip, int hlen, int *off)
{
    mbuf_t m;
    unsigned remain;

    for (m = m0; m && skip > mbuf_len(m); m = mbuf_next(m))
        skip -= mbuf_len(m);
    if (m == NULL)
        return (NULL);
    /*
     * At this point skip is the offset into the mbuf m
     * where the new header should be placed.  Figure out
     * if there's space to insert the new header.  If so,
     * and copying the remainder makes sense then do so.
     * Otherwise insert a new mbuf in the chain, splitting
     * the contents of m as needed.
     */
    remain = mbuf_len(m) - skip;        /* data to move */
    if (skip < remain && hlen <= mbuf_leadingspace(m)) {
        if (skip)
            memmove((uint8_t *)mbuf_data(m)-hlen, mbuf_data(m), skip);
        int len = mbuf_len(m) + hlen;
        mbuf_setdata(m, (uint8_t *)mbuf_data(m) - hlen, len);
        mbuf_setlen(m, len);
        *off = skip;
    } else if (hlen > mbuf_trailingspace(m)) {
        return (NULL);
    } else {
        /*
         * Copy the remainder to the back of the mbuf
         * so there's space to write the new header.
         */
        if (remain > 0)
            memmove(mtod(m, caddr_t) + skip + hlen,
                  mtod(m, caddr_t) + skip, remain);
        mbuf_setlen(m, mbuf_len(m) + hlen);
        *off = skip;
    }
    mbuf_pkthdr_setlen(m0, mbuf_pkthdr_len(m0) + hlen);        /* adjust packet length */
    return m;
}

static inline mbuf_t
mcl_get(mbuf_t m, mbuf_how_t how, size_t size)
{
    size_t real_size;
    if (!m) {
        mbuf_gethdr(how, MBUF_TYPE_DATA, &m);
        if (!m)
            return NULL;
    }
    if (size <= MCLBYTES) {
        mbuf_mclget(how, MBUF_TYPE_DATA, &m);
        real_size = MCLBYTES;
    } else if (size <= MBIGCLBYTES) {
        mbuf_getcluster(how, MBUF_TYPE_DATA, MBIGCLBYTES, &m);
        real_size = MBIGCLBYTES;
    } else {
        mbuf_freem(m);
        return NULL;
    }
    if (!(mbuf_flags(m) & MBUF_EXT)) {
        mbuf_freem(m);
        return NULL;
    }
    mbuf_setlen(m, real_size);
    mbuf_pkthdr_setlen(m, real_size);
    return m;
}

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

typedef int                bus_dma_tag_t;
typedef struct {
    IOBufferMemoryDescriptor  *bmd;
    IODMACommand *cmd;
    size_t size;
    mach_vm_address_t paddr;
    void *vaddr;
} bus_dma_segment_t;
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
	int (*func)(void* arg);
	void* arg;
    bool msi;
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
    IOMemoryDescriptor *_loadDesc;
    IODMACommand    *_loadCmd;
	IOMbufNaturalMemoryCursor*	cursor;
	int				dm_nsegs;
    int             dm_mapsize;
    int             dm_maxsegs;
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
int     bus_space_unmap(bus_space_tag_t tag, bus_space_handle_t handle, bus_size_t size);
int     pci_intr_map_msix(struct pci_attach_args *pa, int vec, pci_intr_handle_t *ihp);
int		pci_intr_map_msi(struct pci_attach_args *paa, pci_intr_handle_t *ih);
int		pci_intr_map(struct pci_attach_args *paa, pci_intr_handle_t *ih);
void*		pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*handler)(void *), void *arg, const char *name);
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
void		bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t dmam, bus_addr_t offset, bus_size_t len, int ops);
void		bus_dmamem_unmap(bus_dma_segment_t seg); // XXX changed args
void		bus_dmamem_free(bus_dma_tag_t tag, bus_dma_segment_t *segs, int nsegs);
void		bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t dmam);
int     bus_dmamap_unload(bus_dma_tag_t tag, bus_dmamap_t dmam);
int     bus_dmamem_unmap(bus_dma_tag_t tag, void *addr, int length);
int     bus_dmamap_load_mbuf(bus_dma_tag_t tag, bus_dmamap_t dmam, mbuf_t m, int ops);
int     bus_dmamap_load(bus_dma_tag_t tag, bus_dmamap_t dmam, void *addr, int size, struct proc *p, int ops);
int     bus_dmamap_load_raw(bus_dma_tag_t t, bus_dmamap_t map, bus_dma_segment_t *segs, int nsegs, bus_size_t size, int flags);
int     bus_dmamem_map(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs, size_t size, caddr_t *kvap, int flags);

#endif
