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
#include "ieee80211_var.h"
#include "ieee80211_mira.h"
#include "ieee80211_amrr.h"

#define PCI_CAP_PCIEXPRESS	kIOPCIPCIExpressCapability
#define PCI_MAPREG_START	kIOPCIConfigBaseAddress0
#define PCI_PCIE_LCSR		0x10		// from BSD
#define PCI_PCIE_LCSR_ASPM_L0S	0x00000001	// from BSD

#define IPL_NET			0 // XXX not used
// the following isn't actually used
#define BUS_SPACE_BARRIER_READ	0
#define BUS_SPACE_BARRIER_WRITE	0
#define BUS_DMA_NOWAIT		0
#define BUS_DMA_ZERO		0
#define BUS_DMA_COHERENT	0
#define BUS_DMA_READ		0

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
typedef uint32_t			bus_size_t;
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
	IOMbufLittleMemoryCursor*	cursor;
	int				dm_nsegs;
	IOPhysicalSegment		dm_segs[8]; // reserve space for 8 segments
};
typedef struct bus_dmamap* bus_dmamap_t;

/* max bufs per tfd the driver will use */
#define IWM_MAX_CMD_TBS_PER_TFD 2

#define IWM_TX_RING_COUNT    256
#define IWM_TX_RING_LOMARK    192
#define IWM_TX_RING_HIMARK    224

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
int		pci_intr_map_msi(struct pci_attach_args *paa, pci_intr_handle_t *ih);
int		pci_intr_map(struct pci_attach_args *paa, pci_intr_handle_t *ih);
void*		pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*handler)(void *), void *arg);
void		pci_intr_disestablish(pci_chipset_tag_t pc, void *ih);

uint32_t	bus_space_read_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset);
void		bus_space_write_4(bus_space_tag_t space, bus_space_handle_t handle, bus_size_t offset, uint32_t value);
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
