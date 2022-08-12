//
//  athnhdr.h
//  itlwm
//
//  Created by qcwap on 2022/8/11.
//  Copyright © 2022 钟先耀. All rights reserved.
//

#ifndef athnhdr_h
#define athnhdr_h

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/timeout.h>
//#include <sys/device.h>

//#include <machine/bus.h>
//#include <machine/intr.h>

#include <net/if.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_amrr.h>
#include <net80211/ieee80211_ra.h>
#include <net80211/ieee80211_radiotap.h>

#include "athnreg.h"
#include "athnvar.h"

#include "pcireg.h"

struct athn_pci_softc {
    struct athn_softc    sc_sc;

    /* PCI specific goo. */
    pci_chipset_tag_t    sc_pc;
    pcitag_t        sc_tag;
    void            *sc_ih;
    bus_space_tag_t        sc_st;
    bus_space_handle_t    sc_sh;
    bus_size_t        sc_mapsize;
    int            sc_cap_off;
};

int        athn_pci_match(IOPCIDevice *);
int        athn_pci_detach(struct device *, int);
int        athn_pci_activate(struct device *, int);
void        athn_pci_wakeup(struct athn_pci_softc *);
static uint32_t    athn_pci_read(struct athn_softc *, uint32_t);
void        athn_pci_write(struct athn_softc *, uint32_t, uint32_t);
void        athn_pci_write_barrier(struct athn_softc *);
void        athn_pci_disable_aspm(struct athn_softc *);

#endif /* athnhdr_h */
