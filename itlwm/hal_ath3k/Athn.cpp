//
//  Athn.cpp
//  itlwm
//
//  Created by qcwap on 2022/8/11.
//  Copyright © 2022 钟先耀. All rights reserved.
//

#include "Athn.hpp"

#define super ItlHalService
OSDefineMetaClassAndStructors(Athn, ItlHalService)

void Athn::
detach(IOPCIDevice *device)
{
    struct _ifnet *ifp = &com.sc_sc.sc_ic.ic_ac.ac_if;
    struct athn_pci_softc *sc = &com;
    
//    for (int txq_i = 0; txq_i < nitems(sc->txq); txq_i++)
//        iwm_free_tx_ring(sc, &sc->txq[txq_i]);
//    iwm_free_rx_ring(sc, &sc->rxq);
//    iwm_dma_contig_free(&sc->ict_dma);
//    iwm_dma_contig_free(&sc->kw_dma);
//    iwm_dma_contig_free(&sc->sched_dma);
//    iwm_dma_contig_free(&sc->fw_dma);
    athn_pci_detach((struct device *)sc, 0);
    ieee80211_ifdetach(ifp);
    taskq_destroy(systq);
//    taskq_destroy(com.sc_nswq);
    releaseAll();
}

bool Athn::
attach(IOPCIDevice *device)
{
    pci.pa_tag = device;
    pci.workloop = getMainWorkLoop();
    if (!athn_pci_attach(NULL, (struct device *)&com, &pci)) {
        detach(device);
        releaseAll();
        return false;
    }
    return true;
}

void Athn::
free()
{
    XYLog("%s\n", __FUNCTION__);
    super::free();
}

void Athn::
releaseAll()
{
    XYLog("%s\n", __FUNCTION__);
    if (com.sc_sc.scan_to) {
        timeout_del(&com.sc_sc.scan_to);
        timeout_free(&com.sc_sc.scan_to);
    }
    if (com.sc_sc.calib_to) {
        timeout_del(&com.sc_sc.calib_to);
        timeout_free(&com.sc_sc.calib_to);
    }
    pci.pa_tag = NULL;
    pci.workloop = NULL;
}

IOReturn Athn::
enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &com.sc_sc.sc_ic.ic_ac.ac_if;
    if (ifp->if_flags & IFF_UP) {
        XYLog("%s already in activating state\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    ifp->if_flags |= IFF_UP;
    athn_pci_activate((struct device *)&com, DVACT_RESUME);
    athn_pci_activate((struct device *)&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn Athn::
disable(IONetworkInterface *netif)
{
    struct _ifnet *ifp = &com.sc_sc.sc_ic.ic_ac.ac_if;
    ifp->if_flags &= ~IFF_UP;
    athn_pci_activate((struct device *)&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

struct ieee80211com *Athn::
get80211Controller()
{
    return &com.sc_sc.sc_ic;
}

ItlDriverInfo *Athn::
getDriverInfo()
{
    return this;
}

ItlDriverController *Athn::
getDriverController()
{
    return this;
}

void Athn::
clearScanningFlags()
{
}

IOReturn Athn::
setMulticastList(IOEthernetAddress *addr, int count)
{
    return kIOReturnError;
}

const char *Athn::
getFirmwareVersion()
{
    return "";
}

const char *Athn::
getFirmwareName()
{
    return "";
}

UInt32 Athn::
supportedFeatures()
{
    return kIONetworkFeatureMultiPages;
}

const char *Athn::
getFirmwareCountryCode()
{
    return "";
}

uint32_t Athn::
getTxQueueSize()
{
    return 2048;
}

int16_t Athn::
getBSSNoise()
{
    return 0;
}

bool Athn::
is5GBandSupport()
{
    return false;
}

int Athn::
getTxNSS()
{
    return 1;
}

#define PCI_SUBSYSID_ATHEROS_COEX2WIRE        0x309b
#define PCI_SUBSYSID_ATHEROS_COEX3WIRE_SA    0x30aa
#define PCI_SUBSYSID_ATHEROS_COEX3WIRE_DA    0x30ab
#define    PCI_VENDOR_ATHEROS    0x168c        /* Atheros */
#define    PCI_VENDOR_3COM    0x10b7        /* 3Com */
#define    PCI_VENDOR_3COM2    0xa727        /* 3Com */

/* Atheros products */
#define    PCI_PRODUCT_ATHEROS_AR5210    0x0007        /* AR5210 */
#define    PCI_PRODUCT_ATHEROS_AR5311    0x0011        /* AR5311 */
#define    PCI_PRODUCT_ATHEROS_AR5211    0x0012        /* AR5211 */
#define    PCI_PRODUCT_ATHEROS_AR5212    0x0013        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_2    0x0014        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_3    0x0015        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_4    0x0016        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_5    0x0017        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_6    0x0018        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_7    0x0019        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR2413    0x001a        /* AR2413 */
#define    PCI_PRODUCT_ATHEROS_AR5413    0x001b        /* AR5413 */
#define    PCI_PRODUCT_ATHEROS_AR5424    0x001c        /* AR5424 */
#define    PCI_PRODUCT_ATHEROS_AR2417    0x001d        /* AR2417 */
#define    PCI_PRODUCT_ATHEROS_AR5416    0x0023        /* AR5416 */
#define    PCI_PRODUCT_ATHEROS_AR5418    0x0024        /* AR5418 */
#define    PCI_PRODUCT_ATHEROS_AR9160    0x0027        /* AR9160 */
#define    PCI_PRODUCT_ATHEROS_AR9280    0x0029        /* AR9280 */
#define    PCI_PRODUCT_ATHEROS_AR9281    0x002a        /* AR9281 */
#define    PCI_PRODUCT_ATHEROS_AR9285    0x002b        /* AR9285 */
#define    PCI_PRODUCT_ATHEROS_AR2427    0x002c        /* AR2427 */
#define    PCI_PRODUCT_ATHEROS_AR9227    0x002d        /* AR9227 */
#define    PCI_PRODUCT_ATHEROS_AR9287    0x002e        /* AR9287 */
#define    PCI_PRODUCT_ATHEROS_AR9300    0x0030        /* AR9300 */
#define    PCI_PRODUCT_ATHEROS_AR9485    0x0032        /* AR9485 */
#define    PCI_PRODUCT_ATHEROS_AR9462    0x0034        /* AR9462 */
#define    PCI_PRODUCT_ATHEROS_AR9565    0x0036        /* AR9565 */
#define    PCI_PRODUCT_ATHEROS_QCA988X    0x003c        /* QCA986x/988x */
#define    PCI_PRODUCT_ATHEROS_QCA6174    0x003e        /* QCA6174 */
#define    PCI_PRODUCT_ATHEROS_QCA6164    0x0041        /* QCA6164 */
#define    PCI_PRODUCT_ATHEROS_QCA9377    0x0042        /* QCA9377 */
#define    PCI_PRODUCT_ATHEROS_AR5210_AP    0x0207        /* AR5210 */
#define    PCI_PRODUCT_ATHEROS_AR5212_IBM    0x1014        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5210_DEFAULT    0x1107        /* AR5210 */
#define    PCI_PRODUCT_ATHEROS_AR5211_DEFAULT    0x1112        /* AR5211 */
#define    PCI_PRODUCT_ATHEROS_AR5212_DEFAULT    0x1113        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5212_FPGA    0xf013        /* AR5212 */
#define    PCI_PRODUCT_ATHEROS_AR5211_FPGA11B    0xf11b        /* AR5211Ref */
#define    PCI_PRODUCT_ATHEROS_AR5211_LEGACY    0xff12        /* AR5211Ref */
#define    PCI_PRODUCT_3COM_3CRDAG675    0x0013        /* 3CRDAG675 */
#define    PCI_PRODUCT_3COM2_3CRPAG175    0x0013        /* 3CRPAG175 */

static const struct pci_matchid athn_pci_devices[] = {
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR5416 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR5418 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9160 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9280 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9281 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9285 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR2427 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9227 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9287 },
    
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9300 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9485 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9462 },
    { PCI_VENDOR_ATHEROS, PCI_PRODUCT_ATHEROS_AR9565 }
};

int 
athn_pci_match(IOPCIDevice *device)
{
    int vendorId = device->configRead16(kIOPCIConfigVendorID);
    int devId = device->configRead16(kIOPCIConfigDeviceID);
    return (pci_matchbyid(vendorId, devId, athn_pci_devices,
        nitems(athn_pci_devices)));
}

bool Athn::
athn_pci_attach(struct device *parent, struct device *self, void *aux)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)self;
    struct athn_softc *sc = &psc->sc_sc;
    struct pci_attach_args *pa = (struct pci_attach_args *)aux;
    const char *intrstr;
    pci_intr_handle_t ih;
    pcireg_t memtype, reg;
    pci_product_id_t subsysid;
    int error;

    sc->sc_dmat = pa->pa_dmat;
    psc->sc_pc = pa->pa_pc;
    psc->sc_tag = pa->pa_tag;

    sc->ops.read = athn_pci_read;
    sc->ops.write = athn_pci_write;
    sc->ops.write_barrier = athn_pci_write_barrier;

    /*
     * Get the offset of the PCI Express Capability Structure in PCI
     * Configuration Space (Linux hardcodes it as 0x60.)
     */
    error = pci_get_capability(pa->pa_pc, pa->pa_tag, PCI_CAP_PCIEXPRESS,
        &psc->sc_cap_off, NULL);
    if (error != 0) {    /* Found. */
        sc->sc_disable_aspm = athn_pci_disable_aspm;
        sc->flags |= ATHN_FLAG_PCIE;
    }
    /* 
     * Clear device-specific "PCI retry timeout" register (41h) to prevent
     * PCI Tx retries from interfering with C3 CPU state.
     */
    reg = pci_conf_read(pa->pa_pc, pa->pa_tag, 0x40);
    if (reg & 0xff00)
        pci_conf_write(pa->pa_pc, pa->pa_tag, 0x40, reg & ~0xff00);

    /* 
     * Set the cache line size to a reasonable value if it is 0.
     * Change latency timer; default value yields poor results.
     */
    reg = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_BHLC_REG);
    if (PCI_CACHELINE(reg) == 0) {
        reg &= ~(PCI_CACHELINE_MASK << PCI_CACHELINE_SHIFT);
        reg |= 8 << PCI_CACHELINE_SHIFT;
    }
    reg &= ~(PCI_LATTIMER_MASK << PCI_LATTIMER_SHIFT);
    reg |= 168 << PCI_LATTIMER_SHIFT;
    pci_conf_write(pa->pa_pc, pa->pa_tag, PCI_BHLC_REG, reg);

    /* Determine if bluetooth is also supported (combo chip.) */
    reg = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_SUBSYS_ID_REG);
    subsysid = PCI_PRODUCT(reg);
    if (subsysid == PCI_SUBSYSID_ATHEROS_COEX3WIRE_SA ||
        subsysid == PCI_SUBSYSID_ATHEROS_COEX3WIRE_DA)
        sc->flags |= ATHN_FLAG_BTCOEX3WIRE;
    else if (subsysid == PCI_SUBSYSID_ATHEROS_COEX2WIRE)
        sc->flags |= ATHN_FLAG_BTCOEX2WIRE;

    /* Map control/status registers. */
    memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_MAPREG_START);
    error = pci_mapreg_map(pa, PCI_MAPREG_START, memtype, 0, &psc->sc_st,
        &psc->sc_sh, NULL, &psc->sc_mapsize, 0);
    if (error != 0) {
        printf(": can't map mem space\n");
        return false;
    }

    if (pci_intr_map(pa, &ih) != 0) {
        printf(": can't map interrupt\n");
        return false;
    }
    intrstr = pci_intr_string(psc->sc_pc, ih);
    psc->sc_ih = pci_intr_establish(psc->sc_pc, ih, IPL_NET,
        athn_intr, sc, sc->sc_dev.dv_xname);
    if (psc->sc_ih == NULL) {
        printf(": can't establish interrupt");
        if (intrstr != NULL)
            printf(" at %s", intrstr);
        printf("\n");
        return false;
    }
    printf(": %s\n", intrstr);

    sc->sc_ic.ic_ac.ac_if.controller = getController();
    return athn_attach(sc) == 0;
}

int
athn_pci_detach(struct device *self, int flags)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)self;
    struct athn_softc *sc = &psc->sc_sc;

    if (psc->sc_ih != NULL) {
        athn_detach(sc);
        pci_intr_disestablish(psc->sc_pc, psc->sc_ih);
    }
    if (psc->sc_mapsize > 0)
        bus_space_unmap(psc->sc_st, psc->sc_sh, psc->sc_mapsize);

    return (0);
}

int
athn_pci_activate(struct device *self, int act)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)self;
    struct athn_softc *sc = &psc->sc_sc;

    switch (act) {
    case DVACT_QUIESCE:
    case DVACT_SUSPEND:
        athn_suspend(sc);
        break;
    case DVACT_WAKEUP:
        athn_pci_wakeup(psc);
        break;
    }

    return (0);
}

void
athn_pci_wakeup(struct athn_pci_softc *psc)
{
    struct athn_softc *sc = &psc->sc_sc;
    pcireg_t reg;
    int s;

    reg = pci_conf_read(psc->sc_pc, psc->sc_tag, 0x40);
    if (reg & 0xff00)
        pci_conf_write(psc->sc_pc, psc->sc_tag, 0x40, reg & ~0xff00);

    s = splnet();
    athn_wakeup(sc);
    splx(s);
}

uint32_t
athn_pci_read(struct athn_softc *sc, uint32_t addr)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)sc;

    return (bus_space_read_4(psc->sc_st, psc->sc_sh, addr));
}

void
athn_pci_write(struct athn_softc *sc, uint32_t addr, uint32_t val)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)sc;

    bus_space_write_4(psc->sc_st, psc->sc_sh, addr, val);
}

void
athn_pci_write_barrier(struct athn_softc *sc)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)sc;

    bus_space_barrier(psc->sc_st, psc->sc_sh, 0, psc->sc_mapsize,
        BUS_SPACE_BARRIER_WRITE);
}

void
athn_pci_disable_aspm(struct athn_softc *sc)
{
    struct athn_pci_softc *psc = (struct athn_pci_softc *)sc;
    pcireg_t reg;

    /* Disable PCIe Active State Power Management (ASPM). */
    reg = pci_conf_read(psc->sc_pc, psc->sc_tag,
        psc->sc_cap_off + PCI_PCIE_LCSR);
    reg &= ~(PCI_PCIE_LCSR_ASPM_L0S | PCI_PCIE_LCSR_ASPM_L1);
    pci_conf_write(psc->sc_pc, psc->sc_tag,
        psc->sc_cap_off + PCI_PCIE_LCSR, reg);
}
