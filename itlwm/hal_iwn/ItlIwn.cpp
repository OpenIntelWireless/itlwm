/*
 * Copyright (C) 2020  pigworlds
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
/*    $OpenBSD: if_iwn.c,v 1.243 2020/11/12 15:16:18 krw Exp $    */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Driver for Intel WiFi Link 4965 and 1000/5000/6000 Series 802.11 network
 * adapters.
 */

#include "ItlIwn.hpp"
#include <linux/types.h>
#include <linux/kernel.h>
#include <FwData.h>
#include <crypto/sha1.h>

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/ethernet.h>

#include <sys/_task.h>
#include <sys/pcireg.h>

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlIwn, ItlHalService)

#define DEVNAME(_s)    ((_s)->sc_dev.dv_xname)

#define IC2IFP(_ic_) (&(_ic_)->ic_if)

#define IWN_DEBUG

#ifdef IWN_DEBUG
#define DPRINTF(x)    do { if (iwn_debug > 0) XYLog x; } while (0)
#define DPRINTFN(n, x)    do { if (iwn_debug >= (n)) XYLog x; } while (0)
int iwn_debug = 1;
#else
#define DPRINTF(x)    do { ; } while (0)
#define DPRINTFN(n, x)    do { ; } while (0)
#endif

#define M_DEVBUF 2

#ifdef DELAY
#undef DELAY
#define DELAY IODelay
#endif

bool ItlIwn::attach(IOPCIDevice *device)
{
    pci.pa_tag = device;
    pci.workloop = getMainWorkLoop();
    if (!iwn_attach(&com, &pci)) {
        detach(device);
        releaseAll();
        return false;
    }
    return true;
}

void ItlIwn::
detach(IOPCIDevice *device)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    struct iwn_softc *sc = &com;
    
    for (int txq_i = 0; txq_i < nitems(sc->txq); txq_i++)
        iwn_free_tx_ring(sc, &sc->txq[txq_i]);
    iwn_free_rx_ring(sc, &sc->rxq);
    iwn_free_sched(sc);
    iwn_free_ict(sc);
    iwn_free_kw(sc);
    iwn_free_fwmem(sc);
    ieee80211_ifdetach(ifp);
    taskq_destroy(systq);
    releaseAll();
}

void ItlIwn::
releaseAll()
{
    pci_intr_handle *intrHandler = com.ih;
    
    if (com.calib_to) {
        timeout_del(&com.calib_to);
        timeout_free(&com.calib_to);
    }
    if (intrHandler) {
        if (intrHandler->intr && intrHandler->workloop) {
//            intrHandler->intr->disable();
            intrHandler->workloop->removeEventSource(intrHandler->intr);
            intrHandler->intr->release();
        }
        intrHandler->intr = NULL;
        intrHandler->workloop = NULL;
        intrHandler->arg = NULL;
        intrHandler->dev = NULL;
        intrHandler->func = NULL;
        intrHandler->release();
        com.ih = NULL;
    }
    pci.pa_tag = NULL;
    pci.workloop = NULL;
}

void ItlIwn::free()
{
    XYLog("%s\n", __FUNCTION__);
    super::free();
}

ItlDriverInfo *ItlIwn::
getDriverInfo()
{
    return this;
}

ItlDriverController *ItlIwn::
getDriverController()
{
    return this;
}

IOReturn ItlIwn::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    if (ifp->if_flags & IFF_UP) {
        XYLog("%s already in activating state\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    ifp->if_flags |= IFF_UP;
    iwn_activate(&com, DVACT_RESUME);
    iwn_activate(&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn ItlIwn::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    if (!(ifp->if_flags & IFF_UP)) {
        XYLog("%s already in diactivating state\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    ifp->if_flags &= ~IFF_UP;
    iwn_activate(&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

void ItlIwn::
clearScanningFlags()
{
    com.sc_flags &= ~(IWN_FLAG_SCANNING | IWN_FLAG_BGSCAN);
}

IOReturn ItlIwn::
setMulticastList(IOEthernetAddress *addr, int count)
{
    return kIOReturnSuccess;
}

const char *ItlIwn::
getFirmwareVersion()
{
    return com.fwname;
}

const char *ItlIwn::
getFirmwareName()
{
    return com.fwname;
}

UInt32 ItlIwn::
supportedFeatures()
{
    return kIONetworkFeatureMultiPages;
}

const char *ItlIwn::
getFirmwareCountryCode()
{
    return "ZZ";
}

uint32_t ItlIwn::
getTxQueueSize()
{
    return IWN_TX_RING_COUNT;
}

int16_t ItlIwn::
getBSSNoise()
{
    return com.noise;
}

bool ItlIwn::
is5GBandSupport()
{
    return com.sc_flags & IWN_FLAG_HAS_5GHZ;
}

int ItlIwn::
getTxNSS()
{
    return com.ntxchains;
}

struct ieee80211com *ItlIwn::
get80211Controller()
{
    return &com.sc_ic;
}

#define    PCI_VENDOR_INTEL    0x8086        /* Intel */
#define    PCI_PRODUCT_INTEL_WL_4965_1    0x4229        /* Wireless WiFi Link 4965 */
#define    PCI_PRODUCT_INTEL_WL_6300_1    0x422b        /* Centrino Ultimate-N 6300 */
#define    PCI_PRODUCT_INTEL_WL_6200_1    0x422c        /* Centrino Advanced-N 6200 */
#define    PCI_PRODUCT_INTEL_WL_4965_2    0x4230        /* Wireless WiFi Link 4965 */
#define    PCI_PRODUCT_INTEL_WL_5100_1    0x4232        /* WiFi Link 5100 */
#define    PCI_PRODUCT_INTEL_WL_5300_1    0x4235        /* WiFi Link 5300 */
#define    PCI_PRODUCT_INTEL_WL_5300_2    0x4236        /* WiFi Link 5300 */
#define    PCI_PRODUCT_INTEL_WL_5100_2    0x4237        /* WiFi Link 5100 */
#define    PCI_PRODUCT_INTEL_WL_6300_2    0x4238        /* Centrino Ultimate-N 6300 */
#define    PCI_PRODUCT_INTEL_WL_6200_2    0x4239        /* Centrino Advanced-N 6200 */
#define    PCI_PRODUCT_INTEL_WL_5350_1    0x423a        /* WiFi Link 5350 */
#define    PCI_PRODUCT_INTEL_WL_5350_2    0x423b        /* WiFi Link 5350 */
#define    PCI_PRODUCT_INTEL_WL_5150_1    0x423c        /* WiFi Link 5150 */
#define    PCI_PRODUCT_INTEL_WL_5150_2    0x423d        /* WiFi Link 5150 */
#define    PCI_PRODUCT_INTEL_WL_6005_1    0x0082        /* Centrino Advanced-N 6205 */
#define    PCI_PRODUCT_INTEL_WL_1000_1    0x0083        /* WiFi Link 1000 */
#define    PCI_PRODUCT_INTEL_WL_1000_2    0x0084        /* WiFi Link 1000 */
#define    PCI_PRODUCT_INTEL_WL_6005_2    0x0085        /* Centrino Advanced-N 6205 */
#define    PCI_PRODUCT_INTEL_WL_6050_1    0x0087        /* Centrino Advanced-N 6250 */
#define    PCI_PRODUCT_INTEL_WL_6050_2    0x0089        /* Centrino Advanced-N 6250 */
#define    PCI_PRODUCT_INTEL_WL_1030_1    0x008a        /* WiFi Link 1030 */
#define    PCI_PRODUCT_INTEL_WL_1030_2    0x008b        /* WiFi Link 1030 */
#define    PCI_PRODUCT_INTEL_WL_6030_1    0x0090        /* Centrino Advanced-N 6030 */
#define    PCI_PRODUCT_INTEL_WL_6030_2    0x0091        /* Centrino Advanced-N 6030 */
#define    PCI_PRODUCT_INTEL_WL_135_1    0x0892        /* Centrino Wireless-N 135 */
#define    PCI_PRODUCT_INTEL_WL_135_2    0x0893        /* Centrino Wireless-N 135 */
#define    PCI_PRODUCT_INTEL_WL_105_1    0x0894        /* Centrino Wireless-N 105 */
#define    PCI_PRODUCT_INTEL_WL_105_2    0x0895        /* Centrino Wireless-N 105 */
#define    PCI_PRODUCT_INTEL_WL_130_1    0x0896        /* Centrino Wireless-N 130 */
#define    PCI_PRODUCT_INTEL_WL_130_2    0x0897        /* Centrino Wireless-N 130 */
#define    PCI_PRODUCT_INTEL_WL_100_1    0x08ae        /* Centrino Wireless-N 100 */
#define    PCI_PRODUCT_INTEL_WL_100_2    0x08af        /* Centrino Wireless-N 100 */
#define    PCI_PRODUCT_INTEL_WL_6235_1    0x088e        /* Centrino Advanced-N 6235 */
#define    PCI_PRODUCT_INTEL_WL_6235_2    0x088f        /* Centrino Advanced-N 6235 */
#define    PCI_PRODUCT_INTEL_WL_2200_1    0x0890        /* Centrino Wireless-N 2200 */
#define    PCI_PRODUCT_INTEL_WL_2200_2    0x0891        /* Centrino Wireless-N 2200 */
#define    PCI_PRODUCT_INTEL_WL_6150_1    0x0885        /* Centrino Wireless-N 6150 */
#define    PCI_PRODUCT_INTEL_WL_6150_2    0x0886        /* Centrino Wireless-N 6150 */
#define    PCI_PRODUCT_INTEL_WL_2230_1    0x0887        /* Centrino Wireless-N 2230 */
#define    PCI_PRODUCT_INTEL_WL_2230_2    0x0888        /* Centrino Wireless-N 2230 */

static const struct pci_matchid iwn_devices[] = {
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_4965_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_4965_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5100_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5100_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5150_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5150_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5300_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5300_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5350_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_5350_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_1000_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_1000_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6300_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6300_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6200_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6200_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6050_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6050_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6005_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6005_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6030_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6030_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_1030_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_1030_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_100_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_100_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_130_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_130_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6235_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6235_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_2230_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_2230_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_2200_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_2200_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_135_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_135_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_105_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_105_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6150_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_6150_2 },
};

int ItlIwn::
iwn_match(struct IOPCIDevice *device)
{
    int devId = device->configRead16(kIOPCIConfigDeviceID);
    return pci_matchbyid(PCI_VENDOR_INTEL, devId, iwn_devices,
                         nitems(iwn_devices));
}

bool ItlIwn::
intrFilter(OSObject *object, IOFilterInterruptEventSource *src)
{
    ItlIwn *that = (ItlIwn*)object;
    IWN_WRITE(&that->com, IWN_INT_MASK, 0);
    return true;
}

bool ItlIwn::
iwn_attach(struct iwn_softc *sc, struct pci_attach_args *pa)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    pcireg_t memtype, reg;
    int i, error;

    sc->sc_pct = pa->pa_pc;
    sc->sc_pcitag = pa->pa_tag;
    sc->sc_dmat = pa->pa_dmat;

    /*
     * Get the offset of the PCI Express Capability Structure in PCI
     * Configuration Space.
     */
    error = pci_get_capability(sc->sc_pct, sc->sc_pcitag,
        PCI_CAP_PCIEXPRESS, &sc->sc_cap_off, NULL);
    if (error == 0) {
        XYLog(": PCIe capability structure not found!\n");
        return false;
    }

    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    if (reg & 0xff00)
        pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);

    /* Hardware bug workaround. */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, PCI_COMMAND_STATUS_REG);
    if (reg & PCI_COMMAND_INTERRUPT_DISABLE) {
        DPRINTF(("PCIe INTx Disable set\n"));
        reg &= ~PCI_COMMAND_INTERRUPT_DISABLE;
        pci_conf_write(sc->sc_pct, sc->sc_pcitag,
            PCI_COMMAND_STATUS_REG, reg);
    }

    memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, IWN_PCI_BAR0);
    error = pci_mapreg_map(pa, IWN_PCI_BAR0, memtype, 0, &sc->sc_st,
        &sc->sc_sh, NULL, &sc->sc_sz, 0);
    if (error != 0) {
        XYLog(": can't map mem space\n");
        return false;
    }

    /* Install interrupt handler. */
    if (pci_intr_map_msi(pa, &sc->ih) != 0) {
        XYLog(": can't map interrupt\n");
        return false;
    }

    int msiIntrIndex = -1;
    for (int index = 0; ; index++)
    {
        int interruptType;
        int ret = pa->pa_tag->getInterruptType(index, &interruptType);
        if (ret != kIOReturnSuccess)
            break;
        if (interruptType & kIOInterruptTypePCIMessaged)
        {
            msiIntrIndex = index;
            break;
        }
    }
    if (msiIntrIndex == -1) {
        XYLog("%s: can't find MSI interrupt controller\n", DEVNAME(sc));
        return false;
    }

    sc->sc_ih = IOFilterInterruptEventSource::filterInterruptEventSource(this,
                                                                         (IOInterruptEventSource::Action)&ItlIwn::iwn_intr, &ItlIwn::intrFilter
                                                                         ,pa->pa_tag, msiIntrIndex);
    if (sc->sc_ih == NULL || pa->workloop->addEventSource(sc->sc_ih) != kIOReturnSuccess) {
        XYLog("%s: can't establish interrupt\n", DEVNAME(sc));
        return false;
    }
    sc->sc_ih->enable();

    /* Read hardware revision and attach. */
    sc->hw_type = (IWN_READ(sc, IWN_HW_REV) >> 4) & 0x1f;
    int pa_id = pa->pa_tag->configRead16(kIOPCIConfigDeviceID);
    if (sc->hw_type == IWN_HW_REV_TYPE_4965)
        error = iwn4965_attach(sc, pa_id);
    else
        error = iwn5000_attach(sc, pa_id);
    if (error != 0) {
        XYLog(": could not attach device\n");
        return false;
    }

    if ((error = iwn_hw_prepare(sc)) != 0) {
        XYLog(": hardware not ready\n");
        return false;
    }

    /* Read MAC address, channels, etc from EEPROM. */
    if ((error = iwn_read_eeprom(sc)) != 0) {
        XYLog(": could not read EEPROM\n");
        return false;
    }

    /* Allocate DMA memory for firmware transfers. */
    if ((error = iwn_alloc_fwmem(sc)) != 0) {
        XYLog(": could not allocate memory for firmware\n");
        return false;
    }

    /* Allocate "Keep Warm" page. */
    if ((error = iwn_alloc_kw(sc)) != 0) {
        XYLog(": could not allocate keep warm page\n");
        goto fail1;
    }

    /* Allocate ICT table for 5000 Series. */
    if (sc->hw_type != IWN_HW_REV_TYPE_4965 &&
        (error = iwn_alloc_ict(sc)) != 0) {
        XYLog(": could not allocate ICT table\n");
        goto fail2;
    }

    /* Allocate TX scheduler "rings". */
    if ((error = iwn_alloc_sched(sc)) != 0) {
        XYLog(": could not allocate TX scheduler rings\n");
        goto fail3;
    }

    /* Allocate TX rings (16 on 4965AGN, 20 on >=5000). */
    for (i = 0; i < sc->ntxqs; i++) {
        if ((error = iwn_alloc_tx_ring(sc, &sc->txq[i], i)) != 0) {
            XYLog(": could not allocate TX ring %d\n", i);
            goto fail4;
        }
    }

    /* Allocate RX ring. */
    if ((error = iwn_alloc_rx_ring(sc, &sc->rxq)) != 0) {
        XYLog(": could not allocate RX ring\n");
        goto fail4;
    }

    /* Clear pending interrupts. */
    IWN_WRITE(sc, IWN_INT, 0xffffffff);

    /* Count the number of available chains. */
    sc->ntxchains =
        ((sc->txchainmask >> 2) & 1) +
        ((sc->txchainmask >> 1) & 1) +
        ((sc->txchainmask >> 0) & 1);
    sc->nrxchains =
        ((sc->rxchainmask >> 2) & 1) +
        ((sc->rxchainmask >> 1) & 1) +
        ((sc->rxchainmask >> 0) & 1);
    XYLog(", MIMO %dT%dR, %.4s, address %s\n", sc->ntxchains,
        sc->nrxchains, sc->eeprom_domain, ether_sprintf(ic->ic_myaddr));

    taskq_init();
    
    ic->ic_phytype = IEEE80211_T_OFDM;    /* not only, but not used */
    ic->ic_opmode = IEEE80211_M_STA;    /* default to BSS mode */
    ic->ic_state = IEEE80211_S_INIT;

    /* Set device capabilities. */
    ic->ic_caps =
        IEEE80211_C_WEP |        /* WEP */
        IEEE80211_C_RSN |        /* WPA/RSN */
        IEEE80211_C_SCANALL |    /* device scans all channels at once */
        IEEE80211_C_SCANALLBAND |    /* driver scans all bands at once */
        IEEE80211_C_MONITOR |    /* monitor mode supported */
        IEEE80211_C_SHSLOT |    /* short slot time supported */
        IEEE80211_C_SHPREAMBLE |    /* short preamble supported */
        IEEE80211_C_PMGT;        /* power saving supported */

    /* No optional HT features supported for now, */
    ic->ic_htcaps = 0;
    ic->ic_htxcaps = 0;
    ic->ic_txbfcaps = 0;
    ic->ic_aselcaps = 0;
    ic->ic_ampdu_params = (IEEE80211_AMPDU_PARAM_SS_4 | 0x3 /* 64k */);
    if (sc->sc_flags & IWN_FLAG_HAS_11N) {
        ic->ic_caps |= (IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU | IEEE80211_C_AMSDU_IN_AMPDU);
        /* Set HT capabilities. */
        ic->ic_htcaps = IEEE80211_HTCAP_SGI20;
        /* 6200 devices have issues with SGI40 for some reason. */
        if ((sc->sc_flags & IWN_FLAG_INTERNAL_PA) == 0)
            ic->ic_htcaps |= IEEE80211_HTCAP_SGI40;
        ic->ic_htcaps |= IEEE80211_HTCAP_CBW20_40;
#if IWN_RBUF_SIZE == 8192
        ic->ic_htcaps |=
            IEEE80211_HTCAP_AMSDU7935;
#endif
#ifdef notyet
        if (sc->hw_type != IWN_HW_REV_TYPE_4965)
            ic->ic_htcaps |= IEEE80211_HTCAP_GF;
#endif
        if (sc->hw_type == IWN_HW_REV_TYPE_6050)
            ic->ic_htcaps |= IEEE80211_HTCAP_SMPS_DYN << IEEE80211_HTCAP_SMPS_SHIFT;
        else
            ic->ic_htcaps |= IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT;
    }

    /* Set supported legacy rates. */
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;
    if (sc->sc_flags & IWN_FLAG_HAS_5GHZ) {
        ic->ic_sup_rates[IEEE80211_MODE_11A] =
            ieee80211_std_rateset_11a;
    }
    if (sc->sc_flags & IWN_FLAG_HAS_11N) {
        /* Set supported HT rates. */
        if (ic->ic_userflags & IEEE80211_F_NOMIMO)
            sc->ntxchains = sc->nrxchains = 1;

        int ntxstreams = sc->ntxchains;
        int nrxstreams = sc->nrxchains;

        ic->ic_sup_mcs[0] = 0xff;        /* MCS 0-7 */
        if (nrxstreams > 1)
            ic->ic_sup_mcs[1] = 0xff;    /* MCS 8-15 */
        if (nrxstreams > 2)
            ic->ic_sup_mcs[2] = 0xff;    /* MCS 16-23 */

        ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;
        if (ntxstreams != nrxstreams) {
            ic->ic_tx_mcs_set |= IEEE80211_TX_RX_MCS_NOT_EQUAL;
            ic->ic_tx_mcs_set |= (ntxstreams - 1) << 2;
        }
    }

    /* IBSS channel undefined for now. */
    ic->ic_ibss_chan = &ic->ic_channels[0];
    
    ic->ic_max_rssi = IWN_MAX_DBM - IWN_MIN_DBM;

    ifp->if_softc = sc;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST | IFF_DEBUG;
    ifp->if_ioctl = iwn_ioctl;
    ifp->if_start = iwn_start;
    ifp->if_watchdog = iwn_watchdog;
    memcpy(ifp->if_xname, sc->sc_dev.dv_xname, IFNAMSIZ);

    if_attach(ifp);
    ieee80211_ifattach(ifp, getController());
    ic->ic_node_alloc = iwn_node_alloc;
    ic->ic_bgscan_start = iwn_bgscan;
    ic->ic_newassoc = iwn_newassoc;
    ic->ic_updateedca = iwn_updateedca;
    ic->ic_set_key = iwn_set_key;
    ic->ic_delete_key = iwn_delete_key;
    ic->ic_updateprot = iwn_updateprot;
    ic->ic_updateslot = iwn_updateslot;
    ic->ic_ampdu_rx_start = iwn_ampdu_rx_start;
    ic->ic_ampdu_rx_stop = iwn_ampdu_rx_stop;
    ic->ic_ampdu_tx_start = iwn_ampdu_tx_start;
    ic->ic_ampdu_tx_stop = iwn_ampdu_tx_stop;
    ic->ic_update_chw = iwn_update_chw;

    /* Override 802.11 state transition machine. */
    sc->sc_newstate = ic->ic_newstate;
    ic->ic_newstate = iwn_newstate;
    ieee80211_media_init(ifp);

    sc->amrr.amrr_min_success_threshold =  1;
    sc->amrr.amrr_max_success_threshold = 15;

#if NBPFILTER > 0
    iwn_radiotap_attach(sc);
#endif
    timeout_set(&sc->calib_to, iwn_calib_timeout, sc);
//    rw_init(&sc->sc_rwlock, "iwnlock");
    task_set(&sc->init_task, iwn_init_task, sc, "iwn_init_task");
    return true;

    /* Free allocated memory if something failed during attachment. */
fail4:    while (--i >= 0)
        iwn_free_tx_ring(sc, &sc->txq[i]);
    iwn_free_sched(sc);
fail3:    if (sc->ict != NULL)
        iwn_free_ict(sc);
fail2:    iwn_free_kw(sc);
fail1:    iwn_free_fwmem(sc);
    return false;
}

int ItlIwn::
iwn4965_attach(struct iwn_softc *sc, pci_product_id_t pid)
{
    struct iwn_ops *ops = &sc->ops;

    ops->load_firmware = iwn4965_load_firmware;
    ops->read_eeprom = iwn4965_read_eeprom;
    ops->post_alive = iwn4965_post_alive;
    ops->nic_config = iwn4965_nic_config;
    ops->reset_sched = iwn4965_reset_sched;
    ops->update_sched = iwn4965_update_sched;
    ops->update_rxon = iwn4965_update_rxon;
    ops->get_temperature = iwn4965_get_temperature;
    ops->get_rssi = iwn4965_get_rssi;
    ops->set_txpower = iwn4965_set_txpower;
    ops->init_gains = iwn4965_init_gains;
    ops->set_gains = iwn4965_set_gains;
    ops->add_node = iwn4965_add_node;
    ops->tx_done = iwn4965_tx_done;
    ops->ampdu_tx_start = iwn4965_ampdu_tx_start;
    ops->ampdu_tx_stop = iwn4965_ampdu_tx_stop;
    sc->ntxqs = IWN4965_NTXQUEUES;
    sc->first_agg_txq = IWN4965_FIRST_AGG_TXQUEUE;
    sc->ndmachnls = IWN4965_NDMACHNLS;
    sc->broadcast_id = IWN4965_ID_BROADCAST;
    sc->rxonsz = IWN4965_RXONSZ;
    sc->schedsz = IWN4965_SCHEDSZ;
    sc->fw_text_maxsz = IWN4965_FW_TEXT_MAXSZ;
    sc->fw_data_maxsz = IWN4965_FW_DATA_MAXSZ;
    sc->fwsz = IWN4965_FWSZ;
    sc->sched_txfact_addr = IWN4965_SCHED_TXFACT;
    sc->limits = &iwn4965_sensitivity_limits;
    sc->fwname = "iwn-4965";
    /* Override chains masks, ROM is known to be broken. */
    sc->txchainmask = IWN_ANT_AB;
    sc->rxchainmask = IWN_ANT_ABC;

    return 0;
}

int ItlIwn::
iwn5000_attach(struct iwn_softc *sc, pci_product_id_t pid)
{
    struct iwn_ops *ops = &sc->ops;

    ops->load_firmware = iwn5000_load_firmware;
    ops->read_eeprom = iwn5000_read_eeprom;
    ops->post_alive = iwn5000_post_alive;
    ops->nic_config = iwn5000_nic_config;
    ops->reset_sched = iwn5000_reset_sched;
    ops->update_sched = iwn5000_update_sched;
    ops->update_rxon = iwn5000_update_rxon;
    ops->get_temperature = iwn5000_get_temperature;
    ops->get_rssi = iwn5000_get_rssi;
    ops->set_txpower = iwn5000_set_txpower;
    ops->init_gains = iwn5000_init_gains;
    ops->set_gains = iwn5000_set_gains;
    ops->add_node = iwn5000_add_node;
    ops->tx_done = iwn5000_tx_done;
    ops->ampdu_tx_start = iwn5000_ampdu_tx_start;
    ops->ampdu_tx_stop = iwn5000_ampdu_tx_stop;
    sc->ntxqs = IWN5000_NTXQUEUES;
    sc->first_agg_txq = IWN5000_FIRST_AGG_TXQUEUE;
    sc->ndmachnls = IWN5000_NDMACHNLS;
    sc->broadcast_id = IWN5000_ID_BROADCAST;
    sc->rxonsz = IWN5000_RXONSZ;
    sc->schedsz = IWN5000_SCHEDSZ;
    sc->fw_text_maxsz = IWN5000_FW_TEXT_MAXSZ;
    sc->fw_data_maxsz = IWN5000_FW_DATA_MAXSZ;
    sc->fwsz = IWN5000_FWSZ;
    sc->sched_txfact_addr = IWN5000_SCHED_TXFACT;

    switch (sc->hw_type) {
    case IWN_HW_REV_TYPE_5100:
        sc->limits = &iwn5000_sensitivity_limits;
        sc->fwname = "iwn-5000";
        /* Override chains masks, ROM is known to be broken. */
        sc->txchainmask = IWN_ANT_B;
        sc->rxchainmask = IWN_ANT_AB;
        break;
    case IWN_HW_REV_TYPE_5150:
        sc->limits = &iwn5150_sensitivity_limits;
        sc->fwname = "iwn-5150";
        break;
    case IWN_HW_REV_TYPE_5300:
    case IWN_HW_REV_TYPE_5350:
        sc->limits = &iwn5000_sensitivity_limits;
        sc->fwname = "iwn-5000";
        break;
    case IWN_HW_REV_TYPE_1000:
        sc->limits = &iwn1000_sensitivity_limits;
        sc->fwname = "iwn-1000";
        break;
    case IWN_HW_REV_TYPE_6000:
        sc->limits = &iwn6000_sensitivity_limits;
        sc->fwname = "iwn-6000";
        if (pid == PCI_PRODUCT_INTEL_WL_6200_1 ||
            pid == PCI_PRODUCT_INTEL_WL_6200_2) {
            sc->sc_flags |= IWN_FLAG_INTERNAL_PA;
            /* Override chains masks, ROM is known to be broken. */
            sc->txchainmask = IWN_ANT_BC;
            sc->rxchainmask = IWN_ANT_BC;
        }
        break;
    case IWN_HW_REV_TYPE_6050:
        sc->limits = &iwn6000_sensitivity_limits;
        sc->fwname = "iwn-6050";
        break;
    case IWN_HW_REV_TYPE_6005:
        sc->limits = &iwn6000_sensitivity_limits;
        if (pid != PCI_PRODUCT_INTEL_WL_6005_1 &&
            pid != PCI_PRODUCT_INTEL_WL_6005_2) {
            sc->fwname = "iwn-6030";
            sc->sc_flags |= IWN_FLAG_ADV_BT_COEX;
        } else
            sc->fwname = "iwn-6005";
        break;
    case IWN_HW_REV_TYPE_2030:
        sc->limits = &iwn2000_sensitivity_limits;
        sc->fwname = "iwn-2030";
        sc->sc_flags |= IWN_FLAG_ADV_BT_COEX;
        break;
    case IWN_HW_REV_TYPE_2000:
        sc->limits = &iwn2000_sensitivity_limits;
        sc->fwname = "iwn-2000";
        break;
    case IWN_HW_REV_TYPE_135:
        sc->limits = &iwn2000_sensitivity_limits;
        sc->fwname = "iwn-135";
        sc->sc_flags |= IWN_FLAG_ADV_BT_COEX;
        break;
    case IWN_HW_REV_TYPE_105:
        sc->limits = &iwn2000_sensitivity_limits;
        sc->fwname = "iwn-105";
        break;
    default:
        XYLog(": adapter type %d not supported\n", sc->hw_type);
        return ENOTSUP;
    }
    return 0;
}

#if NBPFILTER > 0
/*
 * Attach the interface to 802.11 radiotap.
 */
void ItlIwn::
iwn_radiotap_attach(struct iwn_softc *sc)
{
    bpfattach(&sc->sc_drvbpf, &sc->sc_ic.ic_if, DLT_IEEE802_11_RADIO,
        sizeof (struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN);

    sc->sc_rxtap_len = sizeof sc->sc_rxtapu;
    sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
    sc->sc_rxtap.wr_ihdr.it_present = htole32(IWN_RX_RADIOTAP_PRESENT);

    sc->sc_txtap_len = sizeof sc->sc_txtapu;
    sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
    sc->sc_txtap.wt_ihdr.it_present = htole32(IWN_TX_RADIOTAP_PRESENT);
}
#endif

int ItlIwn::
iwn_activate(struct iwn_softc *sc, int act)
{
    XYLog("%s\n", __FUNCTION__);
    struct _ifnet *ifp = &sc->sc_ic.ic_if;

    switch (act) {
    case DVACT_QUIESCE:
        if (ifp->if_flags & IFF_RUNNING)
            iwn_stop(ifp);
        break;
    case DVACT_WAKEUP:
        iwn_wakeup(sc);
        break;
    }

    return 0;
}

void ItlIwn::
iwn_wakeup(struct iwn_softc *sc)
{
    pcireg_t reg;

    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    if (reg & 0xff00)
        pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);
    task_add(systq, &sc->init_task);
}

void ItlIwn::
iwn_init_task(void *arg1)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)arg1;
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int s;

//    rw_enter_write(&sc->sc_rwlock);
    s = splnet();

    if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP)
        that->iwn_init(ifp);

    splx(s);
//    rw_exit_write(&sc->sc_rwlock);
}

int
iwn_nic_lock(struct iwn_softc *sc)
{
    int ntries;

    /* Request exclusive access to NIC. */
    IWN_SETBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_MAC_ACCESS_REQ);

    /* Spin until we actually get the lock. */
    for (ntries = 0; ntries < 1000; ntries++) {
        if ((IWN_READ(sc, IWN_GP_CNTRL) &
             (IWN_GP_CNTRL_MAC_ACCESS_ENA | IWN_GP_CNTRL_SLEEP)) ==
            IWN_GP_CNTRL_MAC_ACCESS_ENA)
            return 0;
        DELAY(10);
    }
    
    XYLog("%s acquiring device failed.", __FUNCTION__);
    return ETIMEDOUT;
}

void
iwn_nic_unlock(struct iwn_softc *sc)
{
    IWN_CLRBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_MAC_ACCESS_REQ);
}

uint32_t
iwn_prph_read(struct iwn_softc *sc, uint32_t addr)
{
    IWN_WRITE(sc, IWN_PRPH_RADDR, IWN_PRPH_DWORD | addr);
    IWN_BARRIER_READ_WRITE(sc);
    return IWN_READ(sc, IWN_PRPH_RDATA);
}

void
iwn_prph_write(struct iwn_softc *sc, uint32_t addr, uint32_t data)
{
    IWN_WRITE(sc, IWN_PRPH_WADDR, IWN_PRPH_DWORD | addr);
    IWN_BARRIER_WRITE(sc);
    IWN_WRITE(sc, IWN_PRPH_WDATA, data);
}

void
iwn_prph_setbits(struct iwn_softc *sc, uint32_t addr, uint32_t mask)
{
    iwn_prph_write(sc, addr, iwn_prph_read(sc, addr) | mask);
}

void
iwn_prph_clrbits(struct iwn_softc *sc, uint32_t addr, uint32_t mask)
{
    iwn_prph_write(sc, addr, iwn_prph_read(sc, addr) & ~mask);
}

void
iwn_prph_write_region_4(struct iwn_softc *sc, uint32_t addr,
    const uint32_t *data, int count)
{
    for (; count > 0; count--, data++, addr += 4)
        iwn_prph_write(sc, addr, *data);
}

uint32_t
iwn_mem_read(struct iwn_softc *sc, uint32_t addr)
{
    IWN_WRITE(sc, IWN_MEM_RADDR, addr);
    IWN_BARRIER_READ_WRITE(sc);
    return IWN_READ(sc, IWN_MEM_RDATA);
}

void
iwn_mem_write(struct iwn_softc *sc, uint32_t addr, uint32_t data)
{
    IWN_WRITE(sc, IWN_MEM_WADDR, addr);
    IWN_BARRIER_WRITE(sc);
    IWN_WRITE(sc, IWN_MEM_WDATA, data);
}

void
iwn_mem_write_2(struct iwn_softc *sc, uint32_t addr, uint16_t data)
{
    uint32_t tmp;

    tmp = iwn_mem_read(sc, addr & ~3);
    if (addr & 3)
        tmp = (tmp & 0x0000ffff) | data << 16;
    else
        tmp = (tmp & 0xffff0000) | data;
    iwn_mem_write(sc, addr & ~3, tmp);
}

#ifdef IWN_DEBUG

void
iwn_mem_read_region_4(struct iwn_softc *sc, uint32_t addr, uint32_t *data,
    int count)
{
    for (; count > 0; count--, addr += 4)
        *data++ = iwn_mem_read(sc, addr);
}

#endif

void
iwn_mem_set_region_4(struct iwn_softc *sc, uint32_t addr, uint32_t val,
    int count)
{
    for (; count > 0; count--, addr += 4)
        iwn_mem_write(sc, addr, val);
}

int ItlIwn::
iwn_eeprom_lock(struct iwn_softc *sc)
{
    int i, ntries;

    for (i = 0; i < 100; i++) {
        /* Request exclusive access to EEPROM. */
        IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
            IWN_HW_IF_CONFIG_EEPROM_LOCKED);

        /* Spin until we actually get the lock. */
        for (ntries = 0; ntries < 100; ntries++) {
            if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
                IWN_HW_IF_CONFIG_EEPROM_LOCKED)
                return 0;
            DELAY(10);
        }
    }
    return ETIMEDOUT;
}

void
iwn_eeprom_unlock(struct iwn_softc *sc)
{
    IWN_CLRBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_EEPROM_LOCKED);
}

/*
 * Initialize access by host to One Time Programmable ROM.
 * NB: This kind of ROM can be found on 1000 or 6000 Series only.
 */
int ItlIwn::
iwn_init_otprom(struct iwn_softc *sc)
{
    uint16_t prev, base, next;
    int count, error;

    /* Wait for clock stabilization before accessing prph. */
    if ((error = iwn_clock_wait(sc)) != 0)
        return error;

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    iwn_prph_setbits(sc, IWN_APMG_PS, IWN_APMG_PS_RESET_REQ);
    DELAY(5);
    iwn_prph_clrbits(sc, IWN_APMG_PS, IWN_APMG_PS_RESET_REQ);
    iwn_nic_unlock(sc);

    /* Set auto clock gate disable bit for HW with OTP shadow RAM. */
    if (sc->hw_type != IWN_HW_REV_TYPE_1000) {
        IWN_SETBITS(sc, IWN_DBG_LINK_PWR_MGMT,
            IWN_RESET_LINK_PWR_MGMT_DIS);
    }
    IWN_CLRBITS(sc, IWN_EEPROM_GP, IWN_EEPROM_GP_IF_OWNER);
    /* Clear ECC status. */
    IWN_SETBITS(sc, IWN_OTP_GP,
        IWN_OTP_GP_ECC_CORR_STTS | IWN_OTP_GP_ECC_UNCORR_STTS);

    /*
     * Find the block before last block (contains the EEPROM image)
     * for HW without OTP shadow RAM.
     */
    if (sc->hw_type == IWN_HW_REV_TYPE_1000) {
        /* Switch to absolute addressing mode. */
        IWN_CLRBITS(sc, IWN_OTP_GP, IWN_OTP_GP_RELATIVE_ACCESS);
        base = 0;
        for (count = 0; count < IWN1000_OTP_NBLOCKS; count++) {
            error = iwn_read_prom_data(sc, base, &next, 2);
            if (error != 0)
                return error;
            if (next == 0)    /* End of linked-list. */
                break;
            prev = base;
            base = letoh16(next);
        }
        if (count == 0 || count == IWN1000_OTP_NBLOCKS)
            return EIO;
        /* Skip "next" word. */
        sc->prom_base = prev + 1;
    }
    return 0;
}

int ItlIwn::
iwn_read_prom_data(struct iwn_softc *sc, uint32_t addr, void *data, int count)
{
    uint8_t *out = (uint8_t *)data;
    uint32_t val, tmp;
    int ntries;

    addr += sc->prom_base;
    for (; count > 0; count -= 2, addr++) {
        IWN_WRITE(sc, IWN_EEPROM, addr << 2);
        for (ntries = 0; ntries < 10; ntries++) {
            val = IWN_READ(sc, IWN_EEPROM);
            if (val & IWN_EEPROM_READ_VALID)
                break;
            DELAY(5);
        }
        if (ntries == 10) {
            XYLog("%s: timeout reading ROM at 0x%x\n",
                sc->sc_dev.dv_xname, addr);
            return ETIMEDOUT;
        }
        if (sc->sc_flags & IWN_FLAG_HAS_OTPROM) {
            /* OTPROM, check for ECC errors. */
            tmp = IWN_READ(sc, IWN_OTP_GP);
            if (tmp & IWN_OTP_GP_ECC_UNCORR_STTS) {
                XYLog("%s: OTPROM ECC error at 0x%x\n",
                    sc->sc_dev.dv_xname, addr);
                return EIO;
            }
            if (tmp & IWN_OTP_GP_ECC_CORR_STTS) {
                /* Correctable ECC error, clear bit. */
                IWN_SETBITS(sc, IWN_OTP_GP,
                    IWN_OTP_GP_ECC_CORR_STTS);
            }
        }
        *out++ = val >> 16;
        if (count > 1)
            *out++ = val >> 24;
    }
    return 0;
}

bool allocDmaMemory2(struct iwn_dma_info *dma, size_t size, int alignment)
{
    IOBufferMemoryDescriptor *bmd;
    IODMACommand::Segment64 seg;
    UInt64 ofs = 0;
    UInt32 numSegs = 1;
    
    bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache, size, DMA_BIT_MASK(64));
    
    if (bmd == NULL) {
        XYLog("%s alloc DMA memory failed.\n", __FUNCTION__);
        return false;
    }
    
    bmd->prepare();
    IODMACommand *cmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, alignment);
    
    if (cmd == NULL) {
        XYLog("%s alloc IODMACommand memory failed.\n", __FUNCTION__);
        bmd->complete();
        bmd->release();
        return false;
    }
    
    cmd->setMemoryDescriptor(bmd);

    if (cmd->gen64IOVMSegments(&ofs, &seg, &numSegs) != kIOReturnSuccess) {
        cmd->release();
        cmd = NULL;
        bmd->complete();
        bmd->release();
        bmd = NULL;
        return false;
    }
    dma->paddr = seg.fIOVMAddr;
    dma->vaddr = bmd->getBytesNoCopy();
    dma->size = size;
    dma->buffer = bmd;
    dma->cmd = cmd;
    memset(dma->vaddr, 0, dma->size);
    return true;
}

int ItlIwn::
iwn_dma_contig_alloc(bus_dma_tag_t tag, struct iwn_dma_info *dma,
                     void** kvap, bus_size_t size, bus_size_t alignment)
{
    if (!allocDmaMemory2(dma, size, alignment)) {
        return 1;
    }
    
    if (kvap != NULL)
        *kvap = dma->vaddr;

    return 0;
}

void ItlIwn::
iwn_dma_contig_free(struct iwn_dma_info *dma)
{
    if (dma == NULL || dma->cmd == NULL)
        return;
    if (dma->vaddr == NULL)
        return;
    dma->cmd->clearMemoryDescriptor();
    dma->cmd->release();
    dma->cmd = NULL;
    dma->buffer->complete();
    dma->buffer->release();
    dma->buffer = NULL;
    dma->vaddr = NULL;
}

int ItlIwn::
iwn_alloc_sched(struct iwn_softc *sc)
{
    /* TX scheduler rings must be aligned on a 1KB boundary. */
    return iwn_dma_contig_alloc(sc->sc_dmat, &sc->sched_dma,
        (void **)&sc->sched, sc->schedsz, 1024);
}

void ItlIwn::
iwn_free_sched(struct iwn_softc *sc)
{
    iwn_dma_contig_free(&sc->sched_dma);
}

int ItlIwn::
iwn_alloc_kw(struct iwn_softc *sc)
{
    /* "Keep Warm" page must be aligned on a 4KB boundary. */
    return iwn_dma_contig_alloc(sc->sc_dmat, &sc->kw_dma, NULL, 4096,
        4096);
}

void ItlIwn::
iwn_free_kw(struct iwn_softc *sc)
{
    iwn_dma_contig_free(&sc->kw_dma);
}

int ItlIwn::
iwn_alloc_ict(struct iwn_softc *sc)
{
    /* ICT table must be aligned on a 4KB boundary. */
    return iwn_dma_contig_alloc(sc->sc_dmat, &sc->ict_dma,
        (void **)&sc->ict, IWN_ICT_SIZE, 4096);
}

void ItlIwn::
iwn_free_ict(struct iwn_softc *sc)
{
    iwn_dma_contig_free(&sc->ict_dma);
}

int ItlIwn::
iwn_alloc_fwmem(struct iwn_softc *sc)
{
    /* Must be aligned on a 16-byte boundary. */
    return iwn_dma_contig_alloc(sc->sc_dmat, &sc->fw_dma, NULL,
        sc->fwsz, 16);
}

void ItlIwn::
iwn_free_fwmem(struct iwn_softc *sc)
{
    iwn_dma_contig_free(&sc->fw_dma);
}

int ItlIwn::
iwn_alloc_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
    bus_size_t size;
    int i, error;
    mbuf_t m;

    ring->cur = 0;

    /* Allocate RX descriptors (256-byte aligned). */
    size = IWN_RX_RING_COUNT * sizeof (uint32_t);
    error = iwn_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma,
        (void **)&ring->desc, size, 256);
    if (error != 0) {
        XYLog("%s: could not allocate RX ring DMA memory\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    /* Allocate RX status area (16-byte aligned). */
    error = iwn_dma_contig_alloc(sc->sc_dmat, &ring->stat_dma,
        (void **)&ring->stat, sizeof (struct iwn_rx_status), 16);
    if (error != 0) {
        XYLog("%s: could not allocate RX status DMA memory\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    /*
     * Allocate and map RX buffers.
     */
    for (i = 0; i < IWN_RX_RING_COUNT; i++) {
        struct iwn_rx_data *data = &ring->data[i];

        error = bus_dmamap_create(sc->sc_dmat, IWN_RBUF_SIZE, 1,
            IWN_RBUF_SIZE, 0, BUS_DMA_NOWAIT,
            &data->map);
        if (error != 0) {
            XYLog("%s: could not create RX buf DMA map\n",
                sc->sc_dev.dv_xname);
            goto fail;
        }

        m = getController()->allocatePacket(IWN_RBUF_SIZE);
        if (m == NULL) {
            XYLog("could not allocate RX mbuf\n");
            error = ENOBUFS;
            goto fail;
        }
        data->map->dm_nsegs = data->map->cursor->getPhysicalSegments(m, &data->map->dm_segs[0], 1);
        if (data->map->dm_nsegs == 0) {
            mbuf_freem(m);
            error = ENOMEM;
            goto fail;
        }
        
        data->m = m;
        
//        data->m = MCLGETI(NULL, M_DONTWAIT, NULL, IWN_RBUF_SIZE);
//        if (data->m == NULL) {
//            XYLog("%s: could not allocate RX mbuf\n",
//                sc->sc_dev.dv_xname);
//            error = ENOBUFS;
//            goto fail;
//        }
//
//        error = bus_dmamap_load(sc->sc_dmat, data->map,
//            mtod(data->m, void *), IWN_RBUF_SIZE, NULL,
//            BUS_DMA_NOWAIT | BUS_DMA_READ);
//        if (error != 0) {
//            XYLog("%s: can't map mbuf (error %d)\n",
//                sc->sc_dev.dv_xname, error);
//            goto fail;
//        }

        /* Set physical address of RX buffer (256-byte aligned). */
        ring->desc[i] = htole32(data->map->dm_segs[0].location >> 8);
    }

//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map, 0, size,
//        BUS_DMASYNC_PREWRITE);

    return 0;

fail:    iwn_free_rx_ring(sc, ring);
    return error;
}

void ItlIwn::
iwn_reset_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
    int ntries;

    if (iwn_nic_lock(sc) == 0) {
        IWN_WRITE(sc, IWN_FH_RX_CONFIG, 0);
        for (ntries = 0; ntries < 1000; ntries++) {
            if (IWN_READ(sc, IWN_FH_RX_STATUS) &
                IWN_FH_RX_STATUS_IDLE)
                break;
            DELAY(10);
        }
        iwn_nic_unlock(sc);
    }
    ring->cur = 0;
    sc->last_rx_valid = 0;
}

void ItlIwn::
iwn_free_rx_ring(struct iwn_softc *sc, struct iwn_rx_ring *ring)
{
    int i;

    iwn_dma_contig_free(&ring->desc_dma);
    iwn_dma_contig_free(&ring->stat_dma);

    for (i = 0; i < IWN_RX_RING_COUNT; i++) {
        struct iwn_rx_data *data = &ring->data[i];

        if (data->m != NULL) {
//            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
//                data->map->dm_mapsize, BUS_DMASYNC_POSTREAD);
//            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
}

int ItlIwn::
iwn_alloc_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring, int qid)
{
    bus_addr_t paddr;
    bus_size_t size;
    int i, error;

    ring->qid = qid;
    ring->queued = 0;
    ring->cur = 0;

    /* Allocate TX descriptors (256-byte aligned). */
    size = IWN_TX_RING_COUNT * sizeof (struct iwn_tx_desc);
    error = iwn_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma,
        (void **)&ring->desc, size, 256);
    if (error != 0) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    size = IWN_TX_RING_COUNT * sizeof (struct iwn_tx_cmd);
    error = iwn_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma,
        (void **)&ring->cmd, size, 4);
    if (error != 0) {
        XYLog("%s: could not allocate TX cmd DMA memory\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    paddr = ring->cmd_dma.paddr;
    for (i = 0; i < IWN_TX_RING_COUNT; i++) {
        struct iwn_tx_data *data = &ring->data[i];

        data->cmd_paddr = paddr;
        data->scratch_paddr = paddr + 12;
        paddr += sizeof (struct iwn_tx_cmd);

        error = bus_dmamap_create(sc->sc_dmat, MCLBYTES,
            IWN_MAX_SCATTER - 1, MCLBYTES, 0, BUS_DMA_NOWAIT,
            &data->map);
        if (error != 0) {
            XYLog("%s: could not create TX buf DMA map\n",
                sc->sc_dev.dv_xname);
            goto fail;
        }
    }
    return 0;

fail:    iwn_free_tx_ring(sc, ring);
    return error;
}

void ItlIwn::
iwn_reset_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring)
{
    int i;

    for (i = 0; i < IWN_TX_RING_COUNT; i++) {
        struct iwn_tx_data *data = &ring->data[i];

        if (data->m != NULL) {
//            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
//                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
//            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
    }
    /* Clear TX descriptors. */
    memset(ring->desc, 0, ring->desc_dma.size);
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map, 0,
//        ring->desc_dma.size, BUS_DMASYNC_PREWRITE);
    sc->qfullmsk &= ~(1 << ring->qid);
    ring->queued = 0;
    ring->cur = 0;
}

void ItlIwn::
iwn_free_tx_ring(struct iwn_softc *sc, struct iwn_tx_ring *ring)
{
    int i;

    iwn_dma_contig_free(&ring->desc_dma);
    iwn_dma_contig_free(&ring->cmd_dma);

    for (i = 0; i < IWN_TX_RING_COUNT; i++) {
        struct iwn_tx_data *data = &ring->data[i];

        if (data->m != NULL) {
//            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
//                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
//            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
}

void ItlIwn::
iwn5000_ict_reset(struct iwn_softc *sc)
{
    /* Disable interrupts. */
    IWN_WRITE(sc, IWN_INT_MASK, 0);

    /* Reset ICT table. */
    memset(sc->ict, 0, IWN_ICT_SIZE);
    sc->ict_cur = 0;

    /* Set physical address of ICT table (4KB aligned). */
    DPRINTF(("enabling ICT\n"));
    IWN_WRITE(sc, IWN_DRAM_INT_TBL, IWN_DRAM_INT_TBL_ENABLE |
        IWN_DRAM_INT_TBL_WRAP_CHECK | sc->ict_dma.paddr >> 12);

    /* Enable periodic RX interrupt. */
    sc->int_mask |= IWN_INT_RX_PERIODIC;
    /* Switch to ICT interrupt mode in driver. */
    sc->sc_flags |= IWN_FLAG_USE_ICT;

    /* Re-enable interrupts. */
    IWN_WRITE(sc, IWN_INT, 0xffffffff);
    IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
}

int ItlIwn::
iwn_read_eeprom(struct iwn_softc *sc)
{
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    uint16_t val;
    int error;

    /* Check whether adapter has an EEPROM or an OTPROM. */
    if (sc->hw_type >= IWN_HW_REV_TYPE_1000 &&
        (IWN_READ(sc, IWN_OTP_GP) & IWN_OTP_GP_DEV_SEL_OTP))
        sc->sc_flags |= IWN_FLAG_HAS_OTPROM;
    DPRINTF(("%s found\n", (sc->sc_flags & IWN_FLAG_HAS_OTPROM) ?
        "OTPROM" : "EEPROM"));

    /* Adapter has to be powered on for EEPROM access to work. */
    if ((error = iwn_apm_init(sc)) != 0) {
        XYLog("%s: could not power ON adapter\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    if ((IWN_READ(sc, IWN_EEPROM_GP) & 0x7) == 0) {
        XYLog("%s: bad ROM signature\n", sc->sc_dev.dv_xname);
        return EIO;
    }
    if ((error = iwn_eeprom_lock(sc)) != 0) {
        XYLog("%s: could not lock ROM (error=%d)\n",
            sc->sc_dev.dv_xname, error);
        return error;
    }
    if (sc->sc_flags & IWN_FLAG_HAS_OTPROM) {
        if ((error = iwn_init_otprom(sc)) != 0) {
            XYLog("%s: could not initialize OTPROM\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }

    iwn_read_prom_data(sc, IWN_EEPROM_SKU_CAP, &val, 2);
    DPRINTF(("SKU capabilities=0x%04x\n", letoh16(val)));
    /* Check if HT support is bonded out. */
    if (val & htole16(IWN_EEPROM_SKU_CAP_11N))
        sc->sc_flags |= IWN_FLAG_HAS_11N;

    iwn_read_prom_data(sc, IWN_EEPROM_RFCFG, &val, 2);
    sc->rfcfg = letoh16(val);
    DPRINTF(("radio config=0x%04x\n", sc->rfcfg));
    /* Read Tx/Rx chains from ROM unless it's known to be broken. */
    if (sc->txchainmask == 0)
        sc->txchainmask = IWN_RFCFG_TXANTMSK(sc->rfcfg);
    if (sc->rxchainmask == 0)
        sc->rxchainmask = IWN_RFCFG_RXANTMSK(sc->rfcfg);

    /* Read MAC address. */
    iwn_read_prom_data(sc, IWN_EEPROM_MAC, ic->ic_myaddr, 6);

    /* Read adapter-specific information from EEPROM. */
    ops->read_eeprom(sc);

    iwn_apm_stop(sc);    /* Power OFF adapter. */

    iwn_eeprom_unlock(sc);
    return 0;
}

void ItlIwn::
iwn4965_read_eeprom(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    
    uint32_t addr;
    uint16_t val;
    int i;

    /* Read regulatory domain (4 ASCII characters). */
    that->iwn_read_prom_data(sc, IWN4965_EEPROM_DOMAIN, sc->eeprom_domain, 4);

    /* Read the list of authorized channels. */
    for (i = 0; i < 7; i++) {
        addr = iwn4965_regulatory_bands[i];
        that->iwn_read_eeprom_channels(sc, i, addr);
    }

    /* Read maximum allowed TX power for 2GHz and 5GHz bands. */
    that->iwn_read_prom_data(sc, IWN4965_EEPROM_MAXPOW, &val, 2);
    sc->maxpwr2GHz = val & 0xff;
    sc->maxpwr5GHz = val >> 8;
    /* Check that EEPROM values are within valid range. */
    if (sc->maxpwr5GHz < 20 || sc->maxpwr5GHz > 50)
        sc->maxpwr5GHz = 38;
    if (sc->maxpwr2GHz < 20 || sc->maxpwr2GHz > 50)
        sc->maxpwr2GHz = 38;
    DPRINTF(("maxpwr 2GHz=%d 5GHz=%d\n", sc->maxpwr2GHz, sc->maxpwr5GHz));

    /* Read samples for each TX power group. */
    that->iwn_read_prom_data(sc, IWN4965_EEPROM_BANDS, sc->bands,
        sizeof sc->bands);

    /* Read voltage at which samples were taken. */
    that->iwn_read_prom_data(sc, IWN4965_EEPROM_VOLTAGE, &val, 2);
    sc->eeprom_voltage = (int16_t)letoh16(val);
    DPRINTF(("voltage=%d (in 0.3V)\n", sc->eeprom_voltage));

#ifdef IWN_DEBUG
    /* Print samples. */
    if (iwn_debug > 0) {
        for (i = 0; i < IWN_NBANDS; i++)
            that->iwn4965_print_power_group(sc, i);
    }
#endif
}

#ifdef IWN_DEBUG
void ItlIwn::
iwn4965_print_power_group(struct iwn_softc *sc, int i)
{
    struct iwn4965_eeprom_band *band = &sc->bands[i];
    struct iwn4965_eeprom_chan_samples *chans = band->chans;
    int j, c;

    XYLog("===band %d===\n", i);
    XYLog("chan lo=%d, chan hi=%d\n", band->lo, band->hi);
    XYLog("chan1 num=%d\n", chans[0].num);
    for (c = 0; c < 2; c++) {
        for (j = 0; j < IWN_NSAMPLES; j++) {
            XYLog("chain %d, sample %d: temp=%d gain=%d "
                "power=%d pa_det=%d\n", c, j,
                chans[0].samples[c][j].temp,
                chans[0].samples[c][j].gain,
                chans[0].samples[c][j].power,
                chans[0].samples[c][j].pa_det);
        }
    }
    XYLog("chan2 num=%d\n", chans[1].num);
    for (c = 0; c < 2; c++) {
        for (j = 0; j < IWN_NSAMPLES; j++) {
            XYLog("chain %d, sample %d: temp=%d gain=%d "
                "power=%d pa_det=%d\n", c, j,
                chans[1].samples[c][j].temp,
                chans[1].samples[c][j].gain,
                chans[1].samples[c][j].power,
                chans[1].samples[c][j].pa_det);
        }
    }
}
#endif

void ItlIwn::
iwn5000_read_eeprom(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_eeprom_calib_hdr hdr;
    int32_t volt;
    uint32_t base, addr;
    uint16_t val;
    int i;

    /* Read regulatory domain (4 ASCII characters). */
    that->iwn_read_prom_data(sc, IWN5000_EEPROM_REG, &val, 2);
    base = letoh16(val);
    that->iwn_read_prom_data(sc, base + IWN5000_EEPROM_DOMAIN,
        sc->eeprom_domain, 4);

    /* Read the list of authorized channels. */
    for (i = 0; i < 7; i++) {
        addr = base + iwn5000_regulatory_bands[i];
        that->iwn_read_eeprom_channels(sc, i, addr);
    }

    /* Read enhanced TX power information for 6000 Series. */
    if (sc->hw_type >= IWN_HW_REV_TYPE_6000)
        that->iwn_read_eeprom_enhinfo(sc);

    that->iwn_read_prom_data(sc, IWN5000_EEPROM_CAL, &val, 2);
    base = letoh16(val);
    that->iwn_read_prom_data(sc, base, &hdr, sizeof hdr);
    DPRINTF(("calib version=%u pa type=%u voltage=%u\n",
        hdr.version, hdr.pa_type, letoh16(hdr.volt)));
    sc->calib_ver = hdr.version;

    if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
        sc->hw_type == IWN_HW_REV_TYPE_2000 ||
        sc->hw_type == IWN_HW_REV_TYPE_135 ||
        sc->hw_type == IWN_HW_REV_TYPE_105) {
        sc->eeprom_voltage = letoh16(hdr.volt);
        that->iwn_read_prom_data(sc, base + IWN5000_EEPROM_TEMP, &val, 2);
        sc->eeprom_temp = letoh16(val);
        that->iwn_read_prom_data(sc, base + IWN2000_EEPROM_RAWTEMP, &val, 2);
        sc->eeprom_rawtemp = letoh16(val);
    }

    if (sc->hw_type == IWN_HW_REV_TYPE_5150) {
        /* Compute temperature offset. */
        that->iwn_read_prom_data(sc, base + IWN5000_EEPROM_TEMP, &val, 2);
        sc->eeprom_temp = letoh16(val);
        that->iwn_read_prom_data(sc, base + IWN5000_EEPROM_VOLT, &val, 2);
        volt = letoh16(val);
        sc->temp_off = sc->eeprom_temp - (volt / -5);
        DPRINTF(("temp=%d volt=%d offset=%dK\n",
            sc->eeprom_temp, volt, sc->temp_off));
    } else {
        /* Read crystal calibration. */
        that->iwn_read_prom_data(sc, base + IWN5000_EEPROM_CRYSTAL,
            &sc->eeprom_crystal, sizeof (uint32_t));
        DPRINTF(("crystal calibration 0x%08x\n",
            letoh32(sc->eeprom_crystal)));
    }
}

void ItlIwn::
iwn_read_eeprom_channels(struct iwn_softc *sc, int n, uint32_t addr)
{
    struct ieee80211com *ic = &sc->sc_ic;
    const struct iwn_chan_band *band = &iwn_bands[n];
    struct iwn_eeprom_chan channels[IWN_MAX_CHAN_PER_BAND];
    uint8_t chan;
    int i;

    iwn_read_prom_data(sc, addr, channels,
        band->nchan * sizeof (struct iwn_eeprom_chan));

    for (i = 0; i < band->nchan; i++) {
        if (!(channels[i].flags & IWN_EEPROM_CHAN_VALID))
            continue;

        chan = band->chan[i];

        if (n == 0) {    /* 2GHz band */
            ic->ic_channels[chan].ic_freq =
                ieee80211_ieee2mhz(chan, IEEE80211_CHAN_2GHZ);
            ic->ic_channels[chan].ic_flags =
                IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
                IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;

        } else if (n < 5) {    /* 5GHz band */
            /*
             * Some adapters support channels 7, 8, 11 and 12
             * both in the 2GHz and 4.9GHz bands.
             * Because of limitations in our net80211 layer,
             * we don't support them in the 4.9GHz band.
             */
            if (chan <= 14)
                continue;

            ic->ic_channels[chan].ic_freq =
                ieee80211_ieee2mhz(chan, IEEE80211_CHAN_5GHZ);
            ic->ic_channels[chan].ic_flags = IEEE80211_CHAN_A;
            /* We have at least one valid 5GHz channel. */
            sc->sc_flags |= IWN_FLAG_HAS_5GHZ;
        } else  { /* 40 MHz */
            sc->maxpwr40[chan] = channels[i].maxpwr;
            ic->ic_channels[chan].ic_flags |= IEEE80211_CHAN_HT40;
        }

        /* Is active scan allowed on this channel? */
        if (n < 5) {
            /* Is active scan allowed on this channel? */
            if (!(channels[i].flags & IWN_EEPROM_CHAN_ACTIVE)) {
                ic->ic_channels[chan].ic_flags |=
                IEEE80211_CHAN_PASSIVE;
            }

            /* Save maximum allowed TX power for this channel. */
            sc->maxpwr[chan] = channels[i].maxpwr;

            if (sc->sc_flags & IWN_FLAG_HAS_11N)
                ic->ic_channels[chan].ic_flags |=
                IEEE80211_CHAN_HT;
        }

        DPRINTF(("adding chan %d flags=0x%x maxpwr=%d maxpwr40=%d\n",
                 chan, channels[i].flags, sc->maxpwr[chan],
                 sc->maxpwr40[chan]));
    }
}

void ItlIwn::
iwn_read_eeprom_enhinfo(struct iwn_softc *sc)
{
    struct iwn_eeprom_enhinfo enhinfo[35];
    uint16_t val, base;
    int8_t maxpwr;
    int i;

    iwn_read_prom_data(sc, IWN5000_EEPROM_REG, &val, 2);
    base = letoh16(val);
    iwn_read_prom_data(sc, base + IWN6000_EEPROM_ENHINFO,
        enhinfo, sizeof enhinfo);

    memset(sc->enh_maxpwr, 0, sizeof sc->enh_maxpwr);
    for (i = 0; i < nitems(enhinfo); i++) {
        if ((enhinfo[i].flags & IWN_TXP_VALID) == 0)
            continue;    /* Skip invalid entries. */

        maxpwr = 0;
        if (sc->txchainmask & IWN_ANT_A)
            maxpwr = MAX(maxpwr, enhinfo[i].chain[0]);
        if (sc->txchainmask & IWN_ANT_B)
            maxpwr = MAX(maxpwr, enhinfo[i].chain[1]);
        if (sc->txchainmask & IWN_ANT_C)
            maxpwr = MAX(maxpwr, enhinfo[i].chain[2]);
        if (sc->ntxchains == 2)
            maxpwr = MAX(maxpwr, enhinfo[i].mimo2);
        else if (sc->ntxchains == 3)
            maxpwr = MAX(maxpwr, enhinfo[i].mimo3);
        maxpwr /= 2;    /* Convert half-dBm to dBm. */

        DPRINTF(("enhinfo %d, maxpwr=%d\n", i, maxpwr));
        sc->enh_maxpwr[i] = maxpwr;
    }
}

struct ieee80211_node * ItlIwn::
iwn_node_alloc(struct ieee80211com *ic)
{
    return (ieee80211_node *)malloc(sizeof (struct iwn_node), M_DEVBUF, M_NOWAIT | M_ZERO);
}

void ItlIwn::
iwn_newassoc(struct ieee80211com *ic, struct ieee80211_node *ni, int isnew)
{
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_if.if_softc;
    struct iwn_node *wn = (struct iwn_node *)ni;
    uint8_t rate;
    int ridx, i;

    if ((ni->ni_flags & IEEE80211_NODE_HT) == 0)
        ieee80211_amrr_node_init(&sc->amrr, &wn->amn);

    /* Start at lowest available bit-rate, AMRR/MiRA will raise. */
    ni->ni_txrate = 0;
    ni->ni_txmcs = 0;

    for (i = 0; i < ni->ni_rates.rs_nrates; i++) {
        rate = ni->ni_rates.rs_rates[i] & IEEE80211_RATE_VAL;
        /* Map 802.11 rate to HW rate index. */
        for (ridx = 0; ridx <= IWN_RIDX_MAX; ridx++) {
            if (iwn_rates[ridx].plcp != IWN_RATE_INVM_PLCP &&
                iwn_rates[ridx].rate == rate)
                break;
        }
        wn->ridx[i] = ridx;
    }
}

int ItlIwn::
iwn_media_change(struct _ifnet *ifp)
{
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rate, ridx;
    int error;

    error = ieee80211_media_change(ifp);
    if (error != ENETRESET)
        return error;

    if (ic->ic_fixed_mcs != -1)
        sc->fixed_ridx = iwn_mcs2ridx[ic->ic_fixed_mcs];
    if (ic->ic_fixed_rate != -1) {
        rate = ic->ic_sup_rates[ic->ic_curmode].
            rs_rates[ic->ic_fixed_rate] & IEEE80211_RATE_VAL;
        /* Map 802.11 rate to HW rate index. */
        for (ridx = 0; ridx <= IWN_RIDX_MAX; ridx++)
            if (iwn_rates[ridx].plcp != IWN_RATE_INVM_PLCP &&
                iwn_rates[ridx].rate == rate)
                break;
        sc->fixed_ridx = ridx;
    }

    if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
        (IFF_UP | IFF_RUNNING)) {
        iwn_stop(ifp);
        error = iwn_init(ifp);
    }
    return error;
}

int ItlIwn::
iwn_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
    XYLog("%s nstate=%d\n", __FUNCTION__, nstate);
    struct _ifnet *ifp = &ic->ic_if;
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    struct ieee80211_node *ni = ic->ic_bss;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int error;

    if (ic->ic_state == IEEE80211_S_RUN) {
        if (nstate == IEEE80211_S_SCAN) {
            /*
             * During RUN->SCAN we don't call sc_newstate() so
             * we must stop A-MPDU Tx ourselves in this case.
             */
            ieee80211_stop_ampdu_tx(ic, ni, -1);
            ieee80211_ba_del(ni);
        }
        timeout_del(&sc->calib_to);
        sc->calib.state = IWN_CALIB_STATE_INIT;
        if (sc->sc_flags & IWN_FLAG_BGSCAN)
            that->iwn_scan_abort(sc);
    }

    if (ic->ic_state == IEEE80211_S_SCAN) {
        if (nstate == IEEE80211_S_SCAN) {
            if (sc->sc_flags & IWN_FLAG_SCANNING)
                return 0;
        } else
            sc->sc_flags &= ~IWN_FLAG_SCANNING;
        /* Turn LED off when leaving scan state. */
        that->iwn_set_led(sc, IWN_LED_LINK, 1, 0);
    }

    if (ic->ic_state >= IEEE80211_S_ASSOC &&
        nstate <= IEEE80211_S_ASSOC) {
        /* Reset state to handle re- and disassociations. */
        sc->rxon.associd = 0;
        sc->rxon.filter &= ~htole32(IWN_FILTER_BSS);
        sc->rxon.flags &= ~htole32(IWN_RXON_HT_CHANMODE_MIXED2040 |
                                   IWN_RXON_HT_CHANMODE_PURE40 | IWN_RXON_HT_HT40MINUS);
        sc->calib.state = IWN_CALIB_STATE_INIT;
        sc->agg_queue_mask = 0;
        error = that->iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
        if (error != 0)
            XYLog("%s: RXON command failed\n",
                sc->sc_dev.dv_xname);
    }

    switch (nstate) {
    case IEEE80211_S_SCAN:
        /* Make the link LED blink while we're scanning. */
        that->iwn_set_led(sc, IWN_LED_LINK, 10, 10);

        if ((sc->sc_flags & IWN_FLAG_BGSCAN) == 0) {
            ieee80211_set_link_state(ic, LINK_STATE_DOWN);
            ieee80211_node_cleanup(ic, ic->ic_bss);
        }
        if (ifp->if_flags & IFF_DEBUG)
            XYLog("%s: %s -> %s\n", ifp->if_xname,
                ieee80211_state_name[ic->ic_state],
                ieee80211_state_name[nstate]);
        ic->ic_state = nstate;
        if ((error = that->iwn_scan(sc, IEEE80211_CHAN_2GHZ, 0)) != 0) {
            printf("%s: could not initiate scan\n",
                sc->sc_dev.dv_xname);
        }
        return error;

    case IEEE80211_S_ASSOC:
        if (ic->ic_state != IEEE80211_S_RUN)
            break;
        /* FALLTHROUGH */
    case IEEE80211_S_AUTH:
        if ((error = that->iwn_auth(sc, arg)) != 0) {
            XYLog("%s: could not move to auth state\n",
                sc->sc_dev.dv_xname);
            return error;
        }
        break;

    case IEEE80211_S_RUN:
        if ((error = that->iwn_run(sc)) != 0) {
            XYLog("%s: could not move to run state\n",
                sc->sc_dev.dv_xname);
            return error;
        }
        break;

    case IEEE80211_S_INIT:
        sc->calib.state = IWN_CALIB_STATE_INIT;
        break;
    }

    return sc->sc_newstate(ic, nstate, arg);
}

void ItlIwn::
iwn_iter_func(void *arg, struct ieee80211_node *ni)
{
    struct iwn_softc *sc = (struct iwn_softc*)arg;
    struct iwn_node *wn = (struct iwn_node*)ni;
    ItlIwn *that = container_of(sc, ItlIwn, com);

    if ((ni->ni_flags & IEEE80211_NODE_HT) == 0) {
        int old_txrate = ni->ni_txrate;
        ieee80211_amrr_choose(&sc->amrr, ni, &wn->amn);
        if (old_txrate != ni->ni_txrate)
            that->iwn_set_link_quality(sc, ni);
    }
}

void ItlIwn::
iwn_calib_timeout(void *arg)
{
    struct iwn_softc *sc = (struct iwn_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int s;

    s = splnet();
    if (ic->ic_fixed_rate == -1) {
        if (ic->ic_opmode == IEEE80211_M_STA)
            that->iwn_iter_func(sc, ic->ic_bss);
        else
            ieee80211_iterate_nodes(ic, iwn_iter_func, sc);
    }
    /* Force automatic TX power calibration every 60 secs. */
    if (++sc->calib_cnt >= 120) {
        uint32_t flags = 0;

        DPRINTFN(2, ("sending request for statistics\n"));
        (void)that->iwn_cmd(sc, IWN_CMD_GET_STATISTICS, &flags,
            sizeof flags, 1);
        sc->calib_cnt = 0;
    }
    splx(s);

    /* Automatic rate control triggered every 500ms. */
    timeout_add_msec(&sc->calib_to, 500);
}

int ItlIwn::
iwn_ccmp_decap(struct iwn_softc *sc, mbuf_t m, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_key *k = &ni->ni_pairwise_key;
    struct ieee80211_frame *wh;
    uint64_t pn, *prsc;
    uint8_t *ivp;
    uint8_t tid;
    int hdrlen, hasqos;

    wh = mtod(m, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);
    ivp = (uint8_t *)wh + hdrlen;

    /* Check that ExtIV bit is set. */
    if (!(ivp[3] & IEEE80211_WEP_EXTIV)) {
        DPRINTF(("CCMP decap ExtIV not set\n"));
        return 1;
    }
    hasqos = ieee80211_has_qos(wh);
    tid = hasqos ? ieee80211_get_qos(wh) & IEEE80211_QOS_TID : 0;
    prsc = &k->k_rsc[tid];

    /* Extract the 48-bit PN from the CCMP header. */
    pn = (uint64_t)ivp[0]       |
         (uint64_t)ivp[1] <<  8 |
         (uint64_t)ivp[4] << 16 |
         (uint64_t)ivp[5] << 24 |
         (uint64_t)ivp[6] << 32 |
         (uint64_t)ivp[7] << 40;
    if (pn <= *prsc) {
        ic->ic_stats.is_ccmp_replays++;
        return 1;
    }
    /* Last seen packet number is updated in ieee80211_inputm(). */

    /* Strip MIC. IV will be stripped by ieee80211_inputm(). */
    mbuf_adj(m, -IEEE80211_CCMP_MICLEN);
    return 0;
}

/*
 * Process an RX_PHY firmware notification.  This is usually immediately
 * followed by an MPDU_RX_DONE notification.
 */
void ItlIwn::
iwn_rx_phy(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    struct iwn_rx_stat *stat = (struct iwn_rx_stat *)(desc + 1);

    DPRINTFN(2, ("received PHY stats\n"));
    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
        sizeof (*stat), BUS_DMASYNC_POSTREAD);

    /* Save RX statistics, they will be used on MPDU_RX_DONE. */
    memcpy(&sc->last_rx_stat, stat, sizeof (*stat));
    sc->last_rx_valid = IWN_LAST_RX_VALID;
    /*
     * The firmware does not send separate RX_PHY
     * notifications for A-MPDU subframes.
     */
    if (stat->flags & htole16(IWN_STAT_FLAG_AGG))
        sc->last_rx_valid |= IWN_LAST_RX_AMPDU;
}

/*
 * Process an RX_DONE (4965AGN only) or MPDU_RX_DONE firmware notification.
 * Each MPDU_RX_DONE notification must be preceded by an RX_PHY one.
 */
void ItlIwn::
iwn_rx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data, struct mbuf_list *ml)
{
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    struct iwn_rx_ring *ring = &sc->rxq;
    struct ieee80211_frame *wh;
    struct ieee80211_rxinfo rxi;
    struct ieee80211_node *ni;
    mbuf_t m, m1;
    struct iwn_rx_stat *stat;
    caddr_t head;
    uint32_t flags;
    int error, len, rssi;
    uint16_t chan;

    if (desc->type == IWN_MPDU_RX_DONE) {
        /* Check for prior RX_PHY notification. */
        if (!sc->last_rx_valid) {
            DPRINTF(("missing RX_PHY\n"));
            return;
        }
        sc->last_rx_valid &= ~IWN_LAST_RX_VALID;
        stat = &sc->last_rx_stat;
        if ((sc->last_rx_valid & IWN_LAST_RX_AMPDU) &&
            (stat->flags & htole16(IWN_STAT_FLAG_AGG)) == 0) {
            DPRINTF(("missing RX_PHY (expecting A-MPDU)\n"));
            return;
        }
        if ((sc->last_rx_valid & IWN_LAST_RX_AMPDU) == 0 &&
            (stat->flags & htole16(IWN_STAT_FLAG_AGG))) {
            DPRINTF(("missing RX_PHY (unexpected A-MPDU)\n"));
            return;
        }
    } else
        stat = (struct iwn_rx_stat *)(desc + 1);

    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWN_RBUF_SIZE,
        BUS_DMASYNC_POSTREAD);

    if (stat->cfg_phy_len > IWN_STAT_MAXLEN) {
        XYLog("%s: invalid RX statistic header\n",
            sc->sc_dev.dv_xname);
        return;
    }
    if (desc->type == IWN_MPDU_RX_DONE) {
        struct iwn_rx_mpdu *mpdu = (struct iwn_rx_mpdu *)(desc + 1);
        head = (caddr_t)(mpdu + 1);
        len = letoh16(mpdu->len);
    } else {
        head = (caddr_t)(stat + 1) + stat->cfg_phy_len;
        len = letoh16(stat->len);
    }

    flags = letoh32(*(uint32_t *)(head + len));

    /* Discard frames with a bad FCS early. */
    if ((flags & IWN_RX_NOERROR) != IWN_RX_NOERROR) {
        DPRINTFN(2, ("RX flags error %x\n", flags));
        ifp->netStat->inputErrors++;
        return;
    }
    /* Discard frames that are too short. */
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Allow control frames in monitor mode. */
        if (len < sizeof (struct ieee80211_frame_cts)) {
            ic->ic_stats.is_rx_tooshort++;
            ifp->netStat->inputErrors++;
            return;
        }
    } else if (len < sizeof (*wh)) {
        ic->ic_stats.is_rx_tooshort++;
        ifp->netStat->inputErrors++;
        return;
    }
    
    m1 = getController()->allocatePacket(IWN_RBUF_SIZE);
    if (m1 == NULL) {
        XYLog("could not allocate RX mbuf\n");
        ic->ic_stats.is_rx_nombuf++;
        ifp->netStat->inputErrors++;
        return;
    }
    data->map->dm_nsegs = data->map->cursor->getPhysicalSegments(m1, &data->map->dm_segs[0], 1);
    if (data->map->dm_nsegs == 0) {
        XYLog("could not map RX mbuf\n");
        mbuf_freem(m1);
        ifp->netStat->inputErrors++;
        return;
    }
    
//    m1 = MCLGETI(NULL, M_DONTWAIT, NULL, IWN_RBUF_SIZE);
//    if (m1 == NULL) {
//        ic->ic_stats.is_rx_nombuf++;
//        ifp->netStat->inputErrors++;
//        return;
//    }
//    bus_dmamap_unload(sc->sc_dmat, data->map);
//
//    error = bus_dmamap_load(sc->sc_dmat, data->map, mtod(m1, void *),
//        IWN_RBUF_SIZE, NULL, BUS_DMA_NOWAIT | BUS_DMA_READ);
//    if (error != 0) {
//        mbuf_freem(m1);
//
//        /* Try to reload the old mbuf. */
//        error = bus_dmamap_load(sc->sc_dmat, data->map,
//            mtod(data->m, void *), IWN_RBUF_SIZE, NULL,
//            BUS_DMA_NOWAIT | BUS_DMA_READ);
//        if (error != 0) {
//            panic("%s: could not load old RX mbuf",
//                sc->sc_dev.dv_xname);
//        }
//        /* Physical address may have changed. */
//        ring->desc[ring->cur] =
//            htole32(data->map->dm_segs[0].ds_addr >> 8);
//        bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//            ring->cur * sizeof (uint32_t), sizeof (uint32_t),
//            BUS_DMASYNC_PREWRITE);
//        ifp->netStat->inputErrors++;
//        return;
//    }

    m = data->m;
    data->m = m1;
    /* Update RX descriptor. */
    ring->desc[ring->cur] = htole32(data->map->dm_segs[0].location >> 8);
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//        ring->cur * sizeof (uint32_t), sizeof (uint32_t),
//        BUS_DMASYNC_PREWRITE);

    /* Finalize mbuf. */
//    m->m_data = pktdata + sizeof(*desc);
//    m->m_pkthdr.len = m->m_len = len;
    mbuf_setdata(m, head, len);
    mbuf_pkthdr_setlen(m, len);
    mbuf_setlen(m, len);

    /*
     * Grab a reference to the source node. Note that control frames are
     * shorter than struct ieee80211_frame but ieee80211_find_rxnode()
     * is being careful about control frames.
     */
    wh = mtod(m, struct ieee80211_frame *);
    if (len < sizeof (*wh) &&
       (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL) {
        ic->ic_stats.is_rx_tooshort++;
        ifp->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    ni = ieee80211_find_rxnode(ic, wh);

    memset(&rxi, 0, sizeof(rxi));
    if (((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL)
        && (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) &&
        !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
        (ni->ni_flags & IEEE80211_NODE_RXPROT) &&
        ni->ni_pairwise_key.k_cipher == IEEE80211_CIPHER_CCMP) {
        if ((flags & IWN_RX_CIPHER_MASK) != IWN_RX_CIPHER_CCMP) {
            ic->ic_stats.is_ccmp_dec_errs++;
            ifp->netStat->inputErrors++;
            mbuf_freem(m);
            ieee80211_release_node(ic, ni);
            return;
        }
        /* Check whether decryption was successful or not. */
        if ((desc->type == IWN_MPDU_RX_DONE &&
             (flags & (IWN_RX_MPDU_DEC | IWN_RX_MPDU_MIC_OK)) !=
              (IWN_RX_MPDU_DEC | IWN_RX_MPDU_MIC_OK)) ||
            (desc->type != IWN_MPDU_RX_DONE &&
             (flags & IWN_RX_DECRYPT_MASK) != IWN_RX_DECRYPT_OK)) {
            DPRINTF(("CCMP decryption failed 0x%x\n", flags));
            ic->ic_stats.is_ccmp_dec_errs++;
            ifp->netStat->inputErrors++;
            mbuf_freem(m);
            ieee80211_release_node(ic, ni);
            return;
        }
        if (iwn_ccmp_decap(sc, m, ni) != 0) {
            ifp->netStat->inputErrors++;
            mbuf_freem(m);
            ieee80211_release_node(ic, ni);
            return;
        }
        rxi.rxi_flags |= IEEE80211_RXI_HWDEC;
    }

    rssi = ops->get_rssi(stat);
    rssi = (0 - IWN_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */

    chan = stat->chan;
    if (chan > IEEE80211_CHAN_MAX)
        chan = IEEE80211_CHAN_MAX;

#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwn_rx_radiotap_header *tap = &sc->sc_rxtap;
        uint16_t chan_flags;

        tap->wr_flags = 0;
        if (stat->flags & htole16(IWN_STAT_FLAG_SHPREAMBLE))
            tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;
        tap->wr_chan_freq = htole16(ic->ic_channels[chan].ic_freq);
        chan_flags = ic->ic_channels[chan].ic_flags;
        if (ic->ic_curmode != IEEE80211_MODE_11N)
            chan_flags &= ~IEEE80211_CHAN_HT;
        tap->wr_chan_flags = htole16(chan_flags);
        tap->wr_dbm_antsignal = (int8_t)rssi;
        tap->wr_dbm_antnoise = (int8_t)sc->noise;
        tap->wr_tsft = stat->tstamp;
        if (stat->rflags & IWN_RFLAG_MCS) {
            tap->wr_rate = (0x80 | stat->rate); /* HT MCS index */
        } else {
            switch (stat->rate) {
            /* CCK rates. */
            case  10: tap->wr_rate =   2; break;
            case  20: tap->wr_rate =   4; break;
            case  55: tap->wr_rate =  11; break;
            case 110: tap->wr_rate =  22; break;
            /* OFDM rates. */
            case 0xd: tap->wr_rate =  12; break;
            case 0xf: tap->wr_rate =  18; break;
            case 0x5: tap->wr_rate =  24; break;
            case 0x7: tap->wr_rate =  36; break;
            case 0x9: tap->wr_rate =  48; break;
            case 0xb: tap->wr_rate =  72; break;
            case 0x1: tap->wr_rate =  96; break;
            case 0x3: tap->wr_rate = 108; break;
            /* Unknown rate: should not happen. */
            default:  tap->wr_rate =  0;
            }
        }

        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_rxtap_len,
            m, BPF_DIRECTION_IN);
    }
#endif

    /* Send the frame to the 802.11 layer. */
    rxi.rxi_rssi = rssi;
    rxi.rxi_chan = chan;
    ieee80211_inputm(ifp, m, ni, &rxi, ml);

    /* Node is no longer needed. */
    ieee80211_release_node(ic, ni);
}

void ItlIwn::
iwn_ra_choose(struct iwn_softc *sc, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_node *wn = (struct iwn_node *)ni;
    int old_txmcs = ni->ni_txmcs;

    ieee80211_ra_choose(&wn->rn, ic, ni);

    /* Update firmware's LQ retry table if RA has chosen a new MCS. */
    if (ni->ni_txmcs != old_txmcs)
        iwn_set_link_quality(sc, ni);
}

void ItlIwn::
iwn_ampdu_rate_control(struct iwn_softc *sc, struct ieee80211_node *ni,
    struct iwn_tx_ring *txq, uint16_t seq, uint16_t ssn)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_node *wn = (struct iwn_node *)ni;
    int idx, end_idx;

    /*
     * Update Tx rate statistics for A-MPDUs before firmware's BA window.
     */
    idx = IWN_AGG_SSN_TO_TXQ_IDX(seq);
    end_idx = IWN_AGG_SSN_TO_TXQ_IDX(ssn);
    while (idx != end_idx) {
        struct iwn_tx_data *txdata = &txq->data[idx];
        if (txdata->m != NULL && txdata->ampdu_nframes > 1) {
            /*
             * We can assume that this subframe has been ACKed
             * because ACK failures come as single frames and
             * before failing an A-MPDU subframe the firmware
             * sends it as a single frame at least once.
             */
            ieee80211_ra_add_stats_ht(&wn->rn, ic, ni,
                                      txdata->ampdu_txmcs, 1, 0);
            
            /* Report this frame only once. */
            txdata->ampdu_nframes = 0;
        }
        
        idx = (idx + 1) % IWN_TX_RING_COUNT;
    }
    
    iwn_ra_choose(sc, ni);
}

void ItlIwn::
iwn_ht_single_rate_control(struct iwn_softc *sc, struct ieee80211_node *ni,
    uint8_t rate, uint8_t rflags, uint8_t ackfailcnt, int txfail)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_node *wn = (struct iwn_node *)ni;
    int mcs = rate;
    const struct ieee80211_ra_rate *rs;
    unsigned int retries = 0, i;
    
    /*
     * Ignore Tx reports which don't match our last LQ command.
     */
    if (rate != ni->ni_txmcs) {
        if (++wn->lq_rate_mismatch > 15) {
            /* Try to sync firmware with driver. */
            iwn_set_link_quality(sc, ni);
            wn->lq_rate_mismatch = 0;
        }
        return;
    }
    
    wn->lq_rate_mismatch = 0;
    
    rs = ieee80211_ra_get_rateset(&wn->rn, ic, ni, rate);
    /*
     * Firmware has attempted rates in this rate set in sequence.
     * Retries at a basic rate are counted against the minimum MCS.
     */
    for (i = 0; i < ackfailcnt; i++) {
        if (mcs > rs->min_mcs) {
            ieee80211_ra_add_stats_ht(&wn->rn, ic, ni, mcs, 1, 1);
            mcs--;
        } else
            retries++;
    }
    
    if (txfail && ackfailcnt == 0)
        ieee80211_ra_add_stats_ht(&wn->rn, ic, ni, mcs, 1, 1);
    else
        ieee80211_ra_add_stats_ht(&wn->rn, ic, ni, mcs, retries + 1, retries);
    
    iwn_ra_choose(sc, ni);
}

/*
 * Process an incoming Compressed BlockAck.
 * Note that these block ack notifications are generated by firmware and do
 * not necessarily correspond to contents of block ack frames seen on the air.
 */
void ItlIwn::
iwn_rx_compressed_ba(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    struct iwn_compressed_ba *cba = (struct iwn_compressed_ba *)(desc + 1);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    struct ieee80211_tx_ba *ba;
    struct iwn_tx_ring *txq;
    uint16_t seq, ssn;
    int qid;

    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc), sizeof (*cba),
        BUS_DMASYNC_POSTREAD);

    if (!IEEE80211_ADDR_EQ(ic->ic_bss->ni_macaddr, cba->macaddr))
        return;

    ni = ic->ic_bss;

    qid = le16toh(cba->qid);
    if (qid < sc->first_agg_txq || qid >= sc->ntxqs)
        return;

    txq = &sc->txq[qid];

    /* Protect against a firmware bug where the queue/TID are off. */
    if (qid != sc->first_agg_txq + cba->tid)
        return;

    ba = &ni->ni_tx_ba[cba->tid];
    if (ba->ba_state != IEEE80211_BA_AGREED)
        return;

    /*
     * The first bit in cba->bitmap corresponds to the sequence number
     * stored in the sequence control field cba->seq.
     * Multiple BA notifications in a row may be using this number, with
     * additional bits being set in cba->bitmap. It is unclear how the
     * firmware decides to shift this window forward.
     * We rely on ba->ba_winstart instead.
     */
    seq = le16toh(cba->seq) >> IEEE80211_SEQ_SEQ_SHIFT;

    /*
     * The firmware's new BA window starting sequence number
     * corresponds to the first hole in cba->bitmap, implying
     * that all frames between 'seq' and 'ssn' (non-inclusive)
     * have been acked.
     */
    ssn = le16toh(cba->ssn);
    
    if (SEQ_LT(ssn, ba->ba_winstart))
        return;

    /* Skip rate control if our Tx rate is fixed. */
    if (ic->ic_fixed_mcs == -1)
        iwn_ampdu_rate_control(sc, ni, txq, ba->ba_winstart, ssn);

    /*
     * SSN corresponds to the first (perhaps not yet transmitted) frame
     * in firmware's BA window. Firmware is not going to retransmit any
     * frames before its BA window so mark them all as done.
     */
    ieee80211_output_ba_move_window(ic, ni, cba->tid, ssn);
    iwn_ampdu_txq_advance(sc, txq, qid,
                          IWN_AGG_SSN_TO_TXQ_IDX(ssn));
    iwn_clear_oactive(sc, txq);
}

/*
 * Process a CALIBRATION_RESULT notification sent by the initialization
 * firmware on response to a CMD_CALIB_CONFIG command (5000 only).
 */
void ItlIwn::
iwn5000_rx_calib_results(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    struct iwn_phy_calib *calib = (struct iwn_phy_calib *)(desc + 1);
    int len, idx = -1;

    /* Runtime firmware should not send such a notification. */
    if (sc->sc_flags & IWN_FLAG_CALIB_DONE)
        return;

    len = (letoh32(desc->len) & IWN_RX_DESC_LEN_MASK) - 4;
    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc), len,
        BUS_DMASYNC_POSTREAD);

    switch (calib->code) {
    case IWN5000_PHY_CALIB_DC:
        if (sc->hw_type == IWN_HW_REV_TYPE_5150 ||
            sc->hw_type == IWN_HW_REV_TYPE_2030 ||
            sc->hw_type == IWN_HW_REV_TYPE_2000 ||
            sc->hw_type == IWN_HW_REV_TYPE_135 ||
            sc->hw_type == IWN_HW_REV_TYPE_105)
            idx = 0;
        break;
    case IWN5000_PHY_CALIB_LO:
        idx = 1;
        break;
    case IWN5000_PHY_CALIB_TX_IQ:
        idx = 2;
        break;
    case IWN5000_PHY_CALIB_TX_IQ_PERIODIC:
        if (sc->hw_type < IWN_HW_REV_TYPE_6000 &&
            sc->hw_type != IWN_HW_REV_TYPE_5150)
            idx = 3;
        break;
    case IWN5000_PHY_CALIB_BASE_BAND:
        idx = 4;
        break;
    }
    if (idx == -1)    /* Ignore other results. */
        return;

    /* Save calibration result. */
    if (sc->calibcmd[idx].buf != NULL)
        ::free(sc->calibcmd[idx].buf);
    sc->calibcmd[idx].buf = (uint8_t *)malloc(len, M_DEVBUF, M_NOWAIT);
    if (sc->calibcmd[idx].buf == NULL) {
        DPRINTF(("not enough memory for calibration result %d\n",
            calib->code));
        return;
    }
    DPRINTF(("saving calibration result code=%d len=%d\n",
        calib->code, len));
    sc->calibcmd[idx].len = len;
    memcpy(sc->calibcmd[idx].buf, calib, len);
}

/*
 * Process an RX_STATISTICS or BEACON_STATISTICS firmware notification.
 * The latter is sent by the firmware after each received beacon.
 */
void ItlIwn::
iwn_rx_statistics(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_calib_state *calib = &sc->calib;
    struct iwn_stats *stats = (struct iwn_stats *)(desc + 1);
    int temp;

    /* Ignore statistics received during a scan. */
    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
        sizeof (*stats), BUS_DMASYNC_POSTREAD);

    DPRINTFN(3, ("received statistics (cmd=%d)\n", desc->type));
    sc->calib_cnt = 0;    /* Reset TX power calibration timeout. */
    
    sc->rx_stats_flags = htole32(stats->flags);

    /* Test if temperature has changed. */
    if (stats->general.temp != sc->rawtemp) {
        /* Convert "raw" temperature to degC. */
        sc->rawtemp = stats->general.temp;
        temp = ops->get_temperature(sc);
        DPRINTFN(2, ("temperature=%dC\n", temp));

        /* Update TX power if need be (4965AGN only). */
        if (sc->hw_type == IWN_HW_REV_TYPE_4965)
            iwn4965_power_calibration(sc, temp);
    }

    if (desc->type != IWN_BEACON_STATISTICS)
        return;    /* Reply to a statistics request. */

    sc->noise = iwn_get_noise(&stats->rx.general);

    /* Test that RSSI and noise are present in stats report. */
    if (sc->noise == -127)
        return;

    if (letoh32(stats->rx.general.flags) != 1) {
        DPRINTF(("received statistics without RSSI\n"));
        return;
    }

    /*
     * XXX Differential gain calibration makes the 6005 firmware
     * crap out, so skip it for now.  This effectively disables
     * sensitivity tuning as well.
     */
    if (sc->hw_type == IWN_HW_REV_TYPE_6005)
        return;

    if (calib->state == IWN_CALIB_STATE_ASSOC)
        iwn_collect_noise(sc, &stats->rx.general);
    else if (calib->state == IWN_CALIB_STATE_RUN)
        iwn_tune_sensitivity(sc, &stats->rx);
}

void ItlIwn::
iwn_ampdu_txq_advance(struct iwn_softc *sc, struct iwn_tx_ring *txq, int qid,
    int idx)
{
    struct iwn_ops *ops = &sc->ops;

    DPRINTFN(3, ("%s: txq->cur=%d txq->read=%d txq->queued=%d qid=%d "
        "idx=%d\n", __func__, txq->cur, txq->read, txq->queued, qid, idx));

    while (txq->read != idx) {
        struct iwn_tx_data *txdata = &txq->data[txq->read];
        if (txdata->m != NULL) {
            ops->reset_sched(sc, qid, txq->read);
            iwn_tx_done_free_txdata(sc, txdata);
            txq->queued--;
        }
        txq->read = (txq->read + 1) % IWN_TX_RING_COUNT;
    }
}

/*
 * Handle A-MPDU Tx queue status report.
 * Tx failures come as single frames (perhaps out of order), and before failing
 * an A-MPDU subframe the firmware transmits it as a single frame at least once.
 * Frames successfully transmitted in an A-MPDU are completed when a compressed
 * block ack notification is received.
 */
void ItlIwn::
iwn_ampdu_tx_done(struct iwn_softc *sc, struct iwn_tx_ring *txq,
    struct iwn_rx_desc *desc, uint16_t status, uint8_t ackfailcnt,
    uint8_t rate, uint8_t rflags, int nframes, uint32_t ssn,
    struct iwn_txagg_status *agg_status)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    int tid = desc->qid - sc->first_agg_txq;
    struct iwn_tx_data *txdata = &txq->data[desc->idx];
    struct ieee80211_node *ni = txdata->ni;
    int txfail = (status != IWN_TX_STATUS_SUCCESS &&
        status != IWN_TX_STATUS_DIRECT_DONE);
    struct ieee80211_tx_ba *ba;
    uint16_t seq;

    sc->sc_tx_timer = 0;

    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    if (nframes > 1) {
        int i;
        
        /*
         * Collect information about this A-MPDU.
         */
        for (i = 0; i < nframes; i++) {
            uint8_t qid = agg_status[i].qid;
            uint8_t idx = agg_status[i].idx;
            uint16_t txstatus = (le16toh(agg_status[i].status) &
                                 IWN_AGG_TX_STATUS_MASK);
            
            if (txstatus != IWN_AGG_TX_STATE_TRANSMITTED)
                continue;
            
            if (qid != desc->qid)
                continue;
            
            txdata = &txq->data[idx];
            if (txdata->ni == NULL)
                continue;
            
            /* The Tx rate was the same for all subframes. */
            txdata->ampdu_txmcs = rate;
            txdata->ampdu_nframes = nframes;
        }
        return;
    }

    if (ni == NULL)
        return;

    ba = &ni->ni_tx_ba[tid];
    if (ba->ba_state != IEEE80211_BA_AGREED)
        return;
    if (SEQ_LT(ssn, ba->ba_winstart))
        return;

    /* This was a final single-frame Tx attempt for frame SSN-1. */
    seq = (ssn - 1) & 0xfff;

    /*
     * Skip rate control if our Tx rate is fixed.
     */
    if (ic->ic_fixed_mcs == -1) {
        if (txdata->ampdu_nframes > 1) {
            struct iwn_node *wn = (struct iwn_node *)ni;
            /*
             * This frame was once part of an A-MPDU.
             * Report one failed A-MPDU Tx attempt.
             * The firmware might have made several such
             * attempts but we don't keep track of this.
             */
            ieee80211_ra_add_stats_ht(&wn->rn, ic, ni,
                                      txdata->ampdu_txmcs, 1, 1);
        }
        
        /* Report the final single-frame Tx attempt. */
        if (rflags & IWN_RFLAG_MCS)
            iwn_ht_single_rate_control(sc, ni, rate, rflags,
                                       ackfailcnt, txfail);
    }

    if (txfail)
        ieee80211_tx_compressed_bar(ic, ni, tid, ssn);

    /*
     * SSN corresponds to the first (perhaps not yet transmitted) frame
     * in firmware's BA window. Firmware is not going to retransmit any
     * frames before its BA window so mark them all as done.
     */
    ieee80211_output_ba_move_window(ic, ni, tid, ssn);
    iwn_ampdu_txq_advance(sc, txq, desc->qid, IWN_AGG_SSN_TO_TXQ_IDX(ssn));
    iwn_clear_oactive(sc, txq);
}

/*
 * Process a TX_DONE firmware notification.  Unfortunately, the 4965AGN
 * and 5000 adapters have different incompatible TX status formats.
 */
void ItlIwn::
iwn4965_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn4965_tx_stat *stat = (struct iwn4965_tx_stat *)(desc + 1);
    struct iwn_tx_ring *ring;
    size_t len = (letoh32(desc->len) & IWN_RX_DESC_LEN_MASK);
    uint16_t status = letoh32(stat->stat.status) & 0xff;
    uint32_t ssn;

    if (desc->qid > IWN4965_NTXQUEUES)
        return;

    ring = &sc->txq[desc->qid];

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
        len, BUS_DMASYNC_POSTREAD);

    /* Sanity checks. */
    if (sizeof(*stat) > len)
        return;
    if (stat->nframes < 1 || stat->nframes > IWN_AMPDU_MAX)
        return;
    if (desc->qid < sc->first_agg_txq && stat->nframes > 1)
        return;
    if (desc->qid >= sc->first_agg_txq && sizeof(*stat) + sizeof(ssn) +
        stat->nframes * sizeof(stat->stat) > len)
        return;

    if (desc->qid < sc->first_agg_txq) {
        /* XXX 4965 does not report byte count */
        struct iwn_tx_data *txdata = &ring->data[desc->idx];
        uint16_t framelen = txdata->totlen + IEEE80211_CRC_LEN;
        int txfail = (status != IWN_TX_STATUS_SUCCESS &&
                      status != IWN_TX_STATUS_DIRECT_DONE);

        that->iwn_tx_done(sc, desc, stat->ackfailcnt, stat->rate,
                          stat->rflags, txfail, desc->qid, framelen);
    } else {
        memcpy(&ssn, &stat->stat.status + stat->nframes, sizeof(ssn));
        ssn = le32toh(ssn) & 0xfff;
        that->iwn_ampdu_tx_done(sc, ring, desc, status, stat->ackfailcnt,
            stat->rate, stat->rflags, stat->nframes, ssn,
            stat->stat.agg_status);
    }
}

void ItlIwn::
iwn5000_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    struct iwn_rx_data *data)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_tx_stat *stat = (struct iwn5000_tx_stat *)(desc + 1);
    struct iwn_tx_ring *ring;
    size_t len = (letoh32(desc->len) & IWN_RX_DESC_LEN_MASK);
    uint16_t status = letoh32(stat->stat.status) & 0xff;
    uint32_t ssn;

    if (desc->qid > IWN5000_NTXQUEUES)
        return;

    ring = &sc->txq[desc->qid];

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
        sizeof (*stat), BUS_DMASYNC_POSTREAD);

    /* Sanity checks. */
    if (sizeof(*stat) > len)
        return;
    if (stat->nframes < 1 || stat->nframes > IWN_AMPDU_MAX)
        return;
    if (desc->qid < sc->first_agg_txq && stat->nframes > 1)
        return;
    if (desc->qid >= sc->first_agg_txq && sizeof(*stat) + sizeof(ssn) +
        stat->nframes * sizeof(stat->stat) > len)
        return;

    /* If this was not an aggregated frame, complete it now. */
    if (desc->qid < sc->first_agg_txq) {
        int txfail = (status != IWN_TX_STATUS_SUCCESS &&
                      status != IWN_TX_STATUS_DIRECT_DONE);
        /* Reset TX scheduler slot. */
        iwn5000_reset_sched(sc, desc->qid, desc->idx);

        that->iwn_tx_done(sc, desc, stat->ackfailcnt, stat->rate,
                          stat->rflags, txfail, desc->qid, letoh16(stat->len));
    } else {
        memcpy(&ssn, &stat->stat.status + stat->nframes, sizeof(ssn));
        ssn = le32toh(ssn) & 0xfff;
        that->iwn_ampdu_tx_done(sc, ring, desc, status, stat->ackfailcnt,
            stat->rate, stat->rflags, stat->nframes, ssn,
            stat->stat.agg_status);
    }
}

void ItlIwn::
iwn_tx_done_free_txdata(struct iwn_softc *sc, struct iwn_tx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;

//    bus_dmamap_sync(sc->sc_dmat, data->map, 0, data->map->dm_mapsize,
//        BUS_DMASYNC_POSTWRITE);
//    bus_dmamap_unload(sc->sc_dmat, data->map);
    mbuf_freem(data->m);
    data->m = NULL;
    ieee80211_release_node(ic, data->ni);
    data->ni = NULL;
    data->totlen = 0;
    data->ampdu_nframes = 0;
    data->ampdu_txmcs = 0;
}

void ItlIwn::
iwn_clear_oactive(struct iwn_softc *sc, struct iwn_tx_ring *ring)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;

    if (ring->queued < IWN_TX_RING_LOMARK) {
        sc->qfullmsk &= ~(1 << ring->qid);
        if (sc->qfullmsk == 0 && ifq_is_oactive(&ifp->if_snd)) {
            ifq_clr_oactive(&ifp->if_snd);
            (*ifp->if_start)(ifp);
        }
#ifdef __PRIVATE_SPI__
        ifp->iface->signalOutputThread();
#endif
    }
}

/*
 * Adapter-independent backend for TX_DONE firmware notifications.
 * This handles Tx status for non-aggregation queues.
 */
void ItlIwn::
iwn_tx_done(struct iwn_softc *sc, struct iwn_rx_desc *desc,
    uint8_t ackfailcnt, uint8_t rate, uint8_t rflags, int txfail,
    int qid, uint16_t len)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    struct iwn_tx_ring *ring = &sc->txq[qid];
    struct iwn_tx_data *data = &ring->data[desc->idx];
    struct iwn_node *wn = (struct iwn_node *)data->ni;

    if (data->ni == NULL)
        return;

    if (data->ni->ni_flags & IEEE80211_NODE_HT) {
        if (ic->ic_state == IEEE80211_S_RUN &&
            ic->ic_fixed_mcs == -1 && (rflags & IWN_RFLAG_MCS)) {
            iwn_ht_single_rate_control(sc, data->ni, rate, rflags,
                                       ackfailcnt, txfail);
        }
    } else {
        if (rate != data->ni->ni_txrate) {
            if (++wn->lq_rate_mismatch > 15) {
                /* Try to sync firmware with driver. */
                iwn_set_link_quality(sc, data->ni);
                wn->lq_rate_mismatch = 0;
            }
        } else {
            wn->lq_rate_mismatch = 0;
            
            wn->amn.amn_txcnt++;
            if (ackfailcnt > 0)
                wn->amn.amn_retrycnt++;
            if (txfail)
                wn->amn.amn_retrycnt++;
        }
    }
    if (txfail) {
        ifp->netStat->outputErrors++;
    }

    iwn_tx_done_free_txdata(sc, data);

    sc->sc_tx_timer = 0;
    ring->queued--;
    iwn_clear_oactive(sc, ring);
}

/*
 * Process a "command done" firmware notification.  This is where we wakeup
 * processes waiting for a synchronous command completion.
 */
void ItlIwn::
iwn_cmd_done(struct iwn_softc *sc, struct iwn_rx_desc *desc)
{
    struct iwn_tx_ring *ring = &sc->txq[4];
    struct iwn_tx_data *data;

    if ((desc->qid & 0xf) != 4)
        return;    /* Not a command ack. */

    data = &ring->data[desc->idx];

    /* If the command was mapped in an mbuf, free it. */
    if (data->m != NULL) {
//        bus_dmamap_sync(sc->sc_dmat, data->map, 0,
//            data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
//        bus_dmamap_unload(sc->sc_dmat, data->map);
        mbuf_freem(data->m);
        data->m = NULL;
    }
    wakeupOn(&ring->desc[desc->idx]);
}

/*
 * Process an INT_FH_RX or INT_SW_RX interrupt.
 */
void ItlIwn::
iwn_notif_intr(struct iwn_softc *sc)
{
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    uint16_t hw;

//    bus_dmamap_sync(sc->sc_dmat, sc->rxq.stat_dma.map,
//        0, sc->rxq.stat_dma.size, BUS_DMASYNC_POSTREAD);

    hw = letoh16(sc->rxq.stat->closed_count) & 0xfff;
    while (sc->rxq.cur != hw) {
        struct iwn_rx_data *data = &sc->rxq.data[sc->rxq.cur];
        struct iwn_rx_desc *desc;

        bus_dmamap_sync(sc->sc_dmat, data->map, 0, sizeof (*desc),
            BUS_DMASYNC_POSTREAD);
        desc = mtod(data->m, struct iwn_rx_desc *);

        DPRINTFN(4, ("notification qid=%d idx=%d flags=%x type=%d\n",
            desc->qid & 0xf, desc->idx, desc->flags, desc->type));

        if (!(desc->qid & 0x80))    /* Reply to a command. */
            iwn_cmd_done(sc, desc);

        switch (desc->type) {
        case IWN_RX_PHY:
            iwn_rx_phy(sc, desc, data);
            break;

        case IWN_RX_DONE:        /* 4965AGN only. */
        case IWN_MPDU_RX_DONE:
            /* An 802.11 frame has been received. */
            iwn_rx_done(sc, desc, data, &ml);
            break;
        case IWN_RX_COMPRESSED_BA:
            /* A Compressed BlockAck has been received. */
            iwn_rx_compressed_ba(sc, desc, data);
            break;
        case IWN_TX_DONE:
            /* An 802.11 frame has been transmitted. */
            ops->tx_done(sc, desc, data);
            break;

        case IWN_RX_STATISTICS:
        case IWN_BEACON_STATISTICS:
            iwn_rx_statistics(sc, desc, data);
            break;

        case IWN_BEACON_MISSED:
        {
            struct iwn_beacon_missed *miss =
                (struct iwn_beacon_missed *)(desc + 1);
            uint32_t missed;

            if ((ic->ic_opmode != IEEE80211_M_STA) ||
                (ic->ic_state != IEEE80211_S_RUN))
                break;

            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
                sizeof (*miss), BUS_DMASYNC_POSTREAD);
            missed = letoh32(miss->consecutive);

            /*
             * If more than 5 consecutive beacons are missed,
             * reinitialize the sensitivity state machine.
             */
            if (missed > 5)
                (void)iwn_init_sensitivity(sc);

            /*
             * Rather than go directly to scan state, try to send a
             * directed probe request first. If that fails then the
             * state machine will drop us into scanning after timing
             * out waiting for a probe response.
             */
            if (missed > ic->ic_bmissthres && !ic->ic_mgt_timer) {
                if (ic->ic_if.if_flags & IFF_DEBUG)
                    XYLog("%s: receiving no beacons from "
                        "%s; checking if this AP is still "
                        "responding to probe requests\n",
                        sc->sc_dev.dv_xname, ether_sprintf(
                        ic->ic_bss->ni_macaddr));
                IEEE80211_SEND_MGMT(ic, ic->ic_bss,
                    IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
            }
            break;
        }
        case IWN_UC_READY:
        {
            struct iwn_ucode_info *uc =
                (struct iwn_ucode_info *)(desc + 1);

            /* The microcontroller is ready. */
            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
                sizeof (*uc), BUS_DMASYNC_POSTREAD);
            DPRINTF(("microcode alive notification version=%d.%d "
                "subtype=%x alive=%x\n", uc->major, uc->minor,
                uc->subtype, letoh32(uc->valid)));

            if (letoh32(uc->valid) != 1) {
                XYLog("%s: microcontroller initialization "
                    "failed\n", sc->sc_dev.dv_xname);
                break;
            }
            if (uc->subtype == IWN_UCODE_INIT) {
                /* Save microcontroller report. */
                memcpy(&sc->ucode_info, uc, sizeof (*uc));
            }
            /* Save the address of the error log in SRAM. */
            sc->errptr = letoh32(uc->errptr);
            break;
        }
        case IWN_STATE_CHANGED:
        {
            uint32_t *status = (uint32_t *)(desc + 1);

            /* Enabled/disabled notification. */
            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
                sizeof (*status), BUS_DMASYNC_POSTREAD);
            DPRINTF(("state changed to %x\n", letoh32(*status)));

            if (letoh32(*status) & 1) {
                /* Radio transmitter is off, power down. */
                iwn_stop(ifp);
                return;    /* No further processing. */
            }
            break;
        }
        case IWN_START_SCAN:
        {
            struct iwn_start_scan *scan =
                (struct iwn_start_scan *)(desc + 1);

            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
                sizeof (*scan), BUS_DMASYNC_POSTREAD);
            DPRINTFN(2, ("scan start: chan %d status %x\n",
                scan->chan, letoh32(scan->status)));

            if (sc->sc_flags & IWN_FLAG_BGSCAN)
                break;

            /* Fix current channel. */
            ic->ic_bss->ni_chan = &ic->ic_channels[scan->chan];
            break;
        }
        case IWN_STOP_SCAN:
        {
            struct iwn_stop_scan *scan =
                (struct iwn_stop_scan *)(desc + 1);

            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof (*desc),
                sizeof (*scan), BUS_DMASYNC_POSTREAD);
            DPRINTFN(2, ("scan stop: nchan=%d status=%d chan=%d\n",
                scan->nchan, scan->status, scan->chan));

            if (scan->status == 1 && scan->chan <= 14 &&
                (sc->sc_flags & IWN_FLAG_HAS_5GHZ)) {
                    int error;
                /*
                 * We just finished scanning 2GHz channels,
                 * start scanning 5GHz ones.
                 */
                error = iwn_scan(sc, IEEE80211_CHAN_5GHZ,
                    (sc->sc_flags & IWN_FLAG_BGSCAN) ? 1 : 0);
                if (error == 0)
                    break;
            }
            sc->sc_flags &= ~IWN_FLAG_SCANNING;
            sc->sc_flags &= ~IWN_FLAG_BGSCAN;
            ieee80211_end_scan(ifp);
            break;
        }
        case IWN5000_CALIBRATION_RESULT:
            iwn5000_rx_calib_results(sc, desc, data);
            break;

        case IWN5000_CALIBRATION_DONE:
            sc->sc_flags |= IWN_FLAG_CALIB_DONE;
            wakeupOn(sc);
            break;
        }

        sc->rxq.cur = (sc->rxq.cur + 1) % IWN_RX_RING_COUNT;
    }
    if_input(&sc->sc_ic.ic_if, &ml);

    /* Tell the firmware what we have processed. */
    hw = (hw == 0) ? IWN_RX_RING_COUNT - 1 : hw - 1;
    IWN_WRITE(sc, IWN_FH_RX_WPTR, hw & ~7);
}

/*
 * Process an INT_WAKEUP interrupt raised when the microcontroller wakes up
 * from power-down sleep mode.
 */
void ItlIwn::
iwn_wakeup_intr(struct iwn_softc *sc)
{
    int qid;

    DPRINTF(("ucode wakeup from power-down sleep\n"));

    /* Wakeup RX and TX rings. */
    IWN_WRITE(sc, IWN_FH_RX_WPTR, sc->rxq.cur & ~7);
    for (qid = 0; qid < sc->ntxqs; qid++) {
        struct iwn_tx_ring *ring = &sc->txq[qid];
        IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | ring->cur);
    }
}

#ifdef IWN_DEBUG
/*
 * Dump the error log of the firmware when a firmware panic occurs.  Although
 * we can't debug the firmware because it is neither open source nor free, it
 * can help us to identify certain classes of problems.
 */
void ItlIwn::
iwn_fatal_intr(struct iwn_softc *sc)
{
    struct iwn_fw_dump dump;
    int i;

    /* Check that the error log address is valid. */
    if (sc->errptr < IWN_FW_DATA_BASE ||
        sc->errptr + sizeof (dump) >
        IWN_FW_DATA_BASE + sc->fw_data_maxsz) {
        XYLog("%s: bad firmware error log address 0x%08x\n",
            sc->sc_dev.dv_xname, sc->errptr);
        return;
    }
    if (iwn_nic_lock(sc) != 0) {
        XYLog("%s: could not read firmware error log\n",
            sc->sc_dev.dv_xname);
        return;
    }
    /* Read firmware error log from SRAM. */
    iwn_mem_read_region_4(sc, sc->errptr, (uint32_t *)&dump,
        sizeof (dump) / sizeof (uint32_t));
    iwn_nic_unlock(sc);

    if (dump.valid == 0) {
        XYLog("%s: firmware error log is empty\n",
            sc->sc_dev.dv_xname);
        return;
    }
    XYLog("firmware error log:\n");
    XYLog("  error type      = \"%s\" (0x%08X)\n",
        (dump.id < nitems(iwn_fw_errmsg)) ?
        iwn_fw_errmsg[dump.id] : "UNKNOWN",
        dump.id);
    XYLog("  program counter = 0x%08X\n", dump.pc);
    XYLog("  source line     = 0x%08X\n", dump.src_line);
    XYLog("  error data      = 0x%08X%08X\n",
        dump.error_data[0], dump.error_data[1]);
    XYLog("  branch link     = 0x%08X%08X\n",
        dump.branch_link[0], dump.branch_link[1]);
    XYLog("  interrupt link  = 0x%08X%08X\n",
        dump.interrupt_link[0], dump.interrupt_link[1]);
    XYLog("  time            = %u\n", dump.time[0]);

    /* Dump driver status (TX and RX rings) while we're here. */
    XYLog("driver status:\n");
    for (i = 0; i < sc->ntxqs; i++) {
        struct iwn_tx_ring *ring = &sc->txq[i];
        XYLog("  tx ring %2d: qid=%-2d cur=%-3d queued=%-3d\n",
            i, ring->qid, ring->cur, ring->queued);
    }
    XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
    XYLog("  802.11 state %d\n", sc->sc_ic.ic_state);
}
#endif

int ItlIwn::
iwn_intr(OSObject *object, IOInterruptEventSource* sender, int count)
{
    ItlIwn *that = (ItlIwn*)object;
    struct iwn_softc *sc = &that->com;
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    uint32_t r1, r2, tmp;

//    IWN_WRITE(sc, IWN_INT_MASK, 0);

    /* Read interrupts from ICT (fast) or from registers (slow). */
    if (sc->sc_flags & IWN_FLAG_USE_ICT) {
        tmp = 0;
        while (sc->ict[sc->ict_cur] != 0) {
            tmp |= sc->ict[sc->ict_cur];
            sc->ict[sc->ict_cur] = 0;    /* Acknowledge. */
            sc->ict_cur = (sc->ict_cur + 1) % IWN_ICT_COUNT;
        }
        tmp = letoh32(tmp);
        if (tmp == 0xffffffff)    /* Shouldn't happen. */
            tmp = 0;
        else if (tmp & 0xc0000)    /* Workaround a HW bug. */
            tmp |= 0x8000;
        r1 = (tmp & 0xff00) << 16 | (tmp & 0xff);
        r2 = 0;    /* Unused. */
    } else {
        r1 = IWN_READ(sc, IWN_INT);
        if (r1 == 0xffffffff || (r1 & 0xfffffff0) == 0xa5a5a5a0)
            return 0;    /* Hardware gone! */
        r2 = IWN_READ(sc, IWN_FH_INT);
    }
    if (r1 == 0 && r2 == 0) {
        if (ifp->if_flags & IFF_UP)
            IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
        return 0;    /* Interrupt not for us. */
    }

    /* Acknowledge interrupts. */
    IWN_WRITE(sc, IWN_INT, r1);
    if (!(sc->sc_flags & IWN_FLAG_USE_ICT))
        IWN_WRITE(sc, IWN_FH_INT, r2);

    if (r1 & IWN_INT_RF_TOGGLED) {
        tmp = IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_RFKILL;
        XYLog("%s: RF switch: radio %s\n", sc->sc_dev.dv_xname,
            tmp ? "enabled" : "disabled");
        if (tmp)
            task_add(systq, &sc->init_task);
    }
    if (r1 & IWN_INT_CT_REACHED) {
        XYLog("%s: critical temperature reached!\n",
            sc->sc_dev.dv_xname);
    }
    if (r1 & (IWN_INT_SW_ERR | IWN_INT_HW_ERR)) {
        XYLog("%s: fatal firmware error\n", sc->sc_dev.dv_xname);

        /* Force a complete recalibration on next init. */
        sc->sc_flags &= ~IWN_FLAG_CALIB_DONE;

        /* Dump firmware error log and stop. */
#ifdef IWN_DEBUG
        that->iwn_fatal_intr(sc);
#endif
        that->iwn_stop(ifp);
        task_add(systq, &sc->init_task);
        return 1;
    }
    if ((r1 & (IWN_INT_FH_RX | IWN_INT_SW_RX | IWN_INT_RX_PERIODIC)) ||
        (r2 & IWN_FH_INT_RX)) {
        if (sc->sc_flags & IWN_FLAG_USE_ICT) {
            if (r1 & (IWN_INT_FH_RX | IWN_INT_SW_RX))
                IWN_WRITE(sc, IWN_FH_INT, IWN_FH_INT_RX);
            IWN_WRITE_1(sc, IWN_INT_PERIODIC,
                IWN_INT_PERIODIC_DIS);
            that->iwn_notif_intr(sc);
            if (r1 & (IWN_INT_FH_RX | IWN_INT_SW_RX)) {
                IWN_WRITE_1(sc, IWN_INT_PERIODIC,
                    IWN_INT_PERIODIC_ENA);
            }
        } else
            that->iwn_notif_intr(sc);
    }

    if ((r1 & IWN_INT_FH_TX) || (r2 & IWN_FH_INT_TX)) {
        if (sc->sc_flags & IWN_FLAG_USE_ICT)
            IWN_WRITE(sc, IWN_FH_INT, IWN_FH_INT_TX);
        that->wakeupOn(sc);    /* FH DMA transfer completed. */
    }

    if (r1 & IWN_INT_ALIVE)
        that->wakeupOn(sc);    /* Firmware is alive. */

    if (r1 & IWN_INT_WAKEUP)
        that->iwn_wakeup_intr(sc);

    /* Re-enable interrupts. */
    if (ifp->if_flags & IFF_UP)
        IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);

    return 1;
}

/*
 * Update TX scheduler ring when transmitting an 802.11 frame (4965AGN and
 * 5000 adapters use a slightly different format).
 */
void ItlIwn::
iwn4965_update_sched(struct iwn_softc *sc, int qid, int idx, uint8_t id,
    uint16_t len)
{
    uint16_t *w = &sc->sched[qid * IWN4965_SCHED_COUNT + idx];

    *w = htole16(len + 8);
//    bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//        (caddr_t)w - sc->sched_dma.vaddr, sizeof (uint16_t),
//        BUS_DMASYNC_PREWRITE);
    if (idx < IWN_SCHED_WINSZ) {
        *(w + IWN_TX_RING_COUNT) = *w;
//        bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//            (caddr_t)(w + IWN_TX_RING_COUNT) - sc->sched_dma.vaddr,
//            sizeof (uint16_t), BUS_DMASYNC_PREWRITE);
    }
}

void ItlIwn::
iwn4965_reset_sched(struct iwn_softc *sc, int qid, int idx)
{
    /* TBD */
}

void ItlIwn::
iwn5000_update_sched(struct iwn_softc *sc, int qid, int idx, uint8_t id,
    uint16_t len)
{
    uint16_t *w = &sc->sched[qid * IWN5000_SCHED_COUNT + idx];

    *w = htole16(id << 12 | (len + 8));
//    bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//        (caddr_t)w - sc->sched_dma.vaddr, sizeof (uint16_t),
//        BUS_DMASYNC_PREWRITE);
    if (idx < IWN_SCHED_WINSZ) {
        *(w + IWN_TX_RING_COUNT) = *w;
//        bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//            (caddr_t)(w + IWN_TX_RING_COUNT) - sc->sched_dma.vaddr,
//            sizeof (uint16_t), BUS_DMASYNC_PREWRITE);
    }
}

void ItlIwn::
iwn5000_reset_sched(struct iwn_softc *sc, int qid, int idx)
{
    uint16_t *w = &sc->sched[qid * IWN5000_SCHED_COUNT + idx];

    *w = (*w & htole16(0xf000)) | htole16(1);
//    bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//        (caddr_t)w - sc->sched_dma.vaddr, sizeof (uint16_t),
//        BUS_DMASYNC_PREWRITE);
    if (idx < IWN_SCHED_WINSZ) {
        *(w + IWN_TX_RING_COUNT) = *w;
//        bus_dmamap_sync(sc->sc_dmat, sc->sched_dma.map,
//            (caddr_t)(w + IWN_TX_RING_COUNT) - sc->sched_dma.vaddr,
//            sizeof (uint16_t), BUS_DMASYNC_PREWRITE);
    }
}

int ItlIwn::
iwn_rval2ridx(int rval)
{
    int ridx;

    for (ridx = 0; ridx < nitems(iwn_rates); ridx++) {
        if (rval == iwn_rates[ridx].rate)
            break;
    }

    return ridx;
}

static int
iwn_is_mimo_ht_plcp(uint8_t ht_plcp)
{
    return (ht_plcp != IWN_RATE_HT_SISO_MCS_INV_PLCP &&
            (ht_plcp & IWN_RATE_HT_MCS_NSS_MSK));
}

static int
iwn_is_mimo_mcs(int mcs)
{
    int ridx = iwn_mcs2ridx[mcs];
    return iwn_is_mimo_ht_plcp(iwn_rates[ridx].ht_plcp);
    
}

int ItlIwn::
iwn_tx(struct iwn_softc *sc, mbuf_t m, struct ieee80211_node *ni)
{
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_tx_ring *ring;
    struct iwn_tx_desc *desc;
    struct iwn_tx_data *data;
    struct iwn_tx_cmd *cmd;
    struct iwn_cmd_data *tx;
    const struct iwn_rate *rinfo;
    struct ieee80211_frame *wh;
    struct ieee80211_key *k = NULL;
    enum ieee80211_edca_ac ac;
    int qid;
    uint32_t flags;
    uint16_t qos;
    u_int hdrlen;
    IOPhysicalSegment *seg;
    IOPhysicalSegment segs[IWN_MAX_SCATTER - 1];
    int nsegs = 0;
    uint8_t *ivp, tid, ridx, txant, type, subtype;
    int i, totlen, hasqos, error, pad;

    wh = mtod(m, struct ieee80211_frame *);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if (type == IEEE80211_FC0_TYPE_CTL)
        hdrlen = sizeof(struct ieee80211_frame_min);
    else
        hdrlen = ieee80211_get_hdrlen(wh);

    if ((hasqos = ieee80211_has_qos(wh))) {
        /* Select EDCA Access Category and TX ring for this frame. */
        struct ieee80211_tx_ba *ba;
        qos = ieee80211_get_qos(wh);
        tid = qos & IEEE80211_QOS_TID;
        ac = ieee80211_up_to_ac(ic, tid);
        qid = ac;

        /* If possible, put this frame on an aggregation queue. */
        if (sc->sc_tx_ba[tid].wn == wn) {
            ba = &ni->ni_tx_ba[tid];
            if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
                ba->ba_state == IEEE80211_BA_AGREED) {
                qid = sc->first_agg_txq + tid;
                if (sc->qfullmsk & (1 << qid)) {
                    mbuf_freem(m);
                    return ENOBUFS;
                }
            }
        }
    } else {
        qos = 0;
        tid = IWN_NONQOS_TID;
        ac = EDCA_AC_BE;
        qid = ac;
    }

    ring = &sc->txq[qid];
    desc = &ring->desc[ring->cur];
    data = &ring->data[ring->cur];

    /* Choose a TX rate index. */
    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA)
        ridx = iwn_rval2ridx(ieee80211_min_basic_rate(ic));
    else if (ic->ic_fixed_mcs != -1)
        ridx = sc->fixed_ridx;
    else if (ic->ic_fixed_rate != -1)
        ridx = sc->fixed_ridx;
    else {
        if (ni->ni_flags & IEEE80211_NODE_HT)
            ridx = iwn_mcs2ridx[ni->ni_txmcs];
        else
            ridx = wn->ridx[ni->ni_txrate];
    }
    rinfo = &iwn_rates[ridx];
#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwn_tx_radiotap_header *tap = &sc->sc_txtap;
        uint16_t chan_flags;

        tap->wt_flags = 0;
        tap->wt_chan_freq = htole16(ni->ni_chan->ic_freq);
        chan_flags = ni->ni_chan->ic_flags;
        if (ic->ic_curmode != IEEE80211_MODE_11N)
            chan_flags &= ~IEEE80211_CHAN_HT;
        tap->wt_chan_flags = htole16(chan_flags);
        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
            !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
            type == IEEE80211_FC0_TYPE_DATA) {
            tap->wt_rate = (0x80 | ni->ni_txmcs);
        } else
            tap->wt_rate = rinfo->rate;
        if ((ic->ic_flags & IEEE80211_F_WEPON) &&
            (wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
            tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_txtap_len,
            m, BPF_DIRECTION_OUT);
    }
#endif

    //    totlen = m->m_pkthdr.len;
    totlen = mbuf_pkthdr_len(m);

    /* Encrypt the frame if need be. */
    if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
        /* Retrieve key for TX. */
        k = ieee80211_get_txkey(ic, wh, ni);
        if (k->k_cipher != IEEE80211_CIPHER_CCMP) {
            /* Do software encryption. */
            if ((m = ieee80211_encrypt(ic, m, k)) == NULL)
                return ENOBUFS;
            /* 802.11 header may have moved. */
            wh = mtod(m, struct ieee80211_frame *);
            //    totlen = m->m_pkthdr.len;
            totlen = mbuf_pkthdr_len(m);

        } else    /* HW appends CCMP MIC. */
            totlen += IEEE80211_CCMP_HDRLEN;
    }

    data->totlen = totlen;

    /* Prepare TX firmware command. */
    cmd = &ring->cmd[ring->cur];
    cmd->code = IWN_CMD_TX_DATA;
    cmd->flags = 0;
    cmd->qid = ring->qid;
    cmd->idx = ring->cur;

    tx = (struct iwn_cmd_data *)cmd->data;
    /* NB: No need to clear tx, all fields are reinitialized here. */
    tx->scratch = 0;    /* clear "scratch" area */

    flags = 0;
    if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
        /* Unicast frame, check if an ACK is expected. */
        if (!hasqos || (qos & IEEE80211_QOS_ACK_POLICY_MASK) !=
            IEEE80211_QOS_ACK_POLICY_NOACK)
            flags |= IWN_TX_NEED_ACK;
    }
    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR) {
        struct ieee80211_frame_min *mwh;
        uint8_t *barfrm;
        uint16_t ctl;
        mwh = mtod(m, struct ieee80211_frame_min *);
        barfrm = (uint8_t *)&mwh[1];
        ctl = LE_READ_2(barfrm);
        tid = (ctl & IEEE80211_BA_TID_INFO_MASK) >>
            IEEE80211_BA_TID_INFO_SHIFT;
        flags |= (IWN_TX_NEED_ACK | IWN_TX_IMM_BA);
    }

    if (wh->i_fc[1] & IEEE80211_FC1_MORE_FRAG)
        flags |= IWN_TX_MORE_FRAG;    /* Cannot happen yet. */

    /* Check if frame must be protected using RTS/CTS or CTS-to-self. */
    if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
        /* NB: Group frames are sent using CCK in 802.11b/g/n (2GHz). */
        if (totlen + IEEE80211_CRC_LEN > ic->ic_rtsthreshold) {
            flags |= IWN_TX_NEED_RTS;
        } else if ((ic->ic_flags & IEEE80211_F_USEPROT) &&
            IWN_RIDX_IS_OFDM(ridx)) {
            if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
                flags |= IWN_TX_NEED_CTS;
            else if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
                flags |= IWN_TX_NEED_RTS;
        }

        if (flags & (IWN_TX_NEED_RTS | IWN_TX_NEED_CTS)) {
            if (sc->hw_type != IWN_HW_REV_TYPE_4965) {
                /* 5000 autoselects RTS/CTS or CTS-to-self. */
                flags &= ~(IWN_TX_NEED_RTS | IWN_TX_NEED_CTS);
                flags |= IWN_TX_NEED_PROTECTION;
            } else
                flags |= IWN_TX_FULL_TXOP;
        }
    }

    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR)
        tx->id = wn->id;
    else if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA)
        tx->id = sc->broadcast_id;
    else
        tx->id = wn->id;

    if (type == IEEE80211_FC0_TYPE_MGT) {
#ifndef IEEE80211_STA_ONLY
        /* Tell HW to set timestamp in probe responses. */
        if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
            flags |= IWN_TX_INSERT_TSTAMP;
#endif
        if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
            subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
            tx->timeout = htole16(3);
        else
            tx->timeout = htole16(2);
    } else
        tx->timeout = htole16(0);

    if (hdrlen & 3) {
        /* First segment length must be a multiple of 4. */
        flags |= IWN_TX_NEED_PADDING;
        pad = 4 - (hdrlen & 3);
    } else
        pad = 0;

    tx->len = htole16(totlen);
    tx->tid = tid;
    tx->rts_ntries = 60;
    tx->data_ntries = 15;
    tx->lifetime = htole32(IWN_LIFETIME_INFINITE);

    if ((ni->ni_flags & IEEE80211_NODE_HT) &&
        tx->id != sc->broadcast_id &&
        rinfo->ht_plcp != IWN_RATE_HT_SISO_MCS_INV_PLCP) {
        tx->plcp = rinfo->ht_plcp;
        tx->rflags = IWN_RFLAG_MCS;
        if (ieee80211_node_supports_ht_sgi20(ni))
            tx->rflags |= IWN_RFLAG_SGI;
        if (iwn_rxon_ht40_enabled(sc)) {
            tx->rflags |= IWN_RFLAG_HT40;
            if (ieee80211_node_supports_ht_sgi40(ni)) {
                tx->rflags |= IWN_RFLAG_SGI;
            }
        }
        if (iwn_is_mimo_ht_plcp(rinfo->ht_plcp))
            tx->rflags |= IWN_RFLAG_ANT(sc->txchainmask);
        else
            tx->rflags |= IWN_RFLAG_ANT(IWN_LSB(sc->txchainmask));
    }
    else {
        tx->plcp = rinfo->plcp;
        if (IWN_RIDX_IS_CCK(ridx))
            tx->rflags = IWN_RFLAG_CCK;
        else
            tx->rflags = 0;
    }
    if (tx->id == sc->broadcast_id || ic->ic_fixed_mcs != -1 ||
        ic->ic_fixed_rate != -1) {
        /* Group or management frame, or fixed Tx rate. */
        tx->linkq = 0;
        /* XXX Alternate between antenna A and B? */
        txant = IWN_LSB(sc->txchainmask);
        tx->rflags |= IWN_RFLAG_ANT(txant);
    } else {
        tx->linkq = 0; /* initial index into firmware LQ retry table */
        flags |= IWN_TX_LINKQ;    /* enable multi-rate retry */
    }
    /* Set physical address of "scratch area". */
    tx->loaddr = htole32(IWN_LOADDR(data->scratch_paddr));
    tx->hiaddr = IWN_HIADDR(data->scratch_paddr);

    /* Copy 802.11 header in TX command. */
    memcpy((uint8_t *)(tx + 1), wh, hdrlen);

    if (k != NULL && k->k_cipher == IEEE80211_CIPHER_CCMP) {
        /* Trim 802.11 header and prepend CCMP IV. */
        mbuf_adj(m, hdrlen - IEEE80211_CCMP_HDRLEN);
        ivp = mtod(m, uint8_t *);
        k->k_tsc++;
        ivp[0] = k->k_tsc;
        ivp[1] = k->k_tsc >> 8;
        ivp[2] = 0;
        ivp[3] = k->k_id << 6 | IEEE80211_WEP_EXTIV;
        ivp[4] = k->k_tsc >> 16;
        ivp[5] = k->k_tsc >> 24;
        ivp[6] = k->k_tsc >> 32;
        ivp[7] = k->k_tsc >> 40;

        tx->security = IWN_CIPHER_CCMP;
        if (qid >= sc->first_agg_txq)
            flags |= IWN_TX_AMPDU_CCMP;
        memcpy(tx->key, k->k_key, k->k_len);

        /* TX scheduler includes CCMP MIC len w/5000 Series. */
        if (sc->hw_type != IWN_HW_REV_TYPE_4965)
            totlen += IEEE80211_CCMP_MICLEN;
    } else {
        /* Trim 802.11 header. */
        mbuf_adj(m, hdrlen);
        tx->security = 0;
    }
    tx->flags = htole32(flags);

    nsegs = data->map->cursor->getPhysicalSegmentsWithCoalesce(m, &segs[0], IWN_MAX_SCATTER - 1);
    if (nsegs == 0) {
        XYLog("%s: can't map mbuf (error %d)\n", DEVNAME(sc),
              nsegs);
        mbuf_freem(m);
        return ENOMEM;
    }

    data->m = m;
    data->ni = ni;
    data->ampdu_txmcs = ni->ni_txmcs; /* updated upon Tx interrupt */

    DPRINTFN(4, ("sending data: qid=%d idx=%d len=%d nsegs=%d\n",
        ring->qid, ring->cur, mbuf_pkthdr_len(m), nsegs));

    /* Fill TX descriptor. */
    desc->nsegs = 1 + nsegs;
    /* First DMA segment is used by the TX command. */
    desc->segs[0].addr = htole32(IWN_LOADDR(data->cmd_paddr));
    desc->segs[0].len  = htole16(IWN_HIADDR(data->cmd_paddr) |
        (4 + sizeof (*tx) + hdrlen + pad) << 4);
    /* Other DMA segments are for data payload. */
    for (i = 0; i < nsegs; i++) {
        seg = &segs[i];
        desc->segs[i + 1].addr = htole32(IWN_LOADDR(seg->location));
        desc->segs[i + 1].len  = htole16(IWN_HIADDR(seg->location) |
            seg->length << 4);
//        XYLog("DMA segments index=%d location=0x%llx length=%llu", i, seg->location, seg->length);
    }
//    XYLog("----------end sending data------\n");

//    bus_dmamap_sync(sc->sc_dmat, data->map, 0, data->map->dm_mapsize,
//        BUS_DMASYNC_PREWRITE);
//    bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
//        (caddr_t)cmd - ring->cmd_dma.vaddr, sizeof (*cmd),
//        BUS_DMASYNC_PREWRITE);
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//        (caddr_t)desc - ring->desc_dma.vaddr, sizeof (*desc),
//        BUS_DMASYNC_PREWRITE);

    /* Update TX scheduler. */
    ops->update_sched(sc, ring->qid, ring->cur, tx->id, totlen);

    /* Kick TX ring. */
    ring->cur = (ring->cur + 1) % IWN_TX_RING_COUNT;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

    /* Mark TX ring as full if we reach a certain threshold. */
    if (++ring->queued > IWN_TX_RING_HIMARK) {
//        XYLog("%s sc->qfullmsk is FULL qid=%d ring->cur=%d ring->queued=%d\n", __FUNCTION__, ring->qid, ring->cur, ring->queued);
        sc->qfullmsk |= 1 << ring->qid;
    }

    return 0;
}

void ItlIwn::
iwn_start(struct _ifnet *ifp)
{
    struct iwn_softc *sc = (struct iwn_softc*)ifp->if_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    that->getMainCommandGate()->attemptAction(_iwn_start_task, &that->com.sc_ic.ic_ac.ac_if);
}

IOReturn ItlIwn::
_iwn_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct _ifnet *ifp = (struct _ifnet *)arg0;
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    mbuf_t m;

    if (!(ifp->if_flags & IFF_RUNNING) || ifq_is_oactive(&ifp->if_snd))
        return kIOReturnError;

    for (;;) {
        if (sc->qfullmsk != 0) {
            ifq_set_oactive(&ifp->if_snd);
            break;
        }

        /* Send pending management frames first. */
        m = mq_dequeue(&ic->ic_mgtq);
        if (m != NULL) {
//            ni = m->m_pkthdr.ph_cookie;
            ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
            goto sendit;
        }
        if (
#ifndef AIRPORT
            ic->ic_state != IEEE80211_S_RUN ||
#endif
            (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
            break;

        /* Encapsulate and send data frames. */
        m = ifq_dequeue(&ifp->if_snd);
        if (m == NULL)
            break;
#if NBPFILTER > 0
        if (ifp->if_bpf != NULL)
            bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
        if ((m = ieee80211_encap(ifp, m, &ni)) == NULL)
            continue;
sendit:
#if NBPFILTER > 0
        if (ic->ic_rawbpf != NULL)
            bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
        if (that->iwn_tx(sc, m, ni) != 0) {
            ieee80211_release_node(ic, ni);
            ifp->netStat->outputErrors++;
            continue;
        }
        ifp->netStat->outputPackets++;

        sc->sc_tx_timer = 5;
        ifp->if_timer = 1;
    }
    
    return kIOReturnSuccess;
}

void ItlIwn::
iwn_watchdog(struct _ifnet *ifp)
{
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);

    ifp->if_timer = 0;

    if (sc->sc_tx_timer > 0) {
        if (--sc->sc_tx_timer == 0) {
            XYLog("%s: device timeout\n", sc->sc_dev.dv_xname);
            that->iwn_stop(ifp);
            task_add(systq, &sc->init_task);
            ifp->netStat->outputErrors++;
            return;
        }
        ifp->if_timer = 1;
    }

    ieee80211_watchdog(ifp);
}

int ItlIwn::
iwn_ioctl(struct _ifnet *ifp, u_long cmd, caddr_t data)
{
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int s, error = 0;

//    error = rw_enter(&sc->sc_rwlock, RW_WRITE | RW_INTR);
    if (error)
        return error;
    s = splnet();

    switch (cmd) {
    case SIOCSIFADDR:
        ifp->if_flags |= IFF_UP;
        /* FALLTHROUGH */
    case SIOCSIFFLAGS:
        if (ifp->if_flags & IFF_UP) {
            if (!(ifp->if_flags & IFF_RUNNING))
                error = that->iwn_init(ifp);
        } else {
            if (ifp->if_flags & IFF_RUNNING)
                that->iwn_stop(ifp);
        }
        break;

    case SIOCS80211POWER:
        error = ieee80211_ioctl(ifp, cmd, data);
        if (error != ENETRESET)
            break;
        if (ic->ic_state == IEEE80211_S_RUN &&
            sc->calib.state == IWN_CALIB_STATE_RUN) {
            if (ic->ic_flags & IEEE80211_F_PMGTON)
                error = that->iwn_set_pslevel(sc, 0, 3, 0);
            else    /* back to CAM */
                error = that->iwn_set_pslevel(sc, 0, 0, 0);
        } else {
            /* Defer until transition to IWN_CALIB_STATE_RUN. */
            error = 0;
        }
        break;

    default:
        error = ieee80211_ioctl(ifp, cmd, data);
    }

    if (error == ENETRESET) {
        error = 0;
        if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
            (IFF_UP | IFF_RUNNING)) {
            that->iwn_stop(ifp);
            error = that->iwn_init(ifp);
        }
    }

    splx(s);
//    rw_exit_write(&sc->sc_rwlock);
    return error;
}

/*
 * Send a command to the firmware.
 */
int ItlIwn::
iwn_cmd(struct iwn_softc *sc, int code, const void *buf, int size, int async)
{
    DPRINTFN(2, ("%s code=%d size=%d\n", __FUNCTION__, code, size));
    struct iwn_ops *ops = &sc->ops;
    struct iwn_tx_ring *ring = &sc->txq[4];
    struct iwn_tx_desc *desc;
    struct iwn_tx_data *data;
    struct iwn_tx_cmd *cmd;
    mbuf_t m;
    bus_addr_t paddr;
    int totlen, error = 0;
    unsigned int max_chunks = 1;
    IOPhysicalSegment seg;

    desc = &ring->desc[ring->cur];
    data = &ring->data[ring->cur];
    totlen = 4 + size;

    if (size > sizeof cmd->data) {
        /* Command is too large to fit in a descriptor. */
        if (totlen > MCLBYTES)
            return EINVAL;
//        MGETHDR(m, M_DONTWAIT, MT_DATA);
//        if (totlen > MHLEN) {
//            MCLGET(m, M_DONTWAIT);
//            if (!(m->m_flags & M_EXT)) {
//                mbuf_freem(m);
//                return ENOMEM;
//            }
//        }
        mbuf_allocpacket(MBUF_WAITOK, totlen, &max_chunks, &m);
        if (m == NULL) {
            XYLog("%s: could not get fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            return ENOMEM;
        }
        mbuf_setlen(m, totlen);
        mbuf_pkthdr_setlen(m, totlen);

        cmd = mtod(m, struct iwn_tx_cmd *);
//        error = bus_dmamap_load(sc->sc_dmat, data->map, cmd, totlen,
//            NULL, BUS_DMA_NOWAIT | BUS_DMA_WRITE);
//        if (error != 0) {
//            mbuf_freem(m);
//            return error;
//        }
        data->map->dm_nsegs = data->map->cursor->getPhysicalSegmentsWithCoalesce(m, &seg, 1);
        if (data->map->dm_nsegs == 0) {
            XYLog("%s: could not load fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            mbuf_freem(m);
            return ENOMEM;
        }
        data->m = m;
        paddr = seg.location;
    } else {
        cmd = &ring->cmd[ring->cur];
        paddr = data->cmd_paddr;
    }

    cmd->code = code;
    cmd->flags = 0;
    cmd->qid = ring->qid;
    cmd->idx = ring->cur;
    memcpy(cmd->data, buf, size);

    desc->nsegs = 1;
    desc->segs[0].addr = htole32(IWN_LOADDR(paddr));
    desc->segs[0].len  = htole16(IWN_HIADDR(paddr) | totlen << 4);

//    if (size > sizeof cmd->data) {
//        bus_dmamap_sync(sc->sc_dmat, data->map, 0, totlen,
//            BUS_DMASYNC_PREWRITE);
//    } else {
//        bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
//            (caddr_t)cmd - ring->cmd_dma.vaddr, totlen,
//            BUS_DMASYNC_PREWRITE);
//    }
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//        (caddr_t)desc - ring->desc_dma.vaddr, sizeof (*desc),
//        BUS_DMASYNC_PREWRITE);

    /* Update TX scheduler. */
    ops->update_sched(sc, ring->qid, ring->cur, 0, 0);

    /* Kick command ring. */
    ring->cur = (ring->cur + 1) % IWN_TX_RING_COUNT;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

    return async ? 0 : tsleep_nsec(desc, PCATCH, "iwncmd", SEC_TO_NSEC(1));
}

int ItlIwn::
iwn4965_add_node(struct iwn_softc *sc, struct iwn_node_info *node, int async)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn4965_node_info hnode;
    caddr_t src, dst;

    /*
     * We use the node structure for 5000 Series internally (it is
     * a superset of the one for 4965AGN). We thus copy the common
     * fields before sending the command.
     */
    src = (caddr_t)node;
    dst = (caddr_t)&hnode;
    memcpy(dst, src, 48);
    /* Skip TSC, RX MIC and TX MIC fields from ``src''. */
    memcpy(dst + 48, src + 72, 20);
    return that->iwn_cmd(sc, IWN_CMD_ADD_NODE, &hnode, sizeof hnode, async);
}

int ItlIwn::
iwn5000_add_node(struct iwn_softc *sc, struct iwn_node_info *node, int async)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    
    /* Direct mapping. */
    return that->iwn_cmd(sc, IWN_CMD_ADD_NODE, node, sizeof (*node), async);
}

int ItlIwn::
iwn_set_link_quality(struct iwn_softc *sc, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_cmd_link_quality linkq;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    uint8_t txant;
    int i, ridx, ridx_min, ridx_max, j, mimo, tab = 0, rflags = 0;

    /* Use the first valid TX antenna. */
    txant = IWN_LSB(sc->txchainmask);

    memset(&linkq, 0, sizeof linkq);
    linkq.id = wn->id;
    linkq.antmsk_1stream = txant;
    linkq.antmsk_2stream = IWN_ANT_AB;
    linkq.ampdu_max = IWN_AMPDU_MAX;
    linkq.ampdu_threshold = 3;
    linkq.ampdu_limit = htole16(4000);    /* 4ms */

#if 0 // RTS/CTS protection not yet tested
    if (ni->ni_flags & IEEE80211_NODE_HT &&
        sc->agg_queue_mask > 0 &&
        ic->ic_flags & IEEE80211_F_USEPROT)
        if (sc->hw_type != IWN_HW_REV_TYPE_4965 &&
            sc->hw_type != IWN_HW_REV_TYPE_5300 &&
            sc->hw_type != IWN_HW_REV_TYPE_5150 &&
            sc->hw_type != IWN_HW_REV_TYPE_5350 &&
            sc->hw_type != IWN_HW_REV_TYPE_5100)
            linkq.flags |= IWN_LINK_QUAL_FLAGS_SET_STA_TLC_RTS;
#endif
    
    /*
     * Fill the LQ rate selection table with legacy and/or HT rates
     * in descending order, i.e. with the node's current TX rate first.
     * In cases where throughput of an HT rate corresponds to a legacy
     * rate it makes no sense to add both. We rely on the fact that
     * iwn_rates is laid out such that equivalent HT/legacy rates share
     * the same IWN_RATE_*_INDEX value. Also, rates not applicable to
     * legacy/HT are assumed to be marked with an 'invalid' PLCP value.
     */
    j = 0;
    ridx_min = iwn_rval2ridx(ieee80211_min_basic_rate(ic));
    mimo = iwn_is_mimo_mcs(ni->ni_txmcs);
    ridx_max = (mimo ? IWN_LAST_HT_RATE : IWN_LAST_HT_SISO_RATE);
    for (ridx = ridx_max; ridx >= ridx_min; ridx--) {
        uint8_t plcp = iwn_rates[ridx].plcp;
        uint8_t ht_plcp = iwn_rates[ridx].ht_plcp;
        
        if (j >= IWN_MAX_TX_RETRIES)
            break;
        tab = 0;
        rflags = 0;
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            if (ht_plcp == IWN_RATE_HT_SISO_MCS_INV_PLCP)
                continue;
            /* Do not mix SISO and MIMO HT rates. */
            if ((mimo && !iwn_is_mimo_ht_plcp(ht_plcp)) ||
                (!mimo && iwn_is_mimo_ht_plcp(ht_plcp)))
                continue;
            for (i = ni->ni_txmcs; i >= 0; i--) {
                if (ic->ic_tx_mcs_set == IEEE80211_TX_MCS_SET_DEFINED &&
                    isclr(ni->ni_rxmcs, i))
                    continue;
                if (ridx != iwn_mcs2ridx[i])
                    continue;
                tab = ht_plcp;
                rflags |= IWN_RFLAG_MCS;
                /* First two Tx attempts may use 40MHz/SGI. */
                if (j > 1)
                    break;
                if (iwn_rxon_ht40_enabled(sc))
                    rflags |= IWN_RFLAG_HT40;
                if (ieee80211_ra_use_ht_sgi(ni))
                    rflags |= IWN_RFLAG_SGI;
            }
        } else if (plcp != IWN_RATE_INVM_PLCP) {
            for (i = ni->ni_txrate; i >= 0; i--) {
                if (iwn_rates[ridx].rate == (rs->rs_rates[i] &
                                             IEEE80211_RATE_VAL)) {
                    tab = plcp;
                    break;
                }
            }
        }
        
        if (tab == 0 && rflags == 0)
            continue;
        
        if (iwn_is_mimo_ht_plcp(ht_plcp))
            rflags |= IWN_RFLAG_ANT(sc->txchainmask);
        else
            rflags |= IWN_RFLAG_ANT(txant);
        
        if (IWN_RIDX_IS_CCK(ridx))
            rflags |= IWN_RFLAG_CCK;

        DPRINTFN(2, ("lq.retry[%d].plcp = 0x%x, lq.retry[i].rflags = 0x%x\n", j, tab, rflags));
        linkq.retry[j].plcp = tab;
        linkq.retry[j].rflags = rflags;
        j++;
    }
    
    linkq.mimo = (mimo ? j : 0);
    
    /* Fill the rest with the lowest possible rate */
    while (j < IWN_MAX_TX_RETRIES) {
        tab = iwn_rates[ridx_min].plcp;
        rflags = 0;
        if (IWN_RIDX_IS_CCK(ridx_min))
            rflags |= IWN_RFLAG_CCK;
        rflags |= IWN_RFLAG_ANT(txant);
        DPRINTFN(2, ("lq.retry[%d].plcp = 0x%x, lq.retry[i].rflags = 0x%x\n", j, tab, rflags));
        linkq.retry[j].plcp = tab;
        linkq.retry[j].rflags = rflags;
        j++;
    }

    return iwn_cmd(sc, IWN_CMD_LINK_QUALITY, &linkq, sizeof linkq, 1);
}

/*
 * Broadcast node is used to send group-addressed and management frames.
 */
int ItlIwn::
iwn_add_broadcast_node(struct iwn_softc *sc, int async, int ridx)
{
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node_info node;
    struct iwn_cmd_link_quality linkq;
    const struct iwn_rate *rinfo;
    uint8_t txant;
    int i, error;

    memset(&node, 0, sizeof node);
    IEEE80211_ADDR_COPY(node.macaddr, etherbroadcastaddr);
    node.id = sc->broadcast_id;
    DPRINTF(("adding broadcast node\n"));
    if ((error = ops->add_node(sc, &node, async)) != 0)
        return error;

    /* Use the first valid TX antenna. */
    txant = IWN_LSB(sc->txchainmask);

    memset(&linkq, 0, sizeof linkq);
    linkq.id = sc->broadcast_id;
    linkq.antmsk_1stream = txant;
    linkq.antmsk_2stream = IWN_ANT_AB;
    linkq.ampdu_max = IWN_AMPDU_MAX_NO_AGG;
    linkq.ampdu_threshold = 3;
    linkq.ampdu_limit = htole16(4000);    /* 4ms */

    /* Use lowest mandatory bit-rate. */
    rinfo = &iwn_rates[ridx];
    linkq.retry[0].plcp = rinfo->plcp;
    if (IWN_RIDX_IS_CCK(ridx))
        linkq.retry[0].rflags = IWN_RFLAG_CCK;
    linkq.retry[0].rflags |= IWN_RFLAG_ANT(txant);
    /* Use same bit-rate for all TX retries. */
    for (i = 1; i < IWN_MAX_TX_RETRIES; i++) {
        linkq.retry[i].plcp = linkq.retry[0].plcp;
        linkq.retry[i].rflags = linkq.retry[0].rflags;
    }
    return iwn_cmd(sc, IWN_CMD_LINK_QUALITY, &linkq, sizeof linkq, async);
}

void ItlIwn::
iwn_updateedca(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);

#define IWN_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct ieee80211_node *ni = ic->ic_bss;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_edca_params cmd;
    int aci;

    memset(&cmd, 0, sizeof cmd);
    for (aci = 0; aci < EDCA_NUM_AC; aci++) {
        const struct ieee80211_edca_ac_params *ac =
            &ic->ic_edca_ac[aci];
        cmd.ac[aci].aifsn = ac->ac_aifsn;
        cmd.ac[aci].cwmin = htole16(IWN_EXP2(ac->ac_ecwmin));
        cmd.ac[aci].cwmax = htole16(IWN_EXP2(ac->ac_ecwmax));
        cmd.ac[aci].txoplimit =
            htole16(IEEE80211_TXOP_TO_US(ac->ac_txoplimit));
    }
    if (ni->ni_flags & IEEE80211_NODE_QOS)
        cmd.flags |= htole32(IWN_EDCA_UPDATE);

    if (ni->ni_flags & IEEE80211_NODE_HT)
        cmd.flags |= htole32(IWN_EDCA_FLG_TGN);

    (void)that->iwn_cmd(sc, IWN_CMD_EDCA_PARAMS, &cmd, sizeof cmd, 1);
#undef IWN_EXP2
}

void ItlIwn::
iwn_set_led(struct iwn_softc *sc, uint8_t which, uint8_t off, uint8_t on)
{
    struct iwn_cmd_led led;

    /* Clear microcode LED ownership. */
    IWN_CLRBITS(sc, IWN_LED, IWN_LED_BSM_CTRL);

    led.which = which;
    led.unit = htole32(10000);    /* on/off in unit of 100ms */
    led.off = off;
    led.on = on;
    (void)iwn_cmd(sc, IWN_CMD_SET_LED, &led, sizeof led, 1);
}

/*
 * Set the critical temperature at which the firmware will stop the radio
 * and notify us.
 */
int ItlIwn::
iwn_set_critical_temp(struct iwn_softc *sc)
{
    struct iwn_critical_temp crit;
    int32_t temp;

    IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_CTEMP_STOP_RF);

    if (sc->hw_type == IWN_HW_REV_TYPE_5150)
        temp = (IWN_CTOK(110) - sc->temp_off) * -5;
    else if (sc->hw_type == IWN_HW_REV_TYPE_4965)
        temp = IWN_CTOK(110);
    else
        temp = 110;
    memset(&crit, 0, sizeof crit);
    crit.tempR = htole32(temp);
    DPRINTF(("setting critical temperature to %d\n", temp));
    return iwn_cmd(sc, IWN_CMD_SET_CRITICAL_TEMP, &crit, sizeof crit, 0);
}

int ItlIwn::
iwn_set_timing(struct iwn_softc *sc, struct ieee80211_node *ni)
{
    struct iwn_cmd_timing cmd;
    uint64_t val, mod;

    memset(&cmd, 0, sizeof cmd);
    memcpy(&cmd.tstamp, ni->ni_tstamp, sizeof (uint64_t));
    cmd.bintval = htole16(ni->ni_intval);
    cmd.lintval = htole16(10);

    /* Compute remaining time until next beacon. */
    val = (uint64_t)ni->ni_intval * IEEE80211_DUR_TU;
    mod = letoh64(cmd.tstamp) % val;
    cmd.binitval = htole32((uint32_t)(val - mod));

    DPRINTF(("timing bintval=%u, tstamp=%llu, init=%u\n",
        ni->ni_intval, letoh64(cmd.tstamp), (uint32_t)(val - mod)));

    return iwn_cmd(sc, IWN_CMD_TIMING, &cmd, sizeof cmd, 1);
}

void ItlIwn::
iwn4965_power_calibration(struct iwn_softc *sc, int temp)
{
    /* Adjust TX power if need be (delta >= 3 degC). */
    DPRINTF(("temperature %d->%d\n", sc->temp, temp));
    if (abs(temp - sc->temp) >= 3) {
        /* Record temperature of last calibration. */
        sc->temp = temp;
        (void)iwn4965_set_txpower(sc, 1);
    }
}

/*
 * Set TX power for current channel (each rate has its own power settings).
 * This function takes into account the regulatory information from EEPROM,
 * the current temperature and the current voltage.
 */
int ItlIwn::
iwn4965_set_txpower(struct iwn_softc *sc, int async)
{
/* Fixed-point arithmetic division using a n-bit fractional part. */
#define fdivround(a, b, n)    \
    ((((1 << n) * (a)) / (b) + (1 << n) / 2) / (1 << n))
/* Linear interpolation. */
#define interpolate(x, x1, y1, x2, y2, n)    \
    ((y1) + fdivround(((int)(x) - (x1)) * ((y2) - (y1)), (x2) - (x1), n))

    static const int tdiv[IWN_NATTEN_GROUPS] = { 9, 8, 8, 8, 6 };
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_ucode_info *uc = &sc->ucode_info;
    struct ieee80211_channel *ch;
    struct iwn4965_cmd_txpower cmd;
    struct iwn4965_eeprom_chan_samples *chans;
    const uint8_t *rf_gain, *dsp_gain;
    int32_t vdiff, tdiff;
    int i, c, grp, maxpwr, is_ht40 = 0;
    uint8_t chan, ext_chan;

    /* Retrieve current channel from last RXON. */
    chan = sc->rxon.chan;
    DPRINTF(("setting TX power for channel %d\n", chan));
    ch = &ic->ic_channels[chan];

    memset(&cmd, 0, sizeof cmd);
    cmd.band = IEEE80211_IS_CHAN_5GHZ(ch) ? 0 : 1;
    cmd.chan = chan;

    if (IEEE80211_IS_CHAN_5GHZ(ch)) {
        maxpwr   = sc->maxpwr5GHz;
        rf_gain  = iwn4965_rf_gain_5ghz;
        dsp_gain = iwn4965_dsp_gain_5ghz;
    } else {
        maxpwr   = sc->maxpwr2GHz;
        rf_gain  = iwn4965_rf_gain_2ghz;
        dsp_gain = iwn4965_dsp_gain_2ghz;
    }

    /* Compute voltage compensation. */
    vdiff = ((int32_t)letoh32(uc->volt) - sc->eeprom_voltage) / 7;
    if (vdiff > 0)
        vdiff *= 2;
    if (abs(vdiff) > 2)
        vdiff = 0;
    DPRINTF(("voltage compensation=%d (UCODE=%d, EEPROM=%d)\n",
        vdiff, letoh32(uc->volt), sc->eeprom_voltage));

    /* Get channel attenuation group. */
    if (chan <= 20)        /* 1-20 */
        grp = 4;
    else if (chan <= 43)    /* 34-43 */
        grp = 0;
    else if (chan <= 70)    /* 44-70 */
        grp = 1;
    else if (chan <= 124)    /* 71-124 */
        grp = 2;
    else            /* 125-200 */
        grp = 3;
    DPRINTF(("chan %d, attenuation group=%d\n", chan, grp));

    /* Get channel sub-band. */
    for (i = 0; i < IWN_NBANDS; i++)
        if (sc->bands[i].lo != 0 &&
            sc->bands[i].lo <= chan && chan <= sc->bands[i].hi)
            break;
    if (i == IWN_NBANDS)    /* Can't happen in real-life. */
        return EINVAL;
    chans = sc->bands[i].chans;
    DPRINTF(("chan %d sub-band=%d\n", chan, i));
    
    if (that->iwn_rxon_ht40_enabled(sc)) {
        is_ht40 = 1;
        if (le32toh(sc->rxon.flags) & IWN_RXON_HT_HT40MINUS)
            ext_chan = chan - 2;
        else
            ext_chan = chan + 2;
    } else
        ext_chan = chan;

    for (c = 0; c < 2; c++) {
        uint8_t power, gain, temp;
        int maxchpwr, pwr, ridx, idx;

        power = interpolate(ext_chan,
            chans[0].num, chans[0].samples[c][1].power,
            chans[1].num, chans[1].samples[c][1].power, 1);
        gain  = interpolate(ext_chan,
            chans[0].num, chans[0].samples[c][1].gain,
            chans[1].num, chans[1].samples[c][1].gain, 1);
        temp  = interpolate(ext_chan,
            chans[0].num, chans[0].samples[c][1].temp,
            chans[1].num, chans[1].samples[c][1].temp, 1);
        DPRINTF(("TX chain %d: power=%d gain=%d temp=%d\n",
            c, power, gain, temp));

        /* Compute temperature compensation. */
        tdiff = ((sc->temp - temp) * 2) / tdiv[grp];
        DPRINTF(("temperature compensation=%d (current=%d, "
            "EEPROM=%d)\n", tdiff, sc->temp, temp));

        for (ridx = 0; ridx <= IWN_RIDX_MAX; ridx++) {
            /* Convert dBm to half-dBm. */
            if (is_ht40)
                maxchpwr = sc->maxpwr40[chan] * 2;
            else
                maxchpwr = sc->maxpwr[chan] * 2;
#ifdef notyet
            if (ridx > iwn_mcs2ridx[7] && ridx < iwn_mcs2ridx[16])
                maxchpwr -= 6;    /* MIMO 2T: -3dB */
#endif

            pwr = maxpwr;

            /* Adjust TX power based on rate. */
            if ((ridx % 8) == 5)
                pwr -= 15;    /* OFDM48: -7.5dB */
            else if ((ridx % 8) == 6)
                pwr -= 17;    /* OFDM54: -8.5dB */
            else if ((ridx % 8) == 7)
                pwr -= 20;    /* OFDM60: -10dB */
            else
                pwr -= 10;    /* Others: -5dB */

            /* Do not exceed channel max TX power. */
            if (pwr > maxchpwr)
                pwr = maxchpwr;

            idx = gain - (pwr - power) - tdiff - vdiff;
            if (ridx > iwn_mcs2ridx[7]) /* MIMO */
                idx += (int32_t)letoh32(uc->atten[grp][c]);

            if (cmd.band == 0)
                idx += 9;    /* 5GHz */
            if (ridx == IWN_RIDX_MAX)
                idx += 5;    /* CCK */

            /* Make sure idx stays in a valid range. */
            if (idx < 0)
                idx = 0;
            else if (idx > IWN4965_MAX_PWR_INDEX)
                idx = IWN4965_MAX_PWR_INDEX;

            DPRINTF(("TX chain %d, rate idx %d: power=%d\n",
                c, ridx, idx));
            cmd.power[ridx].rf_gain[c] = rf_gain[idx];
            cmd.power[ridx].dsp_gain[c] = dsp_gain[idx];
        }
    }

    DPRINTF(("setting TX power for chan %d\n", chan));
    return that->iwn_cmd(sc, IWN_CMD_TXPOWER, &cmd, sizeof cmd, async);

#undef interpolate
#undef fdivround
}

int ItlIwn::
iwn5000_set_txpower(struct iwn_softc *sc, int async)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_cmd_txpower cmd;

    /*
     * TX power calibration is handled automatically by the firmware
     * for 5000 Series.
     */
    memset(&cmd, 0, sizeof cmd);
    cmd.global_limit = 2 * IWN5000_TXPOWER_MAX_DBM;    /* 16 dBm */
    cmd.flags = IWN5000_TXPOWER_NO_CLOSED;
    cmd.srv_limit = IWN5000_TXPOWER_AUTO;
    DPRINTF(("setting TX power\n"));
    return that->iwn_cmd(sc, IWN_CMD_TXPOWER_DBM, &cmd, sizeof cmd, async);
}

/*
 * Retrieve the maximum RSSI (in dBm) among receivers.
 */
int ItlIwn::
iwn4965_get_rssi(const struct iwn_rx_stat *stat)
{
    struct iwn4965_rx_phystat *phy = (struct iwn4965_rx_phystat *)stat->phybuf;
    uint8_t mask, agc;
    int rssi;

    mask = (letoh16(phy->antenna) >> 4) & IWN_ANT_ABC;
    agc  = (letoh16(phy->agc) >> 7) & 0x7f;

    rssi = 0;
    if (mask & IWN_ANT_A)
        rssi = MAX(rssi, phy->rssi[0]);
    if (mask & IWN_ANT_B)
        rssi = MAX(rssi, phy->rssi[2]);
    if (mask & IWN_ANT_C)
        rssi = MAX(rssi, phy->rssi[4]);

    return rssi - agc - IWN_RSSI_TO_DBM;
}

int ItlIwn::
iwn5000_get_rssi(const struct iwn_rx_stat *stat)
{
    struct iwn5000_rx_phystat *phy = (struct iwn5000_rx_phystat *)stat->phybuf;
    uint8_t agc;
    int rssi;

    agc = (letoh32(phy->agc) >> 9) & 0x7f;

    rssi = MAX(letoh16(phy->rssi[0]) & 0xff,
           letoh16(phy->rssi[1]) & 0xff);
    rssi = MAX(letoh16(phy->rssi[2]) & 0xff, rssi);

    return rssi - agc - IWN_RSSI_TO_DBM;
}

/*
 * Retrieve the average noise (in dBm) among receivers.
 */
int ItlIwn::
iwn_get_noise(const struct iwn_rx_general_stats *stats)
{
    int i, total, nbant, noise;

    total = nbant = 0;
    for (i = 0; i < 3; i++) {
        if ((noise = letoh32(stats->noise[i]) & 0xff) == 0)
            continue;
        total += noise;
        nbant++;
    }
    /* There should be at least one antenna but check anyway. */
    return (nbant == 0) ? -127 : (total / nbant) - 107;
}

/*
 * Compute temperature (in degC) from last received statistics.
 */
int ItlIwn::
iwn4965_get_temperature(struct iwn_softc *sc)
{
    struct iwn_ucode_info *uc = &sc->ucode_info;
    int32_t r1, r2, r3, r4, temp;

    if (sc->rx_stats_flags & IWN_STATS_FLAGS_BAND_HT40) {
        r1 = letoh32(uc->temp[0].chan40MHz);
        r2 = letoh32(uc->temp[1].chan40MHz);
        r3 = letoh32(uc->temp[2].chan40MHz);
    } else {
        r1 = letoh32(uc->temp[0].chan20MHz);
        r2 = letoh32(uc->temp[1].chan20MHz);
        r3 = letoh32(uc->temp[2].chan20MHz);
    }
    r4 = letoh32(sc->rawtemp);

    if (r1 == r3)    /* Prevents division by 0 (should not happen). */
        return 0;

    /* Sign-extend 23-bit R4 value to 32-bit. */
    r4 = ((r4 & 0xffffff) ^ 0x800000) - 0x800000;
    /* Compute temperature in Kelvin. */
    temp = (259 * (r4 - r2)) / (r3 - r1);
    temp = (temp * 97) / 100 + 8;

    DPRINTF(("temperature %dK/%dC\n", temp, IWN_KTOC(temp)));
    return IWN_KTOC(temp);
}

int ItlIwn::
iwn5000_get_temperature(struct iwn_softc *sc)
{
    int32_t temp;

    /*
     * Temperature is not used by the driver for 5000 Series because
     * TX power calibration is handled by firmware.
     */
    temp = letoh32(sc->rawtemp);
    if (sc->hw_type == IWN_HW_REV_TYPE_5150) {
        temp = (temp / -5) + sc->temp_off;
        temp = IWN_KTOC(temp);
    }
    return temp;
}

/*
 * Initialize sensitivity calibration state machine.
 */
int ItlIwn::
iwn_init_sensitivity(struct iwn_softc *sc)
{
    struct iwn_ops *ops = &sc->ops;
    struct iwn_calib_state *calib = &sc->calib;
    uint32_t flags;
    int error;

    /* Reset calibration state machine. */
    memset(calib, 0, sizeof (*calib));
    calib->state = IWN_CALIB_STATE_INIT;
    calib->cck_state = IWN_CCK_STATE_HIFA;
    /* Set initial correlation values. */
    calib->ofdm_x1     = sc->limits->min_ofdm_x1;
    calib->ofdm_mrc_x1 = sc->limits->min_ofdm_mrc_x1;
    calib->ofdm_x4     = sc->limits->min_ofdm_x4;
    calib->ofdm_mrc_x4 = sc->limits->min_ofdm_mrc_x4;
    calib->cck_x4      = 125;
    calib->cck_mrc_x4  = sc->limits->min_cck_mrc_x4;
    calib->energy_cck  = sc->limits->energy_cck;

    /* Write initial sensitivity. */
    if ((error = iwn_send_sensitivity(sc)) != 0)
        return error;

    /* Write initial gains. */
    if ((error = ops->init_gains(sc)) != 0)
        return error;

    /* Request statistics at each beacon interval. */
    flags = 0;
    DPRINTFN(2, ("sending request for statistics\n"));
    return iwn_cmd(sc, IWN_CMD_GET_STATISTICS, &flags, sizeof flags, 1);
}

/*
 * Collect noise and RSSI statistics for the first 20 beacons received
 * after association and use them to determine connected antennas and
 * to set differential gains.
 */
void ItlIwn::
iwn_collect_noise(struct iwn_softc *sc,
    const struct iwn_rx_general_stats *stats)
{
    struct iwn_ops *ops = &sc->ops;
    struct iwn_calib_state *calib = &sc->calib;
    uint32_t val;
    int i;

    /* Accumulate RSSI and noise for all 3 antennas. */
    for (i = 0; i < 3; i++) {
        calib->rssi[i] += letoh32(stats->rssi[i]) & 0xff;
        calib->noise[i] += letoh32(stats->noise[i]) & 0xff;
    }
    /* NB: We update differential gains only once after 20 beacons. */
    if (++calib->nbeacons < 20)
        return;

    /* Determine highest average RSSI. */
    val = MAX(calib->rssi[0], calib->rssi[1]);
    val = MAX(calib->rssi[2], val);

    /* Determine which antennas are connected. */
    sc->chainmask = sc->rxchainmask;
    for (i = 0; i < 3; i++)
        if (val - calib->rssi[i] > 15 * 20)
            sc->chainmask &= ~(1 << i);
    DPRINTF(("RX chains mask: theoretical=0x%x, actual=0x%x\n",
        sc->rxchainmask, sc->chainmask));

    /* If none of the TX antennas are connected, keep at least one. */
    if ((sc->chainmask & sc->txchainmask) == 0)
        sc->chainmask |= IWN_LSB(sc->txchainmask);

    (void)ops->set_gains(sc);
    calib->state = IWN_CALIB_STATE_RUN;

#ifdef notyet
    /* XXX Disable RX chains with no antennas connected. */
    sc->rxon.rxchain = htole16(IWN_RXCHAIN_SEL(sc->chainmask));
    (void)iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
#endif

    /* Enable power-saving mode if requested by user. */
    if (sc->sc_ic.ic_flags & IEEE80211_F_PMGTON)
        (void)iwn_set_pslevel(sc, 0, 3, 1);
}

int ItlIwn::
iwn4965_init_gains(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_phy_calib_gain cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = IWN4965_PHY_CALIB_DIFF_GAIN;
    /* Differential gains initially set to 0 for all 3 antennas. */
    DPRINTF(("setting initial differential gains\n"));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

int ItlIwn::
iwn5000_init_gains(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_phy_calib cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = sc->reset_noise_gain;
    cmd.ngroups = 1;
    cmd.isvalid = 1;
    DPRINTF(("setting initial differential gains\n"));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

int ItlIwn::
iwn4965_set_gains(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_calib_state *calib = &sc->calib;
    struct iwn_phy_calib_gain cmd;
    int i, delta, noise;

    /* Get minimal noise among connected antennas. */
    noise = INT_MAX;    /* NB: There's at least one antenna. */
    for (i = 0; i < 3; i++)
        if (sc->chainmask & (1 << i))
            noise = MIN(calib->noise[i], noise);

    memset(&cmd, 0, sizeof cmd);
    cmd.code = IWN4965_PHY_CALIB_DIFF_GAIN;
    /* Set differential gains for connected antennas. */
    for (i = 0; i < 3; i++) {
        if (sc->chainmask & (1 << i)) {
            /* Compute attenuation (in unit of 1.5dB). */
            delta = (noise - (int32_t)calib->noise[i]) / 30;
            /* NB: delta <= 0 */
            /* Limit to [-4.5dB,0]. */
            cmd.gain[i] = MIN(abs(delta), 3);
            if (delta < 0)
                cmd.gain[i] |= 1 << 2;    /* sign bit */
        }
    }
    DPRINTF(("setting differential gains Ant A/B/C: %x/%x/%x (%x)\n",
        cmd.gain[0], cmd.gain[1], cmd.gain[2], sc->chainmask));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

int ItlIwn::
iwn5000_set_gains(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_calib_state *calib = &sc->calib;
    struct iwn_phy_calib_gain cmd;
    int i, ant, div, delta;

    /* We collected 20 beacons and !=6050 need a 1.5 factor. */
    div = (sc->hw_type == IWN_HW_REV_TYPE_6050) ? 20 : 30;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = sc->noise_gain;
    cmd.ngroups = 1;
    cmd.isvalid = 1;
    /*
     * Get first available RX antenna as referential.
     * IWN_LSB() return values start with 1, but antenna gain array
     * cmd.gain[] and noise array calib->noise[] start with 0.
     */
    ant = IWN_LSB(sc->rxchainmask) - 1;

    /* Set differential gains for other antennas. */
    for (i = ant + 1; i < 3; i++) {
        if (sc->chainmask & (1 << i)) {
            /* The delta is relative to antenna "ant". */
            delta = ((int32_t)calib->noise[ant] -
                (int32_t)calib->noise[i]) / div;
            DPRINTF(("Ant[%d] vs. Ant[%d]: delta %d\n", ant, i, delta));
            /* Limit to [-4.5dB,+4.5dB]. */
            cmd.gain[i] = MIN(abs(delta), 3);
            if (delta < 0)
                cmd.gain[i] |= 1 << 2;    /* sign bit */
            DPRINTF(("Setting differential gains for antenna %d: %x\n",
                i, cmd.gain[i]));
        }
    }
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 1);
}

/*
 * Tune RF RX sensitivity based on the number of false alarms detected
 * during the last beacon period.
 */
void ItlIwn::
iwn_tune_sensitivity(struct iwn_softc *sc, const struct iwn_rx_stats *stats)
{
#define inc(val, inc, max)            \
    if ((val) < (max)) {            \
        if ((val) < (max) - (inc))    \
            (val) += (inc);        \
        else                \
            (val) = (max);        \
        needs_update = 1;        \
    }
#define dec(val, dec, min)            \
    if ((val) > (min)) {            \
        if ((val) > (min) + (dec))    \
            (val) -= (dec);        \
        else                \
            (val) = (min);        \
        needs_update = 1;        \
    }

    const struct iwn_sensitivity_limits *limits = sc->limits;
    struct iwn_calib_state *calib = &sc->calib;
    uint32_t val, rxena, fa;
    uint32_t energy[3], energy_min;
    uint8_t noise[3], noise_ref;
    int i, needs_update = 0;

    /* Check that we've been enabled long enough. */
    if ((rxena = letoh32(stats->general.load)) == 0)
        return;

    /* Compute number of false alarms since last call for OFDM. */
    fa  = letoh32(stats->ofdm.bad_plcp) - calib->bad_plcp_ofdm;
    fa += letoh32(stats->ofdm.fa) - calib->fa_ofdm;
    fa *= 200 * IEEE80211_DUR_TU;    /* 200TU */

    /* Save counters values for next call. */
    calib->bad_plcp_ofdm = letoh32(stats->ofdm.bad_plcp);
    calib->fa_ofdm = letoh32(stats->ofdm.fa);

    if (fa > 50 * rxena) {
        /* High false alarm count, decrease sensitivity. */
        DPRINTFN(2, ("OFDM high false alarm count: %u\n", fa));
        inc(calib->ofdm_x1,     1, limits->max_ofdm_x1);
        inc(calib->ofdm_mrc_x1, 1, limits->max_ofdm_mrc_x1);
        inc(calib->ofdm_x4,     1, limits->max_ofdm_x4);
        inc(calib->ofdm_mrc_x4, 1, limits->max_ofdm_mrc_x4);

    } else if (fa < 5 * rxena) {
        /* Low false alarm count, increase sensitivity. */
        DPRINTFN(2, ("OFDM low false alarm count: %u\n", fa));
        dec(calib->ofdm_x1,     1, limits->min_ofdm_x1);
        dec(calib->ofdm_mrc_x1, 1, limits->min_ofdm_mrc_x1);
        dec(calib->ofdm_x4,     1, limits->min_ofdm_x4);
        dec(calib->ofdm_mrc_x4, 1, limits->min_ofdm_mrc_x4);
    }

    /* Compute maximum noise among 3 receivers. */
    for (i = 0; i < 3; i++)
        noise[i] = (letoh32(stats->general.noise[i]) >> 8) & 0xff;
    val = MAX(noise[0], noise[1]);
    val = MAX(noise[2], val);
    /* Insert it into our samples table. */
    calib->noise_samples[calib->cur_noise_sample] = val;
    calib->cur_noise_sample = (calib->cur_noise_sample + 1) % 20;

    /* Compute maximum noise among last 20 samples. */
    noise_ref = calib->noise_samples[0];
    for (i = 1; i < 20; i++)
        noise_ref = MAX(noise_ref, calib->noise_samples[i]);

    /* Compute maximum energy among 3 receivers. */
    for (i = 0; i < 3; i++)
        energy[i] = letoh32(stats->general.energy[i]);
    val = MIN(energy[0], energy[1]);
    val = MIN(energy[2], val);
    /* Insert it into our samples table. */
    calib->energy_samples[calib->cur_energy_sample] = val;
    calib->cur_energy_sample = (calib->cur_energy_sample + 1) % 10;

    /* Compute minimum energy among last 10 samples. */
    energy_min = calib->energy_samples[0];
    for (i = 1; i < 10; i++)
        energy_min = MAX(energy_min, calib->energy_samples[i]);
    energy_min += 6;

    /* Compute number of false alarms since last call for CCK. */
    fa  = letoh32(stats->cck.bad_plcp) - calib->bad_plcp_cck;
    fa += letoh32(stats->cck.fa) - calib->fa_cck;
    fa *= 200 * IEEE80211_DUR_TU;    /* 200TU */

    /* Save counters values for next call. */
    calib->bad_plcp_cck = letoh32(stats->cck.bad_plcp);
    calib->fa_cck = letoh32(stats->cck.fa);

    if (fa > 50 * rxena) {
        /* High false alarm count, decrease sensitivity. */
        DPRINTFN(2, ("CCK high false alarm count: %u\n", fa));
        calib->cck_state = IWN_CCK_STATE_HIFA;
        calib->low_fa = 0;

        if (calib->cck_x4 > 160) {
            calib->noise_ref = noise_ref;
            if (calib->energy_cck > 2)
                dec(calib->energy_cck, 2, energy_min);
        }
        if (calib->cck_x4 < 160) {
            calib->cck_x4 = 161;
            needs_update = 1;
        } else
            inc(calib->cck_x4, 3, limits->max_cck_x4);

        inc(calib->cck_mrc_x4, 3, limits->max_cck_mrc_x4);

    } else if (fa < 5 * rxena) {
        /* Low false alarm count, increase sensitivity. */
        DPRINTFN(2, ("CCK low false alarm count: %u\n", fa));
        calib->cck_state = IWN_CCK_STATE_LOFA;
        calib->low_fa++;

        if (calib->cck_state != IWN_CCK_STATE_INIT &&
            (((int32_t)calib->noise_ref - (int32_t)noise_ref) > 2 ||
             calib->low_fa > 100)) {
            inc(calib->energy_cck, 2, limits->min_energy_cck);
            dec(calib->cck_x4,     3, limits->min_cck_x4);
            dec(calib->cck_mrc_x4, 3, limits->min_cck_mrc_x4);
        }
    } else {
        /* Not worth to increase or decrease sensitivity. */
        DPRINTFN(2, ("CCK normal false alarm count: %u\n", fa));
        calib->low_fa = 0;
        calib->noise_ref = noise_ref;

        if (calib->cck_state == IWN_CCK_STATE_HIFA) {
            /* Previous interval had many false alarms. */
            dec(calib->energy_cck, 8, energy_min);
        }
        calib->cck_state = IWN_CCK_STATE_INIT;
    }

    if (needs_update)
        (void)iwn_send_sensitivity(sc);
#undef dec
#undef inc
}

int ItlIwn::
iwn_send_sensitivity(struct iwn_softc *sc)
{
    struct iwn_calib_state *calib = &sc->calib;
    struct iwn_enhanced_sensitivity_cmd cmd;
    int len;

    memset(&cmd, 0, sizeof cmd);
    len = sizeof (struct iwn_sensitivity_cmd);
    cmd.which = IWN_SENSITIVITY_WORKTBL;
    /* OFDM modulation. */
    cmd.corr_ofdm_x1       = htole16(calib->ofdm_x1);
    cmd.corr_ofdm_mrc_x1   = htole16(calib->ofdm_mrc_x1);
    cmd.corr_ofdm_x4       = htole16(calib->ofdm_x4);
    cmd.corr_ofdm_mrc_x4   = htole16(calib->ofdm_mrc_x4);
    cmd.energy_ofdm        = htole16(sc->limits->energy_ofdm);
    cmd.energy_ofdm_th     = htole16(62);
    /* CCK modulation. */
    cmd.corr_cck_x4        = htole16(calib->cck_x4);
    cmd.corr_cck_mrc_x4    = htole16(calib->cck_mrc_x4);
    cmd.energy_cck         = htole16(calib->energy_cck);
    /* Barker modulation: use default values. */
    cmd.corr_barker        = htole16(190);
    cmd.corr_barker_mrc    = htole16(390);
    if (!(sc->sc_flags & IWN_FLAG_ENH_SENS))
        goto send;
    /* Enhanced sensitivity settings. */
    len = sizeof (struct iwn_enhanced_sensitivity_cmd);
    cmd.ofdm_det_slope_mrc = htole16(668);
    cmd.ofdm_det_icept_mrc = htole16(4);
    cmd.ofdm_det_slope     = htole16(486);
    cmd.ofdm_det_icept     = htole16(37);
    cmd.cck_det_slope_mrc  = htole16(853);
    cmd.cck_det_icept_mrc  = htole16(4);
    cmd.cck_det_slope      = htole16(476);
    cmd.cck_det_icept      = htole16(99);
send:
    return iwn_cmd(sc, IWN_CMD_SET_SENSITIVITY, &cmd, len, 1);
}

/*
 * Set STA mode power saving level (between 0 and 5).
 * Level 0 is CAM (Continuously Aware Mode), 5 is for maximum power saving.
 */
int ItlIwn::
iwn_set_pslevel(struct iwn_softc *sc, int dtim, int level, int async)
{
    struct iwn_pmgt_cmd cmd;
    const struct iwn_pmgt *pmgt;
    uint32_t max, skip_dtim;
    pcireg_t reg;
    int i;

    /* Select which PS parameters to use. */
    if (dtim <= 2)
        pmgt = &iwn_pmgt[0][level];
    else if (dtim <= 10)
        pmgt = &iwn_pmgt[1][level];
    else
        pmgt = &iwn_pmgt[2][level];

    memset(&cmd, 0, sizeof cmd);
    if (level != 0)    /* not CAM */
        cmd.flags |= htole16(IWN_PS_ALLOW_SLEEP);
    if (level == 5)
        cmd.flags |= htole16(IWN_PS_FAST_PD);
    /* Retrieve PCIe Active State Power Management (ASPM). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
        sc->sc_cap_off + PCI_PCIE_LCSR);
    if (!(reg & PCI_PCIE_LCSR_ASPM_L0S))    /* L0s Entry disabled. */
        cmd.flags |= htole16(IWN_PS_PCI_PMGT);
    cmd.rxtimeout = htole32(pmgt->rxtimeout * 1024);
    cmd.txtimeout = htole32(pmgt->txtimeout * 1024);

    if (dtim == 0) {
        dtim = 1;
        skip_dtim = 0;
    } else
        skip_dtim = pmgt->skip_dtim;
    if (skip_dtim != 0) {
        cmd.flags |= htole16(IWN_PS_SLEEP_OVER_DTIM);
        max = pmgt->intval[4];
        if (max == (uint32_t)-1)
            max = dtim * (skip_dtim + 1);
        else if (max > dtim)
            max = (max / dtim) * dtim;
    } else
        max = dtim;
    for (i = 0; i < 5; i++)
        cmd.intval[i] = htole32(MIN(max, pmgt->intval[i]));

    DPRINTF(("setting power saving level to %d\n", level));
    return iwn_cmd(sc, IWN_CMD_SET_POWER_MODE, &cmd, sizeof cmd, async);
}

int ItlIwn::
iwn_send_btcoex(struct iwn_softc *sc)
{
    struct iwn_bluetooth cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.flags = IWN_BT_COEX_CHAN_ANN | IWN_BT_COEX_BT_PRIO;
    cmd.lead_time = IWN_BT_LEAD_TIME_DEF;
    cmd.max_kill = IWN_BT_MAX_KILL_DEF;
    DPRINTF(("configuring bluetooth coexistence\n"));
    return iwn_cmd(sc, IWN_CMD_BT_COEX, &cmd, sizeof(cmd), 0);
}

int ItlIwn::
iwn_send_advanced_btcoex(struct iwn_softc *sc)
{
    static const uint32_t btcoex_3wire[12] = {
        0xaaaaaaaa, 0xaaaaaaaa, 0xaeaaaaaa, 0xaaaaaaaa,
        0xcc00ff28, 0x0000aaaa, 0xcc00aaaa, 0x0000aaaa,
        0xc0004000, 0x00004000, 0xf0005000, 0xf0005000,
    };
    struct iwn_btcoex_priotable btprio;
    struct iwn_btcoex_prot btprot;
    int error, i;

    if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
        sc->hw_type == IWN_HW_REV_TYPE_135) {
        struct iwn2000_btcoex_config btconfig;

        memset(&btconfig, 0, sizeof btconfig);
        btconfig.flags = IWN_BT_COEX6000_CHAN_INHIBITION |
            (IWN_BT_COEX6000_MODE_3W << IWN_BT_COEX6000_MODE_SHIFT) |
            IWN_BT_SYNC_2_BT_DISABLE;
        btconfig.max_kill = 5;
        btconfig.bt3_t7_timer = 1;
        btconfig.kill_ack = htole32(0xffff0000);
        btconfig.kill_cts = htole32(0xffff0000);
        btconfig.sample_time = 2;
        btconfig.bt3_t2_timer = 0xc;
        for (i = 0; i < 12; i++)
            btconfig.lookup_table[i] = htole32(btcoex_3wire[i]);
        btconfig.valid = htole16(0xff);
        btconfig.prio_boost = htole32(0xf0);
        DPRINTF(("configuring advanced bluetooth coexistence\n"));
        error = iwn_cmd(sc, IWN_CMD_BT_COEX, &btconfig,
            sizeof(btconfig), 1);
        if (error != 0)
            return (error);
    } else {
        struct iwn6000_btcoex_config btconfig;

        memset(&btconfig, 0, sizeof btconfig);
        btconfig.flags = IWN_BT_COEX6000_CHAN_INHIBITION |
            (IWN_BT_COEX6000_MODE_3W << IWN_BT_COEX6000_MODE_SHIFT) |
            IWN_BT_SYNC_2_BT_DISABLE;
        btconfig.max_kill = 5;
        btconfig.bt3_t7_timer = 1;
        btconfig.kill_ack = htole32(0xffff0000);
        btconfig.kill_cts = htole32(0xffff0000);
        btconfig.sample_time = 2;
        btconfig.bt3_t2_timer = 0xc;
        for (i = 0; i < 12; i++)
            btconfig.lookup_table[i] = htole32(btcoex_3wire[i]);
        btconfig.valid = htole16(0xff);
        btconfig.prio_boost = 0xf0;
        DPRINTF(("configuring advanced bluetooth coexistence\n"));
        error = iwn_cmd(sc, IWN_CMD_BT_COEX, &btconfig,
            sizeof(btconfig), 1);
        if (error != 0)
            return (error);
    }

    memset(&btprio, 0, sizeof btprio);
    btprio.calib_init1 = 0x6;
    btprio.calib_init2 = 0x7;
    btprio.calib_periodic_low1 = 0x2;
    btprio.calib_periodic_low2 = 0x3;
    btprio.calib_periodic_high1 = 0x4;
    btprio.calib_periodic_high2 = 0x5;
    btprio.dtim = 0x6;
    btprio.scan52 = 0x8;
    btprio.scan24 = 0xa;
    error = iwn_cmd(sc, IWN_CMD_BT_COEX_PRIOTABLE, &btprio, sizeof(btprio),
        1);
    if (error != 0)
        return (error);

    /* Force BT state machine change */
    memset(&btprot, 0, sizeof btprot);
    btprot.open = 1;
    btprot.type = 1;
    error = iwn_cmd(sc, IWN_CMD_BT_COEX_PROT, &btprot, sizeof(btprot), 1);
    if (error != 0)
        return (error);

    btprot.open = 0;
    return (iwn_cmd(sc, IWN_CMD_BT_COEX_PROT, &btprot, sizeof(btprot), 1));
}

int ItlIwn::
iwn5000_runtime_calib(struct iwn_softc *sc)
{
    struct iwn5000_calib_config cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.ucode.once.enable = 0xffffffff;
    cmd.ucode.once.start = IWN5000_CALIB_DC;
    DPRINTF(("configuring runtime calibration\n"));
    return iwn_cmd(sc, IWN5000_CMD_CALIB_CONFIG, &cmd, sizeof(cmd), 0);
}

int ItlIwn::
iwn_config(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    uint32_t txmask;
    uint16_t rxchain;
    int error, ridx;

    /* Set radio temperature sensor offset. */
    if (sc->hw_type == IWN_HW_REV_TYPE_6005) {
        error = iwn6000_temp_offset_calib(sc);
        if (error != 0) {
            XYLog("%s: could not set temperature offset\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }

    if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
        sc->hw_type == IWN_HW_REV_TYPE_2000 ||
        sc->hw_type == IWN_HW_REV_TYPE_135 ||
        sc->hw_type == IWN_HW_REV_TYPE_105) {
        error = iwn2000_temp_offset_calib(sc);
        if (error != 0) {
            XYLog("%s: could not set temperature offset\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }

    if (sc->hw_type == IWN_HW_REV_TYPE_6050 ||
        sc->hw_type == IWN_HW_REV_TYPE_6005) {
        /* Configure runtime DC calibration. */
        error = iwn5000_runtime_calib(sc);
        if (error != 0) {
            XYLog("%s: could not configure runtime calibration\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }

    /* Configure valid TX chains for >=5000 Series. */
    if (sc->hw_type != IWN_HW_REV_TYPE_4965) {
        txmask = htole32(sc->txchainmask);
        DPRINTF(("configuring valid TX chains 0x%x\n", txmask));
        error = iwn_cmd(sc, IWN5000_CMD_TX_ANT_CONFIG, &txmask,
            sizeof txmask, 0);
        if (error != 0) {
            XYLog("%s: could not configure valid TX chains\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }

    /* Configure bluetooth coexistence. */
    if (sc->sc_flags & IWN_FLAG_ADV_BT_COEX)
        error = iwn_send_advanced_btcoex(sc);
    else
        error = iwn_send_btcoex(sc);
    if (error != 0) {
        XYLog("%s: could not configure bluetooth coexistence\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Set mode, channel, RX filter and enable RX. */
    memset(&sc->rxon, 0, sizeof (struct iwn_rxon));
//    IEEE80211_ADDR_COPY(ic->ic_myaddr, LLADDR(ifp->if_sadl));
    IEEE80211_ADDR_COPY(sc->rxon.myaddr, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(sc->rxon.wlap, ic->ic_myaddr);
    sc->rxon.chan = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
    sc->rxon.flags = htole32(IWN_RXON_TSF | IWN_RXON_CTS_TO_SELF);
    if (IEEE80211_IS_CHAN_2GHZ(ic->ic_ibss_chan)) {
        sc->rxon.flags |= htole32(IWN_RXON_AUTO | IWN_RXON_24GHZ);
        if (ic->ic_flags & IEEE80211_F_USEPROT)
            sc->rxon.flags |= htole32(IWN_RXON_TGG_PROT);
        DPRINTF(("%s: 2ghz prot 0x%x\n", __func__,
            le32toh(sc->rxon.flags)));
    }
    switch (ic->ic_opmode) {
    case IEEE80211_M_STA:
        sc->rxon.mode = IWN_MODE_STA;
        sc->rxon.filter = htole32(IWN_FILTER_MULTICAST);
        break;
    case IEEE80211_M_MONITOR:
        sc->rxon.mode = IWN_MODE_MONITOR;
        sc->rxon.filter = htole32(IWN_FILTER_MULTICAST |
            IWN_FILTER_CTL | IWN_FILTER_PROMISC);
        break;
    default:
        /* Should not get there. */
        break;
    }
    sc->rxon.cck_mask  = 0x0f;    /* not yet negotiated */
    sc->rxon.ofdm_mask = 0xff;    /* not yet negotiated */
    sc->rxon.ht_single_mask = 0xff;
    sc->rxon.ht_dual_mask = 0xff;
    sc->rxon.ht_triple_mask = 0xff;
    rxchain =
        IWN_RXCHAIN_VALID(sc->rxchainmask) |
        IWN_RXCHAIN_MIMO_COUNT(sc->nrxchains) |
        IWN_RXCHAIN_IDLE_COUNT(sc->nrxchains);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        rxchain |= IWN_RXCHAIN_FORCE_SEL(sc->rxchainmask);
        rxchain |= IWN_RXCHAIN_FORCE_MIMO_SEL(sc->rxchainmask);
            rxchain |= (IWN_RXCHAIN_DRIVER_FORCE | IWN_RXCHAIN_MIMO_FORCE);
    }
    sc->rxon.rxchain = htole16(rxchain);
    DPRINTF(("setting configuration\n"));
    DPRINTF(("%s: rxon chan %d flags %x cck %x ofdm %x rxchain %x\n",
        __func__, sc->rxon.chan, le32toh(sc->rxon.flags), sc->rxon.cck_mask,
        sc->rxon.ofdm_mask, sc->rxon.rxchain));
    error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 0);
    if (error != 0) {
        XYLog("%s: RXON command failed\n", sc->sc_dev.dv_xname);
        return error;
    }

    ridx = (sc->sc_ic.ic_curmode == IEEE80211_MODE_11A) ?
        IWN_RIDX_OFDM : IWN_RIDX_CCK;
    if ((error = iwn_add_broadcast_node(sc, 0, ridx)) != 0) {
        XYLog("%s: could not add broadcast node\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Configuration has changed, set TX power accordingly. */
    if ((error = ops->set_txpower(sc, 0)) != 0) {
        XYLog("%s: could not set TX power\n", sc->sc_dev.dv_xname);
        return error;
    }

    if ((error = iwn_set_critical_temp(sc)) != 0) {
        XYLog("%s: could not set critical temperature\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Set power saving level to CAM during initialization. */
    if ((error = iwn_set_pslevel(sc, 0, 0, 0)) != 0) {
        XYLog("%s: could not set power saving level\n",
            sc->sc_dev.dv_xname);
        return error;
    }
    return 0;
}

uint16_t ItlIwn::
iwn_get_active_dwell_time(struct iwn_softc *sc,
    uint16_t flags, uint8_t n_probes)
{
    /* No channel? Default to 2GHz settings */
    if (flags & IEEE80211_CHAN_2GHZ) {
        return (IWN_ACTIVE_DWELL_TIME_2GHZ +
        IWN_ACTIVE_DWELL_FACTOR_2GHZ * (n_probes + 1));
    }

    /* 5GHz dwell time */
    return (IWN_ACTIVE_DWELL_TIME_5GHZ +
        IWN_ACTIVE_DWELL_FACTOR_5GHZ * (n_probes + 1));
}

/*
 * Limit the total dwell time to 85% of the beacon interval.
 *
 * Returns the dwell time in milliseconds.
 */
uint16_t ItlIwn::
iwn_limit_dwell(struct iwn_softc *sc, uint16_t dwell_time)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int bintval = 0;

    /* bintval is in TU (1.024mS) */
    if (ni != NULL)
        bintval = ni->ni_intval;

    /*
     * If it's non-zero, we should calculate the minimum of
     * it and the DWELL_BASE.
     *
     * XXX Yes, the math should take into account that bintval
     * is 1.024mS, not 1mS..
     */
    if (ic->ic_state == IEEE80211_S_RUN && bintval > 0)
        return (MIN(IWN_PASSIVE_DWELL_BASE, ((bintval * 85) / 100)));

    /* No association context? Default */
    return dwell_time;
}

uint16_t ItlIwn::
iwn_get_passive_dwell_time(struct iwn_softc *sc, uint16_t flags)
{
    uint16_t passive;
    if (flags & IEEE80211_CHAN_2GHZ) {
        passive = IWN_PASSIVE_DWELL_BASE + IWN_PASSIVE_DWELL_TIME_2GHZ;
    } else {
        passive = IWN_PASSIVE_DWELL_BASE + IWN_PASSIVE_DWELL_TIME_5GHZ;
    }

    /* Clamp to the beacon interval if we're associated */
    return (iwn_limit_dwell(sc, passive));
}

int ItlIwn::
iwn_scan(struct iwn_softc *sc, uint16_t flags, int bgscan)
{
    XYLog("%s flags=%d bgscan=%d\n", __FUNCTION__, flags, bgscan);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_scan_hdr *hdr;
    struct iwn_cmd_data *tx;
    struct iwn_scan_essid *essid;
    struct iwn_scan_chan *chan;
    struct ieee80211_frame *wh;
    struct ieee80211_rateset *rs;
    struct ieee80211_channel *c;
    uint8_t *buf, *frm;
    uint16_t rxchain, dwell_active, dwell_passive;
    uint8_t txant;
    int buflen, error, is_active;

    buf = (uint8_t *)malloc(IWN_SCAN_MAXSZ, M_DEVBUF, M_NOWAIT | M_ZERO);
    if (buf == NULL) {
        XYLog("%s: could not allocate buffer for scan command\n",
            sc->sc_dev.dv_xname);
        return ENOMEM;
    }
    hdr = (struct iwn_scan_hdr *)buf;
    /*
     * Move to the next channel if no frames are received within 10ms
     * after sending the probe request.
     */
    hdr->quiet_time = htole16(10);        /* timeout in milliseconds */
    hdr->quiet_threshold = htole16(1);    /* min # of packets */

    if (bgscan) {
        int bintval;

        /* Set maximum off-channel time. */
        hdr->max_out = htole32(200 * 1024);

        /* Configure scan pauses which service on-channel traffic. */
        bintval = ic->ic_bss->ni_intval ? ic->ic_bss->ni_intval : 100;
        hdr->pause_scan = htole32(((100 / bintval) << 22) |
            ((100 % bintval) * 1024));
    }

    /* Select antennas for scanning. */
    rxchain =
        IWN_RXCHAIN_VALID(sc->rxchainmask) |
        IWN_RXCHAIN_FORCE_MIMO_SEL(sc->rxchainmask) |
        IWN_RXCHAIN_DRIVER_FORCE;
    if ((flags & IEEE80211_CHAN_5GHZ) &&
        sc->hw_type == IWN_HW_REV_TYPE_4965) {
        /*
         * On 4965 ant A and C must be avoided in 5GHz because of a
         * HW bug which causes very weak RSSI values being reported.
         */
        rxchain |= IWN_RXCHAIN_FORCE_SEL(IWN_ANT_B);
    } else    /* Use all available RX antennas. */
        rxchain |= IWN_RXCHAIN_FORCE_SEL(sc->rxchainmask);
    hdr->rxchain = htole16(rxchain);
    hdr->filter = htole32(IWN_FILTER_MULTICAST | IWN_FILTER_BEACON);

    tx = (struct iwn_cmd_data *)(hdr + 1);
    tx->flags = htole32(IWN_TX_AUTO_SEQ);
    tx->id = sc->broadcast_id;
    tx->lifetime = htole32(IWN_LIFETIME_INFINITE);

    if (flags & IEEE80211_CHAN_5GHZ) {
        /* Send probe requests at 6Mbps. */
        tx->plcp = iwn_rates[IWN_RATE_6M_INDEX].plcp;
        rs = &ic->ic_sup_rates[IEEE80211_MODE_11A];
    } else {
        hdr->flags = htole32(IWN_RXON_24GHZ | IWN_RXON_AUTO);
        if (bgscan && sc->hw_type == IWN_HW_REV_TYPE_4965 &&
            sc->rxon.chan > 14) {
            /*
             * 4965 firmware can crash when sending probe requests
             * with CCK rates while associated to a 5GHz AP.
             * Send probe requests at 6Mbps OFDM as a workaround.
             */
            tx->plcp = iwn_rates[IWN_RATE_6M_INDEX].plcp;
        } else {
            /* Send probe requests at 1Mbps. */
            tx->plcp = iwn_rates[IWN_RATE_1M_INDEX].plcp;
            tx->rflags = IWN_RFLAG_CCK;
        }
        rs = &ic->ic_sup_rates[IEEE80211_MODE_11G];
    }
    /* Use the first valid TX antenna. */
    txant = IWN_LSB(sc->txchainmask);
    tx->rflags |= IWN_RFLAG_ANT(txant);

    /*
     * Only do active scanning if we're announcing a probe request
     * for a given SSID (or more, if we ever add it to the driver.)
     */
    is_active = 0;

    /*
     * If we're scanning for a specific SSID, add it to the command.
     */
    essid = (struct iwn_scan_essid *)(tx + 1);
    if (ic->ic_des_esslen != 0) {
        essid[0].id = IEEE80211_ELEMID_SSID;
        essid[0].len = ic->ic_des_esslen;
        memcpy(essid[0].data, ic->ic_des_essid, ic->ic_des_esslen);

        is_active = 1;
    }
    /*
     * Build a probe request frame.  Most of the following code is a
     * copy & paste of what is done in net80211.
     */
    wh = (struct ieee80211_frame *)(essid + 20);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_PROBE_REQ;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
    IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, etherbroadcastaddr);
    *(uint16_t *)&wh->i_dur[0] = 0;    /* filled by HW */
    *(uint16_t *)&wh->i_seq[0] = 0;    /* filled by HW */

    frm = (uint8_t *)(wh + 1);
    frm = ieee80211_add_ssid(frm, NULL, 0);
    frm = ieee80211_add_rates(frm, rs);
    if (rs->rs_nrates > IEEE80211_RATE_SIZE)
        frm = ieee80211_add_xrates(frm, rs);
    if (ic->ic_flags & IEEE80211_F_HTON)
        frm = ieee80211_add_htcaps(frm, ic);

    /* Set length of probe request. */
    tx->len = htole16(frm - (uint8_t *)wh);

    /*
     * If active scanning is requested but a certain channel is
     * marked passive, we can do active scanning if we detect
     * transmissions.
     *
     * There is an issue with some firmware versions that triggers
     * a sysassert on a "good CRC threshold" of zero (== disabled),
     * on a radar channel even though this means that we should NOT
     * send probes.
     *
     * The "good CRC threshold" is the number of frames that we
     * need to receive during our dwell time on a channel before
     * sending out probes -- setting this to a huge value will
     * mean we never reach it, but at the same time work around
     * the aforementioned issue. Thus use IWN_GOOD_CRC_TH_NEVER
     * here instead of IWN_GOOD_CRC_TH_DISABLED.
     *
     * This was fixed in later versions along with some other
     * scan changes, and the threshold behaves as a flag in those
     * versions.
     */

    /*
     * If we're doing active scanning, set the crc_threshold
     * to a suitable value.  This is different to active veruss
     * passive scanning depending upon the channel flags; the
     * firmware will obey that particular check for us.
     */
    if (sc->tlv_feature_flags & IWN_UCODE_TLV_FLAGS_NEWSCAN)
        hdr->crc_threshold = is_active ?
            IWN_GOOD_CRC_TH_DEFAULT : IWN_GOOD_CRC_TH_DISABLED;
    else
        hdr->crc_threshold = is_active ?
            IWN_GOOD_CRC_TH_DEFAULT : IWN_GOOD_CRC_TH_NEVER;

    chan = (struct iwn_scan_chan *)frm;
    for (c  = &ic->ic_channels[1];
         c <= &ic->ic_channels[IEEE80211_CHAN_MAX]; c++) {
        if ((c->ic_flags & flags) != flags)
            continue;

        chan->chan = htole16(ieee80211_chan2ieee(ic, c));
        DPRINTFN(2, ("adding channel %d\n", chan->chan));
        chan->flags = 0;
        if (ic->ic_des_esslen != 0)
            chan->flags |= htole32(IWN_CHAN_NPBREQS(1));

        if (c->ic_flags & IEEE80211_CHAN_PASSIVE)
            chan->flags |= htole32(IWN_CHAN_PASSIVE);
        else
            chan->flags |= htole32(IWN_CHAN_ACTIVE);

        /*
         * Calculate the active/passive dwell times.
         */

        dwell_active = iwn_get_active_dwell_time(sc, flags, is_active);
        dwell_passive = iwn_get_passive_dwell_time(sc, flags);

        /* Make sure they're valid */
        if (dwell_passive <= dwell_active)
            dwell_passive = dwell_active + 1;

        chan->active = htole16(dwell_active);
        chan->passive = htole16(dwell_passive);

        chan->dsp_gain = 0x6e;
        if (IEEE80211_IS_CHAN_5GHZ(c)) {
            chan->rf_gain = 0x3b;
        } else {
            chan->rf_gain = 0x28;
        }
        hdr->nchan++;
        chan++;
    }

    buflen = (uint8_t *)chan - buf;
    hdr->len = htole16(buflen);

    error = iwn_cmd(sc, IWN_CMD_SCAN, buf, buflen, 1);
    if (error == 0) {
        /*
         * The current mode might have been fixed during association.
         * Ensure all channels get scanned.
         */
        if (IFM_MODE(ic->ic_media.ifm_cur->ifm_media) == IFM_AUTO)
            ieee80211_setmode(ic, IEEE80211_MODE_AUTO);

        sc->sc_flags |= IWN_FLAG_SCANNING;
        if (bgscan)
            sc->sc_flags |= IWN_FLAG_BGSCAN;
    }
    ::free(buf);
    return error;
}

void ItlIwn::
iwn_scan_abort(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    iwn_cmd(sc, IWN_CMD_SCAN_ABORT, NULL, 0, 1);

    /* XXX Cannot wait for status response in interrupt context. */
    DELAY(100);

    sc->sc_flags &= ~IWN_FLAG_SCANNING;
    sc->sc_flags &= ~IWN_FLAG_BGSCAN;
}

int ItlIwn::
iwn_bgscan(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int error;

    if (sc->sc_flags & IWN_FLAG_SCANNING)
        return 0;

    error = that->iwn_scan(sc, IEEE80211_CHAN_2GHZ, 1);
    if (error)
        XYLog("%s: could not initiate background scan\n",
            sc->sc_dev.dv_xname);
    return error;
}

void ItlIwn::
iwn_rxon_configure_ht40(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    uint8_t sco = (ni->ni_htop0 & IEEE80211_HTOP0_SCO_MASK);
    int htprot = (ni->ni_htop1 &
                  IEEE80211_HTOP1_PROT_MASK);
    
    sc->rxon.flags &= ~htole32(IWN_RXON_HT_CHANMODE_MIXED2040 |
                               IWN_RXON_HT_CHANMODE_PURE40 | IWN_RXON_HT_HT40MINUS);
    
    if (ieee80211_node_supports_ht_chan40(ni) &&
        (sco == IEEE80211_HTOP0_SCO_SCA ||
         sco == IEEE80211_HTOP0_SCO_SCB)) {
        if (sco == IEEE80211_HTOP0_SCO_SCB)
            sc->rxon.flags |= htole32(IWN_RXON_HT_HT40MINUS);
        if (htprot == IEEE80211_HTPROT_20MHZ)
            sc->rxon.flags |= htole32(IWN_RXON_HT_CHANMODE_PURE40);
        else
            sc->rxon.flags |= htole32(
                                      IWN_RXON_HT_CHANMODE_MIXED2040);
    }
}

int ItlIwn::
iwn_rxon_ht40_enabled(struct iwn_softc *sc)
{
    return ((le32toh(sc->rxon.flags) & IWN_RXON_HT_CHANMODE_MIXED2040) ||
            (le32toh(sc->rxon.flags) & IWN_RXON_HT_CHANMODE_PURE40)) ? 1 : 0;
}

int ItlIwn::
iwn_auth(struct iwn_softc *sc, int arg)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int error, ridx;
    int bss_switch =
        (!IEEE80211_ADDR_EQ(sc->bss_node_addr, etheranyaddr) &&
        !IEEE80211_ADDR_EQ(sc->bss_node_addr, ni->ni_macaddr));

    /* Update adapter configuration. */
    IEEE80211_ADDR_COPY(sc->rxon.bssid, ni->ni_bssid);
    sc->rxon.chan = ieee80211_chan2ieee(ic, ni->ni_chan);
    sc->rxon.flags = htole32(IWN_RXON_TSF | IWN_RXON_CTS_TO_SELF);
    if (IEEE80211_IS_CHAN_2GHZ(ni->ni_chan)) {
        sc->rxon.flags |= htole32(IWN_RXON_AUTO | IWN_RXON_24GHZ);
        if (ic->ic_flags & IEEE80211_F_USEPROT)
            sc->rxon.flags |= htole32(IWN_RXON_TGG_PROT);
        DPRINTF(("%s: 2ghz prot 0x%x\n", __func__,
            le32toh(sc->rxon.flags)));
    }
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        sc->rxon.flags |= htole32(IWN_RXON_SHSLOT);
    else
        sc->rxon.flags &= ~htole32(IWN_RXON_SHSLOT);
    if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
        sc->rxon.flags |= htole32(IWN_RXON_SHPREAMBLE);
    else
        sc->rxon.flags &= ~htole32(IWN_RXON_SHPREAMBLE);
    switch (ic->ic_curmode) {
    case IEEE80211_MODE_11A:
        sc->rxon.cck_mask  = 0;
        sc->rxon.ofdm_mask = 0x15;
        break;
    case IEEE80211_MODE_11B:
        sc->rxon.cck_mask  = 0x03;
        sc->rxon.ofdm_mask = 0;
        break;
    default:    /* Assume 802.11b/g/n. */
        sc->rxon.cck_mask  = 0x0f;
        sc->rxon.ofdm_mask = 0x15;
    }
    /* Configure 40MHz early to avoid problems on 6205 devices. */
    iwn_rxon_configure_ht40(ic, ni);
    DPRINTF(("%s: rxon chan %d flags %x cck %x ofdm %x\n", __func__,
        sc->rxon.chan, le32toh(sc->rxon.flags), sc->rxon.cck_mask,
        sc->rxon.ofdm_mask));
    error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
    if (error != 0) {
        XYLog("%s: RXON command failed\n", sc->sc_dev.dv_xname);
        return error;
    }

    /* Configuration has changed, set TX power accordingly. */
    if ((error = ops->set_txpower(sc, 1)) != 0) {
        XYLog("%s: could not set TX power\n", sc->sc_dev.dv_xname);
        return error;
    }
    /*
     * Reconfiguring RXON clears the firmware nodes table so we must
     * add the broadcast node again.
     */
    ridx = IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) ?
        IWN_RIDX_OFDM : IWN_RIDX_CCK;
    if ((error = iwn_add_broadcast_node(sc, 1, ridx)) != 0) {
        XYLog("%s: could not add broadcast node\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /*
     * Make sure the firmware gets to see a beacon before we send
     * the auth request. Otherwise the Tx attempt can fail due to
     * the firmware's built-in regulatory domain enforcement.
     * Delaying here for every incoming deauth frame can result in a DoS.
     * Don't delay if we're here because of an incoming frame (arg != -1)
     * or if we're already waiting for a response (ic_mgt_timer != 0).
     * If we are switching APs after a background scan then net80211 has
     * just faked the reception of a deauth frame from our old AP, so it
     * is safe to delay in that case.
     */
    if ((arg == -1 || bss_switch) && ic->ic_mgt_timer == 0)
        DELAY(ni->ni_intval * 3 * IEEE80211_DUR_TU);

    /* We can now clear the cached address of our previous AP. */
    memset(sc->bss_node_addr, 0, sizeof(sc->bss_node_addr));

    return 0;
}

int ItlIwn::
iwn_run(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_ops *ops = &sc->ops;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;
    int error;

    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Link LED blinks while monitoring. */
        iwn_set_led(sc, IWN_LED_LINK, 50, 50);
        return 0;
    }
    if ((error = iwn_set_timing(sc, ni)) != 0) {
        XYLog("%s: could not set timing\n", sc->sc_dev.dv_xname);
        return error;
    }

    /* Update adapter configuration. */
    sc->rxon.associd = htole16(IEEE80211_AID(ni->ni_associd));
    /* Short preamble and slot time are negotiated when associating. */
    sc->rxon.flags &= ~htole32(IWN_RXON_SHPREAMBLE | IWN_RXON_SHSLOT);
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        sc->rxon.flags |= htole32(IWN_RXON_SHSLOT);
    if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
        sc->rxon.flags |= htole32(IWN_RXON_SHPREAMBLE);
    sc->rxon.filter |= htole32(IWN_FILTER_BSS);

    /* HT is negotiated when associating. */
    if (ni->ni_flags & IEEE80211_NODE_HT) {
        enum ieee80211_htprot htprot =
            (ieee80211_htprot)(ni->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
        DPRINTF(("%s: htprot = %d\n", __func__, htprot));
        sc->rxon.flags |= htole32(IWN_RXON_HT_PROTMODE(htprot));
    } else
        sc->rxon.flags &= ~htole32(IWN_RXON_HT_PROTMODE(3));
    iwn_rxon_configure_ht40(ic, ni);

    if (IEEE80211_IS_CHAN_5GHZ(ni->ni_chan)) {
        /* 11a or 11n 5GHz */
        sc->rxon.cck_mask  = 0;
        sc->rxon.ofdm_mask = 0x15;
    } else if (ni->ni_flags & IEEE80211_NODE_HT) {
        /* 11n 2GHz */
        sc->rxon.cck_mask  = 0x0f;
        sc->rxon.ofdm_mask = 0x15;
    } else {
        if (ni->ni_rates.rs_nrates == 4) {
            /* 11b */
            sc->rxon.cck_mask  = 0x03;
            sc->rxon.ofdm_mask = 0;
        } else {
            /* assume 11g */
            sc->rxon.cck_mask  = 0x0f;
            sc->rxon.ofdm_mask = 0x15;
        }
    }
    DPRINTF(("%s: rxon chan %d flags %x cck %x ofdm %x\n", __func__,
        sc->rxon.chan, le32toh(sc->rxon.flags), sc->rxon.cck_mask,
        sc->rxon.ofdm_mask));
    error = iwn_cmd(sc, IWN_CMD_RXON, &sc->rxon, sc->rxonsz, 1);
    if (error != 0) {
        XYLog("%s: could not update configuration\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Configuration has changed, set TX power accordingly. */
    if ((error = ops->set_txpower(sc, 1)) != 0) {
        XYLog("%s: could not set TX power\n", sc->sc_dev.dv_xname);
        return error;
    }

    /* Fake a join to initialize the TX rate. */
    ((struct iwn_node *)ni)->id = IWN_ID_BSS;
    iwn_newassoc(ic, ni, 1);

    /* Add BSS node. */
    memset(&node, 0, sizeof node);
    IEEE80211_ADDR_COPY(node.macaddr, ni->ni_macaddr);
    node.id = IWN_ID_BSS;
    if (ni->ni_flags & IEEE80211_NODE_HT) {
        node.htmask = (IWN_AMDPU_SIZE_FACTOR_MASK |
            IWN_AMDPU_DENSITY_MASK);
        node.htflags = htole32(
            IWN_AMDPU_SIZE_FACTOR(
            (ic->ic_ampdu_params & IEEE80211_AMPDU_PARAM_LE)) |
            IWN_AMDPU_DENSITY(
            (ic->ic_ampdu_params & IEEE80211_AMPDU_PARAM_SS) >> 2));
        
        if (iwn_rxon_ht40_enabled(sc))
            node.htflags |= htole32(IWN_40MHZ_ENABLE);
    }
    DPRINTF(("adding BSS node\n"));
    error = ops->add_node(sc, &node, 1);
    if (error != 0) {
        XYLog("%s: could not add BSS node\n", sc->sc_dev.dv_xname);
        return error;
    }

    /* Cache address of AP in case it changes after a background scan. */
    IEEE80211_ADDR_COPY(sc->bss_node_addr, ni->ni_macaddr);

    DPRINTF(("setting link quality for node %d\n", node.id));
    if ((error = iwn_set_link_quality(sc, ni)) != 0) {
        XYLog("%s: could not setup link quality for node %d\n",
            sc->sc_dev.dv_xname, node.id);
        return error;
    }

    if ((error = iwn_init_sensitivity(sc)) != 0) {
        XYLog("%s: could not set sensitivity\n",
            sc->sc_dev.dv_xname);
        return error;
    }
    /* Start periodic calibration timer. */
    sc->calib.state = IWN_CALIB_STATE_ASSOC;
    sc->calib_cnt = 0;
    timeout_add_msec(&sc->calib_to, 500);

    ieee80211_ra_node_init(ic, &wn->rn, &wn->ni);

    /* Link LED always on while associated. */
    iwn_set_led(sc, IWN_LED_LINK, 0, 1);
    return 0;
}

/*
 * We support CCMP hardware encryption/decryption of unicast frames only.
 * HW support for TKIP really sucks.  We should let TKIP die anyway.
 */
int ItlIwn::
iwn_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node *wn = (iwn_node *)ni;
    struct iwn_node_info node;
    uint16_t kflags;

    if ((k->k_flags & IEEE80211_KEY_GROUP) ||
        k->k_cipher != IEEE80211_CIPHER_CCMP)
        return ieee80211_set_key(ic, ni, k);

    kflags = IWN_KFLAG_CCMP | IWN_KFLAG_MAP | IWN_KFLAG_KID(k->k_id);
    if (k->k_flags & IEEE80211_KEY_GROUP)
        kflags |= IWN_KFLAG_GROUP;

    memset(&node, 0, sizeof node);
    node.id = (k->k_flags & IEEE80211_KEY_GROUP) ?
        sc->broadcast_id : wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_KEY;
    node.kflags = htole16(kflags);
    node.kid = k->k_id;
    memcpy(node.key, k->k_key, k->k_len);
    DPRINTF(("set key id=%d for node %d\n", k->k_id, node.id));
    return ops->add_node(sc, &node, 1);
}

void ItlIwn::
iwn_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;

    if ((k->k_flags & IEEE80211_KEY_GROUP) ||
        k->k_cipher != IEEE80211_CIPHER_CCMP) {
        /* See comment about other ciphers above. */
        ieee80211_delete_key(ic, ni, k);
        return;
    }
    if (ic->ic_state != IEEE80211_S_RUN)
        return;    /* Nothing to do. */
    memset(&node, 0, sizeof node);
    node.id = (k->k_flags & IEEE80211_KEY_GROUP) ?
        sc->broadcast_id : wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_KEY;
    node.kflags = htole16(IWN_KFLAG_INVALID);
    node.kid = 0xff;
    DPRINTF(("delete keys for node %d\n", node.id));
    (void)ops->add_node(sc, &node, 1);
}

void ItlIwn::
iwn_update_chw(struct ieee80211com *ic)
{
    XYLog("%s update channel info\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    
    that->iwn_rxon_configure_ht40(ic, ic->ic_bss);
    sc->ops.update_rxon(sc);
    that->iwn_set_link_quality(sc, ic->ic_bss);
}

void ItlIwn::
iwn_updateprot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    enum ieee80211_htprot htprot;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    
    /* Update ERP protection setting. */
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        sc->rxon.flags |= htole32(IWN_RXON_TGG_PROT);
    else
        sc->rxon.flags &= ~htole32(IWN_RXON_TGG_PROT);

    /* Update HT protection mode setting. */
    htprot = (enum ieee80211_htprot)((ic->ic_bss->ni_htop1 & IEEE80211_HTOP1_PROT_MASK) >>
        IEEE80211_HTOP1_PROT_SHIFT);
    sc->rxon.flags &= ~htole32(IWN_RXON_HT_PROTMODE(3));
    sc->rxon.flags |= htole32(IWN_RXON_HT_PROTMODE(htprot));

    sc->ops.update_rxon(sc);
}

void ItlIwn::
iwn_updateslot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        sc->rxon.flags |= htole32(IWN_RXON_SHSLOT);
    else
        sc->rxon.flags &= ~htole32(IWN_RXON_SHSLOT);
    
    if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
        sc->rxon.flags |= htole32(IWN_RXON_SHPREAMBLE);
    else
        sc->rxon.flags &= ~htole32(IWN_RXON_SHPREAMBLE);
    
    sc->ops.update_rxon(sc);
}

void ItlIwn::
iwn_update_rxon_restore_power(struct iwn_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwn_ops *ops = &sc->ops;
    int error;
    
    DELAY(100);
    
    /* All RXONs wipe the firmware's txpower table. Restore it. */
    error = ops->set_txpower(sc, 1);
    if (error != 0)
        printf("%s: could not set TX power\n", sc->sc_dev.dv_xname);
    
    DELAY(100);
    
    /* Restore power saving level */
    if (ic->ic_flags & IEEE80211_F_PMGTON)
        error = iwn_set_pslevel(sc, 0, 3, 1);
    else
        error = iwn_set_pslevel(sc, 0, 0, 1);
    if (error != 0)
        printf("%s: could not set PS level\n", sc->sc_dev.dv_xname);
}

void ItlIwn::
iwn5000_update_rxon(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_rxon_assoc rxon_assoc;
    int s, error;
    
    /* Update RXON config. */
    memset(&rxon_assoc, 0, sizeof(rxon_assoc));
    rxon_assoc.flags = sc->rxon.flags;
    rxon_assoc.filter = sc->rxon.filter;
    rxon_assoc.ofdm_mask = sc->rxon.ofdm_mask;
    rxon_assoc.cck_mask = sc->rxon.cck_mask;
    rxon_assoc.ht_single_mask = sc->rxon.ht_single_mask;
    rxon_assoc.ht_dual_mask = sc->rxon.ht_dual_mask;
    rxon_assoc.ht_triple_mask = sc->rxon.ht_triple_mask;
    rxon_assoc.rxchain = sc->rxon.rxchain;
    rxon_assoc.acquisition = sc->rxon.acquisition;
    
    s = splnet();
    
    error = that->iwn_cmd(sc, IWN_CMD_RXON_ASSOC, &rxon_assoc, sizeof(rxon_assoc), 1);
    if (error != 0)
        printf("%s: RXON_ASSOC command failed\n", sc->sc_dev.dv_xname);
    
    that->iwn_update_rxon_restore_power(sc);
    
    splx(s);
}

void ItlIwn::
iwn4965_update_rxon(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn4965_rxon_assoc rxon_assoc;
    int s, error;
    
    /* Update RXON config. */
    memset(&rxon_assoc, 0, sizeof(rxon_assoc));
    rxon_assoc.flags = sc->rxon.flags;
    rxon_assoc.filter = sc->rxon.filter;
    rxon_assoc.ofdm_mask = sc->rxon.ofdm_mask;
    rxon_assoc.cck_mask = sc->rxon.cck_mask;
    rxon_assoc.ht_single_mask = sc->rxon.ht_single_mask;
    rxon_assoc.ht_dual_mask = sc->rxon.ht_dual_mask;
    rxon_assoc.rxchain = sc->rxon.rxchain;
    
    s = splnet();
    
    error = that->iwn_cmd(sc, IWN_CMD_RXON_ASSOC, &rxon_assoc, sizeof(rxon_assoc), 1);
    if (error != 0)
        printf("%s: RXON_ASSOC command failed\n", sc->sc_dev.dv_xname);
    
    that->iwn_update_rxon_restore_power(sc);
    
    splx(s);
}

/*
 * This function is called by upper layer when an ADDBA request is received
 * from another STA and before the ADDBA response is sent.
 */
int ItlIwn::
iwn_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;

    memset(&node, 0, sizeof node);
    node.id = wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_ADDBA;
    node.addba_tid = tid;
    node.addba_ssn = htole16(ba->ba_winstart);
    DPRINTF(("ADDBA RA=%d TID=%d SSN=%d\n", wn->id, tid,
        ba->ba_winstart));
    /* XXX async command, so firmware may still fail to add BA agreement */
    return ops->add_node(sc, &node, 1);
}

/*
 * This function is called by upper layer on teardown of an HT-immediate
 * Block Ack agreement (eg. uppon receipt of a DELBA frame).
 */
void ItlIwn::
iwn_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;

    memset(&node, 0, sizeof node);
    node.id = wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_DELBA;
    node.delba_tid = tid;
    DPRINTF(("DELBA RA=%d TID=%d\n", wn->id, tid));
    (void)ops->add_node(sc, &node, 1);
}

/*
 * This function is called by upper layer when an ADDBA response is received
 * from another STA.
 */
int ItlIwn::
iwn_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    struct iwn_ops *ops = &sc->ops;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;
    int qid = sc->first_agg_txq + tid;
    int error;

    /* Ensure we can map this TID to an aggregation queue. */
    if (tid >= IWN_NUM_AMPDU_TID || ba->ba_winsize > IWN_SCHED_WINSZ ||
        qid > sc->ntxqs || (sc->agg_queue_mask & (1 << qid)))
        return ENOSPC;

    /* Enable TX for the specified RA/TID. */
    wn->disable_tid &= ~(1 << tid);
    memset(&node, 0, sizeof node);
    node.id = wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_DISABLE_TID;
    node.disable_tid = htole16(wn->disable_tid);
    error = ops->add_node(sc, &node, 1);
    if (error != 0)
        return error;

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    ops->ampdu_tx_start(sc, ni, tid, ba->ba_winstart);
    iwn_nic_unlock(sc);

    sc->agg_queue_mask |= (1 << qid);
    sc->sc_tx_ba[tid].wn = wn;
    ba->ba_bitmap = 0;

    return 0;
}

void ItlIwn::
iwn_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct ieee80211_tx_ba *ba = (struct ieee80211_tx_ba *)&ni->ni_tx_ba[tid];
    struct iwn_softc *sc = (struct iwn_softc *)ic->ic_softc;
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_ops *ops = &sc->ops;
    int qid = sc->first_agg_txq + tid;
    struct iwn_node *wn = (struct iwn_node *)ni;
    struct iwn_node_info node;

    /* Discard all frames in the current window. */
    that->iwn_ampdu_txq_advance(sc, &sc->txq[qid], qid,
        IWN_AGG_SSN_TO_TXQ_IDX(ba->ba_winend));

    if (iwn_nic_lock(sc) != 0)
        return;
    ops->ampdu_tx_stop(sc, tid, ba->ba_winstart);
    iwn_nic_unlock(sc);

    sc->agg_queue_mask &= ~(1 << qid);
    sc->sc_tx_ba[tid].wn = NULL;
    ba->ba_bitmap = 0;

    /* Disable TX for the specified RA/TID. */
    wn->disable_tid |= (1 << tid);
    memset(&node, 0, sizeof node);
    node.id = wn->id;
    node.control = IWN_NODE_UPDATE;
    node.flags = IWN_FLAG_SET_DISABLE_TID;
    node.disable_tid = htole16(wn->disable_tid);
    ops->add_node(sc, &node, 1);
}

void ItlIwn::
iwn4965_ampdu_tx_start(struct iwn_softc *sc, struct ieee80211_node *ni,
    uint8_t tid, uint16_t ssn)
{
    struct iwn_node *wn = (struct iwn_node *)ni;
    int qid = IWN4965_FIRST_AGG_TXQUEUE + tid;
    uint16_t idx = IWN_AGG_SSN_TO_TXQ_IDX(ssn);

    /* Stop TX scheduler while we're changing its configuration. */
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
        IWN4965_TXQ_STATUS_CHGACT);

    /* Assign RA/TID translation to the queue. */
    iwn_mem_write_2(sc, sc->sched_base + IWN4965_SCHED_TRANS_TBL(qid),
        wn->id << 4 | tid);

    /* Enable chain-building mode for the queue. */
    iwn_prph_setbits(sc, IWN4965_SCHED_QCHAIN_SEL, 1 << qid);

    /* Set starting sequence number from the ADDBA request. */
    sc->txq[qid].cur = sc->txq[qid].read = idx;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | idx);
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), ssn);

    /* Set scheduler window size. */
    iwn_mem_write(sc, sc->sched_base + IWN4965_SCHED_QUEUE_OFFSET(qid),
        IWN_SCHED_WINSZ);
    /* Set scheduler frame limit. */
    iwn_mem_write(sc, sc->sched_base + IWN4965_SCHED_QUEUE_OFFSET(qid) + 4,
        IWN_SCHED_LIMIT << 16);

    /* Enable interrupts for the queue. */
    iwn_prph_setbits(sc, IWN4965_SCHED_INTR_MASK, 1 << qid);

    /* Mark the queue as active. */
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
        IWN4965_TXQ_STATUS_ACTIVE | IWN4965_TXQ_STATUS_AGGR_ENA |
        iwn_tid2fifo[tid] << 1);
}

void ItlIwn::
iwn4965_ampdu_tx_stop(struct iwn_softc *sc, uint8_t tid, uint16_t ssn)
{
    int qid = IWN4965_FIRST_AGG_TXQUEUE + tid;
    uint16_t idx = IWN_AGG_SSN_TO_TXQ_IDX(ssn);

    /* Stop TX scheduler while we're changing its configuration. */
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
        IWN4965_TXQ_STATUS_CHGACT);

    /* Set starting sequence number from the ADDBA request. */
    sc->txq[qid].cur = sc->txq[qid].read = idx;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | idx);
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), ssn);

    /* Disable interrupts for the queue. */
    iwn_prph_clrbits(sc, IWN4965_SCHED_INTR_MASK, 1 << qid);

    /* Mark the queue as inactive. */
    iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
        IWN4965_TXQ_STATUS_INACTIVE | iwn_tid2fifo[tid] << 1);
}

void ItlIwn::
iwn5000_ampdu_tx_start(struct iwn_softc *sc, struct ieee80211_node *ni,
    uint8_t tid, uint16_t ssn)
{
    int qid = IWN5000_FIRST_AGG_TXQUEUE + tid;
    int idx = IWN_AGG_SSN_TO_TXQ_IDX(ssn);
    struct iwn_node *wn = (struct iwn_node *)ni;

    /* Stop TX scheduler while we're changing its configuration. */
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
        IWN5000_TXQ_STATUS_CHGACT);

    /* Assign RA/TID translation to the queue. */
    iwn_mem_write_2(sc, sc->sched_base + IWN5000_SCHED_TRANS_TBL(qid),
        wn->id << 4 | tid);

    /* Enable chain-building mode for the queue. */
    iwn_prph_setbits(sc, IWN5000_SCHED_QCHAIN_SEL, 1 << qid);

    /* Enable aggregation for the queue. */
    iwn_prph_setbits(sc, IWN5000_SCHED_AGGR_SEL, 1 << qid);

    /* Set starting sequence number from the ADDBA request. */
    sc->txq[qid].cur = sc->txq[qid].read = idx;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | idx);
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), ssn);

    /* Set scheduler window size and frame limit. */
    iwn_mem_write(sc, sc->sched_base + IWN5000_SCHED_QUEUE_OFFSET(qid) + 4,
        IWN_SCHED_LIMIT << 16 | IWN_SCHED_WINSZ);

    /* Enable interrupts for the queue. */
    iwn_prph_setbits(sc, IWN5000_SCHED_INTR_MASK, 1 << qid);

    /* Mark the queue as active. */
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
        IWN5000_TXQ_STATUS_ACTIVE | iwn_tid2fifo[tid]);
}

void ItlIwn::
iwn5000_ampdu_tx_stop(struct iwn_softc *sc, uint8_t tid, uint16_t ssn)
{
    int qid = IWN5000_FIRST_AGG_TXQUEUE + tid;
    int idx = IWN_AGG_SSN_TO_TXQ_IDX(ssn);

    /* Stop TX scheduler while we're changing its configuration. */
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
        IWN5000_TXQ_STATUS_CHGACT);

    /* Disable aggregation for the queue. */
    iwn_prph_clrbits(sc, IWN5000_SCHED_AGGR_SEL, 1 << qid);

    /* Set starting sequence number from the ADDBA request. */
    sc->txq[qid].cur = sc->txq[qid].read = idx;
    IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | idx);
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), ssn);

    /* Disable interrupts for the queue. */
    iwn_prph_clrbits(sc, IWN5000_SCHED_INTR_MASK, 1 << qid);

    /* Mark the queue as inactive. */
    iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
        IWN5000_TXQ_STATUS_INACTIVE | iwn_tid2fifo[tid]);
}

/*
 * Query calibration tables from the initialization firmware.  We do this
 * only once at first boot.  Called from a process context.
 */
int ItlIwn::
iwn5000_query_calibration(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_calib_config cmd;
    int error;

    memset(&cmd, 0, sizeof cmd);
    cmd.ucode.once.enable = 0xffffffff;
    cmd.ucode.once.start  = 0xffffffff;
    cmd.ucode.once.send   = 0xffffffff;
    cmd.ucode.flags       = 0xffffffff;
    DPRINTF(("sending calibration query\n"));
    error = that->iwn_cmd(sc, IWN5000_CMD_CALIB_CONFIG, &cmd, sizeof cmd, 0);
    if (error != 0)
        return error;

    /* Wait at most two seconds for calibration to complete. */
    if (!(sc->sc_flags & IWN_FLAG_CALIB_DONE))
        error = that->tsleep_nsec(sc, PCATCH, "iwncal", SEC_TO_NSEC(2));
    return error;
}

/*
 * Send calibration results to the runtime firmware.  These results were
 * obtained on first boot from the initialization firmware.
 */
int ItlIwn::
iwn5000_send_calibration(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int idx, error;

    for (idx = 0; idx < 5; idx++) {
        if (sc->calibcmd[idx].buf == NULL)
            continue;    /* No results available. */
        DPRINTF(("send calibration result idx=%d len=%d\n",
            idx, sc->calibcmd[idx].len));
        error = that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, sc->calibcmd[idx].buf,
            sc->calibcmd[idx].len, 0);
        if (error != 0) {
            XYLog("%s: could not send calibration result\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }
    return 0;
}

int ItlIwn::
iwn5000_send_wimax_coex(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_wimax_coex wimax;

#ifdef notyet
    if (sc->hw_type == IWN_HW_REV_TYPE_6050) {
        /* Enable WiMAX coexistence for combo adapters. */
        wimax.flags =
            IWN_WIMAX_COEX_ASSOC_WA_UNMASK |
            IWN_WIMAX_COEX_UNASSOC_WA_UNMASK |
            IWN_WIMAX_COEX_STA_TABLE_VALID |
            IWN_WIMAX_COEX_ENABLE;
        memcpy(wimax.events, iwn6050_wimax_events,
            sizeof iwn6050_wimax_events);
    } else
#endif
    {
        /* Disable WiMAX coexistence. */
        wimax.flags = 0;
        memset(wimax.events, 0, sizeof wimax.events);
    }
    DPRINTF(("Configuring WiMAX coexistence\n"));
    return that->iwn_cmd(sc, IWN5000_CMD_WIMAX_COEX, &wimax, sizeof wimax, 0);
}

int ItlIwn::
iwn5000_crystal_calib(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn5000_phy_calib_crystal cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = IWN5000_PHY_CALIB_CRYSTAL;
    cmd.ngroups = 1;
    cmd.isvalid = 1;
    cmd.cap_pin[0] = letoh32(sc->eeprom_crystal) & 0xff;
    cmd.cap_pin[1] = (letoh32(sc->eeprom_crystal) >> 16) & 0xff;
    DPRINTF(("sending crystal calibration %d, %d\n",
        cmd.cap_pin[0], cmd.cap_pin[1]));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
}

int ItlIwn::
iwn6000_temp_offset_calib(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn6000_phy_calib_temp_offset cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = IWN6000_PHY_CALIB_TEMP_OFFSET;
    cmd.ngroups = 1;
    cmd.isvalid = 1;
    if (sc->eeprom_temp != 0)
        cmd.offset = htole16(sc->eeprom_temp);
    else
        cmd.offset = htole16(IWN_DEFAULT_TEMP_OFFSET);
    DPRINTF(("setting radio sensor offset to %d\n", letoh16(cmd.offset)));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
}

int ItlIwn::
iwn2000_temp_offset_calib(struct iwn_softc *sc)
{
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn2000_phy_calib_temp_offset cmd;

    memset(&cmd, 0, sizeof cmd);
    cmd.code = IWN2000_PHY_CALIB_TEMP_OFFSET;
    cmd.ngroups = 1;
    cmd.isvalid = 1;
    if (sc->eeprom_rawtemp != 0) {
        cmd.offset_low = htole16(sc->eeprom_rawtemp);
        cmd.offset_high = htole16(sc->eeprom_temp);
    } else {
        cmd.offset_low = htole16(IWN_DEFAULT_TEMP_OFFSET);
        cmd.offset_high = htole16(IWN_DEFAULT_TEMP_OFFSET);
    }
    cmd.burnt_voltage_ref = htole16(sc->eeprom_voltage);
    DPRINTF(("setting radio sensor offset to %d:%d, voltage to %d\n",
        letoh16(cmd.offset_low), letoh16(cmd.offset_high),
        letoh16(cmd.burnt_voltage_ref)));
    return that->iwn_cmd(sc, IWN_CMD_PHY_CALIB, &cmd, sizeof cmd, 0);
}

/*
 * This function is called after the runtime firmware notifies us of its
 * readiness (called in a process context).
 */
int ItlIwn::
iwn4965_post_alive(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int error, qid;

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;

    /* Clear TX scheduler state in SRAM. */
    sc->sched_base = iwn_prph_read(sc, IWN_SCHED_SRAM_ADDR);
    iwn_mem_set_region_4(sc, sc->sched_base + IWN4965_SCHED_CTX_OFF, 0,
        IWN4965_SCHED_CTX_LEN / sizeof (uint32_t));

    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwn_prph_write(sc, IWN4965_SCHED_DRAM_ADDR, sc->sched_dma.paddr >> 10);

    IWN_SETBITS(sc, IWN_FH_TX_CHICKEN, IWN_FH_TX_CHICKEN_SCHED_RETRY);

    /* Disable chain mode for all our 16 queues. */
    iwn_prph_write(sc, IWN4965_SCHED_QCHAIN_SEL, 0);

    for (qid = 0; qid < IWN4965_NTXQUEUES; qid++) {
        iwn_prph_write(sc, IWN4965_SCHED_QUEUE_RDPTR(qid), 0);
        IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | 0);

        /* Set scheduler window size. */
        iwn_mem_write(sc, sc->sched_base +
            IWN4965_SCHED_QUEUE_OFFSET(qid), IWN_SCHED_WINSZ);
        /* Set scheduler frame limit. */
        iwn_mem_write(sc, sc->sched_base +
            IWN4965_SCHED_QUEUE_OFFSET(qid) + 4,
            IWN_SCHED_LIMIT << 16);
    }

    /* Enable interrupts for all our 16 queues. */
    iwn_prph_write(sc, IWN4965_SCHED_INTR_MASK, 0xffff);
    /* Identify TX FIFO rings (0-7). */
    iwn_prph_write(sc, IWN4965_SCHED_TXFACT, 0xff);

    /* Mark TX rings (4 EDCA + cmd + 2 HCCA) as active. */
    for (qid = 0; qid < 7; qid++) {
        static uint8_t qid2fifo[] = { 3, 2, 1, 0, 4, 5, 6 };
        iwn_prph_write(sc, IWN4965_SCHED_QUEUE_STATUS(qid),
            IWN4965_TXQ_STATUS_ACTIVE | qid2fifo[qid] << 1);
    }
    iwn_nic_unlock(sc);
    return 0;
}

/*
 * This function is called after the initialization or runtime firmware
 * notifies us of its readiness (called in a process context).
 */
int ItlIwn::
iwn5000_post_alive(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    ItlIwn *that = container_of(sc, ItlIwn, com);
    int error, qid;

    /* Switch to using ICT interrupt mode. */
    that->iwn5000_ict_reset(sc);

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;

    /* Clear TX scheduler state in SRAM. */
    sc->sched_base = iwn_prph_read(sc, IWN_SCHED_SRAM_ADDR);
    iwn_mem_set_region_4(sc, sc->sched_base + IWN5000_SCHED_CTX_OFF, 0,
        IWN5000_SCHED_CTX_LEN / sizeof (uint32_t));

    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwn_prph_write(sc, IWN5000_SCHED_DRAM_ADDR, sc->sched_dma.paddr >> 10);

    /* Disable scheduler chain extension (enabled by default in HW). */
    iwn_prph_write(sc, IWN5000_SCHED_CHAINEXT_EN, 0);

    IWN_SETBITS(sc, IWN_FH_TX_CHICKEN, IWN_FH_TX_CHICKEN_SCHED_RETRY);

    /* Enable chain mode for all queues, except command queue. */
    iwn_prph_write(sc, IWN5000_SCHED_QCHAIN_SEL, 0xfffef);
    iwn_prph_write(sc, IWN5000_SCHED_AGGR_SEL, 0);

    for (qid = 0; qid < IWN5000_NTXQUEUES; qid++) {
        iwn_prph_write(sc, IWN5000_SCHED_QUEUE_RDPTR(qid), 0);
        IWN_WRITE(sc, IWN_HBUS_TARG_WRPTR, qid << 8 | 0);

        iwn_mem_write(sc, sc->sched_base +
            IWN5000_SCHED_QUEUE_OFFSET(qid), 0);
        /* Set scheduler window size and frame limit. */
        iwn_mem_write(sc, sc->sched_base +
            IWN5000_SCHED_QUEUE_OFFSET(qid) + 4,
            IWN_SCHED_LIMIT << 16 | IWN_SCHED_WINSZ);
    }

    /* Enable interrupts for all our 20 queues. */
    iwn_prph_write(sc, IWN5000_SCHED_INTR_MASK, 0xfffff);
    /* Identify TX FIFO rings (0-7). */
    iwn_prph_write(sc, IWN5000_SCHED_TXFACT, 0xff);

    /* Mark TX rings (4 EDCA + cmd + 2 HCCA) as active. */
    for (qid = 0; qid < 7; qid++) {
        static uint8_t qid2fifo[] = { 3, 2, 1, 0, 7, 5, 6 };
        iwn_prph_write(sc, IWN5000_SCHED_QUEUE_STATUS(qid),
            IWN5000_TXQ_STATUS_ACTIVE | qid2fifo[qid]);
    }
    iwn_nic_unlock(sc);

    /* Configure WiMAX coexistence for combo adapters. */
    error = iwn5000_send_wimax_coex(sc);
    if (error != 0) {
        XYLog("%s: could not configure WiMAX coexistence\n",
            sc->sc_dev.dv_xname);
        return error;
    }
    if (sc->hw_type != IWN_HW_REV_TYPE_5150) {
        /* Perform crystal calibration. */
        error = iwn5000_crystal_calib(sc);
        if (error != 0) {
            XYLog("%s: crystal calibration failed\n",
                sc->sc_dev.dv_xname);
            return error;
        }
    }
    if (!(sc->sc_flags & IWN_FLAG_CALIB_DONE)) {
        /* Query calibration from the initialization firmware. */
        if ((error = iwn5000_query_calibration(sc)) != 0) {
            XYLog("%s: could not query calibration\n",
                sc->sc_dev.dv_xname);
            return error;
        }
        /*
         * We have the calibration results now, reboot with the
         * runtime firmware (call ourselves recursively!)
         */
        that->iwn_hw_stop(sc);
        error = that->iwn_hw_init(sc);
    } else {
        /* Send calibration results to runtime firmware. */
        error = iwn5000_send_calibration(sc);
    }
    return error;
}

/*
 * The firmware boot code is small and is intended to be copied directly into
 * the NIC internal memory (no DMA transfer).
 */
int ItlIwn::
iwn4965_load_bootcode(struct iwn_softc *sc, const uint8_t *ucode, int size)
{
    XYLog("%s\n", __FUNCTION__);
    int error, ntries;

    size /= sizeof (uint32_t);

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;

    /* Copy microcode image into NIC memory. */
    iwn_prph_write_region_4(sc, IWN_BSM_SRAM_BASE,
        (const uint32_t *)ucode, size);

    iwn_prph_write(sc, IWN_BSM_WR_MEM_SRC, 0);
    iwn_prph_write(sc, IWN_BSM_WR_MEM_DST, IWN_FW_TEXT_BASE);
    iwn_prph_write(sc, IWN_BSM_WR_DWCOUNT, size);

    /* Start boot load now. */
    iwn_prph_write(sc, IWN_BSM_WR_CTRL, IWN_BSM_WR_CTRL_START);

    /* Wait for transfer to complete. */
    for (ntries = 0; ntries < 1000; ntries++) {
        if (!(iwn_prph_read(sc, IWN_BSM_WR_CTRL) &
            IWN_BSM_WR_CTRL_START))
            break;
        DELAY(10);
    }
    if (ntries == 1000) {
        XYLog("%s: could not load boot firmware\n",
            sc->sc_dev.dv_xname);
        iwn_nic_unlock(sc);
        return ETIMEDOUT;
    }

    /* Enable boot after power up. */
    iwn_prph_write(sc, IWN_BSM_WR_CTRL, IWN_BSM_WR_CTRL_START_EN);

    iwn_nic_unlock(sc);
    return 0;
}

int ItlIwn::
iwn4965_load_firmware(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_fw_info *fw = &sc->fw;
    struct iwn_dma_info *dma = &sc->fw_dma;
    int error;

    /* Copy initialization sections into pre-allocated DMA-safe memory. */
    memcpy(dma->vaddr, fw->init.data, fw->init.datasz);
//    bus_dmamap_sync(sc->sc_dmat, dma->map, 0, fw->init.datasz,
//        BUS_DMASYNC_PREWRITE);
    memcpy((uint8_t *)dma->vaddr + IWN4965_FW_DATA_MAXSZ,
        fw->init.text, fw->init.textsz);
//    bus_dmamap_sync(sc->sc_dmat, dma->map, IWN4965_FW_DATA_MAXSZ,
//        fw->init.textsz, BUS_DMASYNC_PREWRITE);

    /* Tell adapter where to find initialization sections. */
    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    iwn_prph_write(sc, IWN_BSM_DRAM_DATA_ADDR, dma->paddr >> 4);
    iwn_prph_write(sc, IWN_BSM_DRAM_DATA_SIZE, fw->init.datasz);
    iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_ADDR,
        (dma->paddr + IWN4965_FW_DATA_MAXSZ) >> 4);
    iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_SIZE, fw->init.textsz);
    iwn_nic_unlock(sc);

    /* Load firmware boot code. */
    error = iwn4965_load_bootcode(sc, fw->boot.text, fw->boot.textsz);
    if (error != 0) {
        XYLog("%s: could not load boot firmware\n",
            sc->sc_dev.dv_xname);
        return error;
    }
    /* Now press "execute". */
    IWN_WRITE(sc, IWN_RESET, 0);

    /* Wait at most one second for first alive notification. */
    if ((error = that->tsleep_nsec(sc, PCATCH, "iwninit", SEC_TO_NSEC(1))) != 0) {
        XYLog("%s: timeout waiting for adapter to initialize\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Retrieve current temperature for initial TX power calibration. */
    sc->rawtemp = sc->ucode_info.temp[3].chan20MHz;
    sc->temp = iwn4965_get_temperature(sc);

    /* Copy runtime sections into pre-allocated DMA-safe memory. */
    memcpy(dma->vaddr, fw->main.data, fw->main.datasz);
//    bus_dmamap_sync(sc->sc_dmat, dma->map, 0, fw->main.datasz,
//        BUS_DMASYNC_PREWRITE);
    memcpy((uint8_t *)dma->vaddr + IWN4965_FW_DATA_MAXSZ,
        fw->main.text, fw->main.textsz);
//    bus_dmamap_sync(sc->sc_dmat, dma->map, IWN4965_FW_DATA_MAXSZ,
//        fw->main.textsz, BUS_DMASYNC_PREWRITE);

    /* Tell adapter where to find runtime sections. */
    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    iwn_prph_write(sc, IWN_BSM_DRAM_DATA_ADDR, dma->paddr >> 4);
    iwn_prph_write(sc, IWN_BSM_DRAM_DATA_SIZE, fw->main.datasz);
    iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_ADDR,
        (dma->paddr + IWN4965_FW_DATA_MAXSZ) >> 4);
    iwn_prph_write(sc, IWN_BSM_DRAM_TEXT_SIZE,
        IWN_FW_UPDATED | fw->main.textsz);
    iwn_nic_unlock(sc);

    return 0;
}

int ItlIwn::
iwn5000_load_firmware_section(struct iwn_softc *sc, uint32_t dst,
    const uint8_t *section, int size)
{
    XYLog("%s\n", __FUNCTION__);
    ItlIwn *that = container_of(sc, ItlIwn, com);
    struct iwn_dma_info *dma = &sc->fw_dma;
    int error;

    /* Copy firmware section into pre-allocated DMA-safe memory. */
    memcpy(dma->vaddr, section, size);
//    bus_dmamap_sync(sc->sc_dmat, dma->map, 0, size, BUS_DMASYNC_PREWRITE);

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;

    IWN_WRITE(sc, IWN_FH_TX_CONFIG(IWN_SRVC_DMACHNL),
        IWN_FH_TX_CONFIG_DMA_PAUSE);

    IWN_WRITE(sc, IWN_FH_SRAM_ADDR(IWN_SRVC_DMACHNL), dst);
    IWN_WRITE(sc, IWN_FH_TFBD_CTRL0(IWN_SRVC_DMACHNL),
        IWN_LOADDR(dma->paddr));
    IWN_WRITE(sc, IWN_FH_TFBD_CTRL1(IWN_SRVC_DMACHNL),
        IWN_HIADDR(dma->paddr) << 28 | size);
    IWN_WRITE(sc, IWN_FH_TXBUF_STATUS(IWN_SRVC_DMACHNL),
        IWN_FH_TXBUF_STATUS_TBNUM(1) |
        IWN_FH_TXBUF_STATUS_TBIDX(1) |
        IWN_FH_TXBUF_STATUS_TFBD_VALID);

    /* Kick Flow Handler to start DMA transfer. */
    IWN_WRITE(sc, IWN_FH_TX_CONFIG(IWN_SRVC_DMACHNL),
        IWN_FH_TX_CONFIG_DMA_ENA | IWN_FH_TX_CONFIG_CIRQ_HOST_ENDTFD);

    iwn_nic_unlock(sc);

    /* Wait at most five seconds for FH DMA transfer to complete. */
    return that->tsleep_nsec(sc, PCATCH, "iwninit", SEC_TO_NSEC(5));
}

int ItlIwn::
iwn5000_load_firmware(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_fw_part *fw;
    int error;

    /* Load the initialization firmware on first boot only. */
    fw = (sc->sc_flags & IWN_FLAG_CALIB_DONE) ?
        &sc->fw.main : &sc->fw.init;

    error = iwn5000_load_firmware_section(sc, IWN_FW_TEXT_BASE,
        fw->text, fw->textsz);
    if (error != 0) {
        XYLog("%s: could not load firmware %s section\n",
            sc->sc_dev.dv_xname, ".text");
        return error;
    }
    error = iwn5000_load_firmware_section(sc, IWN_FW_DATA_BASE,
        fw->data, fw->datasz);
    if (error != 0) {
        XYLog("%s: could not load firmware %s section\n",
            sc->sc_dev.dv_xname, ".data");
        return error;
    }

    /* Now press "execute". */
    IWN_WRITE(sc, IWN_RESET, 0);
    return 0;
}

/*
 * Extract text and data sections from a legacy firmware image.
 */
int ItlIwn::
iwn_read_firmware_leg(struct iwn_softc *sc, struct iwn_fw_info *fw)
{
    const uint32_t *ptr;
    size_t hdrlen = 24;
    uint32_t rev;

    ptr = (const uint32_t *)fw->data;
    rev = letoh32(*ptr++);

    /* Check firmware API version. */
    if (IWN_FW_API(rev) <= 1) {
        XYLog("%s: bad firmware, need API version >=2\n",
            sc->sc_dev.dv_xname);
        return EINVAL;
    }
    if (IWN_FW_API(rev) >= 3) {
        /* Skip build number (version 2 header). */
        hdrlen += 4;
        ptr++;
    }
    if (fw->size < hdrlen) {
        XYLog("%s: firmware too short: %zu bytes\n",
            sc->sc_dev.dv_xname, fw->size);
        return EINVAL;
    }
    fw->main.textsz = letoh32(*ptr++);
    fw->main.datasz = letoh32(*ptr++);
    fw->init.textsz = letoh32(*ptr++);
    fw->init.datasz = letoh32(*ptr++);
    fw->boot.textsz = letoh32(*ptr++);

    /* Check that all firmware sections fit. */
    if (fw->size < hdrlen + fw->main.textsz + fw->main.datasz +
        fw->init.textsz + fw->init.datasz + fw->boot.textsz) {
        XYLog("%s: firmware too short: %zu bytes\n",
            sc->sc_dev.dv_xname, fw->size);
        return EINVAL;
    }

    /* Get pointers to firmware sections. */
    fw->main.text = (const uint8_t *)ptr;
    fw->main.data = fw->main.text + fw->main.textsz;
    fw->init.text = fw->main.data + fw->main.datasz;
    fw->init.data = fw->init.text + fw->init.textsz;
    fw->boot.text = fw->init.data + fw->init.datasz;
    return 0;
}

/*
 * Extract text and data sections from a TLV firmware image.
 */
int ItlIwn::
iwn_read_firmware_tlv(struct iwn_softc *sc, struct iwn_fw_info *fw,
    uint16_t alt)
{
    const struct iwn_fw_tlv_hdr *hdr;
    const struct iwn_fw_tlv *tlv;
    const uint8_t *ptr, *end;
    uint64_t altmask;
    uint32_t len;

    if (fw->size < sizeof (*hdr)) {
        XYLog("%s: firmware too short: %zu bytes\n",
            sc->sc_dev.dv_xname, fw->size);
        return EINVAL;
    }
    hdr = (const struct iwn_fw_tlv_hdr *)fw->data;
    if (hdr->signature != htole32(IWN_FW_SIGNATURE)) {
        XYLog("%s: bad firmware signature 0x%08x\n",
            sc->sc_dev.dv_xname, letoh32(hdr->signature));
        return EINVAL;
    }
    DPRINTF(("FW: \"%.64s\", build 0x%x\n", hdr->descr,
        letoh32(hdr->build)));

    /*
     * Select the closest supported alternative that is less than
     * or equal to the specified one.
     */
    altmask = letoh64(hdr->altmask);
    while (alt > 0 && !(altmask & (1ULL << alt)))
        alt--;    /* Downgrade. */
    DPRINTF(("using alternative %d\n", alt));

    ptr = (const uint8_t *)(hdr + 1);
    end = (const uint8_t *)(fw->data + fw->size);

    /* Parse type-length-value fields. */
    while (ptr + sizeof (*tlv) <= end) {
        tlv = (const struct iwn_fw_tlv *)ptr;
        len = letoh32(tlv->len);

        ptr += sizeof (*tlv);
        if (ptr + len > end) {
            XYLog("%s: firmware too short: %zu bytes\n",
                sc->sc_dev.dv_xname, fw->size);
            return EINVAL;
        }
        /* Skip other alternatives. */
        if (tlv->alt != 0 && tlv->alt != htole16(alt))
            goto next;

        switch (letoh16(tlv->type)) {
        case IWN_FW_TLV_MAIN_TEXT:
            fw->main.text = ptr;
            fw->main.textsz = len;
            break;
        case IWN_FW_TLV_MAIN_DATA:
            fw->main.data = ptr;
            fw->main.datasz = len;
            break;
        case IWN_FW_TLV_INIT_TEXT:
            fw->init.text = ptr;
            fw->init.textsz = len;
            break;
        case IWN_FW_TLV_INIT_DATA:
            fw->init.data = ptr;
            fw->init.datasz = len;
            break;
        case IWN_FW_TLV_BOOT_TEXT:
            fw->boot.text = ptr;
            fw->boot.textsz = len;
            break;
        case IWN_FW_TLV_ENH_SENS:
            if (len !=  0) {
                XYLog("%s: TLV type %d has invalid size %u\n",
                    sc->sc_dev.dv_xname, letoh16(tlv->type),
                    len);
                goto next;
            }
            sc->sc_flags |= IWN_FLAG_ENH_SENS;
            break;
        case IWN_FW_TLV_PHY_CALIB:
            if (len != sizeof(uint32_t)) {
                XYLog("%s: TLV type %d has invalid size %u\n",
                    sc->sc_dev.dv_xname, letoh16(tlv->type),
                    len);
                goto next;
            }
            if (letoh32(*ptr) <= IWN5000_PHY_CALIB_MAX) {
                sc->reset_noise_gain = letoh32(*ptr);
                sc->noise_gain = letoh32(*ptr) + 1;
            }
            break;
        case IWN_FW_TLV_FLAGS:
            if (len < sizeof(uint32_t))
                break;
            if (len % sizeof(uint32_t))
                break;
            sc->tlv_feature_flags = letoh32(*ptr);
            DPRINTF(("feature: 0x%08x\n", sc->tlv_feature_flags));
            break;
        default:
            DPRINTF(("TLV type %d not handled\n",
                letoh16(tlv->type)));
            break;
        }
 next:        /* TLV fields are 32-bit aligned. */
        ptr += (len + 3) & ~3;
    }
    return 0;
}

int ItlIwn::
iwn_read_firmware(struct iwn_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_fw_info *fw = &sc->fw;
    int error = 0;
    OSData *fwData = NULL;

    /*
     * Some PHY calibration commands are firmware-dependent; these
     * are the default values that will be overridden if
     * necessary.
     */
    sc->reset_noise_gain = IWN5000_PHY_CALIB_RESET_NOISE_GAIN;
    sc->noise_gain = IWN5000_PHY_CALIB_NOISE_GAIN;

    memset(fw, 0, sizeof (*fw));

    /* Read firmware image from filesystem. */
//    if ((error = loadfirmware(sc->fwname, &fw->data, &fw->size)) != 0) {
//        XYLog("%s: could not read firmware %s (error %d)\n",
//            sc->sc_dev.dv_xname, sc->fwname, error);
//        return error;
//    }
    fwData = getFWDescByName(sc->fwname);
    if (fwData == NULL) {
        error = EINVAL;
        XYLog("%s resource load fail.\n", sc->fwname);
        return error;
    }
    fw->size = fwData->getLength() * 4;
    fw->data = (u_char *)malloc(fw->size, 1, 1);
    uncompressFirmware((u_char *)fw->data, (uint *)&fw->size, (u_char *)fwData->getBytesNoCopy(), fwData->getLength());
    XYLog("load firmware %s done\n", sc->fwname);
    OSSafeReleaseNULL(fwData);
    
    if (fw->size < sizeof (uint32_t)) {
        XYLog("%s: firmware too short: %zu bytes\n",
            sc->sc_dev.dv_xname, fw->size);
        ::free(fw->data);
        return EINVAL;
    }

    /* Retrieve text and data sections. */
    if (*(const uint32_t *)fw->data != 0)    /* Legacy image. */
        error = iwn_read_firmware_leg(sc, fw);
    else
        error = iwn_read_firmware_tlv(sc, fw, 1);
    if (error != 0) {
        XYLog("%s: could not read firmware sections\n",
            sc->sc_dev.dv_xname);
        ::free(fw->data);
        return error;
    }

    /* Make sure text and data sections fit in hardware memory. */
    if (fw->main.textsz > sc->fw_text_maxsz ||
        fw->main.datasz > sc->fw_data_maxsz ||
        fw->init.textsz > sc->fw_text_maxsz ||
        fw->init.datasz > sc->fw_data_maxsz ||
        fw->boot.textsz > IWN_FW_BOOT_TEXT_MAXSZ ||
        (fw->boot.textsz & 3) != 0) {
        XYLog("%s: firmware sections too large\n",
            sc->sc_dev.dv_xname);
        ::free(fw->data);
        return EINVAL;
    }
  
    /* We can proceed with loading the firmware. */
    return 0;
}

int ItlIwn::
iwn_clock_wait(struct iwn_softc *sc)
{
    int ntries;

    /* Set "initialization complete" bit. */
    IWN_SETBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_INIT_DONE);

    /* Wait for clock stabilization. */
    for (ntries = 0; ntries < 2500; ntries++) {
        if (IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_MAC_CLOCK_READY)
            return 0;
        DELAY(10);
    }
    XYLog("%s: timeout waiting for clock stabilization\n",
        sc->sc_dev.dv_xname);
    return ETIMEDOUT;
}

int ItlIwn::
iwn_apm_init(struct iwn_softc *sc)
{
    pcireg_t reg;
    int error;

    /* Disable L0s exit timer (NMI bug workaround). */
    IWN_SETBITS(sc, IWN_GIO_CHICKEN, IWN_GIO_CHICKEN_DIS_L0S_TIMER);
    /* Don't wait for ICH L0s (ICH bug workaround). */
    IWN_SETBITS(sc, IWN_GIO_CHICKEN, IWN_GIO_CHICKEN_L1A_NO_L0S_RX);

    /* Set FH wait threshold to max (HW bug under stress workaround). */
    IWN_SETBITS(sc, IWN_DBG_HPET_MEM, 0xffff0000);

    /* Enable HAP INTA to move adapter from L1a to L0s. */
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_HAP_WAKE_L1A);

    /* Retrieve PCIe Active State Power Management (ASPM). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
        sc->sc_cap_off + PCI_PCIE_LCSR);
    /* Workaround for HW instability in PCIe L0->L0s->L1 transition. */
    if (reg & PCI_PCIE_LCSR_ASPM_L1)    /* L1 Entry enabled. */
        IWN_SETBITS(sc, IWN_GIO, IWN_GIO_L0S_ENA);
    else
        IWN_CLRBITS(sc, IWN_GIO, IWN_GIO_L0S_ENA);

    if (sc->hw_type != IWN_HW_REV_TYPE_4965 &&
        sc->hw_type <= IWN_HW_REV_TYPE_1000)
        IWN_SETBITS(sc, IWN_ANA_PLL, IWN_ANA_PLL_INIT);

    /* Wait for clock stabilization before accessing prph. */
    if ((error = iwn_clock_wait(sc)) != 0)
        return error;

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    if (sc->hw_type == IWN_HW_REV_TYPE_4965) {
        /* Enable DMA and BSM (Bootstrap State Machine). */
        iwn_prph_write(sc, IWN_APMG_CLK_EN,
            IWN_APMG_CLK_CTRL_DMA_CLK_RQT |
            IWN_APMG_CLK_CTRL_BSM_CLK_RQT);
    } else {
        /* Enable DMA. */
        iwn_prph_write(sc, IWN_APMG_CLK_EN,
            IWN_APMG_CLK_CTRL_DMA_CLK_RQT);
    }
    DELAY(20);
    /* Disable L1-Active. */
    iwn_prph_setbits(sc, IWN_APMG_PCI_STT, IWN_APMG_PCI_STT_L1A_DIS);
    iwn_nic_unlock(sc);

    return 0;
}

void ItlIwn::
iwn_apm_stop_master(struct iwn_softc *sc)
{
    int ntries;

    /* Stop busmaster DMA activity. */
    IWN_SETBITS(sc, IWN_RESET, IWN_RESET_STOP_MASTER);
    for (ntries = 0; ntries < 100; ntries++) {
        if (IWN_READ(sc, IWN_RESET) & IWN_RESET_MASTER_DISABLED)
            return;
        DELAY(10);
    }
    XYLog("%s: timeout waiting for master\n", sc->sc_dev.dv_xname);
}

void ItlIwn::
iwn_apm_stop(struct iwn_softc *sc)
{
    iwn_apm_stop_master(sc);

    /* Reset the entire device. */
    IWN_SETBITS(sc, IWN_RESET, IWN_RESET_SW);
    DELAY(10);
    /* Clear "initialization complete" bit. */
    IWN_CLRBITS(sc, IWN_GP_CNTRL, IWN_GP_CNTRL_INIT_DONE);
}

int ItlIwn::
iwn4965_nic_config(struct iwn_softc *sc)
{
    if (IWN_RFCFG_TYPE(sc->rfcfg) == 1) {
        /*
         * I don't believe this to be correct but this is what the
         * vendor driver is doing. Probably the bits should not be
         * shifted in IWN_RFCFG_*.
         */
        IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
            IWN_RFCFG_TYPE(sc->rfcfg) |
            IWN_RFCFG_STEP(sc->rfcfg) |
            IWN_RFCFG_DASH(sc->rfcfg));
    }
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
        IWN_HW_IF_CONFIG_RADIO_SI | IWN_HW_IF_CONFIG_MAC_SI);
    return 0;
}

int ItlIwn::
iwn5000_nic_config(struct iwn_softc *sc)
{
    uint32_t tmp;
    int error;

    if (IWN_RFCFG_TYPE(sc->rfcfg) < 3) {
        IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
            IWN_RFCFG_TYPE(sc->rfcfg) |
            IWN_RFCFG_STEP(sc->rfcfg) |
            IWN_RFCFG_DASH(sc->rfcfg));
    }
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG,
        IWN_HW_IF_CONFIG_RADIO_SI | IWN_HW_IF_CONFIG_MAC_SI);

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    iwn_prph_setbits(sc, IWN_APMG_PS, IWN_APMG_PS_EARLY_PWROFF_DIS);

    if (sc->hw_type == IWN_HW_REV_TYPE_1000) {
        /*
         * Select first Switching Voltage Regulator (1.32V) to
         * solve a stability issue related to noisy DC2DC line
         * in the silicon of 1000 Series.
         */
        tmp = iwn_prph_read(sc, IWN_APMG_DIGITAL_SVR);
        tmp &= ~IWN_APMG_DIGITAL_SVR_VOLTAGE_MASK;
        tmp |= IWN_APMG_DIGITAL_SVR_VOLTAGE_1_32;
        iwn_prph_write(sc, IWN_APMG_DIGITAL_SVR, tmp);
    }
    iwn_nic_unlock(sc);

    if (sc->sc_flags & IWN_FLAG_INTERNAL_PA) {
        /* Use internal power amplifier only. */
        IWN_WRITE(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_RADIO_2X2_IPA);
    }
    if ((sc->hw_type == IWN_HW_REV_TYPE_6050 ||
         sc->hw_type == IWN_HW_REV_TYPE_6005) && sc->calib_ver >= 6) {
        /* Indicate that ROM calibration version is >=6. */
        IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_CALIB_VER6);
    }
    if (sc->hw_type == IWN_HW_REV_TYPE_6005)
        IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_6050_1X2);
    if (sc->hw_type == IWN_HW_REV_TYPE_2030 ||
        sc->hw_type == IWN_HW_REV_TYPE_2000 ||
        sc->hw_type == IWN_HW_REV_TYPE_135 ||
        sc->hw_type == IWN_HW_REV_TYPE_105)
        IWN_SETBITS(sc, IWN_GP_DRIVER, IWN_GP_DRIVER_RADIO_IQ_INVERT);
    return 0;
}

/*
 * Take NIC ownership over Intel Active Management Technology (AMT).
 */
int ItlIwn::
iwn_hw_prepare(struct iwn_softc *sc)
{
    int ntries;

    /* Check if hardware is ready. */
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_NIC_READY);
    for (ntries = 0; ntries < 5; ntries++) {
        if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
            IWN_HW_IF_CONFIG_NIC_READY)
            return 0;
        DELAY(10);
    }

    /* Hardware not ready, force into ready state. */
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_PREPARE);
    for (ntries = 0; ntries < 15000; ntries++) {
        if (!(IWN_READ(sc, IWN_HW_IF_CONFIG) &
            IWN_HW_IF_CONFIG_PREPARE_DONE))
            break;
        DELAY(10);
    }
    if (ntries == 15000)
        return ETIMEDOUT;

    /* Hardware should be ready now. */
    IWN_SETBITS(sc, IWN_HW_IF_CONFIG, IWN_HW_IF_CONFIG_NIC_READY);
    for (ntries = 0; ntries < 5; ntries++) {
        if (IWN_READ(sc, IWN_HW_IF_CONFIG) &
            IWN_HW_IF_CONFIG_NIC_READY)
            return 0;
        DELAY(10);
    }
    return ETIMEDOUT;
}

int ItlIwn::
iwn_hw_init(struct iwn_softc *sc)
{
    struct iwn_ops *ops = &sc->ops;
    int error, chnl, qid;

    /* Clear pending interrupts. */
    IWN_WRITE(sc, IWN_INT, 0xffffffff);

    if ((error = iwn_apm_init(sc)) != 0) {
        XYLog("%s: could not power on adapter\n",
            sc->sc_dev.dv_xname);
        return error;
    }

    /* Select VMAIN power source. */
    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    iwn_prph_clrbits(sc, IWN_APMG_PS, IWN_APMG_PS_PWR_SRC_MASK);
    iwn_nic_unlock(sc);

    /* Perform adapter-specific initialization. */
    if ((error = ops->nic_config(sc)) != 0)
        return error;

    /* Initialize RX ring. */
    if ((error = iwn_nic_lock(sc)) != 0)
        return error;
    IWN_WRITE(sc, IWN_FH_RX_CONFIG, 0);
    IWN_WRITE(sc, IWN_FH_RX_WPTR, 0);
    /* Set physical address of RX ring (256-byte aligned). */
    IWN_WRITE(sc, IWN_FH_RX_BASE, sc->rxq.desc_dma.paddr >> 8);
    /* Set physical address of RX status (16-byte aligned). */
    IWN_WRITE(sc, IWN_FH_STATUS_WPTR, sc->rxq.stat_dma.paddr >> 4);
    /* Enable RX. */
    IWN_WRITE(sc, IWN_FH_RX_CONFIG,
        IWN_FH_RX_CONFIG_ENA           |
        IWN_FH_RX_CONFIG_IGN_RXF_EMPTY |    /* HW bug workaround */
        IWN_FH_RX_CONFIG_IRQ_DST_HOST  |
        IWN_FH_RX_CONFIG_SINGLE_FRAME  |
        IWN_FH_RX_CONFIG_RB_TIMEOUT(0x11) | /* about 1/2 msec */
        IWN_FH_RX_CONFIG_NRBD(IWN_RX_RING_COUNT_LOG));
    iwn_nic_unlock(sc);
    IWN_WRITE(sc, IWN_FH_RX_WPTR, (IWN_RX_RING_COUNT - 1) & ~7);

    if ((error = iwn_nic_lock(sc)) != 0)
        return error;

    /* Initialize TX scheduler. */
    iwn_prph_write(sc, sc->sched_txfact_addr, 0);

    /* Set physical address of "keep warm" page (16-byte aligned). */
    IWN_WRITE(sc, IWN_FH_KW_ADDR, sc->kw_dma.paddr >> 4);

    /* Initialize TX rings. */
    for (qid = 0; qid < sc->ntxqs; qid++) {
        struct iwn_tx_ring *txq = &sc->txq[qid];

        /* Set physical address of TX ring (256-byte aligned). */
        IWN_WRITE(sc, IWN_FH_CBBC_QUEUE(qid),
            txq->desc_dma.paddr >> 8);
    }
    iwn_nic_unlock(sc);

    /* Enable DMA channels. */
    for (chnl = 0; chnl < sc->ndmachnls; chnl++) {
        IWN_WRITE(sc, IWN_FH_TX_CONFIG(chnl),
            IWN_FH_TX_CONFIG_DMA_ENA |
            IWN_FH_TX_CONFIG_DMA_CREDIT_ENA);
    }

    /* Clear "radio off" and "commands blocked" bits. */
    IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);
    IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_CMD_BLOCKED);

    /* Clear pending interrupts. */
    IWN_WRITE(sc, IWN_INT, 0xffffffff);
    /* Enable interrupt coalescing. */
    IWN_WRITE(sc, IWN_INT_COALESCING, 512 / 8);
    /* Enable interrupts. */
    IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);

    /* _Really_ make sure "radio off" bit is cleared! */
    IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);
    IWN_WRITE(sc, IWN_UCODE_GP1_CLR, IWN_UCODE_GP1_RFKILL);

    /* Enable shadow registers. */
    if (sc->hw_type >= IWN_HW_REV_TYPE_6000)
        IWN_SETBITS(sc, IWN_SHADOW_REG_CTRL, 0x800fffff);

    if ((error = ops->load_firmware(sc)) != 0) {
        XYLog("%s: could not load firmware\n", sc->sc_dev.dv_xname);
        return error;
    }
    /* Wait at most one second for firmware alive notification. */
    if ((error = tsleep_nsec(sc, PCATCH, "iwninit", SEC_TO_NSEC(1))) != 0) {
        XYLog("%s: timeout waiting for adapter to initialize\n",
            sc->sc_dev.dv_xname);
        return error;
    }
    /* Do post-firmware initialization. */
    return ops->post_alive(sc);
}

void ItlIwn::
iwn_hw_stop(struct iwn_softc *sc)
{
    int chnl, qid, ntries;

    IWN_WRITE(sc, IWN_RESET, IWN_RESET_NEVO);

    /* Disable interrupts. */
    IWN_WRITE(sc, IWN_INT_MASK, 0);
    IWN_WRITE(sc, IWN_INT, 0xffffffff);
    IWN_WRITE(sc, IWN_FH_INT, 0xffffffff);
    sc->sc_flags &= ~IWN_FLAG_USE_ICT;

    /* Make sure we no longer hold the NIC lock. */
    iwn_nic_unlock(sc);

    /* Stop TX scheduler. */
    iwn_prph_write(sc, sc->sched_txfact_addr, 0);

    /* Stop all DMA channels. */
    if (iwn_nic_lock(sc) == 0) {
        for (chnl = 0; chnl < sc->ndmachnls; chnl++) {
            IWN_WRITE(sc, IWN_FH_TX_CONFIG(chnl), 0);
            for (ntries = 0; ntries < 200; ntries++) {
                if (IWN_READ(sc, IWN_FH_TX_STATUS) &
                    IWN_FH_TX_STATUS_IDLE(chnl))
                    break;
                DELAY(10);
            }
        }
        iwn_nic_unlock(sc);
    }

    /* Stop RX ring. */
    iwn_reset_rx_ring(sc, &sc->rxq);

    /* Reset all TX rings. */
    for (qid = 0; qid < sc->ntxqs; qid++)
        iwn_reset_tx_ring(sc, &sc->txq[qid]);

    if (iwn_nic_lock(sc) == 0) {
        iwn_prph_write(sc, IWN_APMG_CLK_DIS,
            IWN_APMG_CLK_CTRL_DMA_CLK_RQT);
        iwn_nic_unlock(sc);
    }
    DELAY(5);
    /* Power OFF adapter. */
    iwn_apm_stop(sc);
}

int ItlIwn::
iwn_init(struct _ifnet *ifp)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    int error;

    memset(sc->bss_node_addr, 0, sizeof(sc->bss_node_addr));
    sc->agg_queue_mask = 0;
    memset(sc->sc_tx_ba, 0, sizeof(sc->sc_tx_ba));

    if ((error = iwn_hw_prepare(sc)) != 0) {
        XYLog("%s: hardware not ready\n", sc->sc_dev.dv_xname);
        goto fail;
    }

    /* Initialize interrupt mask to default value. */
    sc->int_mask = IWN_INT_MASK_DEF;
    sc->sc_flags &= ~IWN_FLAG_USE_ICT;

    /* Check that the radio is not disabled by hardware switch. */
    if (!(IWN_READ(sc, IWN_GP_CNTRL) & IWN_GP_CNTRL_RFKILL)) {
        XYLog("%s: radio is disabled by hardware switch\n",
            sc->sc_dev.dv_xname);
        error = EPERM;    /* :-) */
        /* Re-enable interrupts. */
        IWN_WRITE(sc, IWN_INT, 0xffffffff);
        IWN_WRITE(sc, IWN_INT_MASK, sc->int_mask);
        return error;
    }

    /* Read firmware images from the filesystem. */
    if ((error = iwn_read_firmware(sc)) != 0) {
        XYLog("%s: could not read firmware\n", sc->sc_dev.dv_xname);
        goto fail;
    }

    /* Initialize hardware and upload firmware. */
    error = iwn_hw_init(sc);
    ::free(sc->fw.data);
    if (error != 0) {
        XYLog("%s: could not initialize hardware\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    /* Configure adapter now that it is ready. */
    if ((error = iwn_config(sc)) != 0) {
        XYLog("%s: could not configure device\n",
            sc->sc_dev.dv_xname);
        goto fail;
    }

    ifq_clr_oactive(&ifp->if_snd);
    ifp->if_flags |= IFF_RUNNING;

    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        ieee80211_begin_scan(ifp);
    else
        ieee80211_new_state(ic, IEEE80211_S_RUN, -1);

    return 0;

fail:    iwn_stop(ifp);
    return error;
}

void ItlIwn::
iwn_stop(struct _ifnet *ifp)
{
    struct iwn_softc *sc = (struct iwn_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;

    timeout_del(&sc->calib_to);
    ifp->if_timer = sc->sc_tx_timer = 0;
    ifp->if_flags &= ~IFF_RUNNING;
    ifq_clr_oactive(&ifp->if_snd);

    ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

    /* Power OFF hardware. */
    iwn_hw_stop(sc);
}
