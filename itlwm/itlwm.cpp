/* add your code here */
#include "itlwm.hpp"
#include "types.h"

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/ethernet.h>

#define super IOEthernetController
OSDefineMetaClassAndStructors(itlwm, IOEthernetController)
OSDefineMetaClassAndStructors(CTimeout, OSObject)

bool itlwm::init(OSDictionary *properties)
{
    XYLog("%s\n", __func__);
    super::init(properties);
    fwLoadLock = IOLockAlloc();
    return true;
}

IOService* itlwm::probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __func__);
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return NULL;
    }
    return iwm_match(device) == 0?NULL:this;
}

bool itlwm::start(IOService *provider)
{
    XYLog("%s\n", __func__);
    if (!super::start(provider)) {
        return false;
    }
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return false;
    }
    device->setBusMasterEnable(true);
    device->setIOEnable(true);
    device->setMemoryEnable(true);
    device->configWrite8(0x41, 0);
    fWorkloop = IOWorkLoop::workLoop();
    if (!fWorkloop) {
        return false;
    }
    initTimeout(fWorkloop);
    fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)tsleepHandler);
    if (fCommandGate == 0) {
        XYLog("No command gate!!\n");
        return false;
    }
    fWorkloop->addEventSource(fCommandGate);
    pci.workloop = fWorkloop;
    pci.pa_tag = device;
    if (!iwm_attach(&com, &pci)) {
        return false;
    }
    iwm_init(&com.sc_ic.ic_ac.ac_if);
    registerService();
    return true;
}

void itlwm::stop(IOService *provider)
{
    XYLog("%s\n", __func__);
    super::stop(provider);
}

IOReturn itlwm::setPromiscuousMode(bool active)
{
    XYLog("%s\n", __func__);
    return kIOReturnSuccess;
}

IOReturn itlwm::setMulticastMode(bool active)
{
    XYLog("%s\n", __func__);
    return kIOReturnSuccess;
}

void itlwm::wakeupOn(void *ident)
{
    XYLog("%s\n", __func__);
    if (fCommandGate == 0)
        return;
    else
        fCommandGate->commandWakeup(ident);
}

int itlwm::tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
    XYLog("%s\n", __func__);
    if (fCommandGate == 0) {
        IOSleep(timo);
        return 0;
    }
    XYLog("%s\n", wmesg);
    IOReturn ret;
    if (timo == 0) {
        ret = fCommandGate->runCommand(ident);
    } else {
        ret = fCommandGate->runCommand(ident, &timo);
    }
    if (ret == kIOReturnSuccess)
        return 0;
    else
        return 1;
}

IOReturn itlwm::tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    XYLog("%s\n", __func__);
    itlwm* dev = OSDynamicCast(itlwm, owner);
    if (dev == 0)
        return kIOReturnError;
    
    if (arg1 == 0) {
        if (dev->fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kMillisecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (dev->fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

void itlwm::free()
{
    XYLog("%s\n", __func__);
    IOLockFree(fwLoadLock);
    fwLoadLock = NULL;
    releaseTimeout();
    if (com.ih) {
        ieee80211_ifdetach(&com.sc_ic.ic_ac.ac_if);
        if (fWorkloop) {
            fWorkloop->removeEventSource(com.ih->intr);
            com.ih->intr->release();
        }
        com.ih->release();
        com.ih = NULL;
    }
    if (fCommandGate) {
        if (fWorkloop) {
            fWorkloop->removeEventSource(fCommandGate);
            fCommandGate->disable();
        }
        fCommandGate->release();
        fCommandGate = NULL;
    }
    if (fWorkloop) {
        fWorkloop->release();
        fWorkloop = NULL;
    }
    super::free();
}

IOReturn itlwm::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __func__);
    return super::enable(netif);
}

IOReturn itlwm::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __func__);
    return super::disable(netif);
}

IOReturn itlwm::getHardwareAddress(IOEthernetAddress *addrP) {
    XYLog("%s\n", __func__);
    addrP->bytes[0] = 0x29;
    addrP->bytes[1] = 0xC2;
    addrP->bytes[2] = 0xdd;
    addrP->bytes[3] = 0x8F;
    addrP->bytes[4] = 0x93;
    addrP->bytes[5] = 0x4D;
    return kIOReturnSuccess;
}

IOOutputQueue *itlwm::createOutputQueue()
{
    XYLog("%s\n", __func__);
    if (fOutputQueue == 0) {
        fOutputQueue = IOGatedOutputQueue::withTarget(this, getWorkLoop());
    }
    return fOutputQueue;
}

UInt32 itlwm::outputPacket(mbuf_t m, void *param)
{
    XYLog("%s\n", __func__);
    freePacket(m);
    return kIOReturnOutputDropped;
}

int itlwm::iwm_media_change(struct ifnet *ifp)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rate, ridx;
    int err;
    
    err = ieee80211_media_change(ifp);
    if (err != ENETRESET)
        return err;
    
    if (ic->ic_fixed_mcs != -1)
        sc->sc_fixed_ridx = iwm_mcs2ridx[ic->ic_fixed_mcs];
    else if (ic->ic_fixed_rate != -1) {
        rate = ic->ic_sup_rates[ic->ic_curmode].
        rs_rates[ic->ic_fixed_rate] & IEEE80211_RATE_VAL;
        /* Map 802.11 rate to HW rate index. */
        for (ridx = 0; ridx <= IWM_RIDX_MAX; ridx++)
            if (iwm_rates[ridx].rate == rate)
                break;
        sc->sc_fixed_ridx = ridx;
    }
    
    if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
        (IFF_UP | IFF_RUNNING)) {
        iwm_stop(ifp);
        err = iwm_init(ifp);
    }
    return err;
}

void itlwm::
iwm_newstate_task(void *psc)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc *)psc;
    struct ieee80211com *ic = &sc->sc_ic;
    enum ieee80211_state nstate = sc->ns_nstate;
    enum ieee80211_state ostate = ic->ic_state;
    int arg = sc->ns_arg;
    int err = 0, s = splnet();
    
    if (sc->sc_flags & IWM_FLAG_SHUTDOWN) {
        /* iwm_stop() is waiting for us. */
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    if (ostate == IEEE80211_S_SCAN) {
        if (nstate == ostate) {
            if (sc->sc_flags & IWM_FLAG_SCANNING) {
                //                refcnt_rele_wake(&sc->task_refs);
                splx(s);
                return;
            }
            /* Firmware is no longer scanning. Do another scan. */
            goto next_scan;
        } else
            iwm_led_blink_stop(sc);
    }
    
    if (nstate <= ostate) {
        switch (ostate) {
            case IEEE80211_S_RUN:
                err = iwm_run_stop(sc);
                if (err)
                    goto out;
                /* FALLTHROUGH */
            case IEEE80211_S_ASSOC:
                if (nstate <= IEEE80211_S_ASSOC) {
                    err = iwm_disassoc(sc);
                    if (err)
                        goto out;
                }
                /* FALLTHROUGH */
            case IEEE80211_S_AUTH:
                if (nstate <= IEEE80211_S_AUTH) {
                    err = iwm_deauth(sc);
                    if (err)
                        goto out;
                }
                /* FALLTHROUGH */
            case IEEE80211_S_SCAN:
            case IEEE80211_S_INIT:
                break;
        }
        
        /* Die now if iwm_stop() was called while we were sleeping. */
        if (sc->sc_flags & IWM_FLAG_SHUTDOWN) {
            //            refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
        }
    }
    
    switch (nstate) {
        case IEEE80211_S_INIT:
            break;
            
        case IEEE80211_S_SCAN:
        next_scan:
            err = iwm_scan(sc);
            if (err)
                break;
            //        refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
            
        case IEEE80211_S_AUTH:
            err = iwm_auth(sc);
            break;
            
        case IEEE80211_S_ASSOC:
            err = iwm_assoc(sc);
            break;
            
        case IEEE80211_S_RUN:
            err = iwm_run(sc);
            break;
    }
    
out:
    if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
        if (err) {
            
        }
        //            task_add(systq, &sc->init_task);
        else {
            sc->sc_newstate(ic, nstate, arg);
        }
    }
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

int itlwm::
iwm_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
    XYLog("%s\n", __func__);
    struct ifnet *ifp = IC2IFP(ic);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    
    if (ic->ic_state == IEEE80211_S_RUN) {
        timeout_del(&sc->sc_calib_to);
        ieee80211_mira_cancel_timeouts(&in->in_mn);
        //        iwm_del_task(sc, systq, &sc->ba_task);
        //        iwm_del_task(sc, systq, &sc->htprot_task);
    }
    
    sc->ns_nstate = nstate;
    sc->ns_arg = arg;
    
    //    iwm_add_task(sc, sc->sc_nswq, &sc->newstate_task);
    
    return 0;
}

void itlwm::
iwm_endscan(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    struct ieee80211com *ic = &sc->sc_ic;
    
    if ((sc->sc_flags & (IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN)) == 0)
        return;
    
    sc->sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
    ieee80211_end_scan(&ic->ic_if);
}

/*
 * Aging and idle timeouts for the different possible scenarios
 * in default configuration
 */
static const uint32_t
iwm_sf_full_timeout_def[IWM_SF_NUM_SCENARIO][IWM_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWM_SF_SINGLE_UNICAST_AGING_TIMER_DEF),
        htole32(IWM_SF_SINGLE_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_AGG_UNICAST_AGING_TIMER_DEF),
        htole32(IWM_SF_AGG_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_MCAST_AGING_TIMER_DEF),
        htole32(IWM_SF_MCAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_BA_AGING_TIMER_DEF),
        htole32(IWM_SF_BA_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_TX_RE_AGING_TIMER_DEF),
        htole32(IWM_SF_TX_RE_IDLE_TIMER_DEF)
    },
};

/*
 * Aging and idle timeouts for the different possible scenarios
 * in single BSS MAC configuration.
 */
static const uint32_t
iwm_sf_full_timeout[IWM_SF_NUM_SCENARIO][IWM_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWM_SF_SINGLE_UNICAST_AGING_TIMER),
        htole32(IWM_SF_SINGLE_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_AGG_UNICAST_AGING_TIMER),
        htole32(IWM_SF_AGG_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_MCAST_AGING_TIMER),
        htole32(IWM_SF_MCAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_BA_AGING_TIMER),
        htole32(IWM_SF_BA_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_TX_RE_AGING_TIMER),
        htole32(IWM_SF_TX_RE_IDLE_TIMER)
    },
};

void itlwm::
iwm_fill_sf_command(struct iwm_softc *sc, struct iwm_sf_cfg_cmd *sf_cmd,
                    struct ieee80211_node *ni)
{
    int i, j, watermark;
    
    sf_cmd->watermark[IWM_SF_LONG_DELAY_ON] = htole32(IWM_SF_W_MARK_SCAN);
    
    /*
     * If we are in association flow - check antenna configuration
     * capabilities of the AP station, and choose the watermark accordingly.
     */
    if (ni) {
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            if (ni->ni_rxmcs[1] != 0)
                watermark = IWM_SF_W_MARK_MIMO2;
            else
                watermark = IWM_SF_W_MARK_SISO;
        } else {
            watermark = IWM_SF_W_MARK_LEGACY;
        }
        /* default watermark value for unassociated mode. */
    } else {
        watermark = IWM_SF_W_MARK_MIMO2;
    }
    sf_cmd->watermark[IWM_SF_FULL_ON] = htole32(watermark);
    
    for (i = 0; i < IWM_SF_NUM_SCENARIO; i++) {
        for (j = 0; j < IWM_SF_NUM_TIMEOUT_TYPES; j++) {
            sf_cmd->long_delay_timeouts[i][j] =
            htole32(IWM_SF_LONG_DELAY_AGING_TIMER);
        }
    }
    
    if (ni) {
        memcpy(sf_cmd->full_on_timeouts, iwm_sf_full_timeout,
               sizeof(iwm_sf_full_timeout));
    } else {
        memcpy(sf_cmd->full_on_timeouts, iwm_sf_full_timeout_def,
               sizeof(iwm_sf_full_timeout_def));
    }
    
}

int itlwm::
iwm_sf_config(struct iwm_softc *sc, int new_state)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_sf_cfg_cmd sf_cmd = {
        .state = htole32(IWM_SF_FULL_ON),
    };
    int err = 0;
    
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000)
        sf_cmd.state |= htole32(IWM_SF_CFG_DUMMY_NOTIF_OFF);
    
    switch (new_state) {
        case IWM_SF_UNINIT:
        case IWM_SF_INIT_OFF:
            iwm_fill_sf_command(sc, &sf_cmd, NULL);
            break;
        case IWM_SF_FULL_ON:
            iwm_fill_sf_command(sc, &sf_cmd, ic->ic_bss);
            break;
        default:
            return EINVAL;
    }
    
    err = iwm_send_cmd_pdu(sc, IWM_REPLY_SF_CFG_CMD, IWM_CMD_ASYNC,
                           sizeof(sf_cmd), &sf_cmd);
    return err;
}

int itlwm::
iwm_init_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    struct ieee80211com *ic = &sc->sc_ic;
    int err, i, ac;
    
    err = iwm_preinit(sc);
    if (err)
        return err;
    
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwm_run_init_mvm_ucode(sc, 0);
    if (err)
        return err;
    
    /* Should stop and start HW since INIT image just loaded. */
    iwm_stop_device(sc);
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    /* Restart, this time with the regular firmware */
    err = iwm_load_ucode_wait_alive(sc, IWM_UCODE_TYPE_REGULAR);
    if (err) {
        XYLog("%s: could not load firmware\n", DEVNAME(sc));
        goto err;
    }
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    err = iwm_send_bt_init_conf(sc);
    if (err) {
        XYLog("%s: could not init bt coex (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_tx_ant_cfg(sc, iwm_fw_valid_tx_ant(sc));
    if (err) {
        XYLog("%s: could not init tx ant config (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_phy_db_data(sc);
    if (err) {
        XYLog("%s: could not init phy db (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_phy_cfg_cmd(sc);
    if (err) {
        XYLog("%s: could not send phy config (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    /* Add auxiliary station for scanning */
    err = iwm_add_aux_sta(sc);
    if (err) {
        XYLog("%s: could not add aux station (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    for (i = 0; i < 1; i++) {
        /*
         * The channel used here isn't relevant as it's
         * going to be overwritten in the other flows.
         * For now use the first channel we have.
         */
        sc->sc_phyctxt[i].channel = &ic->ic_channels[1];
        err = iwm_phy_ctxt_cmd(sc, &sc->sc_phyctxt[i], 1, 1,
                               IWM_FW_CTXT_ACTION_ADD, 0);
        if (err) {
            XYLog("%s: could not add phy context %d (error %d)\n",
                  DEVNAME(sc), i, err);
            goto err;
        }
    }
    
    /* Initialize tx backoffs to the minimum. */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
        iwm_tt_tx_backoff(sc, 0);
    
    err = iwm_power_update_device(sc);
    if (err) {
        XYLog("%s: could not send power command (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_LAR_SUPPORT)) {
        err = iwm_send_update_mcc_cmd(sc, "ZZ");
        if (err) {
            XYLog("%s: could not init LAR (error %d)\n",
                  DEVNAME(sc), err);
            goto err;
        }
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_UMAC_SCAN)) {
        err = iwm_config_umac_scan(sc);
        if (err) {
            XYLog("%s: could not configure scan (error %d)\n",
                  DEVNAME(sc), err);
            goto err;
        }
    }
    
    for (ac = 0; ac < EDCA_NUM_AC; ac++) {
        err = iwm_enable_txq(sc, IWM_STATION_ID, ac,
                             iwm_ac_to_tx_fifo[ac]);
        if (err) {
            XYLog("%s: could not enable Tx queue %d (error %d)\n",
                  DEVNAME(sc), ac, err);
            goto err;
        }
    }
    
    err = iwm_disable_beacon_filter(sc);
    if (err) {
        XYLog("%s: could not disable beacon filter (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
err:
    iwm_nic_unlock(sc);
    return err;
}

int itlwm::
iwm_init(struct ifnet *ifp)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    int err, generation;
    
    generation = ++sc->sc_generation;
    
    _KASSERT(sc->task_refs.refs == 0);
    
    err = iwm_init_hw(sc);
    if (err) {
        XYLog("iwm_init_hw fail. err=%d", err);
        if (generation == sc->sc_generation)
            iwm_stop(ifp);
        return err;
    }
    
    //    ifq_clr_oactive(&ifp->if_snd);
    ifp->if_flags |= IFF_RUNNING;
    
    ieee80211_begin_scan(ifp);
    
    /*
     * ieee80211_begin_scan() ends up scheduling iwm_newstate_task().
     * Wait until the transition to SCAN state has completed.
     */
    do {
        err = tsleep_nsec(&ic->ic_state, PCATCH, "iwminit",
                          SEC_TO_NSEC(1));
        if (generation != sc->sc_generation)
            return ENXIO;
        if (err)
            return err;
    } while (ic->ic_state != IEEE80211_S_SCAN);
    
    return 0;
}

void itlwm::
iwm_start(struct ifnet *ifp)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    struct ether_header *eh;
    mbuf_t m;
    int ac = EDCA_AC_BE; /* XXX */
    
    if (!(ifp->if_flags & IFF_RUNNING) /*|| ifq_is_oactive(&ifp->if_snd)*/)
        return;
    
    for (;;) {
        /* why isn't this done per-queue? */
        if (sc->qfullmsk != 0) {
            //            ifq_set_oactive(&ifp->if_snd);
            break;
        }
        
        /* need to send management frames even if we're not RUNning */
        m = mq_dequeue(&ic->ic_mgtq);
        if (m) {
            ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
            goto sendit;
        }
        
        if (ic->ic_state != IEEE80211_S_RUN ||
            (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
            break;
        
        //        IFQ_DEQUEUE(&ifp->if_snd, m);
        if (!m)
            break;
        if (mbuf_len(m) < sizeof (*eh) &&
            mbuf_pullup(&m, sizeof (*eh)) != 0) {
            ifp->if_oerrors++;
            continue;
        }
#if NBPFILTER > 0
        if (ifp->if_bpf != NULL)
            bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
        if ((m = ieee80211_encap(ifp, m, &ni)) == NULL) {
            ifp->if_oerrors++;
            continue;
        }
        
    sendit:
#if NBPFILTER > 0
        if (ic->ic_rawbpf != NULL)
            bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
        if (iwm_tx(sc, m, ni, ac) != 0) {
            ieee80211_release_node(ic, ni);
            ifp->if_oerrors++;
            continue;
        }
        
        if (ifp->if_flags & IFF_UP) {
            sc->sc_tx_timer = 15;
            ifp->if_timer = 1;
        }
    }
    
    return;
}

void itlwm::
iwm_stop(struct ifnet *ifp)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int i, s = splnet();
    
    //    rw_assert_wrlock(&sc->ioctl_rwl);
    
    sc->sc_flags |= IWM_FLAG_SHUTDOWN; /* Disallow new tasks. */
    
    /* Cancel scheduled tasks and let any stale tasks finish up. */
    //    task_del(systq, &sc->init_task);
    //    iwm_del_task(sc, sc->sc_nswq, &sc->newstate_task);
    //    iwm_del_task(sc, systq, &sc->ba_task);
    //    iwm_del_task(sc, systq, &sc->htprot_task);
    //    _KASSERT(sc->task_refs.refs >= 1);
    //    refcnt_finalize(&sc->task_refs, "iwmstop");
    
    iwm_stop_device(sc);
    
    /* Reset soft state. */
    
    sc->sc_generation++;
    for (i = 0; i < nitems(sc->sc_cmd_resp_pkt); i++) {
        free(sc->sc_cmd_resp_pkt[i], M_DEVBUF, sc->sc_cmd_resp_len[i]);
        sc->sc_cmd_resp_pkt[i] = NULL;
        sc->sc_cmd_resp_len[i] = 0;
    }
    ifp->if_flags &= ~IFF_RUNNING;
    //    ifq_clr_oactive(&ifp->if_snd);
    
    in->in_phyctxt = NULL;
    if (ic->ic_state == IEEE80211_S_RUN)
        ieee80211_mira_cancel_timeouts(&in->in_mn); /* XXX refcount? */
    
    sc->sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
    sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_STA_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_TE_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_HW_ERR;
    sc->sc_flags &= ~IWM_FLAG_SHUTDOWN;
    
    sc->sc_newstate(ic, IEEE80211_S_INIT, -1);
    
    timeout_del(&sc->sc_calib_to); /* XXX refcount? */
    iwm_led_blink_stop(sc);
    ifp->if_timer = sc->sc_tx_timer = 0;
    
    splx(s);
}

void itlwm::
iwm_watchdog(struct ifnet *ifp)
{
    struct iwm_softc *sc = (struct iwm_softc *)ifp->if_softc;
    
    ifp->if_timer = 0;
    if (sc->sc_tx_timer > 0) {
        if (--sc->sc_tx_timer == 0) {
            XYLog("%s: device timeout\n", DEVNAME(sc));
#ifdef IWM_DEBUG
            iwm_nic_error(sc);
#endif
            if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
                //                task_add(systq, &sc->init_task);
            }
            ifp->if_oerrors++;
            return;
        }
        ifp->if_timer = 1;
    }
    
    ieee80211_watchdog(ifp);
}

int itlwm::
iwm_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc *)ifp->if_softc;
    int s, err = 0, generation = sc->sc_generation;
    
    /*
     * Prevent processes from entering this function while another
     * process is tsleep'ing in it.
     */
    //    err = rw_enter(&sc->ioctl_rwl, RW_WRITE | RW_INTR);
    if (err == 0 && generation != sc->sc_generation) {
        //        rw_exit(&sc->ioctl_rwl);
        return ENXIO;
    }
    if (err)
        return err;
    s = splnet();
    
    switch (cmd) {
        case SIOCSIFADDR:
            ifp->if_flags |= IFF_UP;
            /* FALLTHROUGH */
        case SIOCSIFFLAGS:
            if (ifp->if_flags & IFF_UP) {
                if (!(ifp->if_flags & IFF_RUNNING)) {
                    err = iwm_init(ifp);
                }
            } else {
                if (ifp->if_flags & IFF_RUNNING)
                    iwm_stop(ifp);
            }
            break;
            
        default:
            err = ieee80211_ioctl(ifp, cmd, data);
    }
    
    if (err == ENETRESET) {
        err = 0;
        if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
            (IFF_UP | IFF_RUNNING)) {
            iwm_stop(ifp);
            err = iwm_init(ifp);
        }
    }
    
    splx(s);
    //    rw_exit(&sc->ioctl_rwl);
    
    return err;
}

#ifdef IWM_DEBUG
/*
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with uint32_t-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwm_error_event_table {
    uint32_t valid;        /* (nonzero) valid, (0) log is empty */
    uint32_t error_id;        /* type of error */
    uint32_t trm_hw_status0;    /* TRM HW status */
    uint32_t trm_hw_status1;    /* TRM HW status */
    uint32_t blink2;        /* branch link */
    uint32_t ilink1;        /* interrupt link */
    uint32_t ilink2;        /* interrupt link */
    uint32_t data1;        /* error-specific data */
    uint32_t data2;        /* error-specific data */
    uint32_t data3;        /* error-specific data */
    uint32_t bcon_time;        /* beacon timer */
    uint32_t tsf_low;        /* network timestamp function timer */
    uint32_t tsf_hi;        /* network timestamp function timer */
    uint32_t gp1;        /* GP1 timer register */
    uint32_t gp2;        /* GP2 timer register */
    uint32_t fw_rev_type;    /* firmware revision type */
    uint32_t major;        /* uCode version major */
    uint32_t minor;        /* uCode version minor */
    uint32_t hw_ver;        /* HW Silicon version */
    uint32_t brd_ver;        /* HW board version */
    uint32_t log_pc;        /* log program counter */
    uint32_t frame_ptr;        /* frame pointer */
    uint32_t stack_ptr;        /* stack pointer */
    uint32_t hcmd;        /* last host command header */
    uint32_t isr0;        /* isr status register LMPM_NIC_ISR0:
                           * rxtx_flag */
    uint32_t isr1;        /* isr status register LMPM_NIC_ISR1:
                           * host_flag */
    uint32_t isr2;        /* isr status register LMPM_NIC_ISR2:
                           * enc_flag */
    uint32_t isr3;        /* isr status register LMPM_NIC_ISR3:
                           * time_flag */
    uint32_t isr4;        /* isr status register LMPM_NIC_ISR4:
                           * wico interrupt */
    uint32_t last_cmd_id;    /* last HCMD id handled by the firmware */
    uint32_t wait_event;        /* wait event() caller address */
    uint32_t l2p_control;    /* L2pControlField */
    uint32_t l2p_duration;    /* L2pDurationField */
    uint32_t l2p_mhvalid;    /* L2pMhValidBits */
    uint32_t l2p_addr_match;    /* L2pAddrMatchStat */
    uint32_t lmpm_pmg_sel;    /* indicate which clocks are turned on
                               * (LMPM_PMG_SEL) */
    uint32_t u_timestamp;    /* indicate when the date and time of the
                              * compilation */
    uint32_t flow_handler;    /* FH read/write pointers, RX credit */
} __packed /* LOG_ERROR_TABLE_API_S_VER_3 */;

/*
 * UMAC error struct - relevant starting from family 8000 chip.
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with u32-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwm_umac_error_event_table {
    uint32_t valid;        /* (nonzero) valid, (0) log is empty */
    uint32_t error_id;    /* type of error */
    uint32_t blink1;    /* branch link */
    uint32_t blink2;    /* branch link */
    uint32_t ilink1;    /* interrupt link */
    uint32_t ilink2;    /* interrupt link */
    uint32_t data1;        /* error-specific data */
    uint32_t data2;        /* error-specific data */
    uint32_t data3;        /* error-specific data */
    uint32_t umac_major;
    uint32_t umac_minor;
    uint32_t frame_pointer;    /* core register 27*/
    uint32_t stack_pointer;    /* core register 28 */
    uint32_t cmd_header;    /* latest host cmd sent to UMAC */
    uint32_t nic_isr_pref;    /* ISR status register */
} __packed;

#define ERROR_START_OFFSET  (1 * sizeof(uint32_t))
#define ERROR_ELEM_SIZE     (7 * sizeof(uint32_t))

void itlwm::
iwm_nic_umac_error(struct iwm_softc *sc)
{
    struct iwm_umac_error_event_table table;
    uint32_t base;
    
    base = sc->sc_uc.uc_umac_error_event_table;
    
    if (base < 0x800000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwm_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
        XYLog("%s: reading errlog failed\n", DEVNAME(sc));
        return;
    }
    
    if (ERROR_START_OFFSET <= table.valid * ERROR_ELEM_SIZE) {
        XYLog("%s: Start UMAC Error Log Dump:\n", DEVNAME(sc));
        XYLog("%s: Status: 0x%x, count: %d\n", DEVNAME(sc),
              sc->sc_flags, table.valid);
    }
    
    XYLog("%s: 0x%08X | %s\n", DEVNAME(sc), table.error_id,
          iwm_desc_lookup(table.error_id));
    XYLog("%s: 0x%08X | umac branchlink1\n", DEVNAME(sc), table.blink1);
    XYLog("%s: 0x%08X | umac branchlink2\n", DEVNAME(sc), table.blink2);
    XYLog("%s: 0x%08X | umac interruptlink1\n", DEVNAME(sc), table.ilink1);
    XYLog("%s: 0x%08X | umac interruptlink2\n", DEVNAME(sc), table.ilink2);
    XYLog("%s: 0x%08X | umac data1\n", DEVNAME(sc), table.data1);
    XYLog("%s: 0x%08X | umac data2\n", DEVNAME(sc), table.data2);
    XYLog("%s: 0x%08X | umac data3\n", DEVNAME(sc), table.data3);
    XYLog("%s: 0x%08X | umac major\n", DEVNAME(sc), table.umac_major);
    XYLog("%s: 0x%08X | umac minor\n", DEVNAME(sc), table.umac_minor);
    XYLog("%s: 0x%08X | frame pointer\n", DEVNAME(sc),
          table.frame_pointer);
    XYLog("%s: 0x%08X | stack pointer\n", DEVNAME(sc),
          table.stack_pointer);
    XYLog("%s: 0x%08X | last host cmd\n", DEVNAME(sc), table.cmd_header);
    XYLog("%s: 0x%08X | isr status reg\n", DEVNAME(sc),
          table.nic_isr_pref);
}

struct {
    const char *name;
    uint8_t num;
} advanced_lookup[] = {
    { "NMI_INTERRUPT_WDG", 0x34 },
    { "SYSASSERT", 0x35 },
    { "UCODE_VERSION_MISMATCH", 0x37 },
    { "BAD_COMMAND", 0x38 },
    { "NMI_INTERRUPT_DATA_ACTION_PT", 0x3C },
    { "FATAL_ERROR", 0x3D },
    { "NMI_TRM_HW_ERR", 0x46 },
    { "NMI_INTERRUPT_TRM", 0x4C },
    { "NMI_INTERRUPT_BREAK_POINT", 0x54 },
    { "NMI_INTERRUPT_WDG_RXF_FULL", 0x5C },
    { "NMI_INTERRUPT_WDG_NO_RBD_RXF_FULL", 0x64 },
    { "NMI_INTERRUPT_HOST", 0x66 },
    { "NMI_INTERRUPT_ACTION_PT", 0x7C },
    { "NMI_INTERRUPT_UNKNOWN", 0x84 },
    { "NMI_INTERRUPT_INST_ACTION_PT", 0x86 },
    { "ADVANCED_SYSASSERT", 0 },
};

const char *itlwm::
iwm_desc_lookup(uint32_t num)
{
    int i;
    
    for (i = 0; i < nitems(advanced_lookup) - 1; i++)
        if (advanced_lookup[i].num == num)
            return advanced_lookup[i].name;
    
    /* No entry matches 'num', so it is the last: ADVANCED_SYSASSERT */
    return advanced_lookup[i].name;
}

/*
 * Support for dumping the error log seemed like a good idea ...
 * but it's mostly hex junk and the only sensible thing is the
 * hw/ucode revision (which we know anyway).  Since it's here,
 * I'll just leave it in, just in case e.g. the Intel guys want to
 * help us decipher some "ADVANCED_SYSASSERT" later.
 */
void itlwm::
iwm_nic_error(struct iwm_softc *sc)
{
    struct iwm_error_event_table table;
    uint32_t base;
    
    XYLog("%s: dumping device error log\n", DEVNAME(sc));
    base = sc->sc_uc.uc_error_event_table;
    if (base < 0x800000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwm_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
        XYLog("%s: reading errlog failed\n", DEVNAME(sc));
        return;
    }
    
    if (!table.valid) {
        XYLog("%s: errlog not found, skipping\n", DEVNAME(sc));
        return;
    }
    
    if (ERROR_START_OFFSET <= table.valid * ERROR_ELEM_SIZE) {
        XYLog("%s: Start Error Log Dump:\n", DEVNAME(sc));
        XYLog("%s: Status: 0x%x, count: %d\n", DEVNAME(sc),
              sc->sc_flags, table.valid);
    }
    
    XYLog("%s: 0x%08X | %-28s\n", DEVNAME(sc), table.error_id,
          iwm_desc_lookup(table.error_id));
    XYLog("%s: %08X | trm_hw_status0\n", DEVNAME(sc),
          table.trm_hw_status0);
    XYLog("%s: %08X | trm_hw_status1\n", DEVNAME(sc),
          table.trm_hw_status1);
    XYLog("%s: %08X | branchlink2\n", DEVNAME(sc), table.blink2);
    XYLog("%s: %08X | interruptlink1\n", DEVNAME(sc), table.ilink1);
    XYLog("%s: %08X | interruptlink2\n", DEVNAME(sc), table.ilink2);
    XYLog("%s: %08X | data1\n", DEVNAME(sc), table.data1);
    XYLog("%s: %08X | data2\n", DEVNAME(sc), table.data2);
    XYLog("%s: %08X | data3\n", DEVNAME(sc), table.data3);
    XYLog("%s: %08X | beacon time\n", DEVNAME(sc), table.bcon_time);
    XYLog("%s: %08X | tsf low\n", DEVNAME(sc), table.tsf_low);
    XYLog("%s: %08X | tsf hi\n", DEVNAME(sc), table.tsf_hi);
    XYLog("%s: %08X | time gp1\n", DEVNAME(sc), table.gp1);
    XYLog("%s: %08X | time gp2\n", DEVNAME(sc), table.gp2);
    XYLog("%s: %08X | uCode revision type\n", DEVNAME(sc),
          table.fw_rev_type);
    XYLog("%s: %08X | uCode version major\n", DEVNAME(sc),
          table.major);
    XYLog("%s: %08X | uCode version minor\n", DEVNAME(sc),
          table.minor);
    XYLog("%s: %08X | hw version\n", DEVNAME(sc), table.hw_ver);
    XYLog("%s: %08X | board version\n", DEVNAME(sc), table.brd_ver);
    XYLog("%s: %08X | hcmd\n", DEVNAME(sc), table.hcmd);
    XYLog("%s: %08X | isr0\n", DEVNAME(sc), table.isr0);
    XYLog("%s: %08X | isr1\n", DEVNAME(sc), table.isr1);
    XYLog("%s: %08X | isr2\n", DEVNAME(sc), table.isr2);
    XYLog("%s: %08X | isr3\n", DEVNAME(sc), table.isr3);
    XYLog("%s: %08X | isr4\n", DEVNAME(sc), table.isr4);
    XYLog("%s: %08X | last cmd Id\n", DEVNAME(sc), table.last_cmd_id);
    XYLog("%s: %08X | wait_event\n", DEVNAME(sc), table.wait_event);
    XYLog("%s: %08X | l2p_control\n", DEVNAME(sc), table.l2p_control);
    XYLog("%s: %08X | l2p_duration\n", DEVNAME(sc), table.l2p_duration);
    XYLog("%s: %08X | l2p_mhvalid\n", DEVNAME(sc), table.l2p_mhvalid);
    XYLog("%s: %08X | l2p_addr_match\n", DEVNAME(sc), table.l2p_addr_match);
    XYLog("%s: %08X | lmpm_pmg_sel\n", DEVNAME(sc), table.lmpm_pmg_sel);
    XYLog("%s: %08X | timestamp\n", DEVNAME(sc), table.u_timestamp);
    XYLog("%s: %08X | flow_handler\n", DEVNAME(sc), table.flow_handler);
    
    if (sc->sc_uc.uc_umac_error_event_table)
        iwm_nic_umac_error(sc);
}
#endif

#define SYNC_RESP_STRUCT(_var_, _pkt_, t)                    \
do {                                    \
bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
sizeof(*(_var_)), BUS_DMASYNC_POSTREAD);            \
_var_ = (t)((_pkt_)+1);                    \
} while (/*CONSTCOND*/0)

#define SYNC_RESP_PTR(_ptr_, _len_, _pkt_)                \
do {                                    \
bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
sizeof(len), BUS_DMASYNC_POSTREAD);                \
_ptr_ = (void *)((_pkt_)+1);                    \
} while (/*CONSTCOND*/0)

#define ADVANCE_RXQ(sc) (sc->rxq.cur = (sc->rxq.cur + 1) % IWM_RX_RING_COUNT);

void itlwm::
iwm_notif_intr(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    uint16_t hw;
    
    //        bus_dmamap_sync(sc->sc_dmat, sc->rxq.stat_dma.map,
    //            0, sc->rxq.stat_dma.size, BUS_DMASYNC_POSTREAD);
    
    hw = le16toh(sc->rxq.stat->closed_rb_num) & 0xfff;
    hw &= (IWM_RX_RING_COUNT - 1);
    while (sc->rxq.cur != hw) {
        struct iwm_rx_data *data = &sc->rxq.data[sc->rxq.cur];
        struct iwm_rx_packet *pkt;
        int qid, idx, code, handled = 1;
        
        bus_dmamap_sync(sc->sc_dmat, data->map, 0, sizeof(*pkt),
                        BUS_DMASYNC_POSTREAD);
        pkt = mtod(data->m, struct iwm_rx_packet *);
        
        qid = pkt->hdr.qid;
        idx = pkt->hdr.idx;
        
        code = IWM_WIDE_ID(pkt->hdr.flags, pkt->hdr.code);
        
        /*
         * randomly get these from the firmware, no idea why.
         * they at least seem harmless, so just ignore them for now
         */
        if ((pkt->hdr.code == 0 && (qid & ~0x80) == 0
             && idx == 0) || pkt->len_n_flags == htole32(0x55550000)) {
            ADVANCE_RXQ(sc);
            continue;
        }
        
        XYLog("code=0x%02x\n", code);
        
        switch (code) {
            case IWM_REPLY_RX_PHY_CMD:
                iwm_rx_rx_phy_cmd(sc, pkt, data);
                break;
                
            case IWM_REPLY_RX_MPDU_CMD:
                iwm_rx_rx_mpdu(sc, pkt, data, &ml);
                break;
                
            case IWM_TX_CMD:
                iwm_rx_tx_cmd(sc, pkt, data);
                break;
                
            case IWM_MISSED_BEACONS_NOTIFICATION:
                iwm_rx_bmiss(sc, pkt, data);
                break;
                
            case IWM_MFUART_LOAD_NOTIFICATION:
                break;
                
            case IWM_ALIVE: {
                struct iwm_alive_resp_v1 *resp1;
                struct iwm_alive_resp_v2 *resp2;
                struct iwm_alive_resp_v3 *resp3;
                
                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp1)) {
                    SYNC_RESP_STRUCT(resp1, pkt, struct iwm_alive_resp_v1 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp1->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp1->log_event_table_ptr);
                    sc->sched_base = le32toh(resp1->scd_base_ptr);
                    if (resp1->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp2)) {
                    SYNC_RESP_STRUCT(resp2, pkt, struct iwm_alive_resp_v2 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp2->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp2->log_event_table_ptr);
                    sc->sched_base = le32toh(resp2->scd_base_ptr);
                    sc->sc_uc.uc_umac_error_event_table
                    = le32toh(resp2->error_info_addr);
                    if (resp2->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp3)) {
                    SYNC_RESP_STRUCT(resp3, pkt, struct iwm_alive_resp_v3 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp3->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp3->log_event_table_ptr);
                    sc->sched_base = le32toh(resp3->scd_base_ptr);
                    sc->sc_uc.uc_umac_error_event_table
                    = le32toh(resp3->error_info_addr);
                    if (resp3->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                sc->sc_uc.uc_intr = 1;
                wakeupOn(&sc->sc_uc);
                break;
            }
                
            case IWM_CALIB_RES_NOTIF_PHY_DB: {
                struct iwm_calib_res_notif_phy_db *phy_db_notif;
                SYNC_RESP_STRUCT(phy_db_notif, pkt, struct iwm_calib_res_notif_phy_db *);
                iwm_phy_db_set_section(sc, phy_db_notif);
                sc->sc_init_complete |= IWM_CALIB_COMPLETE;
                wakeupOn(&sc->sc_init_complete);
                break;
            }
                
            case IWM_STATISTICS_NOTIFICATION: {
                struct iwm_notif_statistics *stats;
                SYNC_RESP_STRUCT(stats, pkt, struct iwm_notif_statistics *);
                memcpy(&sc->sc_stats, stats, sizeof(sc->sc_stats));
                sc->sc_noise = iwm_get_noise(&stats->rx.general);
                break;
            }
                
            case IWM_MCC_CHUB_UPDATE_CMD: {
                struct iwm_mcc_chub_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_mcc_chub_notif *);
                
                sc->sc_fw_mcc[0] = (notif->mcc & 0xff00) >> 8;
                sc->sc_fw_mcc[1] = notif->mcc & 0xff;
                sc->sc_fw_mcc[2] = '\0';
            }
                
            case IWM_DTS_MEASUREMENT_NOTIFICATION:
                break;
                
            case IWM_PHY_CONFIGURATION_CMD:
            case IWM_TX_ANT_CONFIGURATION_CMD:
            case IWM_ADD_STA:
            case IWM_MAC_CONTEXT_CMD:
            case IWM_REPLY_SF_CFG_CMD:
            case IWM_POWER_TABLE_CMD:
            case IWM_PHY_CONTEXT_CMD:
            case IWM_BINDING_CONTEXT_CMD:
            case IWM_WIDE_ID(IWM_ALWAYS_LONG_GROUP, IWM_SCAN_CFG_CMD):
            case IWM_WIDE_ID(IWM_ALWAYS_LONG_GROUP, IWM_SCAN_REQ_UMAC):
            case IWM_WIDE_ID(IWM_ALWAYS_LONG_GROUP, IWM_SCAN_ABORT_UMAC):
            case IWM_SCAN_OFFLOAD_REQUEST_CMD:
            case IWM_SCAN_OFFLOAD_ABORT_CMD:
            case IWM_REPLY_BEACON_FILTERING_CMD:
            case IWM_MAC_PM_POWER_TABLE:
            case IWM_TIME_QUOTA_CMD:
            case IWM_REMOVE_STA:
            case IWM_TXPATH_FLUSH:
            case IWM_LQ_CMD:
            case IWM_BT_CONFIG:
            case IWM_REPLY_THERMAL_MNG_BACKOFF:
            case IWM_NVM_ACCESS_CMD:
            case IWM_MCC_UPDATE_CMD:
            case IWM_TIME_EVENT_CMD: {
                size_t pkt_len;
                
                if (sc->sc_cmd_resp_pkt[idx] == NULL)
                    break;
                
                bus_dmamap_sync(sc->sc_dmat, data->map, 0,
                                sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                
                pkt_len = sizeof(pkt->len_n_flags) +
                iwm_rx_packet_len(pkt);
                
                if ((pkt->hdr.flags & IWM_CMD_FAILED_MSK) ||
                    pkt_len < sizeof(*pkt) ||
                    pkt_len > sc->sc_cmd_resp_len[idx]) {
                    free(sc->sc_cmd_resp_pkt[idx], M_DEVBUF,
                         sc->sc_cmd_resp_len[idx]);
                    sc->sc_cmd_resp_pkt[idx] = NULL;
                    break;
                }
                
                bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
                                pkt_len - sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                memcpy(sc->sc_cmd_resp_pkt[idx], pkt, pkt_len);
                break;
            }
                
                /* ignore */
            case 0x6c: /* IWM_PHY_DB_CMD */
                break;
                
            case IWM_INIT_COMPLETE_NOTIF:
                sc->sc_init_complete |= IWM_INIT_COMPLETE;
                wakeupOn(&sc->sc_init_complete);
                break;
                
            case IWM_SCAN_OFFLOAD_COMPLETE: {
                struct iwm_periodic_scan_complete *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_periodic_scan_complete *);
                break;
            }
                
            case IWM_SCAN_ITERATION_COMPLETE: {
                struct iwm_lmac_scan_complete_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_lmac_scan_complete_notif *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_SCAN_COMPLETE_UMAC: {
                struct iwm_umac_scan_complete *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_umac_scan_complete *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_SCAN_ITERATION_COMPLETE_UMAC: {
                struct iwm_umac_scan_iter_complete_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_umac_scan_iter_complete_notif *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_REPLY_ERROR: {
                struct iwm_error_resp *resp;
                SYNC_RESP_STRUCT(resp, pkt, struct iwm_error_resp *);
                XYLog("%s: firmware error 0x%x, cmd 0x%x\n",
                      DEVNAME(sc), le32toh(resp->error_type),
                      resp->cmd_id);
                break;
            }
                
            case IWM_TIME_EVENT_NOTIFICATION: {
                struct iwm_time_event_notif *notif;
                uint32_t action;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_time_event_notif *);
                
                if (sc->sc_time_event_uid != le32toh(notif->unique_id))
                    break;
                action = le32toh(notif->action);
                if (action & IWM_TE_V2_NOTIF_HOST_EVENT_END)
                    sc->sc_flags &= ~IWM_FLAG_TE_ACTIVE;
                break;
            }
                
            case IWM_WIDE_ID(IWM_SYSTEM_GROUP,
                             IWM_FSEQ_VER_MISMATCH_NOTIFICATION):
                break;
                
                /*
                 * Firmware versions 21 and 22 generate some DEBUG_LOG_MSG
                 * messages. Just ignore them for now.
                 */
            case IWM_DEBUG_LOG_MSG:
                break;
                
            case IWM_MCAST_FILTER_CMD:
                break;
                
            case IWM_SCD_QUEUE_CFG: {
                struct iwm_scd_txq_cfg_rsp *rsp;
                SYNC_RESP_STRUCT(rsp, pkt, struct iwm_scd_txq_cfg_rsp *);
                
                break;
            }
                
            default:
                handled = 0;
                XYLog("%s: unhandled firmware response 0x%x/0x%x "
                      "rx ring %d[%d]\n",
                      DEVNAME(sc), code, pkt->len_n_flags,
                      (qid & ~0x80), idx);
                break;
        }
        
        /*
         * uCode sets bit 0x80 when it originates the notification,
         * i.e. when the notification is not a direct response to a
         * command sent by the driver.
         * For example, uCode issues IWM_REPLY_RX when it sends a
         * received frame to the driver.
         */
        if (handled && !(qid & (1 << 7))) {
            iwm_cmd_done(sc, qid, idx, code);
        }
        
        ADVANCE_RXQ(sc);
    }
    if_input(&sc->sc_ic.ic_if, &ml);
    
    /*
     * Tell the firmware what we have processed.
     * Seems like the hardware gets upset unless we align the write by 8??
     */
    hw = (hw == 0) ? IWM_RX_RING_COUNT - 1 : hw - 1;
    IWM_WRITE(sc, IWM_FH_RSCSR_CHNL0_WPTR, hw & ~7);
}

int itlwm::
iwm_intr(OSObject *arg, IOInterruptEventSource* sender, int count)
{
    XYLog("Interrupt!!!\n");
    struct iwm_softc *sc = &com;
    int handled = 0;
    int r1, r2, rv = 0;
    int isperiodic = 0;
    
    IWM_WRITE(sc, IWM_CSR_INT_MASK, 0);
    
    if (sc->sc_flags & IWM_FLAG_USE_ICT) {
        uint32_t *ict = (uint32_t*)sc->ict_dma.vaddr;
        int tmp;
        
        tmp = htole32(ict[sc->ict_cur]);
        if (!tmp)
            goto out_ena;
        
        /*
         * ok, there was something.  keep plowing until we have all.
         */
        r1 = r2 = 0;
        while (tmp) {
            r1 |= tmp;
            ict[sc->ict_cur] = 0;
            sc->ict_cur = (sc->ict_cur+1) % IWM_ICT_COUNT;
            tmp = htole32(ict[sc->ict_cur]);
        }
        
        /* this is where the fun begins.  don't ask */
        if (r1 == 0xffffffff)
            r1 = 0;
        
        /* i am not expected to understand this */
        if (r1 & 0xc0000)
            r1 |= 0x8000;
        r1 = (0xff & r1) | ((0xff00 & r1) << 16);
    } else {
        r1 = IWM_READ(sc, IWM_CSR_INT);
        if (r1 == 0xffffffff || (r1 & 0xfffffff0) == 0xa5a5a5a0)
            goto out;
        r2 = IWM_READ(sc, IWM_CSR_FH_INT_STATUS);
    }
    if (r1 == 0 && r2 == 0) {
        goto out_ena;
    }
    
    IWM_WRITE(sc, IWM_CSR_INT, r1 | ~sc->sc_intmask);
    
    /* ignored */
    handled |= (r1 & (IWM_CSR_INT_BIT_ALIVE /*| IWM_CSR_INT_BIT_SCD*/));
    
    if (r1 & IWM_CSR_INT_BIT_RF_KILL) {
        handled |= IWM_CSR_INT_BIT_RF_KILL;
        iwm_check_rfkill(sc);
        //        task_add(systq, &sc->init_task);
        rv = 1;
        goto out_ena;
    }
    
    if (r1 & IWM_CSR_INT_BIT_SW_ERR) {
#ifdef IWM_DEBUG
        int i;
        
        iwm_nic_error(sc);
        
        /* Dump driver status (TX and RX rings) while we're here. */
        XYLog("driver status:\n");
        for (i = 0; i < IWM_MAX_QUEUES; i++) {
            struct iwm_tx_ring *ring = &sc->txq[i];
            XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                  "queued=%-3d\n",
                  i, ring->qid, ring->cur, ring->queued);
        }
        XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
        XYLog("  802.11 state %s\n",
              ieee80211_state_name[sc->sc_ic.ic_state]);
#endif
        
        XYLog("%s: fatal firmware error\n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
            //            task_add(systq, &sc->init_task);
        }
        rv = 1;
        goto out;
        
    }
    
    if (r1 & IWM_CSR_INT_BIT_HW_ERR) {
        handled |= IWM_CSR_INT_BIT_HW_ERR;
        XYLog("%s: hardware error, stopping device \n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
            sc->sc_flags |= IWM_FLAG_HW_ERR;
            //            task_add(systq, &sc->init_task);
        }
        rv = 1;
        goto out;
    }
    
    /* firmware chunk loaded */
    if (r1 & IWM_CSR_INT_BIT_FH_TX) {
        IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, IWM_CSR_FH_INT_TX_MASK);
        handled |= IWM_CSR_INT_BIT_FH_TX;
        
        sc->sc_fw_chunk_done = 1;
        wakeupOn(&sc->sc_fw);
    }
    
    if (r1 & IWM_CSR_INT_BIT_RX_PERIODIC) {
        handled |= IWM_CSR_INT_BIT_RX_PERIODIC;
        IWM_WRITE(sc, IWM_CSR_INT, IWM_CSR_INT_BIT_RX_PERIODIC);
        if ((r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX)) == 0)
            IWM_WRITE_1(sc,
                        IWM_CSR_INT_PERIODIC_REG, IWM_CSR_INT_PERIODIC_DIS);
        isperiodic = 1;
    }
    
    if ((r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX)) ||
        isperiodic) {
        handled |= (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX);
        IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, IWM_CSR_FH_INT_RX_MASK);
        
        iwm_notif_intr(sc);
        
        /* enable periodic interrupt, see above */
        if (r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX) &&
            !isperiodic)
            IWM_WRITE_1(sc, IWM_CSR_INT_PERIODIC_REG,
                        IWM_CSR_INT_PERIODIC_ENA);
    }
    
    rv = 1;
    
out_ena:
    iwm_restore_interrupts(sc);
out:
    return rv;
}

typedef void *iwm_match_t;

#define PCI_VENDOR_INTEL 0x8086
#define    PCI_PRODUCT_INTEL_WL_7260_1    0x08b1        /* Dual Band Wireless AC 7260 */
#define    PCI_PRODUCT_INTEL_WL_7260_2    0x08b2        /* Dual Band Wireless AC 7260 */
#define    PCI_PRODUCT_INTEL_WL_3160_1    0x08b3        /* Dual Band Wireless AC 3160 */
#define    PCI_PRODUCT_INTEL_WL_3160_2    0x08b4        /* Dual Band Wireless AC 3160 */
#define    PCI_PRODUCT_INTEL_WL_7265_1    0x095a        /* Dual Band Wireless AC 7265 */
#define    PCI_PRODUCT_INTEL_WL_7265_2    0x095b        /* Dual Band Wireless AC 7265 */
#define    PCI_PRODUCT_INTEL_WL_3165_1    0x3165        /* Dual Band Wireless AC 3165 */
#define    PCI_PRODUCT_INTEL_WL_3165_2    0x3166        /* Dual Band Wireless AC 3165 */
#define    PCI_PRODUCT_INTEL_WL_8260_1    0x24f3        /* Dual Band Wireless AC 8260 */
#define    PCI_PRODUCT_INTEL_WL_8260_2    0x24f4        /* Dual Band Wireless AC 8260 */
#define    PCI_PRODUCT_INTEL_WL_4165_1    0x24f5        /* Dual Band Wireless AC 4165 */
#define    PCI_PRODUCT_INTEL_WL_4165_2    0x24f6        /* Dual Band Wireless AC 4165 */
#define    PCI_PRODUCT_INTEL_WL_3168_1    0x24fb        /* Dual Band Wireless-AC 3168 */
#define    PCI_PRODUCT_INTEL_WL_8265_1    0x24fd        /* Dual Band Wireless-AC 8265 */

static const struct pci_matchid iwm_devices[] = {
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3160_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3160_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3165_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3165_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3168_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7260_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7260_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7265_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7265_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8260_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8260_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8265_1 },
};

int itlwm::
iwm_match(struct IOPCIDevice *device)
{
    XYLog("%s\n", __func__);
    int devId = device->configRead16(kIOPCIConfigDeviceID);
    return pci_matchbyid(PCI_VENDOR_INTEL, devId, iwm_devices,
                         nitems(iwm_devices));
}

int itlwm::
iwm_preinit(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ifnet *ifp = IC2IFP(ic);
    int err;
    static int attached;
    
    err = iwm_prepare_card_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    if (attached) {
        /* Update MAC in case the upper layers changed it. */
        IEEE80211_ADDR_COPY(sc->sc_ic.ic_myaddr,
                            ((struct arpcom *)ifp)->ac_enaddr);
        return 0;
    }
    
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwm_run_init_mvm_ucode(sc, 1);
    iwm_stop_device(sc);
    if (err)
        return err;
    
    /* Print version info and MAC address on first successful fw load. */
    attached = 1;
    XYLog("%s: hw rev 0x%x, fw ver %s, address %s\n",
          DEVNAME(sc), sc->sc_hw_rev & IWM_CSR_HW_REV_TYPE_MSK,
          sc->sc_fwver, ether_sprintf(sc->sc_nvm.hw_addr));
    
    if (sc->sc_nvm.sku_cap_11n_enable)
        iwm_setup_ht_rates(sc);
    
    /* not all hardware can do 5GHz band */
    if (!sc->sc_nvm.sku_cap_band_52GHz_enable)
        memset(&ic->ic_sup_rates[IEEE80211_MODE_11A], 0,
               sizeof(ic->ic_sup_rates[IEEE80211_MODE_11A]));
    
    /* Configure channel information obtained from firmware. */
    ieee80211_channel_init(ifp);
    
    /* Configure MAC address. */
    //    err = if_setlladdr(ifp, ic->ic_myaddr);
    //    if (err)
    //        XYLog("%s: could not set MAC address (error %d)\n",
    //            DEVNAME(sc), err);
    
    ieee80211_media_init(ifp);
    
    return 0;
}

void itlwm::
iwm_attach_hook(struct device *self)
{
    XYLog("%s\n", __func__);
    struct iwm_softc *sc = (struct iwm_softc *)self;
    
    _KASSERT(!cold);
    
    iwm_preinit(sc);
}

bool itlwm::
intrFilter(OSObject *object, IOFilterInterruptEventSource *src)
{
    XYLog("interrupt filter ran\n");
    return true;
}

bool itlwm::
iwm_attach(struct iwm_softc *sc, struct pci_attach_args *pa)
{
    XYLog("%s\n", __func__);
    pcireg_t reg, memtype;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ifnet *ifp = &ic->ic_if;
    const char *intrstr = {0};
    int err;
    int txq_i, i;
    
    sc->sc_pct = pa->pa_pc;
    sc->sc_pcitag = pa->pa_tag;
    sc->sc_dmat = pa->pa_dmat;
    
    //    rw_init(&sc->ioctl_rwl, "iwmioctl");
    
    err = pci_get_capability(sc->sc_pct, sc->sc_pcitag,
                             PCI_CAP_PCIEXPRESS, &sc->sc_cap_off, NULL);
    if (err == 0) {
        XYLog("%s: PCIe capability structure not found!\n",
              DEVNAME(sc));
        return false;
    }
    
    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);
    
    /* Enable bus-mastering and hardware bug workaround. */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, PCI_COMMAND_STATUS_REG);
    reg |= PCI_COMMAND_MASTER_ENABLE;
    /* if !MSI */
    if (reg & PCI_COMMAND_INTERRUPT_DISABLE) {
        reg &= ~PCI_COMMAND_INTERRUPT_DISABLE;
    }
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, PCI_COMMAND_STATUS_REG, reg);
    
    memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_MAPREG_START);
    err = pci_mapreg_map(pa, PCI_MAPREG_START, memtype, 0,
                         &sc->sc_st, &sc->sc_sh, NULL, &sc->sc_sz, 0);
    if (err) {
        XYLog("%s: can't map mem space\n", DEVNAME(sc));
        return false;
    }
    
    if (pci_intr_map_msi(pa, &sc->ih) && pci_intr_map(pa, &sc->ih)) {
        XYLog("%s: can't map interrupt\n", DEVNAME(sc));
        return false;
    }
    
    int msiIntrIndex = 0;
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
    
    sc->sc_ih =
    IOFilterInterruptEventSource::filterInterruptEventSource(this, OSMemberFunctionCast(IOInterruptEventSource::Action,this, &itlwm::iwm_intr), OSMemberFunctionCast(IOFilterInterruptAction, this, &itlwm::intrFilter)
                                                             ,pa->pa_tag, msiIntrIndex);
    if (sc->sc_ih == NULL || getWorkLoop()->addEventSource(sc->sc_ih) != kIOReturnSuccess) {
        XYLog("\n");
        XYLog("%s: can't establish interrupt", DEVNAME(sc));
        if (intrstr != NULL)
            XYLog(" at %s", intrstr);
        XYLog("\n");
        return false;
    }
    sc->sc_ih->enable();
    XYLog(", %s\n", intrstr);
    
    sc->sc_hw_rev = IWM_READ(sc, IWM_CSR_HW_REV);
    int pa_id = pa->pa_tag->configRead16(kIOPCIConfigDeviceID);
    switch (pa_id) {
        case PCI_PRODUCT_INTEL_WL_3160_1:
        case PCI_PRODUCT_INTEL_WL_3160_2:
            sc->sc_fwname = "iwlwifi-3160-16.ucode";
            sc->host_interrupt_operation_mode = 1;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            break;
        case PCI_PRODUCT_INTEL_WL_3165_1:
        case PCI_PRODUCT_INTEL_WL_3165_2:
            sc->sc_fwname = "iwlwifi-7265-16.ucode";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            break;
        case PCI_PRODUCT_INTEL_WL_3168_1:
            sc->sc_fwname = "iwlwifi-3168-27.ucode";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            break;
        case PCI_PRODUCT_INTEL_WL_7260_1:
        case PCI_PRODUCT_INTEL_WL_7260_2:
            sc->sc_fwname = "iwlwifi-7260-16.ucode";
            sc->host_interrupt_operation_mode = 1;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            break;
        case PCI_PRODUCT_INTEL_WL_7265_1:
        case PCI_PRODUCT_INTEL_WL_7265_2:
            sc->sc_fwname = "iwlwifi-7265-16.ucode";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            break;
        case PCI_PRODUCT_INTEL_WL_8260_1:
        case PCI_PRODUCT_INTEL_WL_8260_2:
            sc->sc_fwname = "iwlwifi-8000C-34.ucode";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_8000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            break;
        case PCI_PRODUCT_INTEL_WL_8265_1:
            sc->sc_fwname = "iwlwifi-8265-34.ucode";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_8000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            break;
        default:
            XYLog("%s: unknown adapter type\n", DEVNAME(sc));
            return false;
    }
    
    /*
     * In the 8000 HW family the format of the 4 bytes of CSR_HW_REV have
     * changed, and now the revision step also includes bit 0-1 (no more
     * "dash" value). To keep hw_rev backwards compatible - we'll store it
     * in the old format.
     */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000)
        sc->sc_hw_rev = (sc->sc_hw_rev & 0xfff0) |
        (IWM_CSR_HW_REV_STEP(sc->sc_hw_rev << 2) << 2);
    
    if (iwm_prepare_card_hw(sc) != 0) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return false;
    }
    
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000) {
        uint32_t hw_step;
        
        /*
         * In order to recognize C step the driver should read the
         * chip version id located at the AUX bus MISC address.
         */
        IWM_SETBITS(sc, IWM_CSR_GP_CNTRL,
                    IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
        DELAY(2);
        
        err = iwm_poll_bit(sc, IWM_CSR_GP_CNTRL,
                           IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                           IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                           25000);
        if (!err) {
            XYLog("%s: Failed to wake up the nic\n", DEVNAME(sc));
            return false;
        }
        
        if (iwm_nic_lock(sc)) {
            hw_step = iwm_read_prph(sc, IWM_WFPM_CTRL_REG);
            hw_step |= IWM_ENABLE_WFPM;
            iwm_write_prph(sc, IWM_WFPM_CTRL_REG, hw_step);
            hw_step = iwm_read_prph(sc, IWM_AUX_MISC_REG);
            hw_step = (hw_step >> IWM_HW_STEP_LOCATION_BITS) & 0xF;
            if (hw_step == 0x3)
                sc->sc_hw_rev = (sc->sc_hw_rev & 0xFFFFFFF3) |
                (IWM_SILICON_C_STEP << 2);
            iwm_nic_unlock(sc);
        } else {
            XYLog("%s: Failed to lock the nic\n", DEVNAME(sc));
            return false;
        }
    }
    
    XYLog("alloc contig\n");
    
    /*
     * Allocate DMA memory for firmware transfers.
     * Must be aligned on a 16-byte boundary.
     */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->fw_dma, NULL,
                               sc->sc_fwdmasegsz, 16);
    if (err) {
        XYLog("%s: could not allocate memory for firmware\n",
              DEVNAME(sc));
        return false;
    }
    
    /* Allocate "Keep Warm" page, used internally by the card. */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->kw_dma, NULL, 4096, 4096);
    if (err) {
        XYLog("%s: could not allocate keep warm page\n", DEVNAME(sc));
        goto fail1;
    }
    
    /* Allocate interrupt cause table (ICT).*/
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->ict_dma, NULL,
                               IWM_ICT_SIZE, 1<<IWM_ICT_PADDR_SHIFT);
    if (err) {
        XYLog("%s: could not allocate ICT table\n", DEVNAME(sc));
        goto fail2;
    }
    
    /* TX scheduler rings must be aligned on a 1KB boundary. */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->sched_dma, NULL,
                               nitems(sc->txq) * sizeof(struct iwm_agn_scd_bc_tbl), 1024);
    if (err) {
        XYLog("%s: could not allocate TX scheduler rings\n",
              DEVNAME(sc));
        goto fail3;
    }
    
    XYLog("allocate TX ring\n");
    
    for (txq_i = 0; txq_i < nitems(sc->txq); txq_i++) {
        err = iwm_alloc_tx_ring(sc, &sc->txq[txq_i], txq_i);
        if (err) {
            XYLog("%s: could not allocate TX ring %d\n",
                  DEVNAME(sc), txq_i);
            goto fail4;
        }
    }
    
    XYLog("iwm_alloc_rx_ring\n");
    
    err = iwm_alloc_rx_ring(sc, &sc->rxq);
    if (err) {
        XYLog("%s: could not allocate RX ring\n", DEVNAME(sc));
        goto fail4;
    }
    
    //    sc->sc_nswq = taskq_create("iwmns", 1, IPL_NET, 0);
    //    if (sc->sc_nswq == NULL)
    //        goto fail4;
    
    XYLog("config ieee80211\n");
    
    /* Clear pending interrupts. */
    IWM_WRITE(sc, IWM_CSR_INT, 0xffffffff);
    
    ic->ic_phytype = IEEE80211_T_OFDM;    /* not only, but not used */
    ic->ic_opmode = IEEE80211_M_STA;    /* default to BSS mode */
    ic->ic_state = IEEE80211_S_INIT;
    
    /* Set device capabilities. */
    ic->ic_caps =
    IEEE80211_C_WEP |        /* WEP */
    IEEE80211_C_RSN |        /* WPA/RSN */
    IEEE80211_C_SCANALL |    /* device scans all channels at once */
    IEEE80211_C_SCANALLBAND |    /* device scans all bands at once */
    IEEE80211_C_SHSLOT |    /* short slot time supported */
    IEEE80211_C_SHPREAMBLE;    /* short preamble supported */
    
    ic->ic_htcaps = IEEE80211_HTCAP_SGI20;
    ic->ic_htcaps |=
    (IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT);
    ic->ic_htxcaps = 0;
    ic->ic_txbfcaps = 0;
    ic->ic_aselcaps = 0;
    ic->ic_ampdu_params = (IEEE80211_AMPDU_PARAM_SS_4 | 0x3 /* 64k */);
    
    ic->ic_sup_rates[IEEE80211_MODE_11A] = ieee80211_std_rateset_11a;
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;
    
    for (i = 0; i < nitems(sc->sc_phyctxt); i++) {
        sc->sc_phyctxt[i].id = i;
    }
    
    sc->sc_amrr.amrr_min_success_threshold =  1;
    sc->sc_amrr.amrr_max_success_threshold = 15;
    
    /* IBSS channel undefined for now. */
    ic->ic_ibss_chan = &ic->ic_channels[1];
    
    ic->ic_max_rssi = IWM_MAX_DBM - IWM_MIN_DBM;
    
    ifp->if_softc = sc;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    //    ifp->if_ioctl = iwm_ioctl;
    ifp->if_start = OSMemberFunctionCast(StartAction, this, &itlwm::iwm_start);
    //    ifp->if_watchdog = iwm_watchdog;
    memcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);
    
    attachInterface((IONetworkInterface **)&ifp->iface);
    if (ifp->iface == NULL) {
        XYLog("attacht to interface fail\n");
        goto fail4;
    }
    ifp->output_queue = getOutputQueue();
    ieee80211_ifattach(ifp);
    ieee80211_media_init(ifp);
    
#if NBPFILTER > 0
    iwm_radiotap_attach(sc);
#endif
    timeout_set(&sc->sc_calib_to, OSMemberFunctionCast(TimeoutAction, this, &itlwm::iwm_calib_timeout), sc);
    timeout_set(&sc->sc_led_blink_to, OSMemberFunctionCast(TimeoutAction, this, &itlwm::iwm_led_blink_timeout), sc);
    //    task_set(&sc->init_task, iwm_init_task, sc);
    //    task_set(&sc->newstate_task, iwm_newstate_task, sc);
    //    task_set(&sc->ba_task, iwm_ba_task, sc);
    //    task_set(&sc->htprot_task, iwm_htprot_task, sc);
    
    ic->ic_node_alloc = OSMemberFunctionCast(NodeAllocAction, this, &itlwm::iwm_node_alloc);
    ic->ic_bgscan_start = OSMemberFunctionCast(BgScanAction, this, &itlwm::iwm_bgscan);
    
    /* Override 802.11 state transition machine. */
    sc->sc_newstate = ic->ic_newstate;
    ic->ic_newstate = OSMemberFunctionCast(NewStateAction, this, &itlwm::iwm_newstate);
    ic->ic_update_htprot = OSMemberFunctionCast(UpdateHtProtectAction, this, &itlwm::iwm_update_htprot);
    ic->ic_ampdu_rx_start = OSMemberFunctionCast(AmpduRxStartAction, this, &itlwm::iwm_ampdu_rx_start);
    ic->ic_ampdu_rx_stop = OSMemberFunctionCast(AmpduRxStopAction, this, &itlwm::iwm_ampdu_rx_stop);
#ifdef notyet
    ic->ic_ampdu_tx_start = iwm_ampdu_tx_start;
    ic->ic_ampdu_tx_stop = iwm_ampdu_tx_stop;
#endif
    /*
     * We cannot read the MAC address without loading the
     * firmware from disk. Postpone until mountroot is done.
     */
    //    config_mountroot(self, iwm_attach_hook);
    
    XYLog("attach succeed.\n");
    
    return true;
    
fail4:    while (--txq_i >= 0)
    iwm_free_tx_ring(sc, &sc->txq[txq_i]);
    iwm_free_rx_ring(sc, &sc->rxq);
    iwm_dma_contig_free(&sc->sched_dma);
fail3:    if (sc->ict_dma.vaddr != NULL)
    iwm_dma_contig_free(&sc->ict_dma);
    
fail2:    iwm_dma_contig_free(&sc->kw_dma);
fail1:    iwm_dma_contig_free(&sc->fw_dma);
    XYLog("attach failed.\n");
    return false;
}

#if NBPFILTER > 0
void itlwm::
iwm_radiotap_attach(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    bpfattach(&sc->sc_drvbpf, &sc->sc_ic.ic_if, DLT_IEEE802_11_RADIO,
              sizeof (struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN);
    
    sc->sc_rxtap_len = sizeof sc->sc_rxtapu;
    sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
    sc->sc_rxtap.wr_ihdr.it_present = htole32(IWM_RX_RADIOTAP_PRESENT);
    
    sc->sc_txtap_len = sizeof sc->sc_txtapu;
    sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
    sc->sc_txtap.wt_ihdr.it_present = htole32(IWM_TX_RADIOTAP_PRESENT);
}
#endif

void itlwm::
iwm_init_task(void *arg1)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg1;
    struct ifnet *ifp = &sc->sc_ic.ic_if;
    int s = splnet();
    int generation = sc->sc_generation;
    int fatal = (sc->sc_flags & (IWM_FLAG_HW_ERR | IWM_FLAG_RFKILL));
    
    //    rw_enter_write(&sc->ioctl_rwl);
    if (generation != sc->sc_generation) {
        //        rw_exit(&sc->ioctl_rwl);
        splx(s);
        return;
    }
    
    if (ifp->if_flags & IFF_RUNNING)
        iwm_stop(ifp);
    else
        sc->sc_flags &= ~IWM_FLAG_HW_ERR;
    
    if (!fatal && (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP)
        iwm_init(ifp);
    
    //    rw_exit(&sc->ioctl_rwl);
    splx(s);
}

int itlwm::
iwm_resume(struct iwm_softc *sc)
{
    pcireg_t reg;
    
    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);
    
    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);
    
    return iwm_prepare_card_hw(sc);
}

int itlwm::
iwm_activate(struct device *self, int act)
{
    //    struct iwm_softc *sc = (struct iwm_softc *)self;
    //    struct ifnet *ifp = &sc->sc_ic.ic_if;
    //    int err = 0;
    //
    //    switch (act) {
    //    case DVACT_QUIESCE:
    //        if (ifp->if_flags & IFF_RUNNING) {
    //            rw_enter_write(&sc->ioctl_rwl);
    //            iwm_stop(ifp);
    //            rw_exit(&sc->ioctl_rwl);
    //        }
    //        break;
    //    case DVACT_RESUME:
    //        err = iwm_resume(sc);
    //        if (err)
    //            XYLog("%s: could not initialize hardware\n",
    //                DEVNAME(sc));
    //        break;
    //    case DVACT_WAKEUP:
    //        /* Hardware should be up at this point. */
    //        if (iwm_set_hw_ready(sc))
    //            task_add(systq, &sc->init_task);
    //        break;
    //    }
    
    return 0;
}
