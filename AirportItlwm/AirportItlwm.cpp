/* add your code here */
#include "AirportItlwm.hpp"

#include "sha1.h"

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirportItlwm, IO80211Controller);
OSDefineMetaClassAndStructors(CTimeout, OSObject)

IO80211WorkLoop *_fWorkloop;
IOCommandGate *_fCommandGate;

bool AirportItlwm::init(OSDictionary *properties)
{
    super::init(properties);
    return true;
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

IOService* AirportItlwm::probe(IOService *provider, SInt32 *score)
{
    bool isMatch = false;
    super::probe(provider, score);
    UInt8 msiCap;
    UInt8 msixCap;
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return NULL;
    }
    if (ItlIwx::iwx_match(device)) {
        isMatch = true;
        fHalService = new ItlIwx;
    }
    if (!isMatch && ItlIwm::iwm_match(device)) {
        isMatch = true;
        fHalService = new ItlIwm;
    }
    if (isMatch) {
        device->findPCICapability(PCI_CAP_ID_MSI, &msiCap);
        if (msiCap) {
            pciMsiSetEnable(device, msiCap, 0);
        }
        device->findPCICapability(PCI_CAP_ID_MSIX, &msixCap);
        if (msixCap) {
            pciMsiXClearAndSet(device, msixCap, PCI_MSIX_FLAGS_ENABLE, 0);
        }
        if (!msiCap && !msixCap) {
            XYLog("%s No MSI cap\n", __FUNCTION__);
            fHalService->release();
            fHalService = NULL;
            return NULL;
        }
        return this;
    }
    return NULL;
}

bool AirportItlwm::configureInterface(IONetworkInterface *netif) {
    IONetworkData *nd;
    
    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }
    
    nd = netif->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    fHalService->get80211Controller()->ic_ac.ac_if.netStat = fpNetStats;
    fHalService->get80211Controller()->ic_ac.ac_if.iface = OSDynamicCast(IOEthernetInterface, netif);
    fpNetStats->collisions = 0;
    
    return true;
}

IONetworkInterface *AirportItlwm::createInterface()
{
    AirportItlwmInterface *netif = new AirportItlwmInterface;
    if (!netif) {
        return NULL;
    }
    if (!netif->init(this)) {
        netif->release();
        return NULL;
    }
    return netif;
}

bool AirportItlwm::addMediumType(UInt32 type, UInt32 speed,
                          UInt32 code, char *name)
{
    bool ret = false;
    
    IONetworkMedium *medium = IONetworkMedium::medium(type, speed, 0, code, name);
    if (medium) {
        ret = IONetworkMedium::addMedium(mediumDict, medium);
        if (ret) mediumTable[code] = medium;
        medium->release();
    }
    return ret;
}

ieee80211_wpaparams wpa;
ieee80211_wpapsk psk;
ieee80211_nwkey nwkey;
ieee80211_join join;
struct ieee80211_nwid nwid;

void AirportItlwm::associateSSID(const char *ssid, uint8_t *key, uint16_t keyLen)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (keyLen == 0) {
        memcpy(nwid.i_nwid, ssid, 32);
        nwid.i_len = strlen((char *)nwid.i_nwid);
        memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
        ic->ic_des_esslen = nwid.i_len;
        memcpy(ic->ic_des_essid, nwid.i_nwid, nwid.i_len);
        if (ic->ic_des_esslen > 0) {
            /* 'nwid' disables auto-join magic */
            ic->ic_flags &= ~IEEE80211_F_AUTO_JOIN;
        } else if (!TAILQ_EMPTY(&ic->ic_ess)) {
            /* '-nwid' re-enables auto-join */
            ic->ic_flags |= IEEE80211_F_AUTO_JOIN;
        }
        /* disable WPA/WEP */
        ieee80211_disable_rsn(ic);
        ieee80211_disable_wep(ic);
    } else {
        memset(&psk, 0, sizeof(psk));
        memcpy(nwid.i_nwid, ssid, 32);
        nwid.i_len = strlen((char *)nwid.i_nwid);
        memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
        ic->ic_des_esslen = nwid.i_len;
        memcpy(ic->ic_des_essid, nwid.i_nwid, nwid.i_len);
        if (ic->ic_des_esslen > 0) {
            /* 'nwid' disables auto-join magic */
            ic->ic_flags &= ~IEEE80211_F_AUTO_JOIN;
        } else if (!TAILQ_EMPTY(&ic->ic_ess)) {
            /* '-nwid' re-enables auto-join */
            ic->ic_flags |= IEEE80211_F_AUTO_JOIN;
        }
        /* disable WPA/WEP */
        ieee80211_disable_rsn(ic);
        ieee80211_disable_wep(ic);
        memcpy(psk.i_psk, key, keyLen);
        psk.i_enabled = 1;
        if (psk.i_enabled) {
            ic->ic_flags |= IEEE80211_F_PSK;
            memcpy(ic->ic_psk, psk.i_psk, sizeof(ic->ic_psk));
            if (ic->ic_flags & IEEE80211_F_WEPON)
                ieee80211_disable_wep(ic);
        } else {
            ic->ic_flags &= ~IEEE80211_F_PSK;
            memset(ic->ic_psk, 0, sizeof(ic->ic_psk));
        }
        memset(&wpa, 0, sizeof(wpa));
        ieee80211_ioctl_getwpaparms(ic, &wpa);
        wpa.i_enabled = psk.i_enabled;
        wpa.i_ciphers = 0;
        wpa.i_groupcipher = 0;
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
        wpa.i_akms = IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_PSK | IEEE80211_WPA_AKM_SHA256_8021X;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    ieee80211_del_ess(ic, NULL, 0, 1);
    struct ieee80211_node *selbs = ieee80211_node_choose_bss(ic, 0, NULL);
    if (selbs == NULL) {
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    } else {
        ieee80211_node_join_bss(ic, selbs, 1);
        fHalService->getDriverController()->clearScanningFlags();
    }
}

bool AirportItlwm::start(IOService *provider)
{
    if (!super::start(provider)) {
        return false;
    }
    if (!serviceMatching("AppleSMC")) {
        super::stop(provider);
        XYLog("No matching AppleSMC dictionary, failing\n");
        return false;
    }
    pciNub = OSDynamicCast(IOPCIDevice, provider);
    if (!pciNub) {
        super::stop(provider);
        return false;
    }
    pciNub->setBusMasterEnable(true);
    pciNub->setIOEnable(true);
    pciNub->setMemoryEnable(true);
    pciNub->configWrite8(0x41, 0);
    if (pciNub->requestPowerDomainState(kIOPMPowerOn,
                                        (IOPowerConnection *) getParentEntry(gIOPowerPlane), IOPMLowestState) != IOPMNoErr) {
        super::stop(provider);
        return false;
    }
    if (initPCIPowerManagment(pciNub) == false) {
        super::stop(pciNub);
        return false;
    }
    if (_fWorkloop == NULL) {
        XYLog("No _fWorkloop!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)AirportItlwm::tsleepHandler);
    if (_fCommandGate == 0) {
        XYLog("No command gate!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fWorkloop->addEventSource(_fCommandGate);
    mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
    if (!mediumDict) {
        XYLog("start fail, can not create mediumdict\n");
        releaseAll();
        return false;
    }
    addMediumType(kIOMediumIEEE80211None, 0, MEDIUM_TYPE_NONE);
    addMediumType(kIOMediumIEEE80211Auto, 0, MEDIUM_TYPE_AUTO);
    addMediumType(kIOMediumIEEE80211DS1, 1000000, MEDIUM_TYPE_1MBIT);
    addMediumType(kIOMediumIEEE80211DS2, 2000000, MEDIUM_TYPE_2MBIT);
    addMediumType(kIOMediumIEEE80211DS5, 5500000, MEDIUM_TYPE_5MBIT);
    addMediumType(kIOMediumIEEE80211DS11, 11000000, MEDIUM_TYPE_11MBIT);
    addMediumType(kIOMediumIEEE80211, 54000000, MEDIUM_TYPE_54MBIT, "OFDM54");
    if (!publishMediumDictionary(mediumDict)) {
        XYLog("start fail, can not publish mediumdict\n");
        releaseAll();
        return false;
    }
    
    if (!setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO])) {
        XYLog("Failed to set current medium!\n");
        releaseAll();
        return false;
    }
    
    if (!setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO])) {
        XYLog("start fail, can not set current medium\n");
        releaseAll();
        return false;
    }
    fHalService->initWithController(this, _fWorkloop, _fCommandGate);
    if (!fHalService->attach(pciNub)) {
        XYLog("attach fail\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    if (!attachInterface((IONetworkInterface **)&fNetIf, true)) {
        XYLog("attach to interface fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    fWatchdogWorkLoop = IOWorkLoop::workLoop();
    if (fWatchdogWorkLoop == NULL) {
        XYLog("init watchdog workloop fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &AirportItlwm::watchdogAction));
    if (!watchdogTimer) {
        XYLog("init watchdog fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    fWatchdogWorkLoop->addEventSource(watchdogTimer);
    scanSource = IOTimerEventSource::timerEventSource(this, &fakeScanDone);
    _fWorkloop->addEventSource(scanSource);
    scanSource->enable();
    setLinkStatus(kIONetworkLinkValid);
    if (TAILQ_EMPTY(&fHalService->get80211Controller()->ic_ess)) {
        fHalService->get80211Controller()->ic_flags |= IEEE80211_F_AUTO_JOIN;
    }
    registerService();
    fNetIf->registerService();
    return true;
}

void AirportItlwm::watchdogAction(IOTimerEventSource *timer)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    (*ifp->if_watchdog)(ifp);
    watchdogTimer->setTimeoutMS(1000);
}

void AirportItlwm::fakeScanDone(OSObject *owner, IOTimerEventSource *sender)
{
    AirportItlwm *that = (AirportItlwm *)owner;
    that->getNetworkInterface()->postMessage(APPLE80211_M_SCAN_DONE);
}

const OSString * AirportItlwm::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * AirportItlwm::newModelString() const
{
    return OSString::withCString("Intel Wireless Card");
}

bool AirportItlwm::initPCIPowerManagment(IOPCIDevice *provider)
{
    UInt16 reg16;

    reg16 = provider->configRead16(kIOPCIConfigCommand);

    reg16 |= ( kIOPCICommandBusMaster       |
               kIOPCICommandMemorySpace     |
               kIOPCICommandMemWrInvalidate );

    reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space

    provider->configWrite16( kIOPCIConfigCommand, reg16 );
    provider->findPCICapability(kIOPCIPowerManagementCapability,
                                &pmPCICapPtr);
    if (pmPCICapPtr) {
        UInt16 pciPMCReg = provider->configRead32( pmPCICapPtr ) >> 16;
        if (pciPMCReg & kPCIPMCPMESupportFromD3Cold) {
            magicPacketSupported = true;
        }
        provider->configWrite16((pmPCICapPtr + 4), 0x8000 );
        IOSleep(10);
    }
    return true;
}

bool AirportItlwm::createWorkLoop()
{
    _fWorkloop = IO80211WorkLoop::workLoop();
    return _fWorkloop != 0;
}

IOWorkLoop *AirportItlwm::getWorkLoop() const
{
    return _fWorkloop;
}

IOReturn AirportItlwm::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

void AirportItlwm::stop(IOService *provider)
{
    XYLog("%s\n", __FUNCTION__);
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    super::stop(provider);
    setLinkStatus(kIONetworkLinkValid);
    fHalService->detach(pciNub);
    detachInterface(fNetIf, true);
    OSSafeReleaseNULL(fNetIf);
    ifp->iface = NULL;
    releaseAll();
}

UInt64 currentSpeed;
UInt32 currentStatus;

bool AirportItlwm::
setLinkStatus(UInt32 status, const IONetworkMedium * activeMedium, UInt64 speed, OSData * data)
{
    if (status == currentStatus && activeMedium == getCurrentMedium() && speed == currentSpeed) {
        return true;
    }
    bool ret = super::setLinkStatus(status, activeMedium, speed, data);
    currentSpeed = speed;
    currentStatus = status;
    if (fNetIf) {
        if (status & kIONetworkLinkActive) {
            fNetIf->setLinkState(kIO80211NetworkLinkUp, 4);
            fNetIf->postMessage(APPLE80211_M_LINK_CHANGED);
        } else if (!(status & kIONetworkLinkNoNetworkChange)) {
            fNetIf->setLinkState(kIO80211NetworkLinkDown, 8);
            fNetIf->postMessage(APPLE80211_M_LINK_CHANGED);
        }
    }
    return ret;
}

void AirportItlwm::releaseAll()
{
    if (fHalService) {
        fHalService->release();
        fHalService = NULL;
    }
    if (_fWorkloop) {
        if (_fCommandGate) {
//            _fCommandGate->disable();
            _fWorkloop->removeEventSource(_fCommandGate);
            _fCommandGate->release();
            _fCommandGate = NULL;
        }
        if (scanSource) {
            scanSource->cancelTimeout();
            scanSource->disable();
            _fWorkloop->removeEventSource(scanSource);
            scanSource->release();
            scanSource = NULL;
        }
        if (fWatchdogWorkLoop && watchdogTimer) {
            watchdogTimer->cancelTimeout();
            fWatchdogWorkLoop->removeEventSource(watchdogTimer);
            watchdogTimer->release();
            watchdogTimer = NULL;
            fWatchdogWorkLoop->release();
            fWatchdogWorkLoop = NULL;
        }
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
    unregistPM();
}

void AirportItlwm::free()
{
    XYLog("%s\n", __FUNCTION__);
    if (fHalService != NULL) {
        fHalService->release();
        fHalService = NULL;
    }
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    super::free();
}

IOReturn AirportItlwm::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    super::enable(netif);
    _fCommandGate->enable();
    fHalService->enable(netif);
    watchdogTimer->setTimeoutMS(1000);
    watchdogTimer->enable();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    super::disable(netif);
    fHalService->disable(netif);
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
    setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::getHardwareAddress(IOEthernetAddress *addrP) {
    if (IEEE80211_ADDR_EQ(etheranyaddr, fHalService->get80211Controller()->ic_myaddr)) {
        return kIOReturnError;
    } else {
        IEEE80211_ADDR_COPY(addrP, fHalService->get80211Controller()->ic_myaddr);
        return kIOReturnSuccess;
    }
}

IOReturn AirportItlwm::getHardwareAddressForInterface(
                                               IO80211Interface *netif, IOEthernetAddress *addr)
{
    return getHardwareAddress(addr);
}

UInt32 AirportItlwm::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp == NULL || ifp->if_snd == NULL) {
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (m == NULL) {
        XYLog("%s m==NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
        XYLog("%s pkthdr is NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        XYLog("%s mbuf is FREE!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (ifp->if_snd->lockEnqueue(m)) {
        (*ifp->if_start)(ifp);
        return kIOReturnOutputSuccess;
    } else {
        freePacket(m);
        return kIOReturnOutputDropped;
    }
}

UInt32 AirportItlwm::getFeatures() const
{
    UInt32 features = (kIONetworkFeatureMultiPages);
    return features;
}

IOReturn AirportItlwm::setPromiscuousMode(IOEnetPromiscuousMode mode) {
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastMode(IOEnetMulticastMode mode) {
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastList(IOEthernetAddress* addr, UInt32 len) {
    return kIOReturnSuccess;
}

#ifndef Mojave
SInt32 AirportItlwm::monitorModeSetEnabled(
                                    IO80211Interface *interface, bool enabled, UInt32 dlt)
{
    return kIOReturnSuccess;
}
#endif

bool AirportItlwm::
useAppleRSNSupplicant(IO80211Interface *interface)
{
    return false;
}

IOReturn AirportItlwm::getPacketFilters(const OSSymbol *group, UInt32 *filters) const {
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup && magicPacketSupported) {
        *filters = kIOEthernetWakeOnMagicPacket;
    } else if (group == gIONetworkFilterGroup) {
        *filters = kIOPacketFilterUnicast | kIOPacketFilterBroadcast
        | kIOPacketFilterPromiscuous | kIOPacketFilterMulticast
        | kIOPacketFilterMulticastAll;
    } else {
        rtn = IOEthernetController::getPacketFilters(group, filters);
    }
    return rtn;
}

IOReturn AirportItlwm::getMaxPacketSize(UInt32 *maxSize) const {
    return super::getMaxPacketSize(maxSize);
}

IOReturn AirportItlwm::
tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    AirportItlwm* dev = OSDynamicCast(AirportItlwm, owner);
    if (dev == 0)
        return kIOReturnError;
    
    if (arg1 == 0) {
        if (_fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (_fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

void AirportItlwm::unregistPM()
{
    if (powerOffThreadCall) {
        thread_call_free(powerOffThreadCall);
        powerOffThreadCall = NULL;
    }
    if (powerOnThreadCall) {
        thread_call_free(powerOnThreadCall);
        powerOnThreadCall = NULL;
    }
}

IOReturn AirportItlwm::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;
    
    if (pmPowerState == powerStateOrdinal) {
        return result;
    }
    switch (powerStateOrdinal) {
        case kPowerStateOff:
            if (powerOffThreadCall) {
                retain();
                if (thread_call_enter(powerOffThreadCall)) {
                    release();
                }
                result = 5000000;
            }
            break;
        case kPowerStateOn:
            if (powerOnThreadCall) {
                retain();
                if (thread_call_enter(powerOnThreadCall)) {
                    release();
                }
                result = 5000000;
            }
            break;
            
        default:
            break;
    }
    return result;
}

IOReturn AirportItlwm::setWakeOnMagicPacket(bool active)
{
    magicPacketEnabled = active;
    return kIOReturnSuccess;
}

static void handleSetPowerStateOff(thread_call_param_t param0,
                             thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *)param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOff,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOff();
        self->release();
    }
}

static void handleSetPowerStateOn(thread_call_param_t param0,
                            thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *) param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOn,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOn();
        self->release();
    }
}

IOReturn AirportItlwm::registerWithPolicyMaker(IOService *policyMaker)
{
    IOReturn ret;
    
    pmPowerState = kPowerStateOn;
    pmPolicyMaker = policyMaker;
    
    powerOffThreadCall = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOff,
                                            (thread_call_param_t)this);
    powerOnThreadCall  = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOn,
                                              (thread_call_param_t)this);
    ret = pmPolicyMaker->registerPowerDriver(this,
                                             powerStateArray,
                                             kPowerStateCount);
    return ret;
}

void AirportItlwm::setPowerStateOff()
{
    pmPowerState = kPowerStateOff;
    pmPolicyMaker->acknowledgeSetPowerState();
}

void AirportItlwm::setPowerStateOn()
{
    pmPowerState = kPowerStateOn;
    pmPolicyMaker->acknowledgeSetPowerState();
}

int AirportItlwm::
outputRaw80211Packet(IO80211Interface *interface, mbuf_t m)
{
    XYLog("%s len=%d\n", __FUNCTION__, mbuf_len(m));
    freePacket(m);
    return kIOReturnOutputDropped;
}

int AirportItlwm::
outputActionFrame(IO80211Interface *interface, mbuf_t m)
{
    XYLog("%s len=%d\n", __FUNCTION__, mbuf_len(m));
    freePacket(m);
    return kIOReturnOutputDropped;
}

SInt32 AirportItlwm::
enableVirtualInterface(IO80211VirtualInterface *interface)
{
    XYLog("%s interface=%s role=%d", __FUNCTION__, interface->getBSDName(), interface->getInterfaceRole());
    SInt32 ret = super::enableVirtualInterface(interface);
    if (!ret) {
//        interface->startOutputQueues();
        return kIOReturnSuccess;
    }
    return ret;
}

SInt32 AirportItlwm::
disableVirtualInterface(IO80211VirtualInterface *interface)
{
    XYLog("%s interface=%s role=%d", __FUNCTION__, interface->getBSDName(), interface->getInterfaceRole());
    SInt32 ret = super::disableVirtualInterface(interface);
    if (!ret) {
//        interface->stopOutputQueues();
        return kIOReturnSuccess;
    }
    return ret;
}

IO80211VirtualInterface *AirportItlwm::
createVirtualInterface(ether_addr *ether, UInt role)
{
    if (role - 1 > 3) {
        return super::createVirtualInterface(ether, role);
    }
    IO80211VirtualInterface *inf = new IO80211VirtualInterface;
    if (inf) {
        if (inf->init(this, ether, role, role == 4 ? "awdl" : "p2p")) {
            XYLog("%s role=%d succeed\n", __FUNCTION__, role);
        } else {
            inf->release();
            return NULL;
        }
    }
    return inf;
}
