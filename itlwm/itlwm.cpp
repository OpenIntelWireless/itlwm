/* add your code here */
#include "itlwm.hpp"
#include "types.h"
#include "kernel.h"

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/ethernet.h>

#define super IOEthernetController
OSDefineMetaClassAndStructors(itlwm, IOEthernetController)
OSDefineMetaClassAndStructors(CTimeout, OSObject)

IOWorkLoop *_fWorkloop;
IOCommandGate *_fCommandGate;

#define MBit 1000000

static IOMediumType mediumTypeArray[MEDIUM_INDEX_COUNT] = {
    kIOMediumEthernetAuto,
    (kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE)
};

static UInt32 mediumSpeedArray[MEDIUM_INDEX_COUNT] = {
    0,
    10 * MBit,
    10 * MBit,
    100 * MBit,
    100 * MBit,
    100 * MBit,
    1000 * MBit,
    1000 * MBit,
    1000 * MBit,
    1000 * MBit,
    100 * MBit,
    100 * MBit
};

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
    super::probe(provider, score);
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return NULL;
    }
    return iwm_match(device) == 0?NULL:this;
}

bool itlwm::configureInterface(IONetworkInterface *netif) {
    IONetworkData *nd;
    
    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }
    
    nd = netif->getNetworkData(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    
    XYLog("fpNetStats: %p", fpNetStats);
    
    return true;
}

bool itlwm::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;
    
    OSDictionary *mediumDict = OSDictionary::withCapacity(1);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }
    
    medium = IONetworkMedium::medium(kIOMediumEthernetAuto, 480 * 1000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();  // 'mediumDict' holds a ref now.
    if (primary) {
        *primary = medium;
    }
    
    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }

    // Per comment for 'publishMediumDictionary' in NetworkController.h, the
    // medium dictionary is copied and may be safely relseased after the call.
    mediumDict->release();
    return result;
}

bool itlwm::start(IOService *provider)
{
    ifnet *ifp;
    
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
    _fWorkloop = fWorkloop;
    fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)tsleepHandler);
    _fCommandGate = fCommandGate;
    if (fCommandGate == 0) {
        XYLog("No command gate!!\n");
        return false;
    }
    fCommandGate->retain();
    fWorkloop->addEventSource(fCommandGate);
//    const IONetworkMedium *primaryMedium;
//    if (!createMediumTables(&primaryMedium) ||
//        !setCurrentMedium(primaryMedium)) {
//        return false;
//    }
    IONetworkMedium *medium;
    OSDictionary *mediumDict = OSDictionary::withCapacity(MEDIUM_INDEX_COUNT + 1);
    if (!mediumDict) {
        XYLog("start fail, can not create mediumdict\n");
        return false;
    }
    bool result;
    for (int i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++) {
        medium = IONetworkMedium::medium(mediumTypeArray[i], mediumSpeedArray[i], 0, i);
        if (!medium) {
            XYLog("start fail, can not create mediumdict\n");
            return false;
        }
        result = IONetworkMedium::addMedium(mediumDict, medium);
        medium->release();
        if (!result) {
            XYLog("start fail, can not addMedium\n");
            return false;
        }
        mediumTable[i] = medium;
        if (i == kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE) {
            autoMedium = medium;
        }
    }
    if (!publishMediumDictionary(mediumDict)) {
        XYLog("start fail, can not publish mediumdict\n");
        return false;
    }
    if (!setCurrentMedium(autoMedium)){
        XYLog("start fail, can not set current medium\n");
        return false;
    }
    if (!setSelectedMedium(autoMedium)){
        XYLog("start fail, can not set current medium\n");
        return false;
    }
    pci.workloop = _fWorkloop;
    pci.pa_tag = device;
    if (!iwm_attach(&com, &pci)) {
        return false;
    }
    ifp = &com.sc_ic.ic_ac.ac_if;
    iwm_init(ifp);
    if (!attachInterface((IONetworkInterface **)&com.sc_ic.ic_ac.ac_if.iface)) {
        XYLog("attach to interface fail\n");
        return false;
    }
    setLinkStatus(kIONetworkLinkValid);
    registerService();
    return true;
}

IOReturn itlwm::getPacketFilters(const OSSymbol *group, UInt32 *filters) const {
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup) {
        *filters = 0;
    } else {
        rtn = super::getPacketFilters(group, filters);
    }

    return rtn;
}

IOReturn itlwm::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

void itlwm::stop(IOService *provider)
{
    XYLog("%s\n", __func__);
    taskq_destroy(systq);
    taskq_destroy(systqmp);
    taskq_destroy(com.sc_nswq);
    iwm_stop(&com.sc_ic.ic_ac.ac_if);
    ieee80211_ifdetach(&com.sc_ic.ic_ac.ac_if);
    if (fWorkloop) {
        if (com.sc_ih) {
            fWorkloop->removeEventSource(com.sc_ih);
            OSSafeReleaseNULL(com.sc_ih);
        }
        fWorkloop->release();
        fWorkloop = NULL;
    }
    OSSafeReleaseNULL(com.ih);
    OSSafeReleaseNULL(fCommandGate);
    super::stop(provider);
}

void itlwm::free()
{
    XYLog("%s\n", __func__);
    IOLockFree(fwLoadLock);
    fwLoadLock = NULL;
    if (fWorkloop) {
        if (com.sc_ih) {
            fWorkloop->removeEventSource(com.sc_ih);
            OSSafeReleaseNULL(com.sc_ih);
        }
        fWorkloop->release();
        fWorkloop = NULL;
    }
    OSSafeReleaseNULL(com.ih);
    OSSafeReleaseNULL(fCommandGate);
    super::free();
}

IOReturn itlwm::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __func__);
    super::enable(netif);
    setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, getCurrentMedium());
    return kIOReturnSuccess;
}

IOReturn itlwm::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __func__);
    return super::disable(netif);
}

IOReturn itlwm::getHardwareAddress(IOEthernetAddress *addrP) {
    XYLog("%s\n", __func__);
    if (IEEE80211_ADDR_EQ(etheranyaddr, com.sc_ic.ic_myaddr)) {
        return kIOReturnError;
    } else {
        IEEE80211_ADDR_COPY(addrP, com.sc_ic.ic_myaddr);
        return kIOReturnSuccess;
    }
}

UInt32 itlwm::outputPacket(mbuf_t m, void *param)
{
    XYLog("%s\n", __func__);
    ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    
    ifp->if_snd->enqueue(m);
    ifp->if_start(ifp);
    
    return kIOReturnOutputSuccess;
}

UInt32 itlwm::getFeatures() const
{
    UInt32 features = (kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan);
    features |= kIONetworkFeatureTSOIPv4;
    features |= kIONetworkFeatureTSOIPv6;
    return features;
}

IOReturn itlwm::setPromiscuousMode(IOEnetPromiscuousMode mode) {
    return kIOReturnSuccess;
}

IOReturn itlwm::setMulticastMode(IOEnetMulticastMode mode) {
    return kIOReturnSuccess;
}

IOReturn itlwm::setMulticastList(IOEthernetAddress* addr, UInt32 len) {
    return kIOReturnSuccess;
}
