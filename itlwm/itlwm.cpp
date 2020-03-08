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

enum
{
    MEDIUM_INDEX_AUTO = 0,
    MEDIUM_INDEX_10HD,
    MEDIUM_INDEX_10FD,
    MEDIUM_INDEX_100HD,
    MEDIUM_INDEX_100FD,
    MEDIUM_INDEX_100FDFC,
    MEDIUM_INDEX_1000FD,
    MEDIUM_INDEX_1000FDFC,
    MEDIUM_INDEX_1000FDEEE,
    MEDIUM_INDEX_1000FDFCEEE,
    MEDIUM_INDEX_100FDEEE,
    MEDIUM_INDEX_100FDFCEEE,
    MEDIUM_INDEX_COUNT
};

IONetworkMedium *mediumTable[MEDIUM_INDEX_COUNT];

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
    if (fCommandGate == 0) {
        XYLog("No command gate!!\n");
        return false;
    }
    fCommandGate->retain();
    fWorkloop->addEventSource(fCommandGate);
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
        if (i == MEDIUM_INDEX_AUTO) {
            autoMedium = medium;
        }
    }
    if (!publishMediumDictionary(mediumDict)) {
        XYLog("start fail, can not publish mediumdict\n");
        return false;
    }
//    if (!setCurrentMedium(autoMedium)){
//        XYLog("start fail, can not set current medium\n");
//        return false;
//    }
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
    registerService();
    return true;
}

void itlwm::stop(IOService *provider)
{
    XYLog("%s\n", __func__);
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

IOReturn itlwm::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
    XYLog("%s\n", __func__);
    return kIOReturnSuccess;
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
    setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive, mediumTable[MEDIUM_INDEX_1000FDFCEEE]);
    return super::enable(netif);
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
    struct iwm_softc *sc = &com;
    
    ifp->if_snd->lockEnqueue(m);
    ifp->if_start(ifp);
    
    return kIOReturnOutputSuccess;
}
