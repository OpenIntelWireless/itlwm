//
//  ItlIwm.cpp
//  itlwm
//
//  Created by zhongxianyao on 2020/8/29.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "ItlIwm.hpp"

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlIwm, ItlHalService)

void ItlIwm::
watchdogAction(IOTimerEventSource *timer)
{
    iwm_watchdog(&com.sc_ic.ic_ac.ac_if);
    timer->setTimeoutMS(1000);
}

void ItlIwm::
detach(IOPCIDevice *device)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    ieee80211_ifdetach(ifp);
    taskq_destroy(systq);
    taskq_destroy(com.sc_nswq);
    releaseAll();
}

bool ItlIwm::
attach(IOPCIDevice *device)
{
    pci.pa_tag = device;
    pci.workloop = getMainWorkLoop();
    if (!iwm_attach(&com, &pci)) {
        detach(device);
        releaseAll();
        return false;
    }
    return true;
}

void ItlIwm::
free()
{
    pci.pa_tag = NULL;
    pci.workloop = NULL;
    super::free();
}

void ItlIwm::
releaseAll()
{
    XYLog("%s\n", __FUNCTION__);
    pci_intr_handle *intrHandler = com.ih;
    if (com.sc_calib_to) {
        timeout_del(&com.sc_calib_to);
        timeout_free(&com.sc_calib_to);
    }
    if (com.sc_led_blink_to) {
        timeout_del(&com.sc_led_blink_to);
        timeout_free(&com.sc_led_blink_to);
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
}

IOReturn ItlIwm::
enable(IONetworkInterface *netif)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    ifp->if_flags |= IFF_UP;
    iwm_activate(&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn ItlIwm::
disable(IONetworkInterface *netif)
{
    iwm_activate(&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

struct ieee80211com *ItlIwm::
get80211Controller()
{
    return &com.sc_ic;
}

ItlDriverInfo *ItlIwm::
getDriverInfo()
{
    return this;
}

ItlDriverController *ItlIwm::
getDriverController()
{
    return this;
}

void ItlIwm::
clearScanningFlags()
{
    com.sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
}

char *ItlIwm::
getFirmwareVersion()
{
    return com.sc_fwver;
}

int16_t ItlIwm::
getBSSNoise()
{
    return com.sc_noise;;
}
