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

#ifndef ItlHalService_hpp
#define ItlHalService_hpp

#include <libkern/c++/OSObject.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#ifdef AIRPORT_VTD
#include <ItlDma.hpp>
#endif

#include "ItlDriverInfo.hpp"
#include "ItlDriverController.hpp"

#include <net80211/ieee80211_var.h>

class ItlHalService : public OSObject {
    OSDeclareAbstractStructors(ItlHalService)

public:

    virtual bool attach(IOPCIDevice *device) = 0;

    virtual void detach(IOPCIDevice *device) = 0;

    virtual IOReturn enable(IONetworkInterface *interface) = 0;

    virtual IOReturn disable(IONetworkInterface *interface) = 0;

    virtual struct ieee80211com *get80211Controller() = 0;
#ifdef AIRPORT_WCL
    virtual IOReturn setScanHomeAwayTime(uint32_t) { return kIOReturnUnsupported; }
#endif

    virtual ItlDriverInfo *getDriverInfo() = 0;

    virtual ItlDriverController *getDriverController() = 0;

    virtual void free() override;

public:
    virtual bool initWithController(IOEthernetController *controller, IOWorkLoop *workloop, IOCommandGate *commandGate);

    // Drops what initWithController took (the controller, work loop and gate references, the sleep lock)
    // and, with VT-d, the DMA arena. Called by the controller's releaseAll(), after detach(), so the HAL
    // no longer keeps a stopped controller alive through a reference cycle, and from free(). A shut-down
    // HAL is never started again: the PCI wrapper makes a new one (audit P-R02).
    void shutdown();
    bool isShutDown() const { return shutDown; }

protected:

    int tsleep_nsec(void *ident, int priority, const char *wmesg, int timo);

    void wakeupOn(void* ident);

    IOEthernetController *getController();

    IOCommandGate *getMainCommandGate();

    IOWorkLoop *getMainWorkLoop();

#ifdef AIRPORT_VTD
    bool prepareDma(IOPCIDevice *device, uint8_t addressBits);
    ItlDmaArena *dmaArena;
#endif
    // In every build: detach sets dmaDetaching under the gate before anything is freed, and the transmit
    // and command paths refuse while it is set. These were VT-d only, so the Sonoma kext had no such
    // guard (audit HL01). Zero from OSObject allocation.
    uint64_t dmaEpoch;
    bool dmaDetaching;

private:
    IOEthernetController *controller;
    IOCommandGate *mainCommandGate;
    IOWorkLoop *mainWorkLoop;

    lck_grp_t *inner_gp;
    lck_grp_attr_t *inner_gp_attr;
    lck_attr_t *inner_attr;
    lck_mtx_t *inner_lock;
    bool shutDown;
};

#endif /* ItlHalService_hpp */
