//
//  Athn.hpp
//  itlwm
//
//  Created by qcwap on 2022/8/11.
//  Copyright © 2022 钟先耀. All rights reserved.
//

#ifndef Athn_hpp
#define Athn_hpp

#include <compat.h>
#include "athnhdr.h"
#include <linux/kernel.h>

#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include <HAL/ItlHalService.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>

class Athn : public ItlHalService, ItlDriverInfo, ItlDriverController {
    OSDeclareDefaultStructors(Athn)
    
public:
    //kext
    void free() override;
    virtual bool attach(IOPCIDevice *device) override;
    virtual void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    virtual struct ieee80211com *get80211Controller() override;
    
    static bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    static IOReturn _iwm_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    void releaseAll();
    
    struct _ifnet *getIfp();
    struct iwm_softc *getSoft();
    IOEthernetInterface *getNetworkInterface();
    
    virtual ItlDriverInfo *getDriverInfo() override;
    
    virtual ItlDriverController *getDriverController() override;
    
    //driver info
    virtual const char *getFirmwareVersion() override;
    
    virtual int16_t getBSSNoise() override;
    
    virtual bool is5GBandSupport() override;
    
    virtual int getTxNSS() override;
    
    virtual const char *getFirmwareName() override;
    
    virtual UInt32 supportedFeatures() override;

    virtual const char *getFirmwareCountryCode() override;

    virtual uint32_t getTxQueueSize() override;
    
    //driver controller
    virtual void clearScanningFlags() override;
    
    virtual IOReturn setMulticastList(IOEthernetAddress *addr, int count) override;
    
private:
    bool athn_pci_attach(struct device *parent, struct device *self, void *aux);
    
public:
    IOInterruptEventSource* fInterrupt;
    IOPCIDevice *pciNub;
    struct pci_attach_args pci;
    struct athn_pci_softc com;
};

#endif /* Athn_hpp */
