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
    
    virtual ItlDriverInfo *getDriverInfo() = 0;
    
    virtual ItlDriverController *getDriverController() = 0;
    
    virtual void free() override;

public:
    virtual bool initWithController(IOEthernetController *controller, IOWorkLoop *workloop, IOCommandGate *commandGate);
    
protected:
    
    IOEthernetController *getController();
    
    IOCommandGate *getMainCommandGate();
    
    IOWorkLoop *getMainWorkLoop();
    
private:
    IOEthernetController *controller;
    IOCommandGate *mainCommandGate;
    IOWorkLoop *mainWorkLoop;
};

#endif /* ItlHalService_hpp */
