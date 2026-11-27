//
//  IOPCIEDeviceWrapper.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOPCIEDeviceWrapper_hpp
#define IOPCIEDeviceWrapper_hpp

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>

#include <HAL/ItlHalService.hpp>

class IOPCIEDeviceWrapper : public IOService {
    OSDeclareDefaultStructors(IOPCIEDeviceWrapper)

public:
    virtual IOService* probe(IOService* provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual IOWorkLoop* getWorkLoop() const override;
    virtual IOReturn setPowerState(
        unsigned long powerStateOrdinal,
                                   IOService *   whatDevice ) override;
    virtual void free() override;

public:
    ItlHalService *fHalService;
    IOPCIDevice *pciNub;
    // The HAL for the next controller start: a new one if the last start shut the old one down (P-R02).
    ItlHalService *halForStart();
private:
    int halKind;    // 1 iwx, 2 iwm, 3 iwn
    static ItlHalService *newHal(int kind);
    // This wrapper holds the driver's one card (see probe).
    bool claimedCard;
};

#endif /* IOPCIEDeviceWrapper_hpp */
