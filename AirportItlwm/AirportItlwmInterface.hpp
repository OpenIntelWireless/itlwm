//
//  AirportItlwmInterface.hpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/7.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef AirportItlwmInterface_hpp
#define AirportItlwmInterface_hpp

#include "Airport/Apple80211.h"
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <sys/kernel_types.h>
#include <HAL/ItlHalService.hpp>

class AirportItlwmInterface : public IO80211Interface {
    OSDeclareDefaultStructors(AirportItlwmInterface)
    
public:
    virtual UInt32   inputPacket(
                                 mbuf_t          packet,
                                 UInt32          length  = 0,
                                 IOOptionBits    options = 0,
                                 void *          param   = 0 ) override;

    bool init(IO80211Controller *controller, ItlHalService *halService);

private:
    ItlHalService *fHalService;
};

#endif /* AirportItlwmInterface_hpp */
