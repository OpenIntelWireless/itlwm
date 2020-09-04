//
//  AirportSTAIOCTL.cpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "AirportItlwm.hpp"

SInt32 AirportItlwm::apple80211Request(unsigned int request_type,
                                       int request_number,
                                       IO80211Interface *interface,
                                       void *data)
{
    IOReturn ret = kIOReturnSuccess;
    bool isGet = (request_type == SIOCGA80211);
    
    return ret;
}
