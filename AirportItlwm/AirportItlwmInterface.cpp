//
//  AirportItlwmInterface.cpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/7.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "AirportItlwmInterface.hpp"

#define super IO80211Interface
OSDefineMetaClassAndStructors(AirportItlwmInterface, IO80211Interface);

UInt32 AirportItlwmInterface::
inputPacket(mbuf_t packet, UInt32 length, IOOptionBits options, void *param)
{
    return IOEthernetInterface::inputPacket(packet, length, options, param);
}
