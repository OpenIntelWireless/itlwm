//
//  itlwm_interface.cpp
//  itlwm
//
//  Created by qcwap on 2020/5/27.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm_interface.hpp"

#define super IOEthernetInterface
OSDefineMetaClassAndStructors( itlwm_interface, IOEthernetInterface )

bool itlwm_interface::init(IONetworkController *controller)
{
    if (!super::init(controller))
        return false;
    IOLog("itlwm setting MTU to %d\n", ETHERNET_MTU);
    setMaxTransferUnit(ETHERNET_MTU);
    return true;
}

bool itlwm_interface::setMaxTransferUnit(UInt32 mtu) {
    if (mtu > ETHERNET_MTU) {
        return false;
    }
    super::setMaxTransferUnit(mtu);
    return true;
}

void itlwm_interface::free()
{
    super::free();
}

void itlwm_interface::updateMTU()
{
    setMaxTransferUnit(ETHERNET_MTU);
}
