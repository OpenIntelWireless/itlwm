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

#include "itlwmx_interface.hpp"

#define super IOEthernetInterface
OSDefineMetaClassAndStructors( itlwmx_interface, IOEthernetInterface )

bool itlwmx_interface::init(IONetworkController *controller)
{
    if (!super::init(controller))
        return false;
    setMaxTransferUnit(1482);
    return true;
}

bool itlwmx_interface::setMaxTransferUnit(UInt32 mtu) {
    IOLog("itlwm setting MTU to %d\n", mtu);
    if (mtu > ETHERNET_MTU) {
        return false;
    }
    super::setMaxTransferUnit(mtu);
    return true;
}

void itlwmx_interface::free()
{
    super::free();
}
