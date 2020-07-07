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

#ifndef itlwmx_interface_hpp
#define itlwmx_interface_hpp

#include "itlwmx_interface.hpp"

#include <IOKit/network/IOEthernetInterface.h>

#define ETHERNET_MTU            1500

class itlwmx_interface : public IOEthernetInterface {
    OSDeclareDefaultStructors( itlwmx_interface )
    
public:
    virtual bool init( IONetworkController * controller ) APPLE_KEXT_OVERRIDE;
    
protected:
    
    virtual void free() APPLE_KEXT_OVERRIDE;
    
    virtual bool setMaxTransferUnit(UInt32 mtu) APPLE_KEXT_OVERRIDE;
};

#endif /* itlwmx_interface_hpp */
