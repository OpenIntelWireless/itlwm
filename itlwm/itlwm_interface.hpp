//
//  itlwm_interface.hpp
//  itlwm
//
//  Created by qcwap on 2020/5/27.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef itlwm_interface_hpp
#define itlwm_interface_hpp

#include <IOKit/network/IOEthernetInterface.h>

#define ETHERNET_MTU            1500

class itlwm_interface : public IOEthernetInterface {
    OSDeclareDefaultStructors( itlwm_interface )
    
public:
    virtual bool init( IONetworkController * controller ) APPLE_KEXT_OVERRIDE;
    
    void updateMTU();
    
protected:
    
    virtual void free() APPLE_KEXT_OVERRIDE;
    
    virtual bool setMaxTransferUnit(UInt32 mtu) APPLE_KEXT_OVERRIDE;
};

#endif /* itlwm_interface_hpp */
