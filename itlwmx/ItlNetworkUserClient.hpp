//
//  ItlNetworkUserClient.hpp
//  TestService
//
//  Created by 钟先耀 on 2020/4/14.
//  Copyright © 2020 lhy. All rights reserved.
//

/*
 * This program and the accompanying materials are licensed and made available
 * under the terms and conditions of the The 3-Clause BSD License
 * which accompanies this distribution. The full text of the license may be found at
 * https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef ItlNetworkUserClient_hpp
#define ItlNetworkUserClient_hpp

#include <IOKit/IOLib.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/network/IOEthernetInterface.h>
#include "itlwmx.hpp"
#include "Common.h"

typedef IOReturn (*IOControlMethodAction)(OSObject * target, void *data, bool isSet);
struct IOControlMethod {
    IOControlMethodAction function;
    
};

class ItlNetworkUserClient : public IOUserClient {
    
    OSDeclareDefaultStructors( ItlNetworkUserClient );
    
public:
    
    virtual bool start( IOService * provider ) override;
    virtual void stop( IOService * provider ) override;
    virtual bool initWithTask( task_t owningTask, void * securityID,
    UInt32 type,  OSDictionary * properties ) override;
    virtual IOReturn clientDied (void) override;
    virtual IOReturn clientClose( void ) override;
    virtual IOReturn externalMethod( uint32_t selector, IOExternalMethodArguments * arguments, IOExternalMethodDispatch * dispatch = 0, OSObject * target = 0, void * reference = 0 ) override;
    
private:
    static IOReturn sDRIVER_INFO(OSObject* target, void* data, bool isSet);
    static IOReturn sSTA_INFO(OSObject* target, void* data, bool isSet);
    static IOReturn sPOWER(OSObject* target, void* data, bool isSet);
    static IOReturn sSTATE(OSObject* target, void* data, bool isSet);
    static IOReturn sNW_ID(OSObject* target, void* data, bool isSet);
    static IOReturn sWPA_KEY(OSObject* target, void* data, bool isSet);
    static IOReturn sASSOCIATE(OSObject* target, void* data, bool isSet);
    static IOReturn sDISASSOCIATE(OSObject* target, void* data, bool isSet);
    static IOReturn sJOIN(OSObject* target, void* data, bool isSet);
    static IOReturn sSCAN(OSObject* target, void* data, bool isSet);
    static IOReturn sSCAN_RESULT(OSObject* target, void* data, bool isSet);
    static IOReturn sTX_POWER_LEVEL(OSObject* target, void* data, bool isSet);
    static const IOControlMethodAction sMethods[IOCTL_ID_MAX];
    
private:
    task_t fTask;
    itlwmx *fDriver;
    IOEthernetInterface *fInf;
    struct ifnet *fIfp;
    struct iwx_softc *fSoft;
    
protected:
    bool fScanResultWrapping;
    ieee80211_node *fNextNodeToSend;
};


#endif /* ItlNetworkUserClient_hpp */
