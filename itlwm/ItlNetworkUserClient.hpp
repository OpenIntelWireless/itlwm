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

#ifndef ItlNetworkUserClient_hpp
#define ItlNetworkUserClient_hpp

#include <IOKit/IOLib.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/network/IOEthernetInterface.h>
#include "itlwm.hpp"
#include <ClientKit/Common.h>

typedef IOReturn (*IOControlMethodAction)(OSObject * target, void *data, bool isSet);

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
    itlwm *fDriver;
    IOEthernetInterface *fInf;
    struct _ifnet *fIfp;
    ItlDriverController *fDriverController;
    ItlDriverInfo *fDriverInfo;
    
protected:
    bool fScanResultWrapping;
    ieee80211_node *fNextNodeToSend;
};


#endif /* ItlNetworkUserClient_hpp */
