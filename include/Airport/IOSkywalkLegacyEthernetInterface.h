//
//  IOSkywalkLegacyEthernetInterface.h
//  itlwm
//
//  Created by qcwap on 2023/6/19.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOSkywalkLegacyEthernetInterface_h
#define IOSkywalkLegacyEthernetInterface_h

#include <IOKit/IOService.h>
#include <IOKit/network/IOEthernetInterface.h>

class IOSkywalkLegacyEthernetInterface : public IOEthernetInterface {
    OSDeclareDefaultStructors(IOSkywalkLegacyEthernetInterface)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual OSObject * getProperty( const OSSymbol * aKey) const APPLE_KEXT_OVERRIDE;
    virtual OSObject * copyProperty( const OSSymbol * aKey) const APPLE_KEXT_OVERRIDE;
    virtual bool serializeProperties( OSSerialize * serialize ) const APPLE_KEXT_OVERRIDE;
    virtual IOReturn setProperties( OSObject * properties ) APPLE_KEXT_OVERRIDE;
    virtual bool init( IONetworkController * controller ) APPLE_KEXT_OVERRIDE;
    virtual const char * getNamePrefix() const APPLE_KEXT_OVERRIDE;
    virtual bool controllerDidOpen(IONetworkController * controller) APPLE_KEXT_OVERRIDE;
    virtual void controllerWillClose(IONetworkController * controller) APPLE_KEXT_OVERRIDE;
    virtual ifnet_t  getIfnet( void ) const APPLE_KEXT_OVERRIDE;
    virtual IOReturn attachToDataLinkLayer( IOOptionBits options, void *       parameter ) APPLE_KEXT_OVERRIDE;
    virtual void     detachFromDataLinkLayer( IOOptionBits options,
                                             void *       parameter ) APPLE_KEXT_OVERRIDE;
    
public:
    uint8_t filter[0x160];
};

#endif /* IOSkywalkLegacyEthernetInterface_h */

