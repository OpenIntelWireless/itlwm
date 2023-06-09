#ifndef IOSkywalkEthernetInterface_h
#define IOSkywalkEthernetInterface_h

#include "IOSkywalkNetworkInterface.h"

class IOSkywalkEthernetInterface : public IOSkywalkNetworkInterface {
    OSDeclareAbstractStructors( IOSkywalkEthernetInterface )
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool init(OSDictionary *) APPLE_KEXT_OVERRIDE;
    virtual bool willTerminate( IOService * provider, IOOptionBits options ) APPLE_KEXT_OVERRIDE;
    virtual bool didTerminate( IOService * provider, IOOptionBits options, bool * defer ) APPLE_KEXT_OVERRIDE;
    virtual void stop( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual bool handleOpen(    IOService *   forClient,
                            IOOptionBits      options,
                            void *        arg ) APPLE_KEXT_OVERRIDE;
    virtual void handleClose(   IOService *       forClient,
                             IOOptionBits      options ) APPLE_KEXT_OVERRIDE;
    virtual bool handleIsOpen(  const IOService * forClient ) const APPLE_KEXT_OVERRIDE;
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
                                   UInt32 type, OSDictionary * properties,
                                   LIBKERN_RETURNS_RETAINED IOUserClient ** handler ) APPLE_KEXT_OVERRIDE;
    virtual void joinPMtree( IOService * driver ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setAggressiveness(
                                       unsigned long type,
                                       unsigned long newLevel ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setPowerState(
                                   unsigned long powerStateOrdinal,
                                   IOService *   whatDevice ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable(UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn disable(UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn clientConnectWithTask(task_t,IOService *,UInt) APPLE_KEXT_OVERRIDE;
    virtual void clientDisconnect(IOService *,UInt) APPLE_KEXT_OVERRIDE;
    virtual bool isTerminating(void) APPLE_KEXT_OVERRIDE;
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  0 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  1 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  2 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  3 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  4 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  5 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  6 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  7 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  8 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface,  9 );
    OSMetaClassDeclareReservedUnused( IOSkywalkEthernetInterface, 10 );
};

#endif /* IOSkywalkEthernetInterface_h */
