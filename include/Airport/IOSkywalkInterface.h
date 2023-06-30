//
//  IOSkywalkInterface.h
//  itlwm
//
//  Created by qcwap on 2023/6/7.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOSkywalkInterface_h
#define IOSkywalkInterface_h


class IOSkywalkInterface : public IOService {
    OSDeclareAbstractStructors(IOSkywalkInterface)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool init(OSDictionary *) APPLE_KEXT_OVERRIDE;
    virtual bool willTerminate( IOService * provider, IOOptionBits options ) APPLE_KEXT_OVERRIDE;
    virtual bool didTerminate( IOService * provider, IOOptionBits options, bool * defer ) APPLE_KEXT_OVERRIDE;
    virtual bool handleOpen(    IOService *   forClient,
                            IOOptionBits      options,
                            void *        arg ) APPLE_KEXT_OVERRIDE;
    virtual void handleClose(   IOService *       forClient,
                             IOOptionBits      options ) APPLE_KEXT_OVERRIDE;
    virtual bool handleIsOpen(  const IOService * forClient ) const APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable( IOOptionBits options ) = 0;
    virtual IOReturn disable( IOOptionBits options ) = 0;
    virtual IOReturn clientConnectWithTask( task_t task, IOService * forClient, IOOptionBits options );
    virtual void clientDisconnect( IOService * forClient, IOOptionBits options );
    virtual bool isTerminating(void);
    
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  0 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  1 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  2 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  3 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  4 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  5 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  6 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  7 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  8 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface,  9 );
    OSMetaClassDeclareReservedUnused( IOSkywalkInterface, 10 );
    
public:
    uint8_t filter[0xB0 - 136];
};

static_assert(sizeof(IOSkywalkInterface) == 0xB0, "Invalid class size");

#endif /* IOSkywalkInterface_h */
