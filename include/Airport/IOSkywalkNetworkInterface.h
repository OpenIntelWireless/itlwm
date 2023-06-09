//
//  IOSkywalkNetworkInterface.h
//  itlwm
//
//  Created by qcwap on 2023/6/7.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IOSkywalkNetworkInterface_h
#define IOSkywalkNetworkInterface_h

#include <net/if.h>

#include "IOSkywalkInterface.h"

typedef UInt if_link_status;
class IOSkywalkPacketQueue;
class IOSkywalkLogicalLink;
class IOSkywalkPacketBufferPool;

class IOSkywalkNetworkInterface : public IOSkywalkInterface {
    OSDeclareAbstractStructors( IOSkywalkNetworkInterface )
    
    struct RegistrationInfo;
    struct IOSkywalkTSOOptions;
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool init(OSDictionary *) APPLE_KEXT_OVERRIDE;
    virtual bool willTerminate( IOService * provider, IOOptionBits options ) APPLE_KEXT_OVERRIDE;
    virtual bool didTerminate( IOService * provider, IOOptionBits options, bool * defer ) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *) APPLE_KEXT_OVERRIDE;
    virtual bool handleOpen(    IOService *   forClient,
                            IOOptionBits      options,
                            void *        arg ) APPLE_KEXT_OVERRIDE;
    virtual void handleClose(   IOService *       forClient,
                             IOOptionBits      options ) APPLE_KEXT_OVERRIDE;
    virtual bool handleIsOpen(  const IOService * forClient ) const APPLE_KEXT_OVERRIDE;
    virtual void joinPMtree( IOService * driver ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setAggressiveness(
                                       unsigned long type,
                                       unsigned long newLevel ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable(UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn disable(UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn clientConnectWithTask(task_t,IOService *,UInt) APPLE_KEXT_OVERRIDE;
    virtual void clientDisconnect(IOService *,UInt) APPLE_KEXT_OVERRIDE;
    virtual bool isTerminating(void) APPLE_KEXT_OVERRIDE;
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
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *,sockaddr_dl **) = 0;
    virtual bool prepareBSDInterface(ifnet_t,UInt);
    virtual void finalizeBSDInterface(ifnet_t,UInt);
    virtual ifnet_t getBSDInterface(void);
    virtual void setBSDName(char const*);
    virtual const char *getBSDName(void);
    virtual IOReturn processBSDCommand(ifnet_t,UInt,void *);
    virtual IOReturn processInterfaceCommand(ifdrv *);
    virtual IOReturn interfaceAdvisoryEnable(bool);
    virtual SInt32 setInterfaceEnable(bool);
    virtual SInt32 setRunningState(bool);
    virtual IOReturn handleChosenMedia(UInt);
    virtual void *getSupportedMediaArray(UInt *,UInt *);
    virtual void *getPacketTapInfo(UInt *,UInt *);
    virtual UInt getUnsentDataByteCount(UInt *,UInt *,UInt);
    virtual UInt32 getSupportedWakeFlags(UInt *);
    virtual void enableNetworkWake(UInt);
    virtual void calculateRingSizeForQueue(IOSkywalkPacketQueue const*,UInt *);
    virtual UInt getMaxTransferUnit(void);
    virtual void setMaxTransferUnit(UInt);
    virtual UInt getMinPacketSize(void);
    virtual UInt getHardwareAssists(void);
    virtual void setHardwareAssists(UInt,UInt);
    virtual void *getInterfaceFamily(void);
    virtual void *getInterfaceSubFamily(void);
    virtual UInt getInitialMedia(void);
    virtual UInt getFeatureFlags(void);
    virtual UInt getTxDataOffset(void);
    virtual UInt captureInterfaceState(UInt);
    virtual void restoreInterfaceState(UInt);
    virtual void setMTU(UInt);
    virtual bool bpfTap(UInt,UInt);
    virtual const char *getBSDNamePrefix(void);
    virtual UInt getBSDUnitNumber(void);
    virtual const char *classNameOverride(void);
    virtual void deferBSDAttach(bool);
    virtual void reportDetailedLinkStatus(if_link_status const*);
    virtual IOReturn registerNetworkInterfaceWithLogicalLink(IOSkywalkNetworkInterface::RegistrationInfo const*,IOSkywalkLogicalLink *,IOSkywalkPacketBufferPool *,IOSkywalkPacketBufferPool *,UInt);
    virtual IOReturn deregisterLogicalLink(void);
    virtual UInt getTSOOptions(IOSkywalkNetworkInterface::IOSkywalkTSOOptions *);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  0);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  1);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  2);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  3);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  4);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  5);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  6);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  7);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  8);
    OSMetaClassDeclareReservedUnused( IOSkywalkNetworkInterface,  9);
    
public:
    uint8_t filter[0xD0];
};

#endif /* IOSkywalkNetworkInterface_h */
