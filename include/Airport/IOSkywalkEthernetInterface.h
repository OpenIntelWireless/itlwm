#ifndef IOSkywalkEthernetInterface_h
#define IOSkywalkEthernetInterface_h

#include "IOSkywalkNetworkInterface.h"

struct nicproxy_limits_info_s;
struct nicproxy_info_s;

class IOSkywalkEthernetInterface : public IOSkywalkNetworkInterface {
    OSDeclareAbstractStructors( IOSkywalkEthernetInterface )
    
public:
    struct RegistrationInfo {
        uint8_t pad[304];
    } __attribute__((packed));
    
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
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *,sockaddr_dl **) = 0;
    virtual bool prepareBSDInterface(ifnet_t,UInt) APPLE_KEXT_OVERRIDE;
    virtual void finalizeBSDInterface(ifnet_t,UInt) APPLE_KEXT_OVERRIDE;
    virtual ifnet_t getBSDInterface(void) APPLE_KEXT_OVERRIDE;
    virtual void setBSDName(char const*) APPLE_KEXT_OVERRIDE;
    virtual const char *getBSDName(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processBSDCommand(ifnet_t,UInt,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processInterfaceCommand(ifdrv *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn interfaceAdvisoryEnable(bool) APPLE_KEXT_OVERRIDE;
    virtual SInt32 setInterfaceEnable(bool) APPLE_KEXT_OVERRIDE;
    virtual SInt32 setRunningState(bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn handleChosenMedia(UInt) APPLE_KEXT_OVERRIDE;
    virtual void *getSupportedMediaArray(UInt *,UInt *) APPLE_KEXT_OVERRIDE;
    virtual void *getPacketTapInfo(UInt *,UInt *) APPLE_KEXT_OVERRIDE;
    virtual UInt getUnsentDataByteCount(UInt *,UInt *,UInt) APPLE_KEXT_OVERRIDE;
    virtual UInt32 getSupportedWakeFlags(UInt *) APPLE_KEXT_OVERRIDE;
    virtual void enableNetworkWake(UInt) APPLE_KEXT_OVERRIDE;
    virtual void calculateRingSizeForQueue(IOSkywalkPacketQueue const*,UInt *) APPLE_KEXT_OVERRIDE;
    virtual UInt getMaxTransferUnit(void) APPLE_KEXT_OVERRIDE;
    virtual void setMaxTransferUnit(UInt) APPLE_KEXT_OVERRIDE;
    virtual UInt getMinPacketSize(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getHardwareAssists(void) APPLE_KEXT_OVERRIDE;
    virtual void setHardwareAssists(UInt,UInt) APPLE_KEXT_OVERRIDE;
    virtual void *getInterfaceFamily(void) APPLE_KEXT_OVERRIDE;
    virtual void *getInterfaceSubFamily(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getInitialMedia(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getFeatureFlags(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getTxDataOffset(void) APPLE_KEXT_OVERRIDE;
    virtual UInt captureInterfaceState(UInt) APPLE_KEXT_OVERRIDE;
    virtual void restoreInterfaceState(UInt) APPLE_KEXT_OVERRIDE;
    virtual void setMTU(UInt) APPLE_KEXT_OVERRIDE;
    virtual bool bpfTap(UInt,UInt) APPLE_KEXT_OVERRIDE;
    virtual const char *getBSDNamePrefix(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getBSDUnitNumber(void) APPLE_KEXT_OVERRIDE;
    virtual const char *classNameOverride(void) APPLE_KEXT_OVERRIDE;
    virtual void deferBSDAttach(bool) APPLE_KEXT_OVERRIDE;
    virtual void reportDetailedLinkStatus(if_link_status const*) APPLE_KEXT_OVERRIDE;
    virtual IOReturn registerNetworkInterfaceWithLogicalLink(IOSkywalkNetworkInterface::RegistrationInfo const*,IOSkywalkLogicalLink *,IOSkywalkPacketBufferPool *,IOSkywalkPacketBufferPool *,UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn deregisterLogicalLink(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getTSOOptions(IOSkywalkNetworkInterface::IOSkywalkTSOOptions *) APPLE_KEXT_OVERRIDE;
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
    virtual IOReturn registerNetworkInterfaceWithLogicalLink(IOSkywalkEthernetInterface::RegistrationInfo const*, IOSkywalkLogicalLink*, IOSkywalkPacketBufferPool*, IOSkywalkPacketBufferPool*, UInt);
    virtual void getHardwareAddress(ether_addr *);
    virtual void setHardwareAddress(ether_addr *);
    virtual void setLinkLayerAddress(ether_addr *);
    virtual bool configureMulticastFilter(UInt,ether_addr const*,UInt);
    virtual bool setMulticastAddresses(ether_addr const*,UInt);
    virtual void setAllMulticastModeEnable(bool);
    virtual IOReturn setPromiscuousModeEnable(bool, UInt);
    virtual void reportNicProxyLimits(nicproxy_limits_info_s);
    virtual void hwConfigNicProxyData(nicproxy_info_s *);
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
    
public:
    bool initRegistrationInfo(IOSkywalkEthernetInterface::RegistrationInfo*, unsigned int, unsigned long);
    bool registerEthernetInterface(IOSkywalkEthernetInterface::RegistrationInfo const*, IOSkywalkPacketQueue**, unsigned int, IOSkywalkPacketBufferPool*, IOSkywalkPacketBufferPool*, unsigned int);
};

#endif /* IOSkywalkEthernetInterface_h */
