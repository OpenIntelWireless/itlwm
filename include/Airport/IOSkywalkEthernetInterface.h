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
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
                                   UInt32 type, OSDictionary * properties,
                                   LIBKERN_RETURNS_RETAINED IOUserClient ** handler ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setPowerState(
                                   unsigned long powerStateOrdinal,
                                   IOService *   whatDevice ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable(UInt) APPLE_KEXT_OVERRIDE;
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *,sockaddr_dl **) APPLE_KEXT_OVERRIDE;
    virtual bool prepareBSDInterface(ifnet_t,UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processBSDCommand(ifnet_t,UInt,void *) APPLE_KEXT_OVERRIDE;
    virtual void *getPacketTapInfo(UInt *,UInt *) APPLE_KEXT_OVERRIDE;
    virtual void enableNetworkWake(UInt) APPLE_KEXT_OVERRIDE;
    virtual UInt getMaxTransferUnit(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getMinPacketSize(void) APPLE_KEXT_OVERRIDE;
    virtual void *getInterfaceFamily(void) APPLE_KEXT_OVERRIDE;
    virtual void *getInterfaceSubFamily(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getInitialMedia(void) APPLE_KEXT_OVERRIDE;
    virtual const char *getBSDNamePrefix(void) APPLE_KEXT_OVERRIDE;
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
    
public:
    void *vptr;
    uint8_t pad1[0x30];
    struct ExpansionData
    {
        RegistrationInfo *fRegistrationInfo;
        ifnet_t fBSDInterface;
    };
    ExpansionData *mExpansionData2;
};

static_assert(__offsetof(IOSkywalkEthernetInterface, mExpansionData2) == 0x108, "Invalid class size");

static_assert(sizeof(IOSkywalkEthernetInterface) == 0x110, "Invalid class size");

#endif /* IOSkywalkEthernetInterface_h */
