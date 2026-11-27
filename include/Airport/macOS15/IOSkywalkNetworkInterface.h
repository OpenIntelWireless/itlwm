//
//  IOSkywalkNetworkInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef IOSkywalkNetworkInterface_h
#define IOSkywalkNetworkInterface_h

#include <net/if.h>

#include "IOSkywalkInterface.h"

struct if_link_status;
class IOSkywalkPacketQueue;
class IOSkywalkLogicalLink;
class IOSkywalkPacketBufferPool;

class IO80211Controller;
class CCLogStream;

class IOSkywalkNetworkInterface : public IOSkywalkInterface {
    OSDeclareAbstractStructors(IOSkywalkNetworkInterface)
public:
    struct RegistrationInfo { uint8_t bytes[0x130]; };
    struct IOSkywalkTSOOptions;
    virtual void free() override;
    virtual bool init(OSDictionary*) override;
    virtual void stop(IOService*) override;
    virtual void joinPMtree(IOService*) override;
    virtual IOReturn setAggressiveness(unsigned long, unsigned long) override;
    virtual IOReturn enable(unsigned int) override;
    virtual IOReturn disable(unsigned int) override;
    virtual IOReturn registerNetworkInterfaceWithLogicalLink(IOSkywalkNetworkInterface::RegistrationInfo const*, IOSkywalkLogicalLink*, IOSkywalkPacketBufferPool*, IOSkywalkPacketBufferPool*, unsigned int);
    virtual IOReturn deregisterLogicalLink();
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) = 0;
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int);
    virtual void finalizeBSDInterface(struct __ifnet*, unsigned int);
    virtual ifnet_t getBSDInterface() const;
    virtual void setBSDName(char const*);
    virtual const char * getBSDName() const;
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*);
    virtual IOReturn processInterfaceCommand(ifdrv*);
    virtual IOReturn interfaceAdvisoryEnable(bool);
    virtual SInt32 setInterfaceEnable(bool);
    virtual SInt32 setRunningState(bool);
    virtual IOReturn handleChosenMedia(unsigned int);
    virtual void * getSupportedMediaArray(unsigned int*, unsigned int*);
    virtual void * getPacketTapInfo(unsigned int*, unsigned int*);
    virtual UInt getUnsentDataByteCount(unsigned int*, unsigned int*, unsigned int) const;
    virtual UInt32 getSupportedWakeFlags(unsigned int*);
    virtual void enableNetworkWake(unsigned int);
    virtual void calculateRingSizeForQueue(IOSkywalkPacketQueue const*, unsigned int*) const;
    virtual UInt getMaxTransferUnit();
    virtual void setMaxTransferUnit(unsigned int);
    virtual UInt getMinPacketSize();
    virtual UInt getHardwareAssists();
    virtual void setHardwareAssists(unsigned int, unsigned int);
    virtual void * getInterfaceFamily();
    virtual void * getInterfaceSubFamily();
    virtual UInt getInitialMedia();
    virtual UInt32 getFeatureFlags();
    virtual UInt getTxDataOffset();
    virtual UInt captureInterfaceState(unsigned int);
    virtual void restoreInterfaceState(unsigned int);
    virtual void setMTU(unsigned int);
    virtual bool bpfTap(unsigned int, unsigned int);
    virtual const char * getBSDNamePrefix();
    virtual UInt getBSDUnitNumber();
    virtual const char * classNameOverride();
    virtual void deferBSDAttach(bool);
    virtual void reportDetailedLinkStatus(if_link_status const*);
    virtual UInt getTSOOptions(IOSkywalkNetworkInterface::IOSkywalkTSOOptions*);
    virtual void _RESERVEDIOSkywalkNetworkInterface0();
    virtual void _RESERVEDIOSkywalkNetworkInterface1();
    virtual void _RESERVEDIOSkywalkNetworkInterface2();
    virtual void _RESERVEDIOSkywalkNetworkInterface3();
    virtual void _RESERVEDIOSkywalkNetworkInterface4();
    virtual void _RESERVEDIOSkywalkNetworkInterface5();
    virtual void _RESERVEDIOSkywalkNetworkInterface6();
    virtual void _RESERVEDIOSkywalkNetworkInterface7();
    virtual void _RESERVEDIOSkywalkNetworkInterface8();
    virtual void _RESERVEDIOSkywalkNetworkInterface9();
    void reportLinkStatus(unsigned int, unsigned int);
    struct ExpansionData { RegistrationInfo *fRegistrationInfo; ifnet_t fBSDInterface; };
    uint8_t _layout0[0x8];
    ExpansionData *mExpansionData;
    uint8_t _layout1[0x10];
};
static_assert(sizeof(IOSkywalkNetworkInterface) == 0xd0, "WCL ABI size");
static_assert(__offsetof(IOSkywalkNetworkInterface, mExpansionData) == 0xb8, "WCL ABI offset");
#endif
