//
//  IOSkywalkEthernetInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef IOSkywalkEthernetInterface_h
#define IOSkywalkEthernetInterface_h

#include "IOSkywalkNetworkInterface.h"

struct nicproxy_limits_info_s;
struct nicproxy_info_s;


class IO80211Controller;
class CCLogStream;
struct mloAddrArray;

class IOSkywalkEthernetInterface : public IOSkywalkNetworkInterface {
    OSDeclareAbstractStructors(IOSkywalkEthernetInterface)
public:
    struct RegistrationInfo { uint8_t bytes[0x130]; };
    virtual void free();
    virtual bool init(OSDictionary*);
    virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**);
    virtual IOReturn setPowerState(unsigned long, IOService*);
    virtual IOReturn enable(unsigned int);
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**);
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int);
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*);
    virtual void * getPacketTapInfo(unsigned int*, unsigned int*);
    virtual void enableNetworkWake(unsigned int);
    virtual UInt getMaxTransferUnit();
    virtual UInt getMinPacketSize();
    virtual void * getInterfaceFamily();
    virtual void * getInterfaceSubFamily();
    virtual UInt getInitialMedia();
    virtual const char * getBSDNamePrefix();
    virtual IOReturn getHardwareAddress(ether_addr*);
    virtual IOReturn setHardwareAddress(ether_addr*);
    virtual void setLinkLayerAddress(ether_addr*);
    virtual bool configureMulticastFilter(unsigned int, ether_addr const*, unsigned int);
    virtual bool setMulticastAddresses(ether_addr const*, unsigned int);
    virtual void setAllMulticastModeEnable(bool);
    virtual IOReturn setPromiscuousModeEnable(bool, unsigned int);
    virtual void reportNicProxyLimits(nicproxy_limits_info_s);
    virtual void hwConfigNicProxyData(nicproxy_info_s*);
    virtual void _RESERVEDIOSkywalkEthernetInterface0();
    virtual void _RESERVEDIOSkywalkEthernetInterface1();
    virtual void _RESERVEDIOSkywalkEthernetInterface2();
    virtual void _RESERVEDIOSkywalkEthernetInterface3();
    virtual void _RESERVEDIOSkywalkEthernetInterface4();
    virtual void _RESERVEDIOSkywalkEthernetInterface5();
    virtual void _RESERVEDIOSkywalkEthernetInterface6();
    virtual void _RESERVEDIOSkywalkEthernetInterface7();
    virtual void _RESERVEDIOSkywalkEthernetInterface8();
    virtual void _RESERVEDIOSkywalkEthernetInterface9();
    virtual void _RESERVEDIOSkywalkEthernetInterface10();
    bool initRegistrationInfo(RegistrationInfo *, unsigned int, unsigned long);
    IOReturn registerEthernetInterface(const RegistrationInfo *, IOSkywalkPacketQueue **, unsigned int, IOSkywalkPacketBufferPool *, IOSkywalkPacketBufferPool *, unsigned int);
    IOReturn deregisterEthernetInterface(unsigned int);
    struct ExpansionData { RegistrationInfo *fRegistrationInfo; ifnet_t fBSDInterface; };
    uint8_t _layout0[0x38];
    ExpansionData *mExpansionData2;
};
static_assert(sizeof(IOSkywalkEthernetInterface) == 0x120, "WCL ABI size");
static_assert(__offsetof(IOSkywalkEthernetInterface, mExpansionData2) == 0x118, "WCL ABI offset");
#endif
