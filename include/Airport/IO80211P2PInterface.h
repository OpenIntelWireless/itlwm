#ifndef IO80211P2PInterface_h
#define IO80211P2PInterface_h

#include "IO80211VirtualInterface.h"

class IO80211P2PInterface : public IO80211VirtualInterface {
    OSDeclareDefaultStructors(IO80211P2PInterface)
    
public:
    virtual void free(void) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_11_0
    virtual bool willTerminate(IOService *,uint) APPLE_KEXT_OVERRIDE;
#endif
    virtual IOReturn configureReport(IOReportChannelList   *channels,
                                     IOReportConfigureAction action,
                                     void                  *result,
                                     void                  *destination) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList      *channels,
                                  IOReportUpdateAction      action,
                                  void                     *result,
                                  void                     *destination) APPLE_KEXT_OVERRIDE;
    
    virtual bool terminate( IOOptionBits options = 0 ) APPLE_KEXT_OVERRIDE;
    virtual bool attach(IOService *) APPLE_KEXT_OVERRIDE;
    virtual void detach(IOService *) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_10_15
    virtual IOReturn newUserClient(task_t,void *,UInt,OSDictionary *,IOUserClient **) APPLE_KEXT_OVERRIDE;
#endif
    virtual const char * stringFromReturn( IOReturn rtn ) APPLE_KEXT_OVERRIDE;
    virtual int errnoFromReturn( IOReturn rtn ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn powerStateWillChangeTo(
                                            IOPMPowerFlags  capabilities,
                                            unsigned long   stateNumber,
                                            IOService *     whatDevice ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn powerStateDidChangeTo(
                                           IOPMPowerFlags  capabilities,
                                           unsigned long   stateNumber,
                                           IOService *     whatDevice ) APPLE_KEXT_OVERRIDE;
    virtual bool init(IO80211Controller *,ether_addr *,uint,char const*) APPLE_KEXT_OVERRIDE;
    virtual bool createPeerManager(ether_addr *,IO80211PeerManager **) APPLE_KEXT_OVERRIDE;
    virtual IOMediumType getMediumType() APPLE_KEXT_OVERRIDE;
    virtual void setLinkState(IO80211LinkState,uint) APPLE_KEXT_OVERRIDE;
    virtual bool dequeueOutputPacketsWithServiceClass(uint,IOMbufServiceClass,mbuf_t*,mbuf_t*,UInt *,unsigned long long *) APPLE_KEXT_OVERRIDE;
    virtual UInt32 outputPacket (mbuf_t m, void* param) APPLE_KEXT_OVERRIDE;
    virtual void setEnabledBySystem(bool) APPLE_KEXT_OVERRIDE;
    virtual void handleIoctl(unsigned long,void *) APPLE_KEXT_OVERRIDE;
    virtual UInt32 inputPacket(mbuf_t,packet_info_tag *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn controllerWillChangePowerState(IO80211Controller *,unsigned long,UInt,IOService *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn controllerDidChangePowerState(IO80211Controller *,unsigned long,UInt,IOService *) APPLE_KEXT_OVERRIDE;
    virtual bool handleDebugCmd(apple80211_debug_command *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn postPeerPresence(ether_addr *,int,int,int,char *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn postPeerAbsence(ether_addr *) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_10_15
    virtual IOReturn postPeerPresenceIPv6(ether_addr *,int,int,int,char *,unsigned char *) APPLE_KEXT_OVERRIDE;
#endif
    virtual void signalOutputThread() APPLE_KEXT_OVERRIDE;
    virtual bool isOutputFlowControlled() APPLE_KEXT_OVERRIDE;
    virtual void setOutputFlowControlled() APPLE_KEXT_OVERRIDE;
    virtual void clearOutputFlowControlled() APPLE_KEXT_OVERRIDE;
    virtual void outputStart(uint) APPLE_KEXT_OVERRIDE;
    virtual UInt32 configureAQMOutput() APPLE_KEXT_OVERRIDE;
    virtual void setUnitNumber(char const*) APPLE_KEXT_OVERRIDE;
    virtual bool initIfnetEparams(ifnet_init_eparams *) APPLE_KEXT_OVERRIDE;
    virtual bool attachToBpf() APPLE_KEXT_OVERRIDE;
    virtual bool configureIfnet() APPLE_KEXT_OVERRIDE;
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  0);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  1);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  2);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  3);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  4);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  5);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  6);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  7);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  8);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface,  9);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 10);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 11);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 12);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 13);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 14);
    OSMetaClassDeclareReservedUnused( IO80211P2PInterface, 15);
public:
#if __IO80211_TARGET < __MAC_11_0
    void setJoiningState(UInt,joinStatus,bool);
    void setInfraChannel(apple80211_channel *);
#endif
    void p2pSetUnitNumber(char const*);
    bool p2pCreatePeerManager(ether_addr *,IO80211PeerManager **);
    bool p2pConfigureIfnet(void);
    bool p2pAttachToBpf(void);
#if __IO80211_TARGET < __MAC_11_0
#if __IO80211_TARGET >= __MAC_10_15
    void notifyHostapState(apple80211_hostap_state *);
#endif
    bool isAwdlAssistedDiscoveryEnabled(void);
    void handleChannelSwitchAnnouncement(apple80211_channel_switch_announcement *);
    void awdlSetUnitNumber(char const*);
    void awdlInit(void);
    void awdlFree(void);
    bool awdlCreatePeerManager(ether_addr *,IO80211PeerManager **);
    bool awdlConfigureIfnet(void);
    bool awdlAttachToBpf(void);
#endif
#if __IO80211_TARGET >= __MAC_11_0
    bool isP2P(void);
    bool isAPSTA(void);
#endif
    errno_t apsta_if_output_pre_enqueue(ifnet_t, mbuf_t);
    void apStaSetUnitNumber(char const*);
    bool apStaInitIfnetEparams(ifnet_init_eparams *);
    bool apStaCreatePeerManager(ether_addr *,IO80211PeerManager **);
    bool apStaConfigureIfnet(void);
    bool apStaAttachToBpf(void);

public:
    char buf[0x300];
};

#endif /* IO80211P2PInterface_h */
