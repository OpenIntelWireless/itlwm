#ifndef IO80211P2PInterface_h
#define IO80211P2PInterface_h

#include "IO80211VirtualInterface.h"

class IO80211P2PInterface : public IO80211VirtualInterface {
    OSDeclareDefaultStructors(IO80211P2PInterface)
    
public:
    virtual void free(void) override;
    virtual IOReturn configureReport(IOReportChannelList   *channels,
                                     IOReportConfigureAction action,
                                     void                  *result,
                                     void                  *destination) override;
    virtual IOReturn updateReport(IOReportChannelList      *channels,
                                  IOReportUpdateAction      action,
                                  void                     *result,
                                  void                     *destination) override;
    
    virtual bool terminate( IOOptionBits options = 0 ) override;
    virtual bool attach(IOService *);
    virtual void detach(IOService *);
    virtual const char * stringFromReturn( IOReturn rtn ) override;
    virtual int errnoFromReturn( IOReturn rtn ) override;
    virtual IOReturn powerStateWillChangeTo(
                                            IOPMPowerFlags  capabilities,
                                            unsigned long   stateNumber,
                                            IOService *     whatDevice ) override;

    virtual IOReturn powerStateDidChangeTo(
                                           IOPMPowerFlags  capabilities,
                                           unsigned long   stateNumber,
                                           IOService *     whatDevice ) override;
    virtual bool init(IO80211Controller *,ether_addr *,uint,char const*);
    virtual bool createPeerManager(ether_addr *,IO80211PeerManager **);
    virtual UInt getMediumType();
    virtual void setLinkState(IO80211LinkState,uint);
    virtual bool dequeueOutputPacketsWithServiceClass(uint,IOMbufServiceClass,mbuf_t*,mbuf_t*,uint *,ulong long *);
    virtual UInt32 outputPacket (mbuf_t m, void* param);
    virtual void setEnabledBySystem(bool);
    virtual void handleIoctl(ulong,void *);
    virtual UInt32 inputPacket(mbuf_t,packet_info_tag *);
    virtual IOReturn controllerWillChangePowerState(IO80211Controller *,ulong,uint,IOService *);
    virtual IOReturn controllerDidChangePowerState(IO80211Controller *,ulong,uint,IOService *);
    virtual bool handleDebugCmd(apple80211_debug_command *);
    virtual IOReturn postPeerPresence(ether_addr *,int,int,int,char *);
    virtual IOReturn postPeerAbsence(ether_addr *);
    virtual void signalOutputThread();
    virtual bool isOutputFlowControlled();
    virtual void setOutputFlowControlled();
    virtual void clearOutputFlowControlled();
    virtual void outputStart(uint);
    virtual UInt32 configureAQMOutput();
    virtual void setUnitNumber(char const*);
    virtual bool initIfnetEparams(ifnet_init_eparams *);
    virtual bool attachToBpf();
    virtual bool configureIfnet();
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
    char buf[0x1024];
};

#endif /* IO80211P2PInterface_h */
