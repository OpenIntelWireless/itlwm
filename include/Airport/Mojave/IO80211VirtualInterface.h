#ifndef IO80211VirtualInterface_h
#define IO80211VirtualInterface_h

#include "IO80211Interface.h"
#include "apple_private_spi.h"

class IO80211PeerManager;

class IO80211VirtualInterface : public IOService {
    OSDeclareDefaultStructors(IO80211VirtualInterface)
    
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
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  0);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  1);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  2);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  3);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  4);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  5);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  6);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  7);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  8);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface,  9);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 10);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 11);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 12);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 13);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 14);
    OSMetaClassDeclareReservedUnused( IO80211VirtualInterface, 15);
public:
    
    static void startOutputQueues();
    
    static void stopOutputQueues();
    
    static int getInterfaceRole();
public:
    char buf[0x500];
};


#endif /* IO80211VirtualInterface_h */
