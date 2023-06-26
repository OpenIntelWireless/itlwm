#ifndef IO80211VirtualInterface_h
#define IO80211VirtualInterface_h

#include "IO80211Interface.h"
#include "apple_private_spi.h"

typedef UInt64 IO80211FlowQueueHash;
typedef UInt kIO80211InterfaceType;
class IO80211PeerManager;
class RSNSupplicant;

struct TxPacketRequest;
struct ifmediareq;
struct realTimeServiceId;
struct apple80211_awdl_app_specific_info;
struct apple80211_awdl_statistics;
struct apple80211_lowlatency_peer_statistics_evevt;
struct apple80211_p2p_airplay_statistics;
struct apple80211_awdl_sidecar_statistics;

class IO80211VirtualInterface : public IOService {
    OSDeclareDefaultStructors(IO80211VirtualInterface)
    
public:
    virtual void free(void) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_11_0
    virtual bool willTerminate( IOService * provider, IOOptionBits options ) APPLE_KEXT_OVERRIDE;
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
    virtual bool init(IO80211Controller *,ether_addr *,UInt,char const*);
    virtual bool createPeerManager(ether_addr *,IO80211PeerManager **);
    virtual IOMediumType getMediumType();
    virtual void setLinkState(IO80211LinkState,UInt);
    virtual bool dequeueOutputPacketsWithServiceClass(UInt,IOMbufServiceClass,mbuf_t*,mbuf_t*,UInt *,unsigned long long *);
    virtual UInt32 outputPacket (mbuf_t m, void* param);
    virtual void setEnabledBySystem(bool);
    virtual void handleIoctl(unsigned long,void *);
    virtual UInt32 inputPacket(mbuf_t,packet_info_tag *);
    virtual IOReturn controllerWillChangePowerState(IO80211Controller *,unsigned long,UInt,IOService *);
    virtual IOReturn controllerDidChangePowerState(IO80211Controller *,unsigned long,UInt,IOService *);
    virtual bool handleDebugCmd(apple80211_debug_command *);
    virtual IOReturn postPeerPresence(ether_addr *,int,int,int,char *);
    virtual IOReturn postPeerAbsence(ether_addr *);
#if __IO80211_TARGET >= __MAC_10_15
    virtual IOReturn postPeerPresenceIPv6(ether_addr *,int,int,int,char *,unsigned char *);
#endif
    virtual void signalOutputThread();
    virtual bool isOutputFlowControlled();
    virtual void setOutputFlowControlled();
    virtual void clearOutputFlowControlled();
    virtual void outputStart(UInt);
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
    IOReturn IO80211InterfacePostMessage(UInt,void *,unsigned long);
#if __IO80211_TARGET < __MAC_10_15
    IOReturn _outputStart(OSObject *,void *,void *,void *,void *);
    IOReturn _outputStartGated(UInt);
    IOReturn _outputStartGatedNoPM(UInt);
#endif
    bool attachIfnet(ether_addr *,char const*);
    bool authTimeout(void);
    errno_t bpfAttach(UInt,UInt);
    errno_t bpfAttach(UInt,UInt,OSObject *,UInt (OSObject::*)(mbuf_t,void *),int (OSObject::*)(UInt,UInt),IOWorkLoop *);
    errno_t bpfAttachEN10MB(UInt);
    UInt32 bpfOutput(UInt,mbuf_t);
    UInt32 bpfOutputPacket(mbuf_t,void *);
    UInt32 bpfTap(UInt,UInt);
    void bpfTapInput(mbuf_t,UInt,void *,unsigned long);
    UInt32 cachePMKSA(unsigned char *,unsigned long,ether_addr *);
    UInt32 cachePMKSA(unsigned char *,unsigned long,ether_addr *,unsigned char *);
    bool controllerLostPower(void);
    UInt64 createIOReporters(IOService *);
    UInt64 debugFlags(void);
    mbuf_t dequeueTxPackets(TxPacketRequest *);
    errno_t detachIfnet(void);
    void dropTxPacket(mbuf_t);
    bool dualBandCapable(void);
    bool enabledBySystem(void);
    IO80211FlowQueue *findExistingFlowQueue(IO80211FlowQueueHash);
    IO80211FlowQueue *findOrCreateFlowQueue(IO80211FlowQueueHash);
    void flushPacketQueues(void);
    const char *getBSDName(void);
    IO80211Controller *getController(void);
    IOLock *getDetachLock(void);
    ifnet_t getIfnet(void);
#if __IO80211_TARGET >= __MAC_10_15
    bool getInterfaceAddress(unsigned char *);
#endif
    UInt getInterfaceRole(void);
    IOOutputQueue *getOutputQueueForDLT(UInt);
    void getPMKSAList(apple80211_pmk_cache_data *);
    void getWmeTxCounters(unsigned long long *);
    IO80211WorkLoop *getWorkLoop(void);
#if __IO80211_TARGET >= __MAC_11_0
    void handleChannelSwitchAnnouncement(apple80211_channel_switch_announcement *);
#endif
    IOReturn handleIoctlGated(void *,void *,void *,void *,void *);
    SInt32 handleSIOCGIFMEDIA(unsigned long,ifmediareq *);
    SInt32 handleSIOCSIFADDR(void);
    SInt32 handleSIOCSIFFLAGS(char const*);
    static void ifnet_detach_callback(ifnet_t);
    static void ifnet_ioctl_callback(ifnet_t,unsigned long,void *);
    static void ifnet_start_callback(ifnet_t);
    bool initSupplicant(unsigned char *,int);
    void ioctl_internal(void *);
    IOReturn ioctl_internal_gated(void *,void *,void *,void *,void *);
#if __IO80211_TARGET >= __MAC_11_0
    bool isAwdlAssistedDiscoveryEnabled(void);
    bool isPeerToPeerInterface(void);
#endif
    IO80211LinkState linkState(void);
    void logDebug(char const*,...);
    void logDebug(unsigned long long,char const*,...);
    void logTxCompletionPacket(mbuf_t,int);
    void logTxPacket(mbuf_t);
#if __IO80211_TARGET >= __MAC_11_0
    void notifyHostapState(apple80211_hostap_state *);
    void p2pDaemonExited(void);
#endif
    UInt64 packetSpace(unsigned char);
#if __IO80211_TARGET >= __MAC_11_0
    bool peerToPeerAttachToBpf(void);
    errno_t peerToPeerConfigureIfnet(void);
#endif
    UInt64 pendingPackets(unsigned char);
#if __IO80211_TARGET >= __MAC_10_15
    void postAwdlAppSpecificInfo(apple80211_awdl_app_specific_info *);
#endif
#if __IO80211_TARGET >= __MAC_11_0
    void postAwdlHppStatsEvent(realTimeServiceId);
#else
    void postAwdlSidecarStatistics(apple80211_awdl_sidecar_statistics *);
#endif
    void postAwdlStatistics(apple80211_awdl_statistics *);
#if __IO80211_TARGET >= __MAC_11_0
    void postHostapChannelChanged(apple80211_hostap_state *);
    void postLowlatencyStatistics(apple80211_lowlatency_peer_statistics_evevt *);
#endif
    void postMessage(unsigned int, void* data = NULL, unsigned long dataLen = 0);
    void postNewMasterElected(void);
#if __IO80211_TARGET >= __MAC_11_0
    void postP2PAirplayStatistics(apple80211_p2p_airplay_statistics *);
#endif
    void postServiceIndication(void);
    void postSyncStateChanged(void);
    IOReturn powerStateDidChangeToGated(void *,void *,void *,void *,void *);
    IOReturn powerStateWillChangeToGated(void *,void *,void *,void *,void *);
    mbuf_t preQueuePacket(mbuf_t);
    void printDataPath(userPrintCtx *);
    void pushPacket(mbuf_t);
    UInt64 queueSize(unsigned char);
    void removePacketQueue(IO80211FlowQueueHash const*);
    IOReturn reportDataPathEvents(UInt,void *,unsigned long);
    IOReturn reportDataPathEventsGated(void *,void *,void *,void *,void *);
    IOReturn reportTransmitCompletionStatus(mbuf_t,int,UInt,UInt,UInt);
    void reportTransmitStatus(mbuf_t,int,packet_info_tx *);
    void resetSupplicant(void);
#if __IO80211_TARGET >= __MAC_10_15
    void resetUserClientReference(void);
#endif
#if __IO80211_TARGET >= __MAC_11_0
    IOReturn resetUserClientReferenceGated(OSObject *,void *,void *,void *,void *);
    void sendToBpfTap(mbuf_t,UInt,void *,unsigned long);
    void setAMPDUstat(apple80211_stat_report *,apple80211_ampdu_stat_report *);
#endif
    void setAuthTimeout(unsigned long);
    void setDebugFlags(unsigned long long,UInt);
    bool setFrameStats(apple80211_stat_report *,apple80211_frame_counters *);
#if __IO80211_TARGET >= __MAC_11_0
    void setInfraChannel(apple80211_channel *);
#endif
    void setInfraTxState(bool);
    bool setInterfaceCCA(apple80211_channel,int,apple80211_awdl_sync_channel_sequence *);
    bool setInterfaceChipCounters(apple80211_stat_report *,apple80211_chip_counters_tx *,apple80211_chip_error_counters_tx *,apple80211_chip_counters_rx *);
    bool setInterfaceExtendedCCA(apple80211_channel,apple80211_cca_report *,apple80211_awdl_sync_channel_sequence *);
    bool setInterfaceMIBdot11(apple80211_stat_report *,apple80211_ManagementInformationBasedot11_counters *);
    void setInterfaceRole(UInt);
#if __IO80211_TARGET >= __MAC_11_0
    void setJoiningState(UInt,joinStatus,bool);
#endif
    bool setPMK(unsigned char *);
#if __IO80211_TARGET >= __MAC_10_15
    bool setPSKPMK(unsigned char *);
#endif
    void setScanningState(UInt,bool,apple80211_scan_data *,int);
    void setUnitNumber(char const*,UInt);
    void setWaitingForDetach(bool);
    void setWoWEnabled(bool);
    bool shouldLog(unsigned long long);
#if __IO80211_TARGET >= __MAC_10_15
    IOReturn startAsyncEventUserClientForTask(task *,kIO80211InterfaceType);
#endif
    void startOutputQueues(void);
#if __IO80211_TARGET >= __MAC_11_0
    IOReturn startP2PDaemonUserClientForTask(task *);
#endif
    void stopOutputQueues(void);
    bool supplicantExchangeComplete(void);
    bool supplicantInitialized(void);
    void terminateSupplicant(void);
    void updateInterfaceCoexRiskPct(unsigned long long);
    void updateLinkParameters(apple80211_interface_availability *);
    void vlogDebug(unsigned long long,char const*,va_list);
    void vlogDebugBPF(unsigned long long,char const*,va_list);

public:
    char buf[0x300];
};


#endif /* IO80211VirtualInterface_h */
