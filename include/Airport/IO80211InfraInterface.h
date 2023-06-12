//
//  IO80211InfraInterface.h
//  itlwm
//
//  Created by qcwap on 2023/6/12.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef IO80211InfraInterface_h
#define IO80211InfraInterface_h

struct apple80211_wcl_advisory_info;
struct apple80211_wcl_tx_rx_latency;

class IO80211InfraInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211InfraInterface)
    
public:
    virtual bool init() APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
        UInt32 type, OSDictionary * properties,
        LIBKERN_RETURNS_RETAINED IOUserClient ** handler ) APPLE_KEXT_OVERRIDE;
    virtual const char * stringFromReturn( IOReturn rtn ) APPLE_KEXT_OVERRIDE;
    virtual int errnoFromReturn( IOReturn rtn ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setPowerState(
        unsigned long powerStateOrdinal,
        IOService *   whatDevice ) APPLE_KEXT_OVERRIDE;
    virtual unsigned long maxCapabilityForDomainState( IOPMPowerFlags domainState ) APPLE_KEXT_OVERRIDE;
    virtual unsigned long initialPowerStateForDomainState( IOPMPowerFlags domainState ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable(UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn disable(UInt) APPLE_KEXT_OVERRIDE;
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams *,sockaddr_dl **) APPLE_KEXT_OVERRIDE;
    virtual bool prepareBSDInterface(ifnet_t, UInt) APPLE_KEXT_OVERRIDE;
    virtual IOReturn processBSDCommand(ifnet_t, UInt, void *) APPLE_KEXT_OVERRIDE;
    virtual SInt32 setInterfaceEnable(bool) APPLE_KEXT_OVERRIDE;
    virtual SInt32 setRunningState(bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn handleChosenMedia(UInt) APPLE_KEXT_OVERRIDE;
    virtual void *getSupportedMediaArray(UInt *,UInt *) APPLE_KEXT_OVERRIDE;
    virtual UInt getHardwareAssists(void) APPLE_KEXT_OVERRIDE;
    virtual UInt32 getFeatureFlags(void) APPLE_KEXT_OVERRIDE;
    virtual bool bpfTap(UInt,UInt) APPLE_KEXT_OVERRIDE;
    virtual const char *classNameOverride(void) APPLE_KEXT_OVERRIDE;
    virtual void getHardwareAddress(ether_addr *) APPLE_KEXT_OVERRIDE;
    virtual void setHardwareAddress(ether_addr *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setPromiscuousModeEnable(bool, UInt) APPLE_KEXT_OVERRIDE;
    virtual void *createPeerManager(void) APPLE_KEXT_OVERRIDE;
    virtual void postMessage(UInt,void *,unsigned long,bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn reportDataPathEvents(UInt,void *,unsigned long,bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats *,TxSubmissionDequeueStats *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn recordOutputPacket(apple80211_wme_ac,int,int) APPLE_KEXT_OVERRIDE;
    virtual void logTxPacket(IO80211NetworkPacket *,PacketSkywalkScratch *,apple80211_wme_ac,bool) APPLE_KEXT_OVERRIDE;
    virtual void logTxCompletionPacket(IO80211NetworkPacket *,PacketSkywalkScratch *,unsigned char *,apple80211_wme_ac,int,UInt,bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats *,TxCompletionEnqueueStats *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn inputPacket(IO80211NetworkPacket *,packet_info_tag *,ether_header *,bool *) APPLE_KEXT_OVERRIDE;
    virtual void logSkywalkTxReqPacket(IO80211NetworkPacket *,PacketSkywalkScratch *,unsigned char *,apple80211_wme_ac,bool) APPLE_KEXT_OVERRIDE;
    virtual SInt64 pendingPackets(unsigned char) APPLE_KEXT_OVERRIDE;
    virtual SInt64 packetSpace(unsigned char) APPLE_KEXT_OVERRIDE;
    virtual bool isChipInterfaceReady(void) APPLE_KEXT_OVERRIDE;
    virtual bool isDebounceOnGoing(void) APPLE_KEXT_OVERRIDE;
    virtual bool setLinkState(IO80211LinkState,UInt,bool debounceTimeout = 30,UInt code = 0) APPLE_KEXT_OVERRIDE;
    virtual IO80211LinkState linkState(void) APPLE_KEXT_OVERRIDE;
    virtual void setScanningState(UInt,bool,apple80211_scan_data *,int) APPLE_KEXT_OVERRIDE;
    virtual void setDataPathState(bool) APPLE_KEXT_OVERRIDE;
    virtual void *getScanManager(void) APPLE_KEXT_OVERRIDE;
    virtual void updateLinkParameters(apple80211_interface_availability *) APPLE_KEXT_OVERRIDE;
    virtual void updateInterfaceCoexRiskPct(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void setLQM(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void updateLinkStatus(void) APPLE_KEXT_OVERRIDE;
    virtual void updateLinkStatusGated(void) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceExtendedCCA(apple80211_channel,apple80211_cca_report *) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceCCA(apple80211_channel,int) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceNF(apple80211_channel,long long) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceOFDMDesense(apple80211_channel,long long) APPLE_KEXT_OVERRIDE;
    virtual void removePacketQueue(IO80211FlowQueueHash *) APPLE_KEXT_OVERRIDE;
    virtual void setDebugFlags(unsigned long long,UInt) APPLE_KEXT_OVERRIDE;
    virtual SInt64 debugFlags(void) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceChipCounters(apple80211_stat_report *,apple80211_chip_counters_tx *,apple80211_chip_error_counters_tx *,apple80211_chip_counters_rx *) APPLE_KEXT_OVERRIDE;
    virtual void setInterfaceMIBdot11(apple80211_stat_report *,apple80211_ManagementInformationBasedot11_counters *) APPLE_KEXT_OVERRIDE;
    virtual void setFrameStats(apple80211_stat_report *,apple80211_frame_counters *) APPLE_KEXT_OVERRIDE;
    virtual SInt64 getWmeTxCounters(unsigned long long *) APPLE_KEXT_OVERRIDE;
    virtual void setEnabledBySystem(bool) APPLE_KEXT_OVERRIDE;
    virtual bool enabledBySystem(void) APPLE_KEXT_OVERRIDE;
    virtual bool willRoam(ether_addr *,UInt) APPLE_KEXT_OVERRIDE;
    virtual void setPeerManagerLogFlag(UInt,UInt,UInt) APPLE_KEXT_OVERRIDE;
    virtual void setWoWEnabled(bool) APPLE_KEXT_OVERRIDE;
    virtual bool wowEnabled(void) APPLE_KEXT_OVERRIDE;
    virtual void printDataPath(userPrintCtx *) APPLE_KEXT_OVERRIDE;
    virtual bool findOrCreateFlowQueue(IO80211FlowQueueHash) APPLE_KEXT_OVERRIDE;
    virtual UInt64 findOrCreateFlowQueueWithCache(IO80211FlowQueueHash,bool *) APPLE_KEXT_OVERRIDE;
    virtual UInt64 findExistingFlowQueue(IO80211FlowQueueHash) APPLE_KEXT_OVERRIDE;
    virtual void removePacketQueue(IO80211FlowQueueHash const*) APPLE_KEXT_OVERRIDE;
    virtual void flushPacketQueues(void) APPLE_KEXT_OVERRIDE;
    virtual void cachePeer(ether_addr *,UInt *) APPLE_KEXT_OVERRIDE;
    virtual bool shouldLog(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void vlogDebug(unsigned long long,char const*,va_list) APPLE_KEXT_OVERRIDE;
    virtual void vlogDebugBPF(unsigned long long,char const*,va_list) APPLE_KEXT_OVERRIDE;
    virtual UInt64 createLinkQualityMonitor(IO80211Peer *,IOService *) APPLE_KEXT_OVERRIDE;
    virtual void releaseLinkQualityMonitor(IO80211Peer *) APPLE_KEXT_OVERRIDE;
    virtual void *getP2PSkywalkPeerMgr(void) APPLE_KEXT_OVERRIDE;
    virtual bool isCommandProhibited(int) APPLE_KEXT_OVERRIDE;
    virtual void setNotificationProperty(OSSymbol const*,OSObject const*) APPLE_KEXT_OVERRIDE;
    virtual void *getWorkerMatchingDict(OSString *) APPLE_KEXT_OVERRIDE;
    virtual bool init(IOService *) APPLE_KEXT_OVERRIDE;
    virtual bool isInterfaceEnabled(void) APPLE_KEXT_OVERRIDE;
    virtual ether_addr *getSelfMacAddr(void) APPLE_KEXT_OVERRIDE;
    virtual void setSelfMacAddr(ether_addr *) APPLE_KEXT_OVERRIDE;
    virtual void *getPacketPool(OSString *) APPLE_KEXT_OVERRIDE;
    virtual void *getLogger(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn handleSIOCSIFADDR(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn debugHandler(apple80211_debug_command *) APPLE_KEXT_OVERRIDE;
    virtual void statsDump(void) APPLE_KEXT_OVERRIDE;
    virtual void powerOnNotification(void) APPLE_KEXT_OVERRIDE;
    virtual void powerOffNotification(void) APPLE_KEXT_OVERRIDE;
    virtual UInt64 getTxQueueDepth(void) APPLE_KEXT_OVERRIDE;
    virtual UInt64 getRxQueueCapacity(void) APPLE_KEXT_OVERRIDE;
    virtual void updateRxCounter(unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual void *getMultiCastQueue(void) APPLE_KEXT_OVERRIDE;
    virtual void *getCurrentBssid(void) APPLE_KEXT_OVERRIDE;
    virtual int getAssocState(void) APPLE_KEXT_OVERRIDE;
    virtual void notifyQueueState(apple80211_wme_ac,unsigned short) APPLE_KEXT_OVERRIDE;
    virtual int getTxHeadroom(void) APPLE_KEXT_OVERRIDE;
    virtual void *getRxCompQueue(void) APPLE_KEXT_OVERRIDE;
    virtual void *getTxCompQueue(void) APPLE_KEXT_OVERRIDE;
    virtual void *getTxSubQueue(apple80211_wme_ac) APPLE_KEXT_OVERRIDE;
    virtual void *getTxPacketPool(void) APPLE_KEXT_OVERRIDE;
    virtual void *getRxPacketPool(void) APPLE_KEXT_OVERRIDE;
    virtual void enableDatapath(void) APPLE_KEXT_OVERRIDE;
    virtual void disableDatapath(void) APPLE_KEXT_OVERRIDE;
    virtual int getNumTxQueues(void) APPLE_KEXT_OVERRIDE;
    virtual void *getLQMSummary(apple80211_lqm_summary *) APPLE_KEXT_OVERRIDE;
    virtual int getEventPipeSize(void) APPLE_KEXT_OVERRIDE;
    virtual UInt64 createEventPipe(IO80211APIUserClient *) APPLE_KEXT_OVERRIDE;
    virtual void destroyEventPipe(IO80211APIUserClient *) APPLE_KEXT_OVERRIDE;
    virtual void postMessageIOUC(char const*,UInt,void *,unsigned long) APPLE_KEXT_OVERRIDE;
    virtual bool isIOUCPipeOpened(void) APPLE_KEXT_OVERRIDE;
    virtual void *getRingMD(IO80211APIUserClient *,unsigned long long) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setLinkStateInternal(IO80211LinkState,uint,bool,uint,apple80211_link_changed_event_data &);
    virtual void setPoweredOnByUser(bool);
    virtual void setCurrentBssid(ether_addr *);
    virtual void setWCL_ADVISORTY_INFO(apple80211_wcl_advisory_info *);
    virtual void *getWCL_TX_RX_LATENCY(apple80211_wcl_tx_rx_latency *);
    
public:
    char _data[0x120];
};

#endif /* IO80211InfraInterface_h */
