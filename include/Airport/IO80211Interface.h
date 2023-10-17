#ifndef _IO80211INTERFACE_H
#define _IO80211INTERFACE_H

/*
 * Kernel
 */
#if defined(KERNEL) && defined(__cplusplus)

#include <Availability.h>
#include <libkern/version.h>

// This is necessary, because even the latest Xcode does not support properly targeting 11.0.
#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

#if VERSION_MAJOR > 8
	#define _MODERN_BPF
#endif

#include <IOKit/network/IOEthernetInterface.h>
#include <net/if_var.h>
#include <sys/queue.h>

typedef UInt kIO80211InterfaceType;

/*!	@defined kIO80211InterfaceClass
	@abstract The name of the IO80211Interface class.
	*/
#define kIO80211InterfaceClass     "IO80211Interface"

typedef UInt64 IO80211FlowQueueHash;
class RSNSupplicant;
class IOTimerEventSource;
class IOGatedOutputQueue;
class IO80211Controller;
class IO80211Workloop;
class IO80211ScanManager;
class IO80211PeerManager;
class IO80211FlowQueueDatabase;
class IO80211InterfaceMonitor;
class IO80211AssociationJoinSnapshot;

struct apple80211_debug_command;
struct apple80211_txstats;
struct apple80211_chip_counters_tx;
struct apple80211_chip_error_counters_tx;
struct apple80211_chip_counters_rx;
struct apple80211_ManagementInformationBasedot11_counters;
struct apple80211_leaky_ap_stats;
struct apple80211_leaky_ap_ssid_metrics;
struct apple80211_interface_availability;
struct apple80211_pmk_cache_data;
struct apple80211_ap_cmp_data;

struct TxPacketRequest {
    uint16_t    unk1;       // 0
    uint16_t    t;       // 2
    uint16_t    mU;       // 4
    uint16_t    mM;       // 6
    uint16_t    pkt_cnt;
    uint16_t    unk2;
    uint16_t    unk3;
    uint16_t    unk4;
    uint32_t    pad;
    mbuf_t      bufs[8];    // 18
    uint32_t    reqTx;
};

static_assert(sizeof(struct TxPacketRequest) == 0x60, "TxPacketRequest size error");

struct AWSRequest;
struct packet_info_tx;
struct userPrintCtx;

typedef int apple80211_postMessage_tlv_types;

class IO80211Interface : public IOEthernetInterface
{
    OSDeclareDefaultStructors( IO80211Interface );

public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,uint,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,uint,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual bool terminate(unsigned int) APPLE_KEXT_OVERRIDE;
    virtual bool attach(IOService*) APPLE_KEXT_OVERRIDE;
    virtual void detach(IOService*) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_10_15
    virtual IOReturn newUserClient(task_t, void*, UInt32 type, OSDictionary*, IOUserClient**) APPLE_KEXT_OVERRIDE;
#endif
    virtual const char* stringFromReturn(int) APPLE_KEXT_OVERRIDE;
    virtual int errnoFromReturn(int) APPLE_KEXT_OVERRIDE;
    virtual bool init(IONetworkController*) APPLE_KEXT_OVERRIDE;
    virtual UInt32 inputPacket(mbuf_t          packet,
                               UInt32          length  = 0,
                               IOOptionBits    options = 0,
                               void *          param   = 0) APPLE_KEXT_OVERRIDE;
    virtual bool inputEvent(unsigned int, void*) APPLE_KEXT_OVERRIDE;
    virtual SInt32 performCommand(IONetworkController*, unsigned long, void*, void*) APPLE_KEXT_OVERRIDE;
    virtual IOReturn attachToDataLinkLayer(IOOptionBits, void*) APPLE_KEXT_OVERRIDE;
    virtual void detachFromDataLinkLayer(unsigned int, void*) APPLE_KEXT_OVERRIDE;

    virtual void setPoweredOnByUser(bool);
    virtual void setEnabledBySystem(bool);

    virtual bool setLinkState(IO80211LinkState, unsigned int);
    virtual bool setLinkState(IO80211LinkState, int, unsigned int);
    virtual UInt32 outputPacket(mbuf_t, void*);

    virtual bool setLinkQualityMetric(int);
    virtual void handleDebugCmd(apple80211_debug_command*);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  0);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  1);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  2);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  3);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  4);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  5);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  6);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  7);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  8);
    OSMetaClassDeclareReservedUnused( IO80211Interface,  9);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 10);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 11);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 12);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 13);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 14);
    OSMetaClassDeclareReservedUnused( IO80211Interface, 15);
public:
    IOReturn IO80211InterfacePostMessage(UInt,void *,unsigned long);
    struct apple80211_ap_cmp_data *apCompare(apple80211_ap_cmp_data *,apple80211_ap_cmp_data *);
    void associateForNetBoot(IOService *);
    IOReturn associateForNetBootGated(OSObject *,void *,void *,void *,void *);
    bool authTimeout(void);
    UInt32 awsRespond(mbuf_t,AWSRequest *,unsigned long,unsigned short);
    IOReturn bpfAttach(UInt,UInt);
    IOReturn bpfAttach(UInt,UInt,OSObject *,UInt (OSObject::*)(mbuf_t,void *),int (OSObject::*)(UInt,UInt),IOWorkLoop *);
    IOReturn bpfOutput(UInt,mbuf_t);
    UInt32 bpfOutputPacket(mbuf_t,void *);
    void bpfTap(UInt,UInt);
    UInt32 bpfTapInput(mbuf_t,UInt,void *,unsigned long);
    UInt32 cachePMKSA(unsigned char *,unsigned long,ether_addr *);
    UInt32 cachePMKSA(unsigned char *,unsigned long,ether_addr *,unsigned char *);
    void clearAssocHistory(void);
    void configureAntennae(void);
    void configureBpfOutputQueues(bool);
    IOReturn createAssocHistory(void);
    UInt64 createIOReporters(IOService *);
    UInt64 debugFlags(void);
    mbuf_t dequeueTxPackets(TxPacketRequest *);
    mbuf_t dequeueTxPackets(UInt,UInt);
    void dropTxPacket(mbuf_t);
    bool efiNVRAMPublished(void *,void *,IOService *,IONotifier *);
    bool enabledBySystem(void);
    IO80211FlowQueue *findExistingFlowQueue(IO80211FlowQueueHash);
    IO80211FlowQueue *findOrCreateFlowQueue(IO80211FlowQueueHash);
    void finishAttachToDataLinkLayer(void);
    IOReturn finishAttachToDataLinkLayerGated(OSObject *,void *,void *,void *,void *);
    void flushPacketQueues(void);
    void freeBpf(void);
    void freePMKSACache(void);
    const char *getBSDName();
    IO80211Controller *getController(void);
    IO80211WorkLoop *getControllerWorkLoop(void);
    bool getExtendedStats(apple80211_extended_stats *);
    bool getLeakyApStats(apple80211_leaky_ap_stats const**);
    IOOutputQueue *getOutputQueue(void);
    IOOutputQueue *getOutputQueueForDLT(UInt);
    void getPMKSAList(apple80211_pmk_cache_data *);
    void getWmeTxCounters(unsigned long long *);
    void handleLeakyApStatsModeTimer(IOTimerEventSource *);
    void handleLeakyApStatsResetTimer(IOTimerEventSource *);
    bool initSupplicant(unsigned char *,int);
    UInt32 inputAWSPacket(mbuf_t);
    IO80211LinkState linkState(void);
    void logDebug(char const*, ...);
    void logDebug(unsigned long long, char const*, ...);
    void logDebugHex(void const*,unsigned long,char const*,...);
    void logTxCompletionPacket(mbuf_t,int);
    void logTxPacket(mbuf_t);
    UInt32 monitorModeInputPacket(mbuf_t,UInt,void *,unsigned long);
    IOReturn netBootThread(IOService *);
    IOReturn netBootThreadGated(OSObject *,void *,void *,void *,void *);
    bool netBooting(void);
    UInt32 outputEAPOLFrame(mbuf_t);
    void outputPreEnqueueHandler(void *,void *,mbuf_t);
    IOReturn outputStart(UInt);
    UInt64 packetSpace(unsigned char);
    UInt64 pendingPackets(unsigned char);
    IOReturn performCountryCodeOpGated(OSObject *,void *,void *,void *,void *);
    IOReturn performGatedCommand(void *,void *,void *,void *,void *);
    bool pidLocked(void);
    UInt64 pmksaLookup(ether_addr *,unsigned char *);
    void postMessage(unsigned int, void* data = NULL, unsigned long dataLen = 0);
    IOReturn powerChangeHandler(void *,void *,UInt,IOService *,void *,unsigned long);
    bool poweredOnByUser(void);
    mbuf_t preQueuePacket(mbuf_t);
    void printDataPath(userPrintCtx *);
    void printPeers(UInt,UInt);
    void purgePMKSACache(void);
    UInt64 queueSize(unsigned char);
    IOReturn queueWMEPacket(mbuf_t,void *);
    void removePacketQueue(IO80211FlowQueueHash const*);
    IOReturn reportDataPathEvents(UInt,void *,unsigned long);
    IOReturn reportDataPathEventsGated(void *,void *,void *,void *,void *);
    IOReturn reportDataTransferRates(void);
    IOReturn reportDataTransferRatesGated(void);
    IOReturn reportDataTransferRatesStatic(void *);
    IOReturn reportTransmitCompletionStatus(mbuf_t,int,UInt,UInt,UInt);
    void reportTransmitStatus(mbuf_t,int,packet_info_tx *);
    void reportTxStatistics(apple80211_txstats *);
    void resetLeakyApStats(void);
    void resetSupplicant(void);
#if __IO80211_TARGET >= __MAC_10_15
    void resetUserClientReference(void);
#endif
#if __IO80211_TARGET >= __MAC_11_0
    IOReturn resetUserClientReferenceGated(OSObject *,void *,void *,void *,void *);
#endif
    void setAuthTimeout(unsigned long);
    bool setBTCoexWLANLostAntennaTime(unsigned long long,unsigned long long,bool,apple80211_btCoex_report *);
    void setCountermeasuresTimer(IOTimerEventSource *);
    void setDataPathState(bool);
    IOReturn setDataPointerAndLengthForMessageType(apple80211_postMessage_tlv_types,void **,unsigned long *);
    void setDebugFlags(unsigned long long,UInt);
    bool setFrameStats(apple80211_stat_report *,apple80211_frame_counters *);
    bool setInterfaceCCA(apple80211_channel,int);
    bool setInterfaceChipCounters(apple80211_stat_report *,apple80211_chip_counters_tx *,apple80211_chip_error_counters_tx *,apple80211_chip_counters_rx *);
    bool setInterfaceExtendedCCA(apple80211_channel,apple80211_cca_report *);
    bool setInterfaceMIBdot11(apple80211_stat_report *,apple80211_ManagementInformationBasedot11_counters *);
    IOReturn setLQM(unsigned long long);
    IOReturn setLQMGated(long long);
    IOReturn setLQMStatic(void *,void *);
    bool setLeakyAPStats(apple80211_leaky_ap_event *);
    bool setLeakyAPStatsMode(UInt);
    bool setLeakyApSsidMetrics(apple80211_leaky_ap_ssid_metrics *);
    void setNetBooting(bool);
    bool setPMK(unsigned char *,unsigned char *);
#if __IO80211_TARGET >= __MAC_10_15
    bool setPSKPMK(unsigned char *);
#endif
    void setPeerManagerLogFlag(UInt,UInt,UInt);
    bool setPidLock(bool);
    void setScanningState(UInt,bool,apple80211_scan_data *,int);
    void setWoWEnabled(bool);
    bool shortGISupported20MHz(void);
    bool shortGISupported40MHz(void);
    bool shouldLog(unsigned long long);
    bool shouldRoam(apple80211_scan_result *);
#if __IO80211_TARGET >= __MAC_10_15
    IOReturn startAsyncEventUserClientForTask(task *,kIO80211InterfaceType);
#endif
    void startOutputQueues();
    void stopBpf(void);
    void stopCountermeasures(OSObject *,IOTimerEventSource *);
    void stopOutputQueues();
    bool supplicantExchangeComplete(void);
    bool supplicantInitialized(void);
    void terminateSupplicant(void);
    void togglePeerManagerLogFlag(UInt,UInt);
    void updateBSSIDProperty(void);
    void updateChannelProperty(void);
    void updateChannelPropertyGated(void);
    void updateChannelPropertyStatic(void *);
    void updateCountryCodeProperty(bool);
    bool updateInterfaceCoexRiskPct(unsigned long long);
    void updateLinkParameters(apple80211_interface_availability *);
    void updateLinkParametersGated(apple80211_interface_availability *);
    void updateLinkParametersStatic(void *,void *);
    bool updateLinkSpeed();
    IOReturn updateLinkStatus(void);
    IOReturn updateLinkStatusGated(void);
    IOReturn updateLinkStatusStatic(void *);
    void updateSSIDProperty(void);
    void updateStaticProperties(void);
    void vlogDebug(unsigned long long, char const*, va_list);
    void vlogDebugBPF(unsigned long long,char const*,va_list);
    void willRoam(ether_addr *,UInt);

protected:
    u_int8_t dat[0x500];
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* ! _IO80211INTERFACE_H */

