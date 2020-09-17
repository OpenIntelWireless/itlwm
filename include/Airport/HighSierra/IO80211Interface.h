
#ifndef _IO80211INTERFACE_H
#define _IO80211INTERFACE_H

/*
 * Kernel
 */
#if defined(KERNEL) && defined(__cplusplus)

#include <libkern/version.h>

#if VERSION_MAJOR > 8
	#define _MODERN_BPF
#endif

#include <IOKit/network/IOEthernetInterface.h>
#include <net/if_var.h>
#include <sys/queue.h>

enum IO80211LinkState
{
	kIO80211NetworkLinkUndefined,			// Starting link state when an interface is created
	kIO80211NetworkLinkDown,				// Interface not capable of transmitting packets
	kIO80211NetworkLinkUp,					// Interface capable of transmitting packets
};
typedef enum IO80211LinkState IO80211LinkState;

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
struct TxPacketRequest;
struct AWSRequest;
struct packet_info_tx;
struct userPrintCtx;

typedef int apple80211_postMessage_tlv_types;

class IO80211Interface : public IOEthernetInterface
{
    OSDeclareDefaultStructors( IO80211Interface );
    
public:

    
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual bool terminate(unsigned int) override;
    virtual bool attach(IOService*) override;
    virtual void detach(IOService*) override;
    virtual const char * stringFromReturn(IOReturn) override;
    virtual int errnoFromReturn(IOReturn) override;
    virtual bool init(IONetworkController*) override;
    virtual UInt32 inputPacket(mbuf_t, UInt32, IOOptionBits, void*) override;
    virtual bool inputEvent(unsigned int, void*) override;
    virtual SInt32 performCommand(IONetworkController*, unsigned long, void*, void*) override;
    virtual IOReturn attachToDataLinkLayer(IOOptionBits, void*) override;
    virtual void detachFromDataLinkLayer(unsigned int, void*) override;
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
    IO80211FlowQueue * findOrCreateFlowQueue(IO80211FlowQueueHash);
    void dropTxPacket(mbuf_t);
    void logDebug(unsigned long long, char const*, ...);
    void vlogDebug(unsigned long long, char const*, va_list);
    const char * getBSDName();
    bool setLeakyAPStatsMode(unsigned int);
    void stopOutputQueues();
    void startOutputQueues();
    bool updateLinkSpeed();
    bool reportDataTransferRatesStatic(void*);
    void logDebug(char const*, ...);
    void postMessage(unsigned int, void* data=NULL, unsigned long len=0);
    void logDebugHex(void const*, unsigned long, char const*, ...);
    int reportDataPathEventsGated(void*, void*, void*, void*, void*);
    IOReturn IO80211InterfacePostMessage(unsigned int, void*, unsigned long);
    void updateBSSIDProperty();
    void updateChannelPropertyStatic(void*);
    void updateSSIDProperty();
    void updateCountryCodeProperty(bool);
    void updateChannelPropertyGated();
    int updateLinkStatusStatic(void*);
    int updateLinkStatusGated();
    void reportDataTransferRatesGated();
    int configureAntennae();
    IOReturn finishAttachToDataLinkLayerGated(OSObject*, void*, void*, void*, void*);
    IOReturn finishAttachToDataLinkLayer();
    void updateStaticProperties();
    IOReturn powerChangeHandler(void*, void*, unsigned int, IOService*, void*, unsigned long);
    int bpfOutputPacket(mbuf_t, void*);
    int bpfAttach(unsigned int, unsigned int, OSObject*, unsigned int (OSObject::*)(mbuf_t, void*), int (OSObject::*)(unsigned int, unsigned int), IOWorkLoop*);
    int createIOReporters(IOService*);
    int bpfOutput(unsigned int, mbuf_t);
    mbuf_t preQueuePacket(mbuf_t);
    int logTxPacket(mbuf_t);
    IOReturn performCountryCodeOpGated(OSObject*, void*, void*, void*, void*);
    int performGatedCommand(void*, void*, void*, void*, void*);
    int inputAWSPacket(mbuf_t);
    void awsRespond(mbuf_t, AWSRequest*, unsigned long, unsigned short);
    int queueWMEPacket(mbuf_t, void*);
    IOReturn handleLeakyApStatsModeTimer(IOTimerEventSource*);
    void handleLeakyApStatsResetTimer(IOTimerEventSource*);
    void terminateSupplicant();
    void setCountermeasuresTimer(IOTimerEventSource*);
    void freePMKSACache();
    void freeBpf();

    void stopBpf();
    IO80211Controller * getController();
    IOReturn bpfAttach(unsigned int, unsigned int);
    void reportTransmitStatus(mbuf_t, int, packet_info_tx*);
    void logTxCompletionPacket(mbuf_t, int);
    IOReturn reportTransmitCompletionStatus(mbuf_t, int, unsigned int, unsigned int, unsigned int);
    bool reportDataPathEvents(unsigned int, void*, unsigned long);
    IOReturn setDataPointerAndLengthForMessageType(apple80211_postMessage_tlv_types, void**, unsigned long*);
    void reportTxStatistics(apple80211_txstats*);
    SInt32 reportDataTransferRates();
    SInt32 updateChannelProperty();
    bool poweredOnByUser();
    bool enabledBySystem();
    void setAuthTimeout(unsigned long);
    UInt64 authTimeout();
    bool setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*);
    bool setInterfaceCCA(apple80211_channel, int);
    bool setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*);
    bool setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*);
    bool setFrameStats(apple80211_stat_report*, apple80211_frame_counters*);
    bool setLQM(unsigned long long);
    bool setLQMStatic(void*, void*);
    bool setLQMGated(unsigned long long);
    SInt32 updateLinkStatus();
    IOReturn setScanningState(unsigned int, bool, apple80211_scan_data*, int);
    UInt64 debugFlags();
    IO80211LinkState linkState();
    OSString * createAssocHistory();
    void clearAssocHistory();
    bool getLeakyApStats(apple80211_leaky_ap_stats const**);
    bool resetLeakyApStats();
    bool setLeakyApSsidMetrics(apple80211_leaky_ap_ssid_metrics*);
    bool setLeakyAPStats(apple80211_leaky_ap_event*);
    SInt32 updateLinkParameters(apple80211_interface_availability*);
    bool updateLinkParametersStatic(void*, void*);
    bool updateLinkParametersGated(apple80211_interface_availability*);
    bool updateInterfaceCoexRiskPct(unsigned long long);
    bool setBTCoexWLANLostAntennaTime(unsigned long long, unsigned long long, bool, apple80211_btCoex_report*);
    bool initSupplicant(unsigned char*, int);
    bool resetSupplicant();
    bool setPMK(unsigned char*);
    bool supplicantExchangeComplete();
    UInt32 outputEAPOLFrame(mbuf_t);
    void supplicantInitialized();
    void cachePMKSA(unsigned char*, unsigned long, ether_addr*, unsigned char*);
    void purgePMKSACache();
    SInt32 cachePMKSA(unsigned char*, unsigned long, ether_addr*);
    struct rsn_pmksa_node * pmksaLookup(ether_addr*, unsigned char*);
    void getPMKSAList(apple80211_pmk_cache_data*);
    UInt32 getExtendedStats(apple80211_extended_stats*);
    bool shouldRoam(apple80211_scan_result*);
    void willRoam(ether_addr*, unsigned int);
    void outputPreEnqueueHandler(void*, void*, mbuf_t);
    void stopCountermeasures(OSObject*, IOTimerEventSource*);
    IOGatedOutputQueue * getOutputQueue();
    void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int);
    void setDebugFlags(unsigned long long, unsigned int);
    void togglePeerManagerLogFlag(unsigned int, unsigned int);
    bool shouldLog(unsigned long long);
    void vlogDebugBPF(unsigned long long, char const*, va_list);
    void monitorModeInputPacket(mbuf_t, unsigned int, void*, unsigned long);
    void bpfTapInput(mbuf_t, unsigned int, void*, unsigned long);
    void getWmeTxCounters(unsigned long long*);
    void flushPacketQueues();
    void removePacketQueue(IO80211FlowQueueHash const*);

    UInt32 pendingPackets(unsigned char);
    UInt32 queueSize(unsigned char);
    UInt32 packetSpace(unsigned char);
    IO80211FlowQueue * findExistingFlowQueue(IO80211FlowQueueHash);
    IOReturn outputStart(unsigned int);
    void configureInterface();
    void setDataPathState(bool);
    UInt32 bpfTap(unsigned int, unsigned int);
    void configureBpfOutputQueues(bool);
    IOGatedOutputQueue * getOutputQueueForDLT(unsigned int);
    IOReturn setPidLock(bool);
    bool pidLocked();
    bool netBooting();
    void setNetBooting(bool);
    void netBootThreadGated(OSObject*, void*, void*, void*, void*);
    void netBootThread(IOService*);
    void associateForNetBoot(IOService*);
    void associateForNetBootGated(OSObject*, void*, void*, void*, void*);
    bool efiNVRAMPublished(void*, void*, IOService*, IONotifier*);
    apple80211_ap_cmp_data* apCompare(apple80211_ap_cmp_data*, apple80211_ap_cmp_data*);

    bool setWoWEnabled(bool);
    bool shortGISupported40MHz();
    bool shortGISupported20MHz();
    void dequeueTxPackets(unsigned int, unsigned int);
    void dequeueTxPackets(TxPacketRequest*);
    IO80211Workloop * getControllerWorkLoop();
    void printDataPath(userPrintCtx*);
    void printPeers(unsigned int, unsigned int);

private:

    // 0x330 total  0x148 from superclass
    IO80211PeerManager * _peerManager; // 0x148
    UInt64 _dataQueuePath; // 0x150
    IO80211FlowQueueDatabase * _flowQueueDb; // 0x158
    UInt64 _int64_1; // 0x160
    UInt64 _link_status; // 0x168
    UInt32 _link_quality_flags; // 0x170
    UInt32 _link_quality; // 0x174 argument from setLQMGated(int)
    UInt32 * _effective_tx_bws; // 0x178 argument of IO80211InterfaceMonitor::getEffectiveTxBWSinceLastRead(unsigned int*)
    UInt32  _unk180;             // 0x180
    UInt32 _link_stat0; // 0x184 updateLinkParametersGated
    UInt32 _peakLatency; // 0x188 updateLinkParametersGated
    UInt32 _unk18c;                    // 0x18c
    UInt64 _unk190;                    // 0x190
    UInt64 _unk198;                    // 0x198
    UInt32 _unk1a0;                    // 0x1a0

    UInt32 _link_stat2; // 0x1a4 updateLinkParametersGated
    UInt32 _link_stat3; // 0x1a8 updateLinkParametersGated
    UInt32 _unk1ac; // 0x1ac
    UInt64 _unk1b0;                    // 0x1b0
    UInt64 _unk1b8;                    // 0x1b8
    UInt64 _unk1c0;                    // 0x1c0
    UInt64 _unk1c8;                    // 0x1c8
    UInt64 _unk1d0;                   // 0x1d0
    UInt64 _unk1d8;                    // 0x1d8

    IOTimerEventSource * _event_source; // 0x1e0
    IOTimerEventSource * _set_leakyApTimerEvent; // 0x1e8 setLeakyApSsidMetric
    UInt32 _leakyAp_mode; // 0x1f0
    UInt32 _mbuf_class_flag; // 0x1f4
    bool _poweredOnByUser;   // 0x1f8
    bool _enabledBySystem;   // 0x1f9
                               // 6 padding bytes
    UInt64 _timeout; // 0x200
    UInt32 _linkState; // 0x208 0x2: linkup, 0x20c setLeakyAPStatsMode return non-zero, 0x20d
    bool _link_status1; // 0x20c inputEvent
    bool _link_status2; // 0x20d inputEvent
                        // padding
    UInt64 _link_speed; // 0x210 0x2: linkup
    UInt64 _interfaceOpenPercent; // 0x218 updateLinkParametersGated (1 - apple80211_interface_availability:0x8 / apple80211_interface_availability:0x16)*0x64
    UInt64 _coexist_risk; // 0x220 updateInterfaceCoexRiskPct, 1st argument
    UInt64 _bt_wlan_losttime; // 0x228 setBTCoexWLANLostAntennaTime, 1st argument

    UInt64 _unk230;                    // 0x230
    UInt64 _unk238;                    // 0x238

    UInt32 _post_msg; // 0x240 IO80211InterfacePostMessage
    UInt32 _unk244; // 0x244, padding?
    RSNSupplicant * _rsnSupplicant; // 0x248
    ifmultiaddr_t _awsAddr; // 0x250
    IOTimerEventSource* _counterMeasureTimer; // 0x258
    char _bsdName[IFNAMSIZ];       // 0x260
    LIST_HEAD( , rsn_pmksa_node ) _pmksaCacheHead;       // 0x270 0x60 bytes, 0x54-0x61 ethernet address, double linked list, 0x0 next, 0x8 pre, 0x48 time in secs
    IONotifier * _powerChangeNotifier;  // 0x278
    UInt64  _debug_flags; // 0x280 0x4: set to 1 in efiNVRAMPublished, debug print 0x2: log setCounterMeasures, dropTxPacket 0x20, 0x285
    IOGatedOutputQueue * _80211outputQueue; // 0x288
    IO80211Controller * _controller; // 0x290
    void * _llAddr; // 0x298
    UInt8  _ifiType;                // 0x2a0
    UInt8  _flag0;                // 0x2a1
    UInt8  _flag1;                // 0x2a2
    UInt8  _flag2;                // 0x2a3
                                  // 5 bytes padding
    IOGatedOutputQueue * _queueBackground; // 0x2a8
    IOGatedOutputQueue * _queueVoice; // 0x2b0
    IOGatedOutputQueue * _queueVideo; // 0x2b8
    IO80211ScanManager * _scanManager; // 0x2c0
    IO80211InterfaceMonitor * _interfaceMonitor; // 0x2c8
    IO80211AssociationJoinSnapshot * _jointSnapshot; // 0x2d0
    bool _wowEnbled;     // 0x2d8 
                          // 3 bytes padding
    SInt32 _pid_self;     // 0x2dc 
                          // 4 bytes padding
    clock_sec_t _time_secs;     // 0x2e0 
    thread_call_t _net_boot_thread_call;     // 0x2e8 
    bool _net_boot;       // 0x2f0
                          // 3 bytes padding
    UInt32 _ap_cmp_n;     // 0x2f4  0x16 of apple80211_ap_cmp_data
    UInt8 * _ap_flags;     // 0x2f8: UInt8[2]: 0x8 shortGISupported20MHz , 0x4 shortGISupported40MHz, 0x6 phyModeForAsr
    void * _bpf_list;     // 0x300
    IOLock * _lock;     // 0x308
    UInt64  _ap;     // 0x310
    bool _terminate; // 0x318
                     // 7-byte padding
    UInt64 _unkown;  // 0x320
    UInt32 _ap_flag;     // 0x328 phyModeForAsr
    UInt32 _padding;     // 0x32c
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* ! _IO80211INTERFACE_H */

