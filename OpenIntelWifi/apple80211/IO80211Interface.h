
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

#include "IO80211FlowQueue.h"

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

#define uchar unsigned char

typedef int apple80211_postMessage_tlv_types;

class IO80211Interface : public IOEthernetInterface
{
    OSDeclareDefaultStructors( IO80211Interface );
    
public:
    virtual bool terminate(unsigned int) APPLE_KEXT_OVERRIDE;
    virtual bool attach(IOService*) APPLE_KEXT_OVERRIDE;
    virtual void detach(IOService*) APPLE_KEXT_OVERRIDE;
    virtual bool init(IONetworkController*) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,uint,void *,void *) override;
    virtual IOReturn configureReport(IOReportChannelList *,uint,void *,void *) override;
    virtual UInt32 inputPacket(mbuf_t          packet,
                               UInt32          length  = 0,
                               IOOptionBits    options = 0,
                               void *          param   = 0) APPLE_KEXT_OVERRIDE;
    virtual bool inputEvent(unsigned int, void*) APPLE_KEXT_OVERRIDE;
    virtual IOReturn newUserClient(task_t, void*, UInt32 type, OSDictionary*, IOUserClient**) APPLE_KEXT_OVERRIDE;
    virtual SInt32 performCommand(IONetworkController*, unsigned long, void*, void*) APPLE_KEXT_OVERRIDE;
    virtual IOReturn attachToDataLinkLayer(IOOptionBits, void*) APPLE_KEXT_OVERRIDE;
    virtual void detachFromDataLinkLayer(unsigned int, void*) APPLE_KEXT_OVERRIDE;
    virtual int errnoFromReturn(int) override;
    virtual const char* stringFromReturn(int) override;
    
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
    void postMessage(unsigned int, void* data = NULL, unsigned long dataLen = 0);
    void logDebugHex(void const*,ulong,char const*,...);
    void reportDataPathEventsGated(void *,void *,void *,void *,void *);
    void IO80211InterfacePostMessage(uint,void *,ulong);
    void updateBSSIDProperty(void);
    void updateChannelPropertyStatic(void *);
    void updateSSIDProperty(void);
    void updateCountryCodeProperty(bool);
    void updateChannelPropertyGated(void);
    void updateLinkStatusStatic(void *);
    void updateLinkStatusGated(void);
    void reportDataTransferRatesGated(void);
    void configureAntennae(void);
    void finishAttachToDataLinkLayerGated(OSObject *,void *,void *,void *,void *);
    void finishAttachToDataLinkLayer(void);
    void updateStaticProperties(void);
    void powerChangeHandler(void *,void *,uint,IOService *,void *,ulong);
    void bpfOutputPacket(mbuf_t,void *);
    void bpfAttach(uint,uint,OSObject *,uint (OSObject::*)(mbuf_t,void *),int (OSObject::*)(uint,uint),IOWorkLoop *);
    void createIOReporters(IOService *);
    void bpfOutput(uint,mbuf_t);
    void preQueuePacket(mbuf_t);
    void logTxPacket(mbuf_t);
    void performCountryCodeOpGated(OSObject *,void *,void *,void *,void *);
    void performGatedCommand(void *,void *,void *,void *,void *);
    void inputAWSPacket(mbuf_t);
    void awsRespond(mbuf_t,AWSRequest *,ulong,ushort);
    void queueWMEPacket(mbuf_t,void *);
    void handleLeakyApStatsModeTimer(IOTimerEventSource *);
    void handleLeakyApStatsResetTimer(IOTimerEventSource *);
    void terminateSupplicant(void);
    void setCountermeasuresTimer(IOTimerEventSource *);
    void freePMKSACache(void);
    void freeBpf(void);
    void stopBpf(void);
    void getController(void);
    void bpfAttach(uint,uint);
    void reportTransmitStatus(mbuf_t,int,packet_info_tx *);
    void logTxCompletionPacket(mbuf_t,int);
    void reportTransmitCompletionStatus(mbuf_t,int,uint,uint,uint);
    void reportDataPathEvents(uint,void *,ulong);
    void setDataPointerAndLengthForMessageType(apple80211_postMessage_tlv_types,void **,ulong *);
    void reportTxStatistics(apple80211_txstats *);
    void reportDataTransferRates(void);
    void updateChannelProperty(void);
    void poweredOnByUser(void);
    void enabledBySystem(void);
    void setAuthTimeout(ulong);
    void authTimeout(void);
    void setInterfaceExtendedCCA(apple80211_channel,apple80211_cca_report *);
    void setInterfaceCCA(apple80211_channel,int);
    void setInterfaceChipCounters(apple80211_stat_report *,apple80211_chip_counters_tx *,apple80211_chip_error_counters_tx *,apple80211_chip_counters_rx *);
    void setInterfaceMIBdot11(apple80211_stat_report *,apple80211_ManagementInformationBasedot11_counters *);
    void setFrameStats(apple80211_stat_report *,apple80211_frame_counters *);
    void setLQM(ulong long);
    void setLQMStatic(void *,void *);
    void setLQMGated(ulong long);
    void updateLinkStatus(void);
    void setScanningState(uint,bool,apple80211_scan_data *,int);
    void debugFlags(void);
    void linkState(void);
    void createAssocHistory(void);
    void clearAssocHistory(void);
    void getLeakyApStats(apple80211_leaky_ap_stats const**);
    void resetLeakyApStats(void);
    void setLeakyApSsidMetrics(apple80211_leaky_ap_ssid_metrics *);
    void setLeakyAPStats(apple80211_leaky_ap_event *);
    void updateLinkParameters(apple80211_interface_availability *);
    void updateLinkParametersStatic(void *,void *);
    void updateLinkParametersGated(apple80211_interface_availability *);
    void updateInterfaceCoexRiskPct(ulong long);
    void setBTCoexWLANLostAntennaTime(ulong long,ulong long,bool,apple80211_btCoex_report *);
    void initSupplicant(uchar *,int);
    void resetSupplicant(void);
    void setPMK(uchar *);
    void supplicantExchangeComplete(void);
    void outputEAPOLFrame(mbuf_t);
    void supplicantInitialized(void);
    void cachePMKSA(uchar *,ulong,ether_addr *,uchar *);
    void purgePMKSACache(void);
    void cachePMKSA(uchar *,ulong,ether_addr *);
    void pmksaLookup(ether_addr *,uchar *);
    void getPMKSAList(apple80211_pmk_cache_data *);
    void getExtendedStats(apple80211_extended_stats *);
    void shouldRoam(apple80211_scan_result *);
    void willRoam(ether_addr *,uint);
    void outputPreEnqueueHandler(void *,void *,mbuf_t);
    void stopCountermeasures(OSObject *,IOTimerEventSource *);
    void getOutputQueue(void);
    void setPeerManagerLogFlag(uint,uint,uint);
    void setDebugFlags(ulong long,uint);
    void togglePeerManagerLogFlag(uint,uint);
    void shouldLog(ulong long);
    void vlogDebugBPF(ulong long,char const*,va_list);
    void monitorModeInputPacket(mbuf_t,uint,void *,ulong);
    void bpfTapInput(mbuf_t,uint,void *,ulong);
    void getWmeTxCounters(ulong long *);
    void flushPacketQueues(void);
    void removePacketQueue(IO80211FlowQueueHash const*);
    void pendingPackets(uchar);
    void queueSize(uchar);
    void packetSpace(uchar);
    void findExistingFlowQueue(IO80211FlowQueueHash);
    void outputStart(uint);
    void configureInterface(void);
    void setDataPathState(bool);
    void bpfTap(uint,uint);
    void configureBpfOutputQueues(bool);
    void getOutputQueueForDLT(uint);
    void setPidLock(bool);
    void pidLocked(void);
    void netBooting(void);
    void setNetBooting(bool);
    void netBootThreadGated(OSObject *,void *,void *,void *,void *);
    void netBootThread(IOService *);
    void associateForNetBoot(IOService *);
    void associateForNetBootGated(OSObject *,void *,void *,void *,void *);
    void efiNVRAMPublished(void *,void *,IOService *,IONotifier *);
    void apCompare(apple80211_ap_cmp_data *,apple80211_ap_cmp_data *);
    void setWoWEnabled(bool);
    void shortGISupported40MHz(void);
    void shortGISupported20MHz(void);
    void dequeueTxPackets(uint,uint);
    void dequeueTxPackets(TxPacketRequest *);
    void getControllerWorkLoop(void);
    void printDataPath(userPrintCtx *);
    void printPeers(uint,uint);
protected:
    u_int8_t dat[0x500];
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* ! _IO80211INTERFACE_H */

