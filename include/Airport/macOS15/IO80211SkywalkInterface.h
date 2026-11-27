//
//  IO80211SkywalkInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef _IO80211SKYWALK_H
#define _IO80211SKYWALK_H

#include <Availability.h>
#include "IOSkywalkEthernetInterface.h"

#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

class TxSubmissionDequeueStats;
class TxCompletionEnqueueStats;
class IO80211NetworkPacket;
class PacketSkywalkScratch;
typedef UInt64 IO80211FlowQueueHash;
class IO80211Peer;
class CCPipe;
class IO80211APIUserClient;
struct apple80211_wme_ac;
struct apple80211_interface_availability;
struct apple80211_cca_report;
struct apple80211_stat_report;
struct apple80211_chip_counters_tx;
struct apple80211_chip_counters_rx;
struct apple80211_chip_error_counters_tx;
struct apple80211_ManagementInformationBasedot11_counters;
struct apple80211_lteCoex_report;
struct apple80211_frame_counters;
struct userPrintCtx;
struct apple80211_lqm_summary;
struct apple80211_infra_specific_stats;

struct TxPacketRequest {
    uint16_t    unk1;
    uint16_t    t;
    uint16_t    mU;
    uint16_t    mM;
    uint16_t    pkt_cnt;
    uint16_t    unk2;
    uint16_t    unk3;
    uint16_t    unk4;
    uint32_t    pad;
    mbuf_t      bufs[8];
    uint32_t    reqTx;
};

static_assert(sizeof(struct TxPacketRequest) == 0x60, "TxPacketRequest size error");

class IO80211Controller;
class CCLogStream;

class IO80211SkywalkInterface : public IOSkywalkEthernetInterface {
    OSDeclareAbstractStructors(IO80211SkywalkInterface)
public:
    virtual bool init() override;
    virtual void free() override;
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual bool start(IOService*) override;
    virtual void stop(IOService*) override;
    virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**) override;
    virtual const char* stringFromReturn(int) override;
    virtual int errnoFromReturn(int) override;
    virtual IOReturn setPowerState(unsigned long, IOService*) override;
    virtual unsigned long maxCapabilityForDomainState(unsigned long) override;
    virtual unsigned long initialPowerStateForDomainState(unsigned long) override;
    virtual IOReturn enable(unsigned int) override;
    virtual IOReturn disable(unsigned int) override;
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) override;
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int) override;
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*) override;
    virtual SInt32 setInterfaceEnable(bool) override;
    virtual SInt32 setRunningState(bool) override;
    virtual IOReturn handleChosenMedia(unsigned int) override;
    virtual void * getSupportedMediaArray(unsigned int*, unsigned int*) override;
    virtual UInt32 getFeatureFlags() override;
    virtual const char * classNameOverride() override;
    virtual IOReturn getHardwareAddress(ether_addr*) override;
    virtual IOReturn setHardwareAddress(ether_addr*) override;
    virtual IOReturn setPromiscuousModeEnable(bool, unsigned int) override;
    virtual void * createPeerManager();
private: virtual void _abi_0b10() __asm__("__ZN23IO80211SkywalkInterface10createPeerEPKhP18IO80211PeerManager"); public:
    virtual void postMessage(unsigned int, void*, unsigned long, bool);
    virtual IOReturn reportDataPathEvents(unsigned int, void*, unsigned long, bool);
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats*, TxSubmissionDequeueStats*);
    virtual IOReturn recordOutputPacket(apple80211_wme_ac, int, int);
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool);
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool);
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats*, TxCompletionEnqueueStats*);
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool);
    virtual IOReturn forwardInfraRelayPackets(IO80211NetworkPacket*, ether_header*);
    virtual void logSkywalkTxReqPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, bool);
    virtual SInt64 pendingPackets(unsigned char);
    virtual SInt64 packetSpace(unsigned char);
    virtual bool isChipInterfaceReady();
    virtual bool isDebounceOnGoing();
    virtual bool setLinkState(IO80211LinkState, unsigned int, bool, unsigned int);
    virtual IO80211LinkState linkState();
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int);
    virtual void setDataPathState(bool);
    virtual void * getScanManager();
    virtual IO80211Controller * getController();
    virtual void updateLinkParameters(apple80211_interface_availability*);
    virtual void updateInterfaceCoexRiskPct(unsigned long long);
    virtual void setLQM(unsigned long long);
    virtual void updateLinkStatus();
    virtual void updateLinkStatusGated();
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*);
    virtual void setInterfaceCCA(apple80211_channel, int);
    virtual void setInterfaceNF(apple80211_channel, long long);
    virtual void setInterfaceOFDMDesense(apple80211_channel, long long);
private: virtual void _abi_0bf8() __asm__("__ZN23IO80211SkywalkInterface17removePacketQueueEP20IO80211FlowQueueHash"); public:
    virtual void setDebugFlags(unsigned long long, unsigned int);
    virtual SInt64 debugFlags();
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*);
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*);
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*);
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*);
    virtual SInt64 getWmeTxCounters(unsigned long long*);
    virtual void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int);
    virtual void setWoWEnabled(bool);
    virtual bool wowEnabled();
    virtual void printDataPath(userPrintCtx*);
    virtual UInt32 getDataQueueDepth();
private: virtual void _abi_0c68() __asm__("__ZN23IO80211SkywalkInterface21findOrCreateFlowQueueE20IO80211FlowQueueHash"); public:
private: virtual void _abi_0c70() __asm__("__ZN23IO80211SkywalkInterface30findOrCreateFlowQueueWithCacheE20IO80211FlowQueueHashPb"); public:
private: virtual void _abi_0c78() __asm__("__ZN23IO80211SkywalkInterface21findExistingFlowQueueE20IO80211FlowQueueHash"); public:
private: virtual void _abi_0c80() __asm__("__ZN23IO80211SkywalkInterface17removePacketQueueEPK20IO80211FlowQueueHash"); public:
    virtual void flushPacketQueues();
    virtual void cachePeer(ether_addr*, unsigned int*);
    virtual bool shouldLog(unsigned long long);
    virtual void vlogDebug(unsigned long long, char const*, va_list);
    virtual void vlogDebugBPF(unsigned long long, char const*, va_list);
    virtual UInt64 createLinkQualityMonitor(IO80211Peer*, IOService*);
    virtual void releaseLinkQualityMonitor(IO80211Peer*);
    virtual void * getP2PSkywalkPeerMgr();
    virtual bool isCommandProhibited(int);
private: virtual void _abi_0cd0() __asm__("__ZN23IO80211SkywalkInterface8findPeerER10ether_addr"); public:
    virtual void setNotificationProperty(OSSymbol const*, OSObject const*);
    virtual void * getWorkerMatchingDict(OSString*);
    virtual bool init(IOService*, ether_addr*);
    virtual bool isInterfaceEnabled();
    virtual ether_addr * getSelfMacAddr();
    virtual IOReturn setMacAddress(ether_addr&) = 0;
    virtual void * getPacketPool(OSString*);
    virtual CCLogStream * getLogger() const;
    virtual IOReturn handleSIOCSIFADDR();
    virtual IOReturn debugHandler(apple80211_debug_command*);
    virtual void statsDump();
    virtual void powerOnNotification();
    virtual void powerOffNotification();
    virtual UInt64 getTxQueueDepth();
    virtual UInt64 getRxQueueCapacity();
    virtual void updateRxCounter(unsigned long long);
    virtual void * getMultiCastQueue();
    virtual int getAssocState();
    virtual void notifyQueueState(apple80211_wme_ac, unsigned short);
    virtual int getTxHeadroom();
    virtual void * getRxCompQueue();
    virtual void * getTxCompQueue();
    virtual void * getTxSubQueue(apple80211_wme_ac);
    virtual void * getTxPacketPool();
    virtual void * getRxPacketPool();
    virtual void enableDatapath();
    virtual void disableDatapath();
    virtual int getNumTxQueues();
    virtual void * getLQMSummary(apple80211_lqm_summary*);
    virtual int getEventPipeSize();
    virtual UInt64 createEventPipe(IO80211APIUserClient*);
    virtual void destroyEventPipe(IO80211APIUserClient*);
private: virtual void _abi_0dd0() __asm__("__ZN23IO80211SkywalkInterface17setUserBufferInfoEP18IOMemoryDescriptory"); public:
    virtual void postMessageIOUC(char const*, unsigned int, void*, unsigned long);
    virtual bool isIOUCPipeOpened();
    virtual void * getRingMD(IO80211APIUserClient*, unsigned long long);
private: virtual void _abi_0df0() __asm__("__ZN23IO80211SkywalkInterface10attachPeerEP10ether_addr"); public:
private: virtual void _abi_0df8() __asm__("__ZN23IO80211SkywalkInterface10detachPeerEP10ether_addr"); public:
private: virtual void _abi_0e00() __asm__("__ZN23IO80211SkywalkInterface21setDebugTrafficReportEb"); public:
private: virtual void _abi_0e08() __asm__("__ZN23IO80211SkywalkInterface25getDataPathInterfaceStatsEP36apple80211_data_path_interface_stats"); public:
private: virtual void _abi_0e10() __asm__("__ZN23IO80211SkywalkInterface20getDataPathPeerStatsEP31apple80211_data_path_peer_stats"); public:
private: virtual void _abi_0e18() __asm__("__ZN23IO80211SkywalkInterface22getLastQueuePacketTimeEP10ether_addr"); public:
private: virtual void _abi_0e20() __asm__("__ZN23IO80211SkywalkInterface32getLastRxUnicastLinkActivityTimeEP10ether_addr"); public:
private: virtual void _abi_0e28() __asm__("__ZN23IO80211SkywalkInterface24updateInterfaceDataStatsEP36apple80211_data_path_interface_stats"); public:
private: virtual void _abi_0e30() __asm__("__ZN23IO80211SkywalkInterface19updatePeerDataStatsEP31apple80211_data_path_peer_stats"); public:
private: virtual void _abi_0e38() __asm__("__ZN23IO80211SkywalkInterface12logTxLatencyEPhjy"); public:
private: virtual void _abi_0e40() __asm__("__ZN23IO80211SkywalkInterface12logRxLatencyEjy"); public:
private: virtual void _abi_0e48() __asm__("__ZN23IO80211SkywalkInterface20getNClearTxRxLatencyEP25apple80211_latency_all_acS1_"); public:
private: virtual void _abi_0e50() __asm__("__ZN23IO80211SkywalkInterface18getLastTxTimeStampERy"); public:
private: virtual void _abi_0e58() __asm__("__ZN23IO80211SkywalkInterface18getLastRxTimeStampERy"); public:
private: uint8_t _layout[0x118 - sizeof(IOSkywalkEthernetInterface)];
public:
    OSString *setInterfaceRole(unsigned int);
    void *setInterfaceId(unsigned int);
    int getInterfaceRole();
};
static_assert(sizeof(IO80211SkywalkInterface) == 0x118, "WCL ABI size");
#endif
