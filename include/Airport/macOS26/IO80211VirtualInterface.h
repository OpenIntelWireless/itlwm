// Tahoe 25G241 x86_64 declarations reconstructed from native virtual tables.
// Opaque slots preserve native calls and must not be invoked from driver code.
#pragma once
#include "IO80211SkywalkInterface.h"

class IO80211VirtualInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211VirtualInterface)
public:
    virtual void free();
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*);
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*);
    virtual bool start(IOService*);
    virtual void stop(IOService*);
    virtual bool terminate(IOOptionBits);
    virtual bool attach(IOService*);
    virtual void detach(IOService*);
    virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**);
    virtual const char* stringFromReturn(int);
    virtual IOReturn enable(unsigned int);
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int);
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*);
    virtual SInt32 setInterfaceEnable(bool);
    virtual UInt32 getFeatureFlags();
    virtual bool bpfTap(unsigned int, unsigned int);
    virtual bool setMulticastAddresses(ether_addr const*, unsigned int);
    virtual void * createPeerManager();
    virtual void postMessage(unsigned int, void*, unsigned long, bool);
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool);
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool);
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool);
    virtual void logSkywalkTxReqPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, bool);
    virtual SInt64 pendingPackets(unsigned char);
    virtual SInt64 packetSpace(unsigned char);
    virtual IO80211LinkState linkState();
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int);
    virtual void updateLinkParameters(apple80211_interface_availability*);
    virtual void updateInterfaceCoexRiskPct(unsigned long long);
    virtual void setInterfaceNF(apple80211_channel, long long);
    virtual void setDebugFlags(unsigned long long, unsigned int);
    virtual SInt64 debugFlags();
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*);
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*);
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*);
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*);
    virtual SInt64 getWmeTxCounters(unsigned long long*);
    virtual void setWoWEnabled(bool);
    virtual bool wowEnabled();
    virtual void printDataPath(userPrintCtx*);
    private: virtual void _abi_0c68() __asm__("__ZN23IO80211VirtualInterface21findOrCreateFlowQueueE20IO80211FlowQueueHash"); public:
    private: virtual void _abi_0c70() __asm__("__ZN23IO80211VirtualInterface30findOrCreateFlowQueueWithCacheE20IO80211FlowQueueHashPb"); public:
    private: virtual void _abi_0c78() __asm__("__ZN23IO80211VirtualInterface21findExistingFlowQueueE20IO80211FlowQueueHash"); public:
    private: virtual void _abi_0c80() __asm__("__ZN23IO80211VirtualInterface17removePacketQueueEPK20IO80211FlowQueueHash"); public:
    virtual void flushPacketQueues();
    virtual void cachePeer(ether_addr*, unsigned int*);
    virtual bool shouldLog(unsigned long long);
    virtual void vlogDebug(unsigned long long, char const*, va_list);
    virtual void vlogDebugBPF(unsigned long long, char const*, va_list);
    virtual void * getP2PSkywalkPeerMgr();
    private: virtual void _abi_0cd0() __asm__("__ZN23IO80211VirtualInterface8findPeerER10ether_addr"); public:
    virtual int getEventPipeSize();
    virtual UInt64 createEventPipe(IO80211APIUserClient*);
    virtual bool init(IO80211Controller*, ether_addr*, unsigned int, const char*);
private: virtual void _abi_0e70() __asm__("__ZN23IO80211VirtualInterface12setLinkStateE16IO80211LinkStatej"); public:
private: virtual void _abi_0e78() __asm__("__ZN23IO80211VirtualInterface13forwardPacketEP20IO80211NetworkPacket"); public:
private: virtual void _abi_0e80() __asm__("__ZN23IO80211VirtualInterface11handleIoctlEP7__ifnetmPv"); public:
private: virtual void _abi_0e88() __asm__("__ZN23IO80211VirtualInterface14addPeerToCacheEPh"); public:
private: virtual void _abi_0e90() __asm__("__ZN23IO80211VirtualInterface19deletePeerFromCacheEPh"); public:
private: virtual void _abi_0e98() __asm__("__ZN23IO80211VirtualInterface14handleDebugCmdEP24apple80211_debug_command"); public:
private: virtual void _abi_0ea0() __asm__("__ZN23IO80211VirtualInterface20getPeerSlotDataStatsEP10ether_addrbP17peerSlotDataStats"); public:
private: virtual void _abi_0ea8() __asm__("__ZN23IO80211VirtualInterface16getPeerDataStatsEP10ether_addrbP16packetCounters_t"); public:
private: virtual void _abi_0eb0() __asm__("__ZN23IO80211VirtualInterface18clearPeerDataStatsEP10ether_addrb"); public:
private: virtual void _abi_0eb8() __asm__("__ZN23IO80211VirtualInterface34setAwdlCurrentChannelSequenceIndexEj"); public:
private: virtual void _abi_0ec0() __asm__("__ZN23IO80211VirtualInterface22isOutputFlowControlledEv"); public:
private: virtual void _abi_0ec8() __asm__("__ZN23IO80211VirtualInterface23setOutputFlowControlledEv"); public:
private: virtual void _abi_0ed0() __asm__("__ZN23IO80211VirtualInterface25clearOutputFlowControlledEv"); public:
private: virtual void _abi_0ed8() __asm__("__ZN23IO80211VirtualInterface15flushFlowQueuesEP10ether_addr"); public:
private: virtual void _abi_0ee0() __asm__("__ZN23IO80211VirtualInterface18configureAQMOutputEv"); public:
private: virtual void _abi_0ee8() __asm__("__ZN23IO80211VirtualInterface11attachToBpfEv"); public:
private: virtual void _abi_0ef0() __asm__("__ZN23IO80211VirtualInterface14configureIfnetEv"); public:
private: virtual void _abi_0ef8() __asm__("__ZN23IO80211VirtualInterface5resetEv"); public:
private: virtual void _abi_0f00() __asm__("__ZN23IO80211VirtualInterface25dupAndTransmitMcastPacketEP20IO80211NetworkPacketPhS2_"); public:
private: virtual void _abi_0f08() __asm__("__ZN23IO80211VirtualInterface19freeMulticastPacketEP20IO80211NetworkPacket"); public:
private: virtual void _abi_0f10() __asm__("__ZN23IO80211VirtualInterface22triggerAWDLMulticastTxEjh"); public:
private: virtual void _abi_0f18() __asm__("__ZN23IO80211VirtualInterface14p2pMulticastTxEPP20IO80211NetworkPacketj"); public:
private: virtual void _abi_0f20() __asm__("__ZN23IO80211VirtualInterface14p2pMulticastTxEjb"); public:
private: virtual void _abi_0f28() __asm__("__ZN23IO80211VirtualInterface22signalMulticastPacketsEjj"); public:
private: virtual void _abi_0f30() __asm__("__ZN23IO80211VirtualInterface25sendPendingPacketsToStackEPP20IO80211NetworkPacketj"); public:
private: virtual void _abi_0f38() __asm__("__ZN23IO80211VirtualInterface18freePendingPacketsEPP20IO80211NetworkPacketj"); public:
    virtual IOReturn setMacAddress(ether_addr&) = 0;
private: virtual void _abi_0f48() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface0Ev"); public:
private: virtual void _abi_0f50() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface1Ev"); public:
private: virtual void _abi_0f58() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface2Ev"); public:
private: virtual void _abi_0f60() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface3Ev"); public:
private: virtual void _abi_0f68() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface4Ev"); public:
private: virtual void _abi_0f70() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface5Ev"); public:
private: virtual void _abi_0f78() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface6Ev"); public:
private: virtual void _abi_0f80() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface7Ev"); public:
private: virtual void _abi_0f88() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface8Ev"); public:
private: virtual void _abi_0f90() __asm__("__ZN23IO80211VirtualInterface33_RESERVEDIO80211VirtualInterface9Ev"); public:
private: virtual void _abi_0f98() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface10Ev"); public:
private: virtual void _abi_0fa0() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface11Ev"); public:
private: virtual void _abi_0fa8() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface12Ev"); public:
private: virtual void _abi_0fb0() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface13Ev"); public:
private: virtual void _abi_0fb8() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface14Ev"); public:
private: virtual void _abi_0fc0() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface15Ev"); public:
private:
    uint8_t _virtualLayout[0x130-sizeof(IO80211SkywalkInterface)];
};
static_assert(sizeof(IO80211VirtualInterface)==0x130, "Tahoe virtual interface ABI");
