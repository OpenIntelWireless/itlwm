//
//  IO80211InfraInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef IO80211InfraInterface_h
#define IO80211InfraInterface_h

struct apple80211_wcl_advisory_info;
struct apple80211_wcl_tx_rx_latency;


class IO80211Controller;
class CCLogStream;
struct mloAddrArray;
struct apple80211_wcl_update_link_state;
struct mloAddrArray;
class IO80211InfraInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211InfraInterface)
public:
    virtual bool init();
    virtual void free();
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*);
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*);
    virtual bool start(IOService*);
    virtual void stop(IOService*);
    virtual IOReturn setPowerState(unsigned long, IOService*);
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**);
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int);
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*);
    virtual SInt32 setInterfaceEnable(bool);
    virtual UInt getHardwareAssists();
    virtual bool bpfTap(unsigned int, unsigned int);
    virtual void hwConfigNicProxyData(nicproxy_info_s*);
    virtual void postMessage(unsigned int, void*, unsigned long, bool);
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats*, TxSubmissionDequeueStats*);
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool);
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool);
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats*, TxCompletionEnqueueStats*);
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool);
    virtual SInt64 pendingPackets(unsigned char);
    virtual SInt64 packetSpace(unsigned char);
    virtual bool isDebounceOnGoing();
    virtual IO80211LinkState linkState();
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int);
    virtual void setDataPathState(bool);
    virtual void * getScanManager();
    virtual void updateLinkParameters(apple80211_interface_availability*);
    virtual void updateInterfaceCoexRiskPct(unsigned long long);
    virtual void setLQM(unsigned long long);
    virtual void updateLinkStatus();
    virtual void updateLinkStatusGated();
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*);
    virtual void setInterfaceCCA(apple80211_channel, int);
    virtual void setInterfaceNF(apple80211_channel, long long);
    virtual void setInterfaceOFDMDesense(apple80211_channel, long long);
    virtual void setDebugFlags(unsigned long long, unsigned int);
    virtual SInt64 debugFlags();
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*);
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*);
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*);
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*);
private: virtual void _abi_0c30() __asm__("__ZN21IO80211InfraInterface19setRxDataStallStatsEP22apple80211_stat_reportP31apple80211_rx_data_stall_report"); public:
    virtual SInt64 getWmeTxCounters(unsigned long long*);
    virtual void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int);
    virtual void setWoWEnabled(bool);
    virtual bool wowEnabled();
    virtual UInt64 createLinkQualityMonitor(IO80211Peer*, bool);
    virtual void releaseLinkQualityMonitor(IO80211Peer*);
    virtual int getAssocState();
    virtual void * getLQMSummary(apple80211_lqm_summary*);
    virtual bool setLinkState(IO80211LinkState, unsigned int, bool, unsigned int, unsigned int);
    virtual IOReturn setLinkStateInternal(IO80211LinkState, unsigned int, bool, unsigned int, unsigned int);
    virtual void setCurrentApAddress(ether_addr*);
    virtual void setWCL_ADVISORTY_INFO(apple80211_wcl_advisory_info*);
    virtual void * getWCL_TX_RX_LATENCY(apple80211_wcl_tx_rx_latency*);
    virtual IOReturn setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state*);
private: virtual void _abi_0e98() __asm__("__ZN21IO80211InfraInterface13createLQMDataEv"); public:
    virtual IOReturn setMacAddress(mloAddrArray&) = 0;
private: uint8_t _layout[0x130 - sizeof(IO80211SkywalkInterface)];
};
static_assert(sizeof(IO80211InfraInterface) == 0x130, "WCL ABI size");
#endif
