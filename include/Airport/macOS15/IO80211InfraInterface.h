//
//  IO80211InfraInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef IO80211InfraInterface_h
#define IO80211InfraInterface_h

struct apple80211_wcl_advisory_info;
struct apple80211_wcl_tx_rx_latency;

class IO80211Controller;
class CCLogStream;
struct apple80211_wcl_update_link_state;
class IO80211InfraInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211InfraInterface)
public:
    virtual bool init() override;
    virtual void free() override;
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual bool start(IOService*) override;
    virtual void stop(IOService*) override;
    virtual IOReturn setPowerState(unsigned long, IOService*) override;
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) override;
    virtual IOReturn prepareBSDInterface(struct __ifnet*, unsigned int) override;
    virtual IOReturn processBSDCommand(struct __ifnet*, unsigned int, void*) override;
    virtual SInt32 setInterfaceEnable(bool) override;
    virtual UInt getHardwareAssists() override;
    virtual bool bpfTap(unsigned int, unsigned int) override;
    virtual void hwConfigNicProxyData(nicproxy_info_s*) override;
    virtual void postMessage(unsigned int, void*, unsigned long, bool) override;
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats*, TxSubmissionDequeueStats*) override;
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool) override;
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool) override;
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats*, TxCompletionEnqueueStats*) override;
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool) override;
    virtual SInt64 pendingPackets(unsigned char) override;
    virtual SInt64 packetSpace(unsigned char) override;
    virtual bool isDebounceOnGoing() override;
    virtual IO80211LinkState linkState() override;
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int) override;
    virtual void setDataPathState(bool) override;
    virtual void * getScanManager() override;
    virtual void updateLinkParameters(apple80211_interface_availability*) override;
    virtual void updateInterfaceCoexRiskPct(unsigned long long) override;
    virtual void setLQM(unsigned long long) override;
    virtual void updateLinkStatus() override;
    virtual void updateLinkStatusGated() override;
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*) override;
    virtual void setInterfaceCCA(apple80211_channel, int) override;
    virtual void setInterfaceNF(apple80211_channel, long long) override;
    virtual void setInterfaceOFDMDesense(apple80211_channel, long long) override;
    virtual void setDebugFlags(unsigned long long, unsigned int) override;
    virtual SInt64 debugFlags() override;
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*) override;
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*) override;
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*) override;
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*) override;
    virtual SInt64 getWmeTxCounters(unsigned long long*) override;
    virtual void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int) override;
    virtual void setWoWEnabled(bool) override;
    virtual bool wowEnabled() override;
    virtual UInt64 createLinkQualityMonitor(IO80211Peer*, IOService*) override;
    virtual void releaseLinkQualityMonitor(IO80211Peer*) override;
    virtual int getAssocState() override;
    virtual void * getLQMSummary(apple80211_lqm_summary*) override;
    virtual bool setLinkState(IO80211LinkState, unsigned int, bool, unsigned int) override;
    virtual IOReturn setLinkStateInternal(IO80211LinkState, unsigned int, bool, unsigned int);
    virtual void setCurrentApAddress(ether_addr*);
    virtual void setWCL_ADVISORTY_INFO(apple80211_wcl_advisory_info*);
    virtual void * getWCL_TX_RX_LATENCY(apple80211_wcl_tx_rx_latency*);
private: virtual void _abi_0e98() __asm__("__ZN21IO80211InfraInterface13createLQMDataEv"); public:
private: uint8_t _layout[0x120 - sizeof(IO80211SkywalkInterface)];
};
static_assert(sizeof(IO80211InfraInterface) == 0x120, "WCL ABI size");
#endif
