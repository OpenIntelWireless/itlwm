//
//  IO80211Controller.h
//  IO80211Family
//

#ifndef _IO80211CONTROLLER_H
#define _IO80211CONTROLLER_H

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

#include <sys/kpi_mbuf.h>

#include <IOKit/network/IOEthernetController.h>

#include <sys/param.h>
#include <net/bpf.h>

#include "apple80211_ioctl.h"
#include "IO80211WorkLoop.h"

#define AUTH_TIMEOUT            15    // seconds

/*! @enum LinkSpeed.
 @abstract ???.
 @discussion ???.
 @constant LINK_SPEED_80211A 54 Mbps
 @constant LINK_SPEED_80211B 11 Mbps.
 @constant LINK_SPEED_80211G 54 Mbps.
 */
enum {
    LINK_SPEED_80211A    = 54000000ul,        // 54 Mbps
    LINK_SPEED_80211B    = 11000000ul,        // 11 Mbps
    LINK_SPEED_80211G    = 54000000ul,        // 54 Mbps
    LINK_SPEED_80211N    = 300000000ul,        // 300 Mbps (MCS index 15, 400ns GI, 40 MHz channel)
};

enum IO80211CountryCodeOp
{
    kIO80211CountryCodeReset,                // Reset country code to world wide default, and start
    // searching for 802.11d beacon
};
typedef enum IO80211CountryCodeOp IO80211CountryCodeOp;

enum IO80211SystemPowerState
{
    kIO80211SystemPowerStateUnknown,
    kIO80211SystemPowerStateAwake,
    kIO80211SystemPowerStateSleeping,
};
typedef enum IO80211SystemPowerState IO80211SystemPowerState;

enum IO80211FeatureCode
{
    kIO80211Feature80211n = 1,
};
typedef enum IO80211FeatureCode IO80211FeatureCode;


class IOSkywalkInterface;
class IO80211ScanManager;
enum CCStreamLogLevel
{
    LEVEL_1,
};

enum scanSource
{
    SOURCE_1,
};

enum joinStatus
{
    STATUS_1,
};

class IO80211SkywalkInterface;
class IO80211Controller;
class IO80211Interface;
class IO82110WorkLoop;
class IO80211VirtualInterface;
class IO80211ControllerMonitor;
class CCLogPipe;
class CCIOReporterLogStream;
class CCLogStream;
class IO80211VirtualInterface;
class IO80211RangingManager;
class IO80211FlowQueue;
class IO80211FlowQueueLegacy;
class FlowIdMetadata;
class IOReporter;
#if __IO80211_TARGET >= __MAC_11_0
class IO80211InfraInterface;
#endif
extern void IO80211VirtualInterfaceNamerRetain();


struct apple80211_hostap_state;

struct apple80211_awdl_sync_channel_sequence;
struct ieee80211_ht_capability_ie;
struct apple80211_channel_switch_announcement;
struct apple80211_beacon_period_data;
struct apple80211_power_debug_sub_info;
struct apple80211_stat_report;
struct apple80211_frame_counters;
struct apple80211_leaky_ap_event;
struct apple80211_chip_stats;
struct apple80211_extended_stats;
struct apple80211_ampdu_stat_report;
struct apple80211_btCoex_report;
struct apple80211_cca_report;
class CCPipe;
struct apple80211_lteCoex_report;

//typedef int scanSource;
//typedef int joinStatus;
//typedef int CCStreamLogLevel;
typedef IOReturn (*IOCTL_FUNC)(IO80211Controller*, IO80211Interface*, IO80211VirtualInterface*, apple80211req*, bool);
extern IOCTL_FUNC gGetHandlerTable[];
extern IOCTL_FUNC gSetHandlerTable[];

class IO80211Controller : public IOEthernetController {
    OSDeclareAbstractStructors(IO80211Controller)

public:

    virtual void free() APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET <= __MAC_10_15
    virtual bool terminate(unsigned int) APPLE_KEXT_OVERRIDE;
#endif
    virtual bool init(OSDictionary *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *) APPLE_KEXT_OVERRIDE;
    virtual IOService* getProvider(void) const APPLE_KEXT_OVERRIDE;
    virtual IOWorkLoop* getWorkLoop(void) const APPLE_KEXT_OVERRIDE;
    virtual const char* stringFromReturn(int) APPLE_KEXT_OVERRIDE;
    virtual int errnoFromReturn(int) APPLE_KEXT_OVERRIDE;
    virtual IOOutputQueue* getOutputQueue(void) const APPLE_KEXT_OVERRIDE;
    virtual bool createWorkLoop(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enable(IONetworkInterface *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn disable(IONetworkInterface *) APPLE_KEXT_OVERRIDE;
    virtual bool attachInterface(IONetworkInterface **, bool attach = true) APPLE_KEXT_OVERRIDE;
#if __IO80211_TARGET >= __MAC_10_15
    virtual void detachInterface(IONetworkInterface *, bool sync = false) APPLE_KEXT_OVERRIDE;
#endif
    virtual IONetworkInterface* createInterface(void) APPLE_KEXT_OVERRIDE;
    virtual bool configureInterface(IONetworkInterface *) APPLE_KEXT_OVERRIDE;
#ifdef __PRIVATE_SPI__
    virtual IOReturn outputStart(IONetworkInterface *,UInt) APPLE_KEXT_OVERRIDE;
#endif
    virtual IOReturn getHardwareAddress(IOEthernetAddress *) APPLE_KEXT_OVERRIDE;
    virtual void requestPacketTx(void*, UInt);
    virtual IOReturn getHardwareAddressForInterface(IO80211Interface *,IOEthernetAddress *);
    virtual void inputMonitorPacket(mbuf_t,UInt,void *,unsigned long);
    virtual int outputRaw80211Packet(IO80211Interface *,mbuf_t);
    virtual int outputActionFrame(IO80211Interface *,mbuf_t);
    virtual int bpfOutputPacket(OSObject *,UInt,mbuf_t m);
    virtual SInt32 monitorModeSetEnabled(IO80211Interface*, bool, UInt);
    virtual IO80211Interface* getNetworkInterface(void);
#if __IO80211_TARGET >= __MAC_10_15
    virtual IO80211SkywalkInterface* getPrimarySkywalkInterface(void);
#endif
    virtual SInt32 apple80211_ioctl(IO80211Interface *, IO80211VirtualInterface*, ifnet_t,unsigned long,void *);
#if __IO80211_TARGET >= __MAC_10_15
    virtual SInt32 apple80211_ioctl(IO80211SkywalkInterface *,unsigned long,void *);
#endif
    virtual SInt32 apple80211_ioctl(IO80211Interface *interface, ifnet_t net,unsigned long id,void *data) {
        return apple80211_ioctl(interface, NULL, net, id, data);
    }
    virtual SInt32 apple80211Request(unsigned int, int, IO80211Interface*, void*) = 0;
    virtual SInt32 apple80211VirtualRequest(UInt,int,IO80211VirtualInterface *,void *);
#if __IO80211_TARGET >= __MAC_10_15
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *);
#endif
    virtual SInt32 stopDMA() = 0;
    virtual UInt32 hardwareOutputQueueDepth(IO80211Interface*) = 0;
    virtual SInt32 performCountryCodeOperation(IO80211Interface*, IO80211CountryCodeOp) = 0;
    virtual bool useAppleRSNSupplicant(IO80211Interface *);
    virtual bool useAppleRSNSupplicant(IO80211VirtualInterface *);
    virtual void dataLinkLayerAttachComplete(IO80211Interface *);
    virtual SInt32 enableFeature(IO80211FeatureCode, void*) = 0;
    virtual SInt32 setVirtualHardwareAddress(IO80211VirtualInterface *,ether_addr *);
    virtual SInt32 enableVirtualInterface(IO80211VirtualInterface *);
    virtual SInt32 disableVirtualInterface(IO80211VirtualInterface *);
    virtual bool requiresExplicitMBufRelease() {
        return false;
    }
    virtual bool flowIdSupported() {
        return false;
    }
    virtual IO80211FlowQueueLegacy* requestFlowQueue(FlowIdMetadata const*);
    virtual void releaseFlowQueue(IO80211FlowQueue *);
#if __IO80211_TARGET >= __MAC_10_15
    virtual void getLogPipes(CCPipe**, CCPipe**, CCPipe**) {};
#endif
    virtual IOReturn enablePacketTimestamping(void) {
        return kIOReturnUnsupported;
    }
    virtual IOReturn disablePacketTimestamping(void) {
        return kIOReturnUnsupported;
    }
    virtual UInt32 selfDiagnosticsReport(int,char const*,UInt);
    virtual UInt32 getDataQueueDepth(OSObject *);
#if __IO80211_TARGET >= __MAC_11_0
    virtual bool isAssociatedToMovingNetwork(void) { return false; }
#endif
    virtual mbuf_flags_t inputPacket(mbuf_t);
    virtual SInt32 apple80211_ioctl_get(IO80211Interface *,IO80211VirtualInterface *,ifnet_t,void *);
    
    
#if __IO80211_TARGET >= __MAC_10_15
    virtual SInt32 apple80211_ioctl_get(IO80211SkywalkInterface *,void *);
    virtual SInt32 apple80211_ioctl_set(IO80211Interface *,IO80211VirtualInterface *,IO80211SkywalkInterface *,void *);
    virtual SInt32 apple80211_ioctl_set(IO80211SkywalkInterface *,void*);
    virtual bool attachInterface(IOSkywalkInterface *,IOService *);
#else
    virtual SInt32 apple80211_ioctl_set(IO80211Interface *,IO80211VirtualInterface *,ifnet_t,void *);
#endif
    
    
#if __IO80211_TARGET >= __MAC_11_0
    virtual bool detachInterface(IOSkywalkInterface *, bool);
#endif
    virtual IO80211VirtualInterface* createVirtualInterface(ether_addr *,UInt);
    virtual bool attachVirtualInterface(IO80211VirtualInterface **,ether_addr *,UInt,bool);
    virtual bool detachVirtualInterface(IO80211VirtualInterface *,bool);
#if __IO80211_TARGET >= __MAC_10_15
    virtual IOReturn enable(IO80211SkywalkInterface *);
    virtual IOReturn disable(IO80211SkywalkInterface *);
#endif
    
public:
#if __IO80211_TARGET >= __MAC_11_0
    void setDisplayState(bool);
    void resetIO80211ReporterHistory(void);
    bool markInterfaceUnitUnused(char const*,UInt);
    bool markInterfaceUnitUsed(char const*,UInt);
    bool assignUnitNumber(char const*);
#endif
#if __IO80211_TARGET >= __MAC_10_15
    IO80211SkywalkInterface* getInfraInterface(void);
    IO80211ScanManager* getPrimaryInterfaceScanManager(void);
    IO80211ControllerMonitor* getInterfaceMonitor(void);
#endif
    IOReturn addReporterLegend(IOService *,IOReporter *,char const*,char const*);
    IOReturn removeReporterFromLegend(IOService *,IOReporter *,char const*,char const*);
    IOReturn unlockIOReporterLegend(void);
    void lockIOReporterLegend(void);// Suspected return type - int
    IOReturn logIOReportLogStreamSubscription(unsigned long long);
    IOReturn addIOReportLogStreamForProvider(IOService *,unsigned long long *);
    IOReturn addSubscriptionForThisReporterFetchedOnTimer(IOReporter *,char const*,char const*,IOService *) ;
    IOReturn addSubscriptionForProviderFetchedOnTimer(IOService *);
    void handleIOReporterTimer(IOTimerEventSource *);
    void setIOReportersStreamFlags(unsigned long long);
    void updateIOReportersStreamFrequency(void); // Suspected return type - int
    void setIOReportersStreamLevel(CCStreamLogLevel);
    void powerChangeGated(OSObject *,void *,void *,void *,void *);
    int copyOut(void const*,unsigned long long,unsigned long);
#if __IO80211_TARGET >= __MAC_11_0
    SInt32 getASSOCIATE_EXTENDED_RESULT(IO80211Interface *,IO80211VirtualInterface *,IO80211InfraInterface *,apple80211_assoc_result_data *);
#endif
    SInt32 getASSOCIATE_RESULT(IO80211Interface *,IO80211VirtualInterface *,IO80211SkywalkInterface *,apple80211_assoc_result_data *);
    IOReturn copyIn(unsigned long long,void *,unsigned long);
    void logIOCTL(apple80211req *);
    bool isIOCTLLoggingRestricted(apple80211req *);
    IOReturn setChanNoiseFloorLTE(apple80211_stat_report *,int);
    IOReturn setChanNoiseFloor(apple80211_stat_report *,int);
    IOReturn setChanCCA(apple80211_stat_report *,int);
    IOReturn setChanExtendedCCA(apple80211_stat_report *,apple80211_cca_report *);
    bool setLTECoexstat(apple80211_stat_report *,apple80211_lteCoex_report *);
    bool setBTCoexstat(apple80211_stat_report *,apple80211_btCoex_report *);
    bool setAMPDUstat(apple80211_stat_report *,apple80211_ampdu_stat_report *,apple80211_channel *);
    UInt32 getCountryCode(apple80211_country_code_data *);
    IOReturn setCountryCode(apple80211_country_code_data *);
    bool getInfraExtendedStats(apple80211_extended_stats *);
    bool getChipCounterStats(apple80211_chip_stats *);
#if __IO80211_TARGET >= __MAC_10_15
    bool setExtendedChipCounterStats(apple80211_stat_report *,void *);
#endif
    bool setChipCounterStats(apple80211_stat_report *,apple80211_chip_stats *,apple80211_channel *);
    bool setLeakyAPStats(apple80211_leaky_ap_event *);
    bool setFrameStats(apple80211_stat_report *,apple80211_frame_counters *,apple80211_channel *);
    bool setPowerStats(apple80211_stat_report *,apple80211_power_debug_sub_info *);
    bool getBeaconPeriod(apple80211_beacon_period_data *);
    SInt32 apple80211VirtualRequestIoctl(unsigned int,int,IO80211VirtualInterface *,void *);
    bool getBSSIDData(OSObject *,apple80211_bssid_data *);
    bool getSSIDData(apple80211_ssid_data *);
    bool inputInfraPacket(mbuf_t);
#if __IO80211_TARGET >= __MAC_10_15
    void notifyHostapState(apple80211_hostap_state *);
#endif
    bool isAwdlAssistedDiscoveryEnabled(void);
    void joinDone(scanSource,joinStatus);
    void joinStarted(scanSource,joinStatus);
    void handleChannelSwitchAnnouncement(apple80211_channel_switch_announcement *);
    void scanDone(scanSource,int);
    void scanStarted(scanSource,apple80211_scan_data *);
    void printChannels(void);
#if __IO80211_TARGET >= __MAC_10_15
    void updateInterfaceCoexRiskPct(unsigned long long);
#endif
    SInt32 getInfraChannel(apple80211_channel_data *);
    void calculateInterfacesAvaiability(void); // Suspected return type - int
    void setChannelSequenceList(apple80211_awdl_sync_channel_sequence *); // Suspected return type - int
#if __IO80211_TARGET >= __MAC_10_15
    void setPrimaryInterfaceDatapathState(bool);
    UInt32 getPrimaryInterfaceLinkState(void);
#endif
    void setCurrentChannel(apple80211_channel *); // Suspected return type - int
    void setHtCapability(ieee80211_ht_capability_ie *);
    UInt32 getHtCapability(void);
    UInt32 getHtCapabilityLength(void);
    bool io80211isDebuggable(bool* enable);
    void logDebug(unsigned long long,char const*,...); // Suspected return type - int
    void vlogDebug(unsigned long long,char const*,va_list); // Suspected return type - char
    void logDebug(char const*,...); // Suspected return type - int
    bool calculateInterfacesCoex(void);
    void setInfraChannel(apple80211_channel *);
#if __IO80211_TARGET >= __MAC_10_15
    void configureAntennae(void);
#endif
    SInt32 apple80211RequestIoctl(unsigned int,int,IO80211Interface *,void *);
    UInt32 radioCountForInterface(IO80211Interface *);
    void releaseIOReporters(void);
#if __IO80211_TARGET >= __MAC_10_15
    bool findAndAttachToFaultReporter(void);
#endif
    UInt32 setupControlPathLogging(void);
    IOReturn createIOReporters(IOService *);
    IOReturn powerChangeHandler(void *,void *,unsigned int,IOService *,void *,unsigned long);
    
    OSMetaClassDeclareReservedUnused( IO80211Controller,  0);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  1);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  2);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  3);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  4);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  5);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  6);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  7);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  8);
    OSMetaClassDeclareReservedUnused( IO80211Controller,  9);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 10);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 11);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 12);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 13);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 14);
    OSMetaClassDeclareReservedUnused( IO80211Controller, 15);

protected:
    uint8_t  filler[0x500];
};

// 0x215: 1 byte, length of channel sequence, should be 16
// 0x21c: channel sequence, should contain 16 elements of length 12, possibly apple80211_channel (but why 16?)
// struct of three ints, last looks like flags, first unused

/*
 void __thiscall
setChannelSequenceList(IO80211Controller *this,apple80211_awdl_sync_channel_sequence *param_1)

{
  _memcpy(this + 0x210,param_1,400);
  calculateInterfacesAvaiability(this);
  return;
}
*/


#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IO80211CONTROLLER_H */
