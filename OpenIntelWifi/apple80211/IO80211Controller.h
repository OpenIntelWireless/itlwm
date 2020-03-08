#ifndef _IO80211CONTROLLER_H
#define _IO80211CONTROLLER_H

#if defined(KERNEL) && defined(__cplusplus)

#include <libkern/version.h>

#if VERSION_MAJOR > 8
#define _MODERN_BPF
#endif

#include <sys/kpi_mbuf.h>

#include <IOKit/network/IOEthernetController.h>
//#include "IOEthernetController.h"

#include <sys/param.h>
#include <net/bpf.h>

#include "apple80211_ioctl.h"
#include "IO80211SkywalkInterface.h"
#include "IO80211WorkLoop.h"
#include "IO80211FlowQueue.h"

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
class IO80211FlowQueueLegacy;
class FlowIdMetadata;
class IOReporter;
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
struct apple80211_lteCoex_report;

//typedef int scanSource;
//typedef int joinStatus;
//typedef int CCStreamLogLevel;
typedef IOReturn (*IOCTL_FUNC)(IO80211Controller*, IO80211Interface*, IO80211VirtualInterface*, apple80211req*, bool);
extern IOCTL_FUNC gGetHandlerTable[];
extern IOCTL_FUNC gSetHandlerTable[];

#define __int64 int
#define ulong unsigned long
#define _QWORD UInt64
#define uint UInt

class IO80211Controller : public IOEthernetController {
    OSDeclareAbstractStructors(IO80211Controller)
    
public:
    virtual IO80211SkywalkInterface* getInfraInterface(void)
    {
        return NULL;
    };
    virtual IO80211ScanManager* getPrimaryInterfaceScanManager(void)
    {
        return NULL;
    };
    virtual IO80211ControllerMonitor* getInterfaceMonitor(void)
    {
        return NULL;
    };
    virtual IOReturn updateReport(IOReportChannelList *,uint,void *,void *) override
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn configureReport(IOReportChannelList *,uint,void *,void *) override
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn addReporterLegend(IOService *,IOReporter *,char const*,char const*)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn removeReporterFromLegend(IOService *,IOReporter *,char const*,char const*)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn unlockIOReporterLegend(void)
    {
        return kIOReturnSuccess;
    };
    virtual void lockIOReporterLegend(void){};//怀疑对象，之前是返回int
    virtual IOReturn logIOReportLogStreamSubscription(ulong long)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn addIOReportLogStreamForProvider(IOService *,ulong long *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn addSubscriptionForThisReporterFetchedOnTimer(IOReporter *,char const*,char const*,IOService *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn addSubscriptionForProviderFetchedOnTimer(IOService *)
    {
        return kIOReturnSuccess;
    };
    virtual void handleIOReporterTimer(IOTimerEventSource *){};//怀疑对象，之前是返回int
    virtual void setIOReportersStreamFlags(ulong long){};//怀疑对象，之前是返回int
    virtual void updateIOReportersStreamFrequency(void){};//怀疑对象，之前是返回int
    virtual void setIOReportersStreamLevel(CCStreamLogLevel){};//怀疑对象，之前是返回int
    virtual SInt32 apple80211Request(unsigned int, int, IO80211Interface*, void*) {return kIOReturnSuccess;};
    virtual SInt32 apple80211SkywalkRequest(uint,int,IO80211SkywalkInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211VirtualRequest(uint,int,IO80211VirtualInterface *,void *){ return EOPNOTSUPP; };
    virtual SInt32 disableVirtualInterface(IO80211VirtualInterface *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 enableVirtualInterface(IO80211VirtualInterface *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 setVirtualHardwareAddress(IO80211VirtualInterface *,ether_addr *)
    {
        return kIOReturnSuccess;
    };
    virtual UInt32 getDataQueueDepth(OSObject *)
    {
        return kIOReturnSuccess;
    };
    virtual void powerChangeGated(OSObject *,void *,void *,void *,void *){};//怀疑对象，之前是返回int
    virtual int copyOut(void const*,ulong long,ulong)
    {
        return kIOReturnSuccess;
    };
    virtual int bpfOutputPacket(OSObject *,uint,mbuf_t) { return ENXIO; };
    virtual void requestPacketTx(void *,uint){};//怀疑对象，之前是返回int
    virtual int outputActionFrame(IO80211Interface *,mbuf_t)
    {
        return kIOReturnSuccess;
    };
    virtual int outputRaw80211Packet(IO80211Interface *,mbuf_t){ return ENXIO; };
    virtual IOReturn getHardwareAddressForInterface(IO80211Interface *,IOEthernetAddress *)
    {
        return kIOReturnSuccess;
    };
    virtual bool useAppleRSNSupplicant(IO80211VirtualInterface *){ return true; };
    virtual bool useAppleRSNSupplicant(IO80211Interface *){ return true; };
    virtual void dataLinkLayerAttachComplete(IO80211Interface *){};//怀疑对象，之前是返回int
    virtual IO80211VirtualInterface* createVirtualInterface(ether_addr *,uint)
    {
        return NULL;
    };
    virtual bool detachVirtualInterface(IO80211VirtualInterface *,bool)
    {
        return true;
    };
    virtual bool attachVirtualInterface(IO80211VirtualInterface **,ether_addr *,uint,bool)
    {
        return true;
    };
    virtual bool attachInterface(IOSkywalkInterface *,IOService *)
    {
        return true;
    };
    virtual void detachInterface(IONetworkInterface *,bool) override{};
    virtual bool attachInterface(IONetworkInterface **,bool) override
    {
        return true;
    };
    virtual IOService* getProvider(void)
    {
        return NULL;
    };
    virtual SInt32 getASSOCIATE_RESULT(IO80211Interface *,IO80211VirtualInterface *,IO80211SkywalkInterface *,apple80211_assoc_result_data *)
    {
        return kIOReturnSuccess;
    };
    virtual int errnoFromReturn(int) override
    {
        return kIOReturnSuccess;
    };
    virtual const char* stringFromReturn(int) override
    {
        return "";
    };
    virtual SInt32 apple80211_ioctl_set(IO80211SkywalkInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl_set(IO80211Interface *,IO80211VirtualInterface *,ifnet_t,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl_set(IO80211Interface *,IO80211VirtualInterface *,IO80211SkywalkInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl_get(IO80211SkywalkInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl_get(IO80211Interface *,IO80211VirtualInterface *,ifnet_t,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl_get(IO80211Interface *,IO80211VirtualInterface *,IO80211SkywalkInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn copyIn(ulong long,void *,ulong)
    {
        return kIOReturnSuccess;
    };
    virtual void logIOCTL(apple80211req *){};
    virtual bool isIOCTLLoggingRestricted(apple80211req *)
    {
        return kIOReturnSuccess;
    };
    virtual void inputMonitorPacket(mbuf_t,uint,void *,ulong){};//怀疑对象，之前是返回int
    virtual SInt32 apple80211_ioctl(IO80211SkywalkInterface *,ulong,void *)
    {
        return kIOReturnSuccess;
    };
    virtual SInt32 apple80211_ioctl(IO80211Interface *,IO80211VirtualInterface *,ifnet_t,ulong,void *)
    {
        return kIOReturnSuccess;
    };
    virtual IONetworkInterface* createInterface(void) override
    {
        return NULL;
    };
    virtual IOReturn getHardwareAddress(IOEthernetAddress *) override
    {
        return kIOReturnSuccess;
    };
    virtual IO80211SkywalkInterface* getPrimarySkywalkInterface(void)
    {
        return NULL;
    };
    virtual IO80211Interface* getNetworkInterface(void)
    {
        return NULL;
    };
    virtual IOWorkLoop* getWorkLoop(void)
    {
        return NULL;
    };
    virtual bool createWorkLoop(void) override
    {
        return true;
    };
    virtual mbuf_flags_t inputPacket(mbuf_t)
    {
        return 0;
    };
    virtual IOReturn outputStart(IONetworkInterface *,uint)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn setChanNoiseFloorLTE(apple80211_stat_report *,int)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn setChanNoiseFloor(apple80211_stat_report *,int)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn setChanCCA(apple80211_stat_report *,int)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn setChanExtendedCCA(apple80211_stat_report *,apple80211_cca_report *)
    {
        return kIOReturnSuccess;
    };
    virtual bool setLTECoexstat(apple80211_stat_report *,apple80211_lteCoex_report *)
    {
        return true;
    };
    virtual bool setBTCoexstat(apple80211_stat_report *,apple80211_btCoex_report *)
    {
        return true;
    };
    virtual bool setAMPDUstat(apple80211_stat_report *,apple80211_ampdu_stat_report *,apple80211_channel *)
    {
        return true;
    };
    virtual UInt32 getCountryCode(apple80211_country_code_data *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn setCountryCode(apple80211_country_code_data *)
    {
        return kIOReturnSuccess;
    };
    virtual bool getInfraExtendedStats(apple80211_extended_stats *)
    {
        return true;
    };
    virtual bool getChipCounterStats(apple80211_chip_stats *)
    {
        return true;
    };
    virtual bool setExtendedChipCounterStats(apple80211_stat_report *,void *)
    {
        return true;
    };
    virtual bool setChipCounterStats(apple80211_stat_report *,apple80211_chip_stats *,apple80211_channel *)
    {
        return true;
    };
    virtual bool setLeakyAPStats(apple80211_leaky_ap_event *)
    {
        return true;
    };
    virtual bool setFrameStats(apple80211_stat_report *,apple80211_frame_counters *,apple80211_channel *)
    {
        return true;
    };
    virtual bool setPowerStats(apple80211_stat_report *,apple80211_power_debug_sub_info *)
    {
        return true;
    };
    virtual bool getBeaconPeriod(apple80211_beacon_period_data *)
    {
        return true;
    };
    virtual SInt32 apple80211VirtualRequestIoctl(uint,int,IO80211VirtualInterface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual bool getBSSIDData(OSObject *,apple80211_bssid_data *)
    {
        return true;
    };
    virtual bool getSSIDData(apple80211_ssid_data *)
    {
        return true;
    };
    virtual IOOutputQueue* getOutputQueue(void)
    {
        return NULL;
    };
    virtual bool inputInfraPacket(mbuf_t)
    {
        return true;
    };
    virtual void notifyHostapState(apple80211_hostap_state *){};
    virtual bool isAwdlAssistedDiscoveryEnabled(void)
    {
        return true;
    };
    virtual void joinDone(scanSource,joinStatus){};//怀疑对象，之前是返回int
    virtual void joinStarted(scanSource,joinStatus){};//怀疑对象，之前是返回int
    virtual void handleChannelSwitchAnnouncement(apple80211_channel_switch_announcement *){};
    virtual void scanDone(scanSource,int){};
    virtual void scanStarted(scanSource,apple80211_scan_data *){};
    virtual void printChannels(void){};
    virtual void updateInterfaceCoexRiskPct(ulong long){};
    virtual SInt32 getInfraChannel(apple80211_channel_data *)
    {
        return kIOReturnSuccess;
    };
    virtual void calculateInterfacesAvaiability(void){};//怀疑对象，之前是返回int
    virtual void setChannelSequenceList(apple80211_awdl_sync_channel_sequence *){};//怀疑对象，之前是返回int
    virtual void setPrimaryInterfaceDatapathState(bool){};
    virtual UInt32 getPrimaryInterfaceLinkState(void)
    {
        return kIOReturnSuccess;
    };
    virtual void setCurrentChannel(apple80211_channel *){};//怀疑对象，之前是返回int
    virtual void setHtCapability(ieee80211_ht_capability_ie *){};//怀疑对象，之前是返回int
    virtual UInt32 getHtCapability(void)
    {
        return kIOReturnSuccess;
    };//之前是IO80211Controller
    virtual UInt32 getHtCapabilityLength(void)
    {
        return kIOReturnSuccess;
    };
    virtual bool io80211isDebuggable(bool *)
    {
        return true;
    };
    virtual UInt32 selfDiagnosticsReport(int,char const*,uint)
    {
        return kIOReturnSuccess;
    };
    virtual void logDebug(ulong long,char const*,...){};//怀疑对象，之前是返回int
    virtual void vlogDebug(ulong long,char const*,va_list){};//怀疑对象，之前是返回char
    virtual void logDebug(char const*,...){};//怀疑对象，之前是返回int
    virtual void releaseFlowQueue(IO80211FlowQueue *){};//怀疑对象，之前是返回char
    virtual IO80211FlowQueueLegacy* requestFlowQueue(FlowIdMetadata const*)
    {
        return NULL;
    };
    virtual bool calculateInterfacesCoex(void)
    {
        return true;
    };
    virtual void setInfraChannel(apple80211_channel *){};//怀疑对象，之前是返回char
    virtual bool configureInterface(IONetworkInterface *) override
    {
        return true;
    };
    virtual IOReturn disable(IO80211SkywalkInterface *);
    virtual IOReturn enable(IO80211SkywalkInterface *);
    virtual IOReturn disable(IONetworkInterface *) override;
    virtual void configureAntennae(void){};
    virtual SInt32 apple80211RequestIoctl(uint,int,IO80211Interface *,void *)
    {
        return kIOReturnSuccess;
    };
    virtual UInt32 radioCountForInterface(IO80211Interface *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn enable(IONetworkInterface *) override
    {
        return kIOReturnSuccess;
    };
    virtual void releaseIOReporters(void){};//怀疑对象，之前是返回int
    virtual void stop(IOService *) override{};
    virtual void free(void) override{};
    virtual bool init(OSDictionary *) override
    {
        return true;
    };
    virtual bool findAndAttachToFaultReporter(void)
    {
        return true;
    };
    virtual UInt32 setupControlPathLogging(void)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn createIOReporters(IOService *)
    {
        return kIOReturnSuccess;
    };
    virtual IOReturn powerChangeHandler(void *,void *,uint,IOService *,void *,ulong)
    {
        return kIOReturnSuccess;
    };
    virtual bool start(IOService *) override;
        
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
    static IORegistryPlane gIO80211Plane;
    static IORegistryEntry* kIO80211PlaneName;
    //0x118
    IOTimerEventSource * _report_gathering_timer; // 0x118
    OSArray * _reporter_num;                 // 0x120 OSArray of OSNumber
    UInt32 _var_128;                   // timeout ticks
    bool _wan_debug_enable;            // 0x12c
    // 3 bytes padding
    UInt32 _debug_value;               // 0x130
    IORecursiveLock * _recursive_lock; // 0x138
    UInt64 _ht_cap_0x0;                  // 0x140
    UInt64 _ht_cap_0x8;                // 0x148
    UInt64 _ht_cap_0x10;                // 0x150
    UInt32 _ht_cap_0x18;                // 0x158
    UInt32 _ht_cap_len;                // 0x15c
    IO80211ControllerMonitor * _fControllerMonitor; // 0x160
    CCLogPipe * _fControllerIOReporterPipe;             // 0x168
    CCIOReporterLogStream * _fControllerIOReporterStream; // 0x170
    CCLogPipe * _controlPathLogPipe;       // 0x180
    CCLogStream * _ioctlLogStream;        // 0x188
    CCLogStream *  _eventLogStream;      // 0x190
    IO82110WorkLoop * _workLoop;       // 0x198
    IO80211Interface * _interface;     // 0x1a0
    IO80211VirtualInterface * _v_interface; // 0x1a8
    IO80211VirtualInterface (* _vir_interface)[4]; // 0x1b0
    
    UInt64 _vlog_debug ;                  // 0x1d0 vlogDebug ?
    UInt32 _unknown;                    // 0x1d8
    UInt32 _infra_channel;  // 0x1dc compared with offet 8 of apple80211_stat_report  IO80211Controller::setChanCCA(apple80211_stat_report*, int)
    UInt32 _infra_channel_flags;  // 0x1e0 compared with offet 8 of apple80211_channel
    UInt32 _current_channel;   // 0x1e8 loaded with offet 04 of apple80211_channel
    UInt32 _current_channel_fags;   // 0x1ec loaded with offet 08 of apple80211_channel
    UInt8 _awdl_sync[0x190]; // 0x1f0, 0x190 bytes apple80211_awdl_sync_channel_sequence
    IONotifier * _powerDownNotifier;          // 0x380
    IOService  * _provider;            // 0x388
    IO80211RangingManager * _ranger_manager; // 0x390
    bool       _var_398;               // 0x398 checked in IO80211Controller::disable(IONetworkInterface*)
    // 7 byte padding
    IONotifier * _notifier1;           // 0x3a0
    bool         _var_3a8;             // 0x3a8
    // 7 byte padding
    UInt64       _last_pointer;        // 0x3b0  unused
    uint8_t filler[0x2B2];
    //0x3CA
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IO80211CONTROLLER_H */
