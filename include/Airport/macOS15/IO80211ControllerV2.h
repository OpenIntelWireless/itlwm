//
//  IO80211ControllerV2.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef _IO80211CONTROLLER_H
#define _IO80211CONTROLLER_H

#if defined(KERNEL) && defined(__cplusplus)

#include <Availability.h>
#include <libkern/version.h>

class CommonFaultReporter;

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

#include "../apple80211_ioctl.h"
#include "IO80211SkywalkInterface.h"
#include "../IO80211WorkLoop.h"
#include "IO80211WorkQueue.h"
#include "../CCStream.h"
#include "../CCDataPipe.h"
#include "../CCLogPipe.h"
#include "../CCLogStream.h"

#define AUTH_TIMEOUT            15

enum {
    LINK_SPEED_80211A    = 54000000ul,
    LINK_SPEED_80211B    = 11000000ul,
    LINK_SPEED_80211G    = 54000000ul,
    LINK_SPEED_80211N    = 300000000ul,
};

enum IO80211CountryCodeOp
{
    kIO80211CountryCodeReset,

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
class IO80211RangingManager;
class IO80211FlowQueue;
class IO80211FlowQueueLegacy;
class FlowIdMetadata;
class IOReporter;
class IO80211InfraInterface;
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

typedef IOReturn (*IOCTL_FUNC)(IO80211Controller*, IO80211Interface*, IO80211VirtualInterface*, apple80211req*, bool);
extern IOCTL_FUNC gGetHandlerTable[];
extern IOCTL_FUNC gSetHandlerTable[];

class IO80211InterfaceAVCAdvisory;


class IO80211Controller : public IOEthernetController {
    OSDeclareAbstractStructors(IO80211Controller)
public:
    IOReturn postMessage(IO80211SkywalkInterface *, unsigned int, void *, unsigned long, bool);
    virtual void _RESERVEDIONetworkController6() __asm__("__ZN19IONetworkController20allocatePacketNoWaitEj") override;
    virtual void _RESERVEDIONetworkController7() __asm__("__ZN19IONetworkController18setHardwareAssistsEjj") override;
    virtual void free() override;
    virtual bool init(OSDictionary*) override;
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override;
    virtual bool start(IOService*) override;
    virtual void stop(IOService*) override;
    virtual IOWorkLoop* getWorkLoop() const override;
    virtual const char* stringFromReturn(int) override;
    virtual int errnoFromReturn(int) override;
    virtual UInt32 getFeatures() const override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual bool createWorkLoop() override;
    virtual IOReturn getHardwareAddress(IOEthernetAddress*) override;
    virtual IOReturn setMulticastMode(bool) override;
    virtual IOReturn setPromiscuousMode(bool) override;
    virtual bool isCommandProhibited(int) = 0;
    virtual bool createWorkQueue();
private: virtual void _abi_0c60() __asm__("__ZN17IO80211Controller14debugStateInitEv"); public:
    virtual IO80211WorkQueue * getWorkQueue() const;
    virtual void requestPacketTx(void*, unsigned int);
    virtual IOCommandGate * getIO80211CommandGate() const;
    virtual IO80211SkywalkInterface* getPrimarySkywalkInterface();
    virtual int bpfOutputPacket(OSObject*, unsigned int, struct __mbuf*);
    virtual SInt32 monitorModeSetEnabled(bool, unsigned int);
    virtual SInt32 handleCardSpecific(IO80211SkywalkInterface*, unsigned long, void*, bool) = 0;
    virtual UInt32 hardwareOutputQueueDepth();
    virtual SInt32 performCountryCodeOperation(IO80211CountryCodeOp);
    virtual void dataLinkLayerAttachComplete();
    virtual SInt32 enableFeature(IO80211FeatureCode, void*);
    virtual IOReturn getDRIVER_VERSION(IO80211SkywalkInterface*, apple80211_version_data*) = 0;
    virtual IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface*, apple80211_version_data*) = 0;
    virtual IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface*, apple80211_capability_data*) = 0;
    virtual IOReturn getPOWER(IO80211SkywalkInterface*, apple80211_power_data*) = 0;
    virtual IOReturn setPOWER(IO80211SkywalkInterface*, apple80211_power_data*) = 0;
    virtual IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*) = 0;
    virtual IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*) = 0;
    virtual IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface*, apple80211_debug_command*) = 0;
private: virtual void _abi_0d00() __asm__("__ZN17IO80211Controller18getPLATFORM_CONFIGEP23IO80211SkywalkInterfaceP26apple80211_platform_config"); public:
    virtual SInt32 enableVirtualInterface(IO80211VirtualInterface*);
    virtual SInt32 disableVirtualInterface(IO80211VirtualInterface*);
    virtual bool requiresExplicitMBufRelease();
    virtual bool flowIdSupported();
    virtual IO80211FlowQueueLegacy* requestFlowQueue(FlowIdMetadata const*);
    virtual void releaseFlowQueue(IO80211FlowQueue*);
    virtual bool getLogPipes(CCPipe**, CCPipe**, CCPipe**);
    virtual CCLogStream * getLogger() const = 0;
    virtual void enableFeatureForLoggingFlags(unsigned long long);
    virtual IOReturn requestQueueSizeAndTimeout(unsigned short*, unsigned short*);
    virtual IOReturn enablePacketTimestamping();
    virtual IOReturn disablePacketTimestamping();
    virtual UInt getPacketTSCounter();
    virtual void * getDriverTextLog();
    virtual UInt32 selfDiagnosticsReport(int, char const*, unsigned int);
    virtual CommonFaultReporter * getFaultReporterFromDriver() = 0;
private: virtual void _abi_0d88() __asm__("__ZN17IO80211Controller25allocIO80211RecursiveLockEv"); public:
    virtual UInt32 getDataQueueDepth(OSObject*);
    virtual bool wasDynSARInFailSafeMode();
    virtual void updateAdvisoryScoresIfNeed();
    virtual UInt64 getAVCAdvisoryInfo(IO80211InterfaceAVCAdvisory*);
private: virtual void _abi_0db0() __asm__("__ZN17IO80211Controller26getActionFramePoolCapacityEv"); public:
private: virtual void _abi_0db8() __asm__("__ZN17IO80211Controller13getPostOfficeEv"); public:
private: virtual void _abi_0dc0() __asm__("__ZN17IO80211Controller16CreatePostOfficeEv"); public:
    virtual bool attachInterface(OSObject*, IOService*);
    virtual void detachInterface(OSObject*, bool);
    virtual IO80211VirtualInterface* createVirtualInterface(ether_addr*, unsigned int);
    virtual bool attachVirtualInterface(IO80211VirtualInterface**, ether_addr*, unsigned int, bool);
    virtual bool detachVirtualInterface(IO80211VirtualInterface*, bool);
    virtual void _RESERVEDIO80211Controller0();
    virtual void _RESERVEDIO80211Controller1();
    virtual void _RESERVEDIO80211Controller2();
    virtual void _RESERVEDIO80211Controller3();
    virtual void _RESERVEDIO80211Controller4();
    virtual void _RESERVEDIO80211Controller5();
    virtual void _RESERVEDIO80211Controller6();
    virtual void _RESERVEDIO80211Controller7();
    virtual void _RESERVEDIO80211Controller8();
    virtual void _RESERVEDIO80211Controller9();
    virtual void _RESERVEDIO80211Controller10();
    virtual void _RESERVEDIO80211Controller11();
    virtual void _RESERVEDIO80211Controller12();
    virtual void _RESERVEDIO80211Controller13();
    virtual void _RESERVEDIO80211Controller14();
    virtual void _RESERVEDIO80211Controller15();
    virtual IOReturn setMulticastList(ether_addr const*, unsigned int);
private: uint8_t _layout[0x128 - sizeof(IOEthernetController)];
};
static_assert(sizeof(IO80211Controller) == 0x128, "WCL ABI size");
#endif

#endif
