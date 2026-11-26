//
//  AirportItlwmV2.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmV2_hpp
#define AirportItlwmV2_hpp

#include "Apple80211.h"
#ifdef AIRPORT_WCL
#if __IO80211_TARGET == __MAC_15_2
#include <Airport/macOS15/FaultReporter.h>
#else
#include <Airport/macOS26/FaultReporter.h>
#endif
#endif

#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <AWDLTxPass.hpp>
#include <IOKit/IOFilterInterruptEventSource.h>

#include "ItlIwm.hpp"
#include "ItlIwx.hpp"
#include "ItlIwn.hpp"

#include "AirportItlwmEthernetInterface.hpp"

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kWatchDogTimerPeriod 1000
#ifdef AIRPORT_WCL
#define AIRPORT_LEGACY_OVERRIDE
#else
#define AIRPORT_LEGACY_OVERRIDE override
#endif

extern "C" {
const char *convertApple80211IOCTLToString(signed int cmd);
}

class AirportItlwm : public IO80211Controller {
    OSDeclareDefaultStructors(AirportItlwm)
#define IOCTL(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
} else { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}

#define IOCTL_GET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
}
#define IOCTL_SET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCSA80211) { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}
#define FUNC_IOCTL(REQ, DATA_TYPE) \
FUNC_IOCTL_GET(REQ, DATA_TYPE) \
FUNC_IOCTL_SET(REQ, DATA_TYPE)
#define FUNC_IOCTL_GET(REQ, DATA_TYPE) \
IOReturn get##REQ(OSObject *object, struct DATA_TYPE *data);
#define FUNC_IOCTL_SET(REQ, DATA_TYPE) \
IOReturn set##REQ(OSObject *object, struct DATA_TYPE *data);

public:
    IOReturn receiveAWDLActionFrame(mbuf_t, size_t, uint32_t, int32_t);
    void observeAWDLDataFrame(const uint8_t*, size_t);
    IOReturn buildAWDLSyncProbe(mbuf_t*, uint64_t);
    IOReturn buildAWDLTransmit(mbuf_t*, const uint8_t *holdPayloadFor = nullptr, bool holdEverySize = false,
                               const ItlAWDL::TxPassList *pass = nullptr);
    IOReturn buildAWDLTransmitFor(mbuf_t*, const uint8_t *destination, size_t maxLength);
    bool serviceAWDLTransmit();
    unsigned queuedAWDLTransmit();
    unsigned heldShortAWDLTransmit();
    virtual bool init(OSDictionary *properties) override;
    virtual void free() override;
    virtual IOService* probe(IOService* provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    bool startDriver(IOService *provider);
    // What startDriver has done so far, for failStart (audit P-A07).
    struct StartProgress {
        bool superStarted;
        bool halAttached;
        bool netIfAttached;      // fNetIf->attach(this)
        bool interfaceAttached;  // attachInterface(fNetIf, this)
    };
    bool failStart(IOService *provider, const StartProgress &progress);
    virtual void stop(IOService *provider) override;
    virtual IOReturn enable(IO80211SkywalkInterface *netif) AIRPORT_LEGACY_OVERRIDE;
    virtual IOReturn disable(IO80211SkywalkInterface *netif) AIRPORT_LEGACY_OVERRIDE;
    virtual IOReturn setHardwareAddress(const void *addr, UInt32 addrBytes) override;
    virtual IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    virtual IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    virtual IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    virtual UInt32 getFeatures() const override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    virtual bool createWorkQueue() override;
    virtual IONetworkInterface * createInterface() override;
    virtual bool configureInterface(IONetworkInterface *netif) override;
    virtual UInt32 outputPacket(mbuf_t, void * param) override;
#ifdef AIRPORT_WCL
    UInt32 enqueuePacket(mbuf_t);
    static IOReturn outputPacketGated(OSObject *, void *, void *, void *, void *);
#endif
#ifdef __PRIVATE_SPI__
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options) override;
    virtual IOReturn networkInterfaceNotification(
                        IONetworkInterface * interface,
                        uint32_t              type,
                        void *                  argument ) override;
#endif
    virtual bool setLinkStatus(
                               UInt32                  status,
                               const IONetworkMedium * activeMedium = 0,
                               UInt64                  speed        = 0,
                               OSData *                data         = 0) override;
    static IOReturn setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);

    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    static void eventHandler(struct ieee80211com *, int, void *);
    IOReturn enableAdapter(IONetworkInterface *netif);
    void disableAdapter(IONetworkInterface *netif);
    bool initCCLogs();

    #ifdef AIRPORT_WCL
    virtual IOWorkLoop *getWorkLoop() const override;
    virtual IO80211WorkQueue *getWorkQueue() const override;
    virtual CCLogStream *getLogger() const override { return driverLogger; }
    CCLogStream *driverLogger;
#else
    virtual IO80211WorkQueue *getWorkQueue() override;
    // Sonoma 14.8.9 (23J631) uses IONetworkController's reserved slots 6 and 7. Point them at Apple's
    // functions, which the SDK still declares as reserved. Declared only: never called from the driver.
private:
    virtual void _RESERVEDIONetworkController6() override __asm__("__ZN19IONetworkController20allocatePacketNoWaitEj");
    virtual void _RESERVEDIONetworkController7() override __asm__("__ZN19IONetworkController18setHardwareAssistsEjj");
public:
#endif
    virtual bool requiresExplicitMBufRelease() override {
        return false;
    }
    virtual bool flowIdSupported() override {
        return false;
    }
    virtual SInt32 monitorModeSetEnabled(bool, UInt) override {
        return kIOReturnSuccess;
    }
    virtual IOReturn requestQueueSizeAndTimeout(unsigned short *queue, unsigned short *timeout) override {
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
    }

    virtual bool getLogPipes(CCPipe**, CCPipe**, CCPipe**) override;

#ifdef AIRPORT_WCL
    virtual CommonFaultReporter *getFaultReporterFromDriver() override;
#else
    virtual void *getFaultReporterFromDriver() override;
#endif

    virtual SInt32 apple80211_ioctl(IO80211SkywalkInterface *,unsigned long,void *, bool, bool) AIRPORT_LEGACY_OVERRIDE;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *) AIRPORT_LEGACY_OVERRIDE;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *,void *) AIRPORT_LEGACY_OVERRIDE;
    virtual IO80211VirtualInterface *createVirtualInterface(ether_addr *, UInt) override;

    bool createMediumTables(const IONetworkMedium **primary);
    void releaseAll();
    void watchdogAction(IOTimerEventSource *timer);
    void publishRxErrors();
    uint32_t rxErrorsTick = 0;
    uint32_t rxErrorsLastSum = 0;
    bool rxErrorsPublished = false;
    void reportInfraTraffic();   // (-itlinfrastats), non-virtual

    virtual SInt32 enableFeature(IO80211FeatureCode, void*) override;
    virtual bool isCommandProhibited(int command) override {
//        if (!ml_at_interrupt_context())
//            XYLog("%s %s\n", __FUNCTION__, convertApple80211IOCTLToString(command));
        return false;
    };
    virtual SInt32 handleCardSpecific(IO80211SkywalkInterface *,unsigned long,void *,bool) override {
        XYLog("%s\n", __FUNCTION__);
        return 0;
    };
    virtual IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) override {
        XYLog("%s\n", __FUNCTION__);
        return getDRIVER_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) override {
        XYLog("%s\n", __FUNCTION__);
        return getHARDWARE_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *interface,apple80211_capability_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getCARD_CAPABILITIES((OSObject *)interface, data);
    }
    virtual IOReturn getPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getPOWER((OSObject *)interface, data);
    }
    virtual IOReturn setPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return setPOWER((OSObject *)interface, data);
    }
    virtual IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return getCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) override {
//        XYLog("%s\n", __FUNCTION__);
        return setCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *interface,apple80211_debug_command *data) override {
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
    }

    //scan
    static void fakeScanDone(OSObject *owner, IOTimerEventSource *sender);

    //-----------------------------------------------------------------------
    // Power management support.
    //-----------------------------------------------------------------------
    virtual IOReturn registerWithPolicyMaker( IOService * policyMaker ) override;
    virtual IOReturn setPowerState( unsigned long powerStateOrdinal,
                                    IOService *   policyMaker) override;
    virtual IOReturn setWakeOnMagicPacket( bool active ) override;
    void setPowerStateOff(void);
    void setPowerStateOn(void);
    void unregistPM();
    bool initPCIPowerManagment(IOPCIDevice *provider);

    FUNC_IOCTL_GET(CARD_CAPABILITIES, apple80211_capability_data)
    FUNC_IOCTL(POWER, apple80211_power_data)
    FUNC_IOCTL_GET(DRIVER_VERSION, apple80211_version_data)
    FUNC_IOCTL_GET(HARDWARE_VERSION, apple80211_version_data)
    FUNC_IOCTL(COUNTRY_CODE, apple80211_country_code_data)

public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    IOPCIDevice *pciNub;
    IONetworkStats *fpNetStats;
    AirportItlwmEthernetInterface *bsdInterface;
    #ifdef AIRPORT_WCL
    IO80211InfraInterface *fNetIf;
#else
    IO80211SkywalkInterface *fNetIf;
#endif
    IOWorkLoop *fWatchdogWorkLoop;
    ItlHalService *fHalService;

    //IO80211
    uint8_t power_state;
    struct ieee80211_node *fNextNodeToSend;
    bool fScanResultWrapping;
    IOTimerEventSource *scanSource;

    u_int32_t current_authtype_lower;
    u_int32_t current_authtype_upper;
    UInt64 currentSpeed;
    UInt32 currentStatus;
    bool disassocIsVoluntary;
    char geo_location_cc[3];

    //pm
    thread_call_t powerOnThreadCall;
    thread_call_t powerOffThreadCall;
    UInt32 pmPowerState;
    // Wi-Fi was asked to start while the card's power was still off (#38); started in setPowerStateOn.
    bool enableAwaitingPowerOn = false;
    uint32_t enableDeferrals = 0;
    void enableAdapterWhenPowered();
    IOService *pmPolicyMaker = nullptr;
    UInt8 pmPCICapPtr;
    bool magicPacketEnabled;
    bool magicPacketSupported;
    IO80211VirtualInterface *fAWDLInterface;
    bool awdlInterfaceTest;
    bool awdlExtendFrames;
    uint16_t awdlProbeSequence = 0;
    bool awdlManagementInputEnabled;
    UInt32 awdlManagementActive;
    void teardownAWDLInterface();
    UInt32 awdlCreateRequests;

    //AWDL
    uint8_t *syncFrameTemplate;
    uint32_t syncFrameTemplateLength;
    uint8_t awdlBSSID[6];
    uint32_t awdlSyncState;
    uint32_t awdlElectionId;
    uint32_t awdlPresenceMode;
    uint16_t awdlMasterChannel;
    uint16_t awdlSecondaryMasterChannel;
    uint8_t *roamProfile;
    struct apple80211_btc_profiles_data *btcProfile;
    struct apple80211_btc_config_data btcConfig;
    uint32_t btcMode;
    uint32_t btcOptions;
    bool awdlSyncEnable;

    CCPipe *driverLogPipe;
    CCPipe *driverDataPathPipe;
    CCPipe *driverSnapshotsPipe;

#ifdef AIRPORT_WCL
    bool driverLogPipeStarted = false;
    bool driverDataPathPipeStarted = false;
    bool driverSnapshotsPipeStarted = false;
    CCStream *driverFaultStream;
    CCFaultReporter *driverCoreFaultReporter;
    IO80211FaultReporter *driverFaultReporter;
#else
    CCStream *driverFaultReporter;
#endif
};

#endif /* AirportItlwmV2_hpp */
