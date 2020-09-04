/* add your code here */
#define Catalina

#include "Apple80211.h"

#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include "ItlIwm.hpp"
#include "ItlIwx.hpp"

typedef enum {
  MEDIUM_TYPE_NONE = 0,
  MEDIUM_TYPE_AUTO,
  MEDIUM_TYPE_1MBIT,
  MEDIUM_TYPE_2MBIT,
  MEDIUM_TYPE_5MBIT,
  MEDIUM_TYPE_11MBIT,
  MEDIUM_TYPE_54MBIT,
  MEDIUM_TYPE_INVALID
} mediumType_t;

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

class AirportItlwm : public IO80211Controller {
    OSDeclareDefaultStructors(AirportItlwm)
    
public:
    bool init(OSDictionary *properties) override;
    void free() override;
    IOService* probe(IOService* provider, SInt32* score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    UInt32 outputPacket(mbuf_t, void * param) override;
    IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    bool configureInterface(IONetworkInterface *netif) override;
    virtual bool createWorkLoop() override;
    virtual IOWorkLoop* getWorkLoop() const override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual IOReturn getMaxPacketSize(UInt32* maxSize) const override;
    virtual IONetworkInterface * createInterface() override;
    
    void releaseAll();
    void associateSSID(const char *ssid, const char *pwd);
    void watchdogAction(IOTimerEventSource *timer);
    bool initPCIPowerManagment(IOPCIDevice *provider);
    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    
    //IO80211
    bool addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);
    IOReturn getHardwareAddressForInterface(IO80211Interface* netif,
                                            IOEthernetAddress* addr) override;
    SInt32 monitorModeSetEnabled(IO80211Interface* interface, bool enabled,
                                 UInt32 dlt) override;
    SInt32 apple80211Request(unsigned int request_type, int request_number,
                             IO80211Interface* interface, void* data) override;
    static void fakeScanDone(OSObject *owner, IOTimerEventSource *sender);
    
    
    //AirportSTAInfo
    
    
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
    
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    virtual UInt32 getFeatures() const override;
    
public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    IOPCIDevice *pciNub;
    IONetworkStats *fpNetStats;
    IO80211Interface *fNetIf;
    IOWorkLoop *fWatchdogWorkLoop;
    ItlHalService *fHalService;
    
    //pm
    thread_call_t powerOnThreadCall;
    thread_call_t powerOffThreadCall;
    UInt32 pmPowerState;
    IOService *pmPolicyMaker;
    UInt8 pmPCICapPtr;
    bool magicPacketEnabled;
    bool magicPacketSupported;
    
    //IO80211
    OSDictionary* mediumDict;
    IONetworkMedium* mediumTable[MEDIUM_TYPE_INVALID];
    uint8_t power_state;
    struct ieee80211_node *fNextNodeToSend;
    bool fScanResultWrapping;
    IOTimerEventSource *scanSource;
};
