/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/
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
#include "ItlIwn.hpp"
#include "Athn.hpp"

#include "AirportItlwmInterface.hpp"

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kWatchDogTimerPeriod 1000

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
    virtual bool init(OSDictionary *properties) override;
    virtual void free() override;
    virtual IOService* probe(IOService* provider, SInt32* score) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    virtual IOReturn setHardwareAddress(const IOEthernetAddress * addrP) override;
    virtual IOReturn enable(IONetworkInterface *netif) override;
    virtual IOReturn disable(IONetworkInterface *netif) override;
    virtual UInt32 outputPacket(mbuf_t, void * param) override;
    virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    virtual IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    virtual IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    virtual bool configureInterface(IONetworkInterface *netif) override;
    virtual bool createWorkLoop() override;
    virtual IOWorkLoop* getWorkLoop() const override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual IONetworkInterface * createInterface() override;
    virtual bool setLinkStatus(
                               UInt32                  status,
                               const IONetworkMedium * activeMedium = 0,
                               UInt64                  speed        = 0,
                               OSData *                data         = 0) override;
    
    static IOReturn setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
#ifdef __PRIVATE_SPI__
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options) override;
#endif
    
    void releaseAll();
    void associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index);
    void setPTK(const u_int8_t *key, size_t key_len);
    void setGTK(const u_int8_t *key, size_t key_len, u_int8_t kid, u_int8_t *rsc);
    void watchdogAction(IOTimerEventSource *timer);
    bool initPCIPowerManagment(IOPCIDevice *provider);
    static void eventHandler(struct ieee80211com *, int, void *);
    IOReturn enableAdapter(IONetworkInterface *netif);
    void disableAdapter(IONetworkInterface *netif);
    
    //IO80211
    virtual IOReturn getHardwareAddressForInterface(IO80211Interface* netif,
                                            IOEthernetAddress* addr) override;
    virtual SInt32 monitorModeSetEnabled(IO80211Interface* interface, bool enabled,
                                 UInt32 dlt) override;
    virtual SInt32 apple80211Request(unsigned int request_type, int request_number,
                             IO80211Interface* interface, void* data) override;
    //scan
    static void fakeScanDone(OSObject *owner, IOTimerEventSource *sender);
    //authentication
    virtual bool useAppleRSNSupplicant(IO80211Interface *interface) override;
    virtual int outputRaw80211Packet(IO80211Interface *interface, mbuf_t m) override;
    //virtual interface
    virtual SInt32 enableVirtualInterface(IO80211VirtualInterface *interface) override;
    virtual SInt32 disableVirtualInterface(IO80211VirtualInterface *interface) override;
    virtual IO80211VirtualInterface* createVirtualInterface(ether_addr *eth,uint role) override;
    virtual SInt32 apple80211VirtualRequest(uint request_type, int request_number,IO80211VirtualInterface *interface,void *data) override;
    virtual SInt32 stopDMA() override;
    virtual UInt32 hardwareOutputQueueDepth(IO80211Interface* interface) override;
    virtual SInt32 performCountryCodeOperation(IO80211Interface* interface, IO80211CountryCodeOp op) override;
    virtual SInt32 enableFeature(IO80211FeatureCode code, void* data) override;
    virtual void requestPacketTx(void*, UInt) override;
    virtual int bpfOutputPacket(OSObject *,UInt,mbuf_t) override;
    int outputActionFrame(OSObject *, mbuf_t m);
    int bpfOutput80211Radio(OSObject *, mbuf_t m);
    
    
    
    //AirportSTAIOCTL
    FUNC_IOCTL(SSID, apple80211_ssid_data)
    FUNC_IOCTL(AUTH_TYPE, apple80211_authtype_data)
    FUNC_IOCTL(CHANNEL, apple80211_channel_data)
    FUNC_IOCTL(PROTMODE, apple80211_protmode_data)
    FUNC_IOCTL_GET(TXPOWER, apple80211_txpower_data)
    FUNC_IOCTL_GET(RATE, apple80211_rate_data)
    FUNC_IOCTL(BSSID, apple80211_bssid_data)
    FUNC_IOCTL_SET(SCAN_REQ, apple80211_scan_data)
    FUNC_IOCTL_SET(SCAN_REQ_MULTIPLE, apple80211_scan_multiple_data)
    FUNC_IOCTL_GET(SCAN_RESULT, apple80211_scan_result*)
    FUNC_IOCTL_GET(CARD_CAPABILITIES, apple80211_capability_data)
    FUNC_IOCTL_GET(STATE, apple80211_state_data)
    FUNC_IOCTL_GET(PHY_MODE, apple80211_phymode_data)
    FUNC_IOCTL_GET(OP_MODE, apple80211_opmode_data)
    FUNC_IOCTL_GET(RSSI, apple80211_rssi_data)
    FUNC_IOCTL_GET(NOISE, apple80211_noise_data)
    FUNC_IOCTL_GET(INT_MIT, apple80211_intmit_data)
    FUNC_IOCTL(POWER, apple80211_power_data)
    FUNC_IOCTL_SET(ASSOCIATE, apple80211_assoc_data)
    FUNC_IOCTL_GET(ASSOCIATE_RESULT, apple80211_assoc_result_data)
    IOReturn setDISASSOCIATE(OSObject *);
    FUNC_IOCTL_GET(RATE_SET, apple80211_rate_set_data)
    FUNC_IOCTL_GET(MCS_INDEX_SET, apple80211_mcs_index_set_data)
    FUNC_IOCTL_GET(VHT_MCS_INDEX_SET, apple80211_vht_mcs_index_set_data)
    FUNC_IOCTL(MCS_VHT, apple80211_mcs_vht_data)
    FUNC_IOCTL_GET(SUPPORTED_CHANNELS, apple80211_sup_channel_data)
    FUNC_IOCTL_GET(LOCALE, apple80211_locale_data)
    FUNC_IOCTL(DEAUTH, apple80211_deauth_data)
    FUNC_IOCTL_GET(TX_ANTENNA, apple80211_antenna_data)
    FUNC_IOCTL_GET(ANTENNA_DIVERSITY, apple80211_antenna_data)
    FUNC_IOCTL_GET(DRIVER_VERSION, apple80211_version_data)
    FUNC_IOCTL_GET(HARDWARE_VERSION, apple80211_version_data)
    FUNC_IOCTL(RSN_IE, apple80211_rsn_ie_data)
    FUNC_IOCTL_GET(AP_IE_LIST, apple80211_ap_ie_data)
    FUNC_IOCTL_GET(LINK_CHANGED_EVENT_DATA, apple80211_link_changed_event_data)
    FUNC_IOCTL_GET(ASSOCIATION_STATUS, apple80211_assoc_status_data)
    FUNC_IOCTL(COUNTRY_CODE, apple80211_country_code_data)
    FUNC_IOCTL_GET(RADIO_INFO, apple80211_radio_info_data)
    FUNC_IOCTL_GET(MCS, apple80211_mcs_data)
    FUNC_IOCTL_SET(VIRTUAL_IF_CREATE, apple80211_virt_if_create_data)
    FUNC_IOCTL_SET(VIRTUAL_IF_DELETE, apple80211_virt_if_delete_data)
    FUNC_IOCTL_GET(ROAM_THRESH, apple80211_roam_threshold_data)
    FUNC_IOCTL_GET(POWERSAVE, apple80211_powersave_data)
    FUNC_IOCTL_SET(CIPHER_KEY, apple80211_key)
    FUNC_IOCTL_SET(SCANCACHE_CLEAR, apple80211req)
    FUNC_IOCTL(TX_NSS, apple80211_tx_nss_data)
    FUNC_IOCTL_GET(NSS, apple80211_nss_data)
    FUNC_IOCTL_SET(ROAM, apple80211_sta_roam_data);
    
    //AirportVirtualIOCTL
    FUNC_IOCTL(AWDL_PEER_TRAFFIC_REGISTRATION, apple80211_awdl_peer_traffic_registration)
    FUNC_IOCTL(AWDL_ELECTION_METRIC, apple80211_awdl_election_metric)
    FUNC_IOCTL(SYNC_ENABLED, apple80211_awdl_sync_enabled)
    FUNC_IOCTL(SYNC_FRAME_TEMPLATE, apple80211_awdl_sync_frame_template)
    FUNC_IOCTL_GET(AWDL_HT_CAPABILITY, apple80211_ht_capability)
    FUNC_IOCTL_GET(AWDL_VHT_CAPABILITY, apple80211_vht_capability)
    
    //AWDL
    FUNC_IOCTL(AWDL_BSSID, apple80211_awdl_bssid)
    FUNC_IOCTL_GET(CHANNELS_INFO, apple80211_channels_info)
    FUNC_IOCTL(PEER_CACHE_MAXIMUM_SIZE, apple80211_peer_cache_maximum_size)
    FUNC_IOCTL(AWDL_ELECTION_ID, apple80211_awdl_election_id)
    FUNC_IOCTL(AWDL_MASTER_CHANNEL, apple80211_awdl_master_channel)
    FUNC_IOCTL(AWDL_SECONDARY_MASTER_CHANNEL, apple80211_awdl_secondary_master_channel)
    FUNC_IOCTL(AWDL_MIN_RATE, apple80211_awdl_min_rate)
    FUNC_IOCTL(AWDL_ELECTION_RSSI_THRESHOLDS, apple80211_awdl_election_rssi_thresholds)
    FUNC_IOCTL(AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE, apple80211_awdl_sync_channel_sequence)
    FUNC_IOCTL(AWDL_PRESENCE_MODE, apple80211_awdl_presence_mode)
    FUNC_IOCTL(AWDL_EXTENSION_STATE_MACHINE_PARAMETERS, apple80211_awdl_extension_state_machine_parameter)
    FUNC_IOCTL(AWDL_SYNC_STATE, apple80211_awdl_sync_state)
    FUNC_IOCTL(AWDL_SYNC_PARAMS, apple80211_awdl_sync_params)
    FUNC_IOCTL_GET(AWDL_CAPABILITIES, apple80211_awdl_cap)
    FUNC_IOCTL(AWDL_AF_TX_MODE, apple80211_awdl_af_tx_mode)
    FUNC_IOCTL_SET(AWDL_OOB_AUTO_REQUEST, apple80211_awdl_oob_request)
    FUNC_IOCTL(ROAM_PROFILE, apple80211_roam_profile_band_data)
    FUNC_IOCTL(WOW_PARAMETERS, apple80211_wow_parameter_data)
    FUNC_IOCTL(IE, apple80211_ie_data)
    FUNC_IOCTL_SET(P2P_SCAN, apple80211_scan_data)
    FUNC_IOCTL_SET(P2P_LISTEN, apple80211_p2p_listen_data)
    FUNC_IOCTL_SET(P2P_GO_CONF, apple80211_p2p_go_conf_data)
    FUNC_IOCTL(BTCOEX_PROFILES, apple80211_btc_profiles_data)
    FUNC_IOCTL(BTCOEX_CONFIG, apple80211_btc_config_data)
    FUNC_IOCTL(BTCOEX_OPTIONS, apple80211_btc_options_data)
    FUNC_IOCTL(BTCOEX_MODE, apple80211_btc_mode_data)
    
    
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
    
    bool createMediumTables(const IONetworkMedium **primary);
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    virtual UInt32 getFeatures() const override;
    
public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    IOPCIDevice *pciNub;
    IONetworkStats *fpNetStats;
    AirportItlwmInterface *fNetIf;
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
    
    IO80211P2PInterface *fP2PDISCInterface;
    IO80211P2PInterface *fP2PGOInterface;
    IO80211P2PInterface *fAWDLInterface;
    
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
};
