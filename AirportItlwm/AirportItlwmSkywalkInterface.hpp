//
//  AirportItlwmSkywalkInterface.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmSkywalkInterface_hpp
#define AirportItlwmSkywalkInterface_hpp

#include <ItlScanCursor.hpp>
#ifdef AIRPORT_WCL
#include "WCL/WCL.hpp"

// ItlwmWCLTrace: the last 64 WCL interactions, for joins that fail between WCL and the driver.
// kind: '>' message to WCL (id = message, a = first payload word), '<' WCL command (id = command,
// a = result), 'e' net80211 event (id = code), 'm' MAC address set (a = MacUpdate, b = result),
// 'j' join start (a = result, b = 1 if deferred until the firmware restart ends).
void itlWCLTrace(char kind, uint32_t id, uint32_t a, uint32_t b);
bool itlWCLTraceText(char *out, size_t size, uint32_t *version);
#endif

#include <Airport/Apple80211.h>

#ifdef AIRPORT_WCL
#define AIRPORT_SKYWALK_OVERRIDE
#else
#define AIRPORT_SKYWALK_OVERRIDE override
#endif

// Power save mode.
//
// The SDK only forward declares the structure that travels with
// APPLE80211_IOC_PM_MODE, so the layout was recovered from the framework:
// the framework sends 0x188 (392) bytes with that ioctl. Only the first
// two words are known to carry the request itself, the remainder of the
// payload is reserved and still holds whatever the framework had in its
// buffer.
struct apple80211_pm_mode {
    uint32_t mode;         // 0x00, the power mode the framework asks for
    uint32_t flags;        // 0x04
    uint8_t reserved[384]; // 0x08 .. 0x188
};
static_assert(sizeof(apple80211_pm_mode) == 0x188, "apple80211_pm_mode size");

// Firmware hot channels.
//
// The SDK only forward declares the structure that travels with
// APPLE80211_IOC_WCL_FW_HOT_CHANNELS, so the layout was recovered from the
// framework: WCLNeighborCacheManager::constructNeighborCacheFromFWHotChannels
// asks for it with a length of 0x14 (20) bytes, then it reads the number of
// entries at offset 0x10 and walks that many two byte channel
// specifications, which start at offset 0.
struct apple80211_fw_hot_channels {
    uint16_t channels[8]; // 0x00, one AppleChannelSpec_t per entry
    uint32_t count;       // 0x10, number of entries in the list
};
static_assert(sizeof(apple80211_fw_hot_channels) == 0x14,
              "apple80211_fw_hot_channels size");

class AirportItlwmSkywalkInterface : public IO80211InfraProtocol {
    OSDeclareDefaultStructors(AirportItlwmSkywalkInterface)

public:
#ifdef AIRPORT_WCL
    IOReturn getBSS_BLACKLIST(bss_blacklist*) override { return kIOReturnUnsupported; }
    IOReturn getHE_COUNTERS(apple80211_he_counters_ctl*) override { return kIOReturnUnsupported; }
    IOReturn getWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) override { return kIOReturnUnsupported; }
    IOReturn getFW_CLOCK_INFO(apple80211_fw_clock_info*) override { return kIOReturnUnsupported; }
    IOReturn getTIMESYNC_STATS(apple80211_timesync_stats*) override { return kIOReturnUnsupported; }
    IOReturn getSYSTEM_SLEEP_CONFIG(apple80211_system_sleep_config*) override { return kIOReturnUnsupported; }
#if __IO80211_TARGET != __MAC_15_2
    IOReturn getSMARTCCA_OPMODE(apple80211_smartcca_opmode*) override { return kIOReturnUnsupported; }
    IOReturn getLQM_STATISTICS(apple80211_lqm_statistics*) override { return kIOReturnUnsupported; }
    IOReturn getDEVICE_ORIENTATION(apple80211_device_orientation*) override { return kIOReturnUnsupported; }
    IOReturn getACCESSORY_STATE(apple80211_device_accessory_info*) override { return kIOReturnUnsupported; }
    IOReturn getP2P_DEVICE_CAPABILITY(apple80211_p2p_device_capability*) override { return kIOReturnUnsupported; }
    IOReturn getPOWERTABLE_VERSION(apple80211_powertable_version_data*) override { return kIOReturnUnsupported; }
#endif
    IOReturn setCLEAR_PMKSA_CACHE(void*) override;
    IOReturn setDYNAMIC_RSSI_WINDOW_CONFIG(apple80211_dynamic_rssi_window_config*) override { return kIOReturnUnsupported; }
    IOReturn setBSS_BLACKLIST(bss_blacklist*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_LEGACY_ROAM_PROFILE_CONFIG(apple80211_legacy_roam_profile_config*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_ARP_MODE(apple80211_wcl_arp_mode*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_QOS_PARAMS(apple80211_wcl_qos_params*) override { return kIOReturnUnsupported; }
    IOReturn setVOICE_IND_STATE(apple80211_voice_ind_state*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_ACCESSORY_POWER_LIMIT_WIFI_ENH(apple80211_mws_accessory_power_limit*) override { return kIOReturnUnsupported; }
    IOReturn setPOWER_PROFILE(apple80211_power_profile*) override { return kIOReturnUnsupported; }
    IOReturn setHEARTBEAT(void*) override { return kIOReturnUnsupported; }
    IOReturn setINTERFACE_SETTING(apple80211_interface_setting*) override { return kIOReturnUnsupported; }
    IOReturn setBYPASS_TX_POWER_CAP(apple80211_bypass_tx_power_cap*) override { return kIOReturnUnsupported; }
    IOReturn setFACETIME_WIFICALLING_PARAMS(apple80211_facetime_wificalling_params*) override { return kIOReturnUnsupported; }
    IOReturn setIPV4_PARAMS(apple80211_ipv4_params*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_WNM_OPS(apple80211_wcl_wnm_config_t*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_LIMITED_AGGREGATION(apple80211_limited_aggregation_config*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_BCN_MUTE_CONFIG(apple80211_bcn_mute_config*) override { return kIOReturnUnsupported; }
    IOReturn setEAP_FILTER_CONFIG(apple80211_eap_filter_config*) override { return kIOReturnUnsupported; }
    IOReturn setWOW_LOW_POWER_MODE(apple80211_wow_low_power_mode*) override { return kIOReturnUnsupported; }
    IOReturn setDUAL_POWER_MODE(apple80211_dual_power_mode_params*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_UPDATE_FAST_LANE(apple80211_fastlane*) override;
    IOReturn setWCL_ASSOCIATED_SLEEP(apple80211_associated_sleep_config*) override { return kIOReturnUnsupported; }
    IOReturn setCONGESTION_CTRL_IND(apple80211_congestion_control_indication*) override { return kIOReturnUnsupported; }
    IOReturn setSTAND_ALONE_MODE_STATE(apple80211_standalone_state*) override { return kIOReturnUnsupported; }
    IOReturn setIPV6_PARAMS(apple80211_ipv6_params*) override { return kIOReturnUnsupported; }
    IOReturn setINFRA_ENUMERATED(apple80211_infra_enumerated*) override { return kIOReturnUnsupported; }
    IOReturn setLMTPC_CONFIG(apple80211_lmtpc_config*) override { return kIOReturnUnsupported; }
    IOReturn setTRAFFIC_ENG_PARAMS(apple80211_traffic_eng_params*) override { return kIOReturnUnsupported; }
    IOReturn setLE_SCAN_PARAM(apple80211_le_scan_params*) override { return kIOReturnUnsupported; }
    IOReturn setTIMESYNC_GPIO(apple80211_timesync_gpio*) override { return kIOReturnUnsupported; }
    IOReturn setHOST_CLOCK_INFO(apple80211_host_clock_info*) override { return kIOReturnUnsupported; }
    IOReturn setFW_CLOCK_SOURCE(apple80211_fw_clock_source*) override { return kIOReturnUnsupported; }
    IOReturn setTIMESYNC_TX_POLICY(apple80211_timesync_tx_policy*) override { return kIOReturnUnsupported; }
    IOReturn setTIMESYNC_RX_POLICY(apple80211_timesync_rx_policy*) override { return kIOReturnUnsupported; }
    IOReturn setTIMESTAMPING_EN(apple80211_timestamping_en*) override { return kIOReturnUnsupported; }
    IOReturn setWCL_SOI_CONFIG(appl80211_sleep_on_inactivity_config*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_TIME_SHARING_WIFI_ENH(apple80211_mws_time_sharing*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_WIFI_TYPE_7_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_COEX_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_DISABLE_OCL_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_RFEM_CONFIG_WIFI_ENH(apple80211_mws_rfem_config*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_ASSOC_PROTECTION_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_SCAN_FREQ_WIFI_ENH(apple80211_mws_scan_freq*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_SCAN_FREQ_MODE_WIFI_ENH(apple80211_mws_scan_freq_mode*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_CONDITION_ID_BITMAP_WIFI_ENH(apple80211_mws_condition_id_config*) override { return kIOReturnUnsupported; }
    IOReturn setMWS_ANTENNA_SELECTION_WIFI_ENH(apple80211_mws_antenna_selection*) override { return kIOReturnUnsupported; }
    IOReturn setNDD_REQ(apple80211_ndd_data*) override { return kIOReturnUnsupported; }
    IOReturn setDBRG_ENTROPY(apple80211_drbg_entropy*) override { return kIOReturnUnsupported; }
    IOReturn setSDB_ENABLE(apple80211_sdb_enable*) override { return kIOReturnUnsupported; }
#if __IO80211_TARGET != __MAC_15_2
    IOReturn setBTCOEX_EXT_PROFILE(apple80211_btcoex_ext_profile*) override { return kIOReturnUnsupported; }
    IOReturn setDEVICE_ORIENTATION(apple80211_device_orientation*) override { return kIOReturnUnsupported; }
    IOReturn setACCESSORY_STATE(apple80211_device_accessory_info*) override { return kIOReturnUnsupported; }
    // Acknowledged only: the payload is opaque here and never read (#85, from ann0see's diff).
    IOReturn setOS_ELIGIBILITY(apple80211_os_eligibility*) override { return kIOReturnSuccess; }
    IOReturn setTX_MODE_CONFIG(apple80211_tx_mode_config*) override { return kIOReturnUnsupported; }
    IOReturn setMITIGATE_INTERFERENCE(apple80211_mitigate_interference*) override { return kIOReturnUnsupported; }
    IOReturn setMacAddress(mloAddrArray &) override;
#endif
    IOReturn getROAM_PROFILE(apple80211_roam_profile_all_bands *) override { return kIOReturnUnsupported; }
    IOReturn setROAM_PROFILE(apple80211_roam_profile_all_bands *) override { return kIOReturnUnsupported; }
#if __IO80211_TARGET != __MAC_15_2
    IOReturn setWCL_JOIN_ABORT(apple80211_wcl_abort_join *) override;
#endif
    IOReturn setWCL_ASSOCIATE(apple80211AssocCandidates *) override;
#if __IO80211_TARGET == __MAC_15_2
    IOReturn setMacAddress(ether_addr &) override;
    IOReturn getWIFI_BT_5G_POLICY(apple80211_wifi_bt_5g_policy_t *) override { return kIOReturnUnsupported; }
    IOReturn setWIFI_BT_5G_POLICY(apple80211_wifi_bt_5g_policy_t *) override { return kIOReturnUnsupported; }
#endif
#endif

    virtual bool init(IOService *) AIRPORT_SKYWALK_OVERRIDE;
//    virtual ifnet_t getBSDInterface(void) AIRPORT_SKYWALK_OVERRIDE;

    IOReturn associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index);
    void setPTK(const u_int8_t *key, size_t key_len);
    void setGTK(const u_int8_t *key, size_t key_len, u_int8_t kid, u_int8_t *rsc);

public:
    virtual IOReturn getSSID(apple80211_ssid_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getAUTH_TYPE(apple80211_authtype_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getCHANNEL(apple80211_channel_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getPOWERSAVE(apple80211_powersave_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getTXPOWER(apple80211_txpower_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getRATE(apple80211_rate_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getBSSID(apple80211_bssid_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getSCAN_RESULT(apple80211_scan_result *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getSTATE(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getPHY_MODE(apple80211_phymode_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getOP_MODE(apple80211_opmode_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getRSSI(apple80211_rssi_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getNOISE(apple80211_noise_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getSUPPORTED_CHANNELS(apple80211_sup_channel_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getLOCALE(apple80211_locale_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getDEAUTH(apple80211_deauth_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getRATE_SET(apple80211_rate_set_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getDTIM_INT(apple80211_dtim_int_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSTATION_LIST(apple80211_sta_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRSN_IE(apple80211_rsn_ie_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getAP_IE_LIST(apple80211_ap_ie_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getSTATS(apple80211_stats_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getASSOCIATION_STATUS(apple80211_assoc_status_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getGUARD_INTERVAL(apple80211_guard_interval_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getMCS(apple80211_mcs_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getMCS_INDEX_SET(apple80211_mcs_index_set_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getWOW_PARAMETERS(apple80211_wow_parameter_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getWOW_ENABLED(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getPID_LOCK(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSTA_IE_LIST(apple80211_sta_ie_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSTA_STATS(apple80211_sta_stats_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getBT_COEX_FLAGS(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCURRENT_NETWORK(apple80211_scan_result *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getRSSI_BOUNDS(apple80211_rssi_bounds_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getPOWER_DEBUG_INFO(apple80211_power_debug_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getHT_CAPABILITY(apple80211_ht_capability *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getLINK_CHANGED_EVENT_DATA(apple80211_link_changed_event_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getEXTENDED_STATS(apple80211_extended_stats *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getBEACON_PERIOD(apple80211_beacon_period_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getVHT_MCS_INDEX_SET(apple80211_vht_mcs_index_set_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getMCS_VHT(apple80211_mcs_vht_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getGAS_RESULTS(apple80211_gas_result_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn getCHANNELS_INFO(apple80211_channels_info *) override;
#else
    virtual IOReturn getCHANNELS_INFO(apple80211_channels_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getVHT_CAPABILITY(apple80211_vht_capability *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getBGSCAN_CACHE_RESULTS(apple80211_bgscan_cached_network_data_list *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getROAM_PROFILE(apple80211_roam_profile_band_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_COUNTER_STATS(apple80211_chip_stats *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_CHANNELS(apple80211_country_channel_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getPRIVATE_MAC(apple80211_private_mac_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_ENABLE(apple80211_ranging_enable_request_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_START(apple80211_ranging_start_request_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getAWDL_RSDB_CAPS(apple80211_rsdb_capability *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTKO_PARAMS(apple80211_tko_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTKO_DUMP(apple80211_tko_dump *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    virtual IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data *data) AIRPORT_SKYWALK_OVERRIDE { return getSUPPORTED_CHANNELS(data); }
#else
    virtual IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data *data) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getBTCOEX_PROFILE(apple80211_btcoex_profile *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTRAP_INFO(apple80211_trap_info_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTHERMAL_INDEX(apple80211_thermal_index_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getMAX_NSS_FOR_AP(apple80211_btcoex_max_nss_for_ap_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getPOWER_BUDGET(apple80211_power_budget_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_CAPS(apple80211_ranging_capabilities_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSUPPRESS_SCANS(apple80211_suppress_scans_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getHOST_AP_MODE_HIDDEN(apple80211_host_ap_mode_hidden_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getLQM_CONFIG(apple80211_lqm_config_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTRAP_CRASHTRACER_MINI_DUMP(apple80211_trap_mini_dump_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getHE_CAPABILITY(apple80211_he_capability *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn getBEACON_INFO(apple80211_beacon_info_t *) override;
#else
    virtual IOReturn getBEACON_INFO(apple80211_beacon_info_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getSOFTAP_PARAMS(apple80211_softap_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_POWER_RANGE(apple80211_chip_power_limit *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSOFTAP_STATS(apple80211_softap_stats *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getNSS(apple80211_nss_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getHW_ADDR(apple80211_hw_mac_address *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getHE_MCS_INDEX_SET(apple80211_he_mcs_index_set_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_DIAGS(appl80211_chip_diags_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getHP2P_CTRL(apple80211_hp2p_ctrl *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getREQUEST_BSS_BLACKLIST(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getASSOC_READY_STATUS(apple80211_assoc_ready *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTXRX_CHAIN_INFO(apple80211_txrx_chain_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getMIMO_STATUS(apple80211_mimo_status *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCUR_PMK(apple80211_pmk *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getDYNSAR_DETAIL(apple80211_dynsar_detail *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRANDOMISATION_STATUS(apple80211_mac_randomisation_status *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_CHANNELS_INFO(apple80211_channels_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getLQM_SUMMARY(apple80211_lqm_summary *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn getBEACON_SCAN_CACHE_REQ(apple80211_scan_result *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSLOW_WIFI_FEATURE_ENABLED(apple80211_slow_wifi_feature_enabled *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCCA(apple80211_interface_cca_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRX_RATE(apple80211_rate_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getTIMESYNC_INFO(apple80211_timesync_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSENSING_DATA(apple80211_sensing_data_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_BAND_SUPPORT(apple80211_country_band_support *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels *) AIRPORT_SKYWALK_OVERRIDE;
#ifdef AIRPORT_WCL
    virtual IOReturn getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *) override;
#else
    virtual IOReturn getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
#ifdef AIRPORT_WCL
    virtual IOReturn getWCL_BSS_INFO(apple80211_beacon_msg *) override;
#else
    virtual IOReturn getWCL_BSS_INFO(apple80211_beacon_msg *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
#ifdef AIRPORT_WCL
    IOReturn getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *) override;
#else
    virtual IOReturn getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getWCL_GET_TX_BLANKING_STATUS(uint *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSSID_TRANSITION_SUPPORT(apple80211_ssid_transition_feature_enabled *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn getWCL_VALID_CHANNEL_COUNT(unsigned long *);
#else
    virtual IOReturn getWCL_VALID_CHANNEL_COUNT(unsigned long *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getWCL_P2P_STATUS_FOR_SCAN(p2pStatusForScan *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn getWCL_CHANNELS_INFO(apple80211ChannelInfo *) override;
#else
    virtual IOReturn getWCL_CHANNELS_INFO(apple80211ChannelInfo *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getP2P_STEERING_METRIC(apple80211_p2p_steering_metrics *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getRSN_XE(apple80211_rsn_xe_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getSIB_COEX_STATUS(apple80211_sib_coex_status *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    virtual IOReturn getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *) override;
    IOReturn copyWCLExtendedBss(void *);
    IOReturn copyWCLChannels(void *);
    IOReturn copyWCLTrafficCounters(void *);
#else
    virtual IOReturn getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn getWCL_LOW_LATENCY_INFO_STATS(apple80211_wcl_low_latency_stats *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getWIFI_NOISE_PER_ANT(apple80211_noise_per_ant_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn getBLOCKED_BANDS(apple80211_blocked_bands *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSSID(apple80211_ssid_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setAUTH_TYPE(apple80211_authtype_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setCIPHER_KEY(apple80211_key *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setCHANNEL(apple80211_channel_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setPOWERSAVE(apple80211_powersave_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setTXPOWER(apple80211_txpower_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRATE(apple80211_rate_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSCAN_REQ(apple80211_scan_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setASSOCIATE(apple80211_assoc_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setDISASSOCIATE(apple80211_disassoc_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setIBSS_MODE(apple80211_network_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setHOST_AP_MODE(apple80211_network_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setAP_MODE(apple80211_apmode_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setDEAUTH(apple80211_deauth_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setTX_ANTENNA(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setANTENNA_DIVERSITY(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_IE(apple80211_rsn_ie_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setBACKGROUND_SCAN(apple80211_bgscan_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_PARAMETERS(apple80211_wow_parameter_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_ENABLED(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setPID_LOCK(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_AUTHORIZE(apple80211_sta_authorize_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_DISASSOCIATE(apple80211_sta_disassoc_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_DEAUTH(apple80211_sta_disassoc_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_CONF(apple80211_rsn_conf_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setIE(apple80211_ie_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_TEST(apple80211_wow_test_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSCANCACHE_CLEAR(void *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setBT_COEX_FLAGS(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setROAM(apple80211_sta_roam_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setHT_CAPABILITY(apple80211_ht_capability *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setAWDL_FORCED_ROAM_CONFIG(apple80211_awdl_forced_roam_config *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_ARP(apple80211_offload_arp_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_NDP(apple80211_offload_ndp_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_SCAN(apple80211_offload_scan_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_REQ(apple80211_gas_query_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_START(apple80211_gas_query_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_SET_PEER(apple80211_gas_peer_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setVHT_CAPABILITY(apple80211_vht_capability *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setROAM_PROFILE(apple80211_roam_profile_band_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setAWDL_ENABLE_ROAMING(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setPRIVATE_MAC(apple80211_private_mac_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRESET_CHIP(apple80211_reset_command *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setCRASH(apple80211_crash_command *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_ENABLE(apple80211_ranging_enable_request_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_START(apple80211_ranging_start_request_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_AUTHENTICATE(apple80211_ranging_authenticate_request_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setTKO_PARAMS(apple80211_tko_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_PROFILE(apple80211_btcoex_profile *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setTHERMAL_INDEX(apple80211_thermal_index_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setPOWER_BUDGET(apple80211_power_budget_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSUPPRESS_SCANS(apple80211_suppress_scans_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setHOST_AP_MODE_HIDDEN(apple80211_host_ap_mode_hidden_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setLQM_CONFIG(apple80211_lqm_config_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_PARAMS(apple80211_softap_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_TRIGGER_CSA(apple80211_softap_csa_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_WIFI_NETWORK_INFO_IE(apple80211_softap_wifi_network_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_DISABLE_ULOFDMA(uint *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSCAN_CONTROL(apple80211_scan_control_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setUSB_HOST_NOTIFICATION(apple80211_usb_host_notification_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSET_MAC_ADDRESS(apple80211_set_mac_address *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setHP2P_CTRL(apple80211_hp2p_ctrl *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setABORT_SCAN(apple80211_abort_scan *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSET_PROPERTY(apple80211_set_property_unserialized_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setROAM_CACHE_UPDATE(apple80211_roam_cache_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setPM_MODE(apple80211_pm_mode *) AIRPORT_SKYWALK_OVERRIDE;
    virtual IOReturn setSET_WIFI_ASSERTION_STATE(apple80211_wifi_assertion_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setREASSOCIATE_WITH_CORECAPTURE(apple80211_capture_debug_info_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setLINKDOWN_DEBOUNCE_STATUS(apple80211_linkdown_debounce_status *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_EXTENDED_CAPABILITIES_IE(apple80211_softap_extended_capabilities_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setREALTIME_QOS_MSCS(apple80211_state_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSENSING_ENABLE(apple80211_sensing_enable_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setSENSING_DISABLE(apple80211_sensing_disable_t *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setNANPHS_ASSOCIATION(apple80211_nan_link_association_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setNANPHS_TERMINATED(apple80211_nan_link_association_info *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn set6G_MODE(apple80211_6G_mode *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn setWCL_LEAVE_NETWORK(apple80211_leave_network *) override;
#else
    virtual IOReturn setWCL_LEAVE_NETWORK(apple80211_leave_network *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setWCL_REASSOC(apple80211_reassoc *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_PROFILE_CONFIG(apple80211_roam_profile_config *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_PROFILE_CONFIGV1(apple80211_roam_profile_configV1 *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_USER_CACHE(apple80211_user_roam_cache *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SET_MULTI_AP_ENV(apple80211_set_multi_ap_env *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn setWCL_SCAN_ABORT(void *) override;
#else
    virtual IOReturn setWCL_SCAN_ABORT(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setWCL_REAL_TIME_MODE(apple80211_wcl_real_time_mode *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_GARP_MODE(apple80211_wcl_garp_mode *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#if defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_15_2
    IOReturn setWCL_JOIN_ABORT(void *) override;
#else
    virtual IOReturn setWCL_JOIN_ABORT(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setWCL_TRIGGER_CC(triggerCC *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn setWCL_SCAN_REQ(apple80211ScanRequest *) override;
#else
    virtual IOReturn setWCL_SCAN_REQ(apple80211ScanRequest *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setWCL_ASSOCIATE(apple80211_assoc_candidates *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_PROTECT_IP(apple80211_wcl_protect_ip_mode *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_LINK_UP_DONE(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *) override;
#else
    virtual IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setWCL_VOLUNTARY_NETWORK_DISCONNECT(apple80211_wcl_voluntary_network_disconnect *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#ifdef AIRPORT_WCL
    virtual IOReturn setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *) override;
#else
    virtual IOReturn setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
#endif
    virtual IOReturn setSLOW_WIFI_RECOVERY(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_XE(apple80211_rsn_xe_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ULOFDMA_STATE(apple80211_wcl_ulofdma_state *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ACTION_FRAME(apple80211_wcl_action_frame *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_REAL_TIME_POLICY(apple80211_wcl_real_time_policy *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_ABORT(void *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setOS_FEATURE_FLAGS(apple80211_feature_flags *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setDHCP_RENEWAL_DATA(apple80211_dhcp_renewal_data *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setMOVING_NETWORK(apple80211_network_flags *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBATTERY_POWERSAVE_CONFIG(apple80211_battery_ps_config *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setMIMO_CONFIG(apple80211_mimo_config *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_MOTIONPROFILE(apple80211_bg_motion_profile *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_NETWORK(apple80211_bg_network *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BGSCAN(apple80211_bg_scan *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_PARAMS(apple80211_bg_params *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }
    virtual IOReturn setBLOCKED_BANDS(apple80211_blocked_bands *) AIRPORT_SKYWALK_OVERRIDE { return kIOReturnUnsupported; }

#ifdef AIRPORT_WCL
    bool initWCL();
    void free() override;
    void stopWCL();
    void handleWCLEvent(int, void *);
    void handleWCLLink(bool);
    // Called from the controller's 1 s watchdog: posts the link's RSSI to WCL every few seconds.
    void wclPostLinkQuality();
    bool wclLqmPostAllowed(int32_t rssi);
    void completeWCLScan();
private:
    static IOReturn wclCommand(OSObject *, void *, void *, void *, void *);
    static IOReturn wclCommandBody(OSObject *, void *, void *, void *);
    void wclPost(uint32_t, void *, unsigned long, bool);
    struct CountryUpdate;
    static void wclCountryUpdateThread(void *, void *);
    static IOReturn wclCountryUpdateGated(OSObject *, void *, void *, void *, void *);
    static IOReturn stopWCLGated(OSObject *, void *, void *, void *, void *);
    static IOReturn updateWCLLinkQualityGated(OSObject *, void *, void *, void *, void *);
    void deferWCLCountryUpdate();
    void updateWCLLinkQuality(bool = false);
    static void wclJoinTimeout(OSObject *, IOTimerEventSource *);
    IOReturn beginWCLScan(apple80211ScanRequest *);
    IOReturn startWCLScan(apple80211ScanRequest *);
    void clearWCLPMKSA();
    IOReturn installWCLKey(apple80211_key *);
    IOReturn accessWCLRSN(apple80211_rsn_ie_data *, bool);
    IOReturn beginWCLJoin(apple80211AssocCandidates *);
    IOReturn startWCLJoin(AirportWCL::JoinRequest &);
    void resumeWCLJoin();
    IOReturn abortWCLJoin();
    IOReturn leaveWCLNetwork();
    void finishWCLScan(IOReturn);
    void finishWCLJoin(uint16_t, uint16_t, IOReturn);
    void publishWCLBeacon(const ieee80211_node *, const uint8_t *, size_t);
    IOTimerEventSource *joinTimer;
    uint8_t joinBSSID[6];
    bool scanPending;
    bool scanCompleted;
    bool scanSkipCompletion;
    bool wclBssValid;
    bool wclLinkIndicated;
    uint8_t wclBssInfo[sizeof(AirportWCL::BeaconMetadata) + 0x800];
    uint8_t wclBeaconInfo[0x808] = {};
    uint32_t wclAssociatedBeacons = 0;
    uint32_t wclLqmBeacons = 0;
    uint32_t wclLqmTicks = 0, wclLqmPeriodicPosts = 0, wclLqmBeaconPosts = 0;
    int32_t wclLinkQualityReported = 0;   // 0: nothing reported since the link came up
    uint32_t wclLqmReportedBeacons = 0;
    uint64_t wclLqmLastPostNs = 0;        // itlwm_lqmint gate: last LqmUpdate posted
    int32_t wclLqmLastPostRssi = 0;
    uint32_t wclLqmSuppressed = 0;
    int wclReportedLinkQuality = -2;
    ifnet_t wclLinkQualityInterface = nullptr;
    bool joinPending;
    bool joinDeferred = false;
    AirportWCL::JoinRequest deferredJoin = {};
    bool assocNotified;
    bool firstBeaconNotified;
    bool portAuthorized;
    // The first beacon of a personal network arrived before the four way
    // handshake was done, so the link status was held back until the port
    // was authorized.
    bool wclFirstBeaconHeld = false;
    // Whether the command gate may be taken.
    //
    // Waiting for the gate is the one thing in the driver that can block the
    // shutdown: the framework holds the gate while it tears the interface
    // down and waits for the driver in return, so a request that arrives in
    // that window deadlocks. Every entry point that takes the gate has to ask
    // this first and fail instead of waiting.
    bool canUseCommandGate() const;
    // Publishes the BSSID that was captured while the network was still being
    // scanned, for a join request that did not name one.
    void publishEarlyBssid();
    uint8_t earlyBssid[6] = {};
    bool earlyBssidPending = false;
    // The name of a network that hides it, learned from a directed scan that
    // was asked for it by name.
    uint8_t wclHiddenSsid[32] = {};
    uint8_t wclHiddenSsidLength = 0;
    uint8_t wclHiddenBssid[6] = {};
    bool wclHasHiddenSsid = false;
    // The power mode the framework asked for with APPLE80211_IOC_PM_MODE.
    uint32_t pmMode = 0;
    uint32_t pmModeFlags = 0;
    // The power save level the framework asked for with APPLE80211_IOC_POWERSAVE.
    // Disabled until the framework sets a level: the driver does no power saving of its own.
    uint32_t wclPowersaveLevel = APPLE80211_POWERSAVE_MODE_DISABLED;
    uint8_t wclPermanentMAC[6] = {};
    bool wclStopping;
#endif
#ifndef AIRPORT_WCL
public:
    // Sonoma (no WCL): called from the controller's 1 s watchdog. Sets en0's link quality metric from
    // the signal strength, as the WCL builds do, so push, iMessage and other Apple services use Wi-Fi.
    void postLinkQuality();
private:
    int32_t linkQualityReported = 0;   // 0: nothing reported since the link came up
    uint32_t linkQualityTicks = 0;
#endif

private:
    AirportItlwm *instance;
    ItlHalService *fHalService;

    //IO80211
    IOTimerEventSource *scanSource;
    // Scan-result cursor: the MAC address of the last node returned, not a pointer kept between requests
    // (audit ST02: the node could be freed in between). include/ItlScanCursor.hpp.
    ItlScan::Cursor fScanCursor;

    u_int32_t current_authtype_lower;
    u_int32_t current_authtype_upper;
    bool disassocIsVoluntary;
};


#endif /* AirportItlwmSkywalkInterface_hpp */
