//
//  AirportItlwmSkywalkInterface.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmSkywalkInterface_hpp
#define AirportItlwmSkywalkInterface_hpp

#include <Airport/Apple80211.h>

class AirportItlwmSkywalkInterface : public IO80211InfraProtocol {
    OSDeclareDefaultStructors(AirportItlwmSkywalkInterface)
    
public:
    virtual bool init(IOService *) override;
//    virtual ifnet_t getBSDInterface(void) override;
    
    void associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index);
    void setPTK(const u_int8_t *key, size_t key_len);
    void setGTK(const u_int8_t *key, size_t key_len, u_int8_t kid, u_int8_t *rsc);
    
public:
    virtual IOReturn getSSID(apple80211_ssid_data *) override;
    virtual IOReturn getAUTH_TYPE(apple80211_authtype_data *) override;
    virtual IOReturn getCHANNEL(apple80211_channel_data *) override;
    virtual IOReturn getPOWERSAVE(apple80211_powersave_data *) override;
    virtual IOReturn getTXPOWER(apple80211_txpower_data *) override;
    virtual IOReturn getRATE(apple80211_rate_data *) override;
    virtual IOReturn getBSSID(apple80211_bssid_data *) override;
    virtual IOReturn getSCAN_RESULT(apple80211_scan_result *) override;
    virtual IOReturn getSTATE(apple80211_state_data *) override;
    virtual IOReturn getPHY_MODE(apple80211_phymode_data *) override;
    virtual IOReturn getOP_MODE(apple80211_opmode_data *) override;
    virtual IOReturn getRSSI(apple80211_rssi_data *) override;
    virtual IOReturn getNOISE(apple80211_noise_data *) override;
    virtual IOReturn getSUPPORTED_CHANNELS(apple80211_sup_channel_data *) override;
    virtual IOReturn getLOCALE(apple80211_locale_data *) override;
    virtual IOReturn getDEAUTH(apple80211_deauth_data *) override;
    virtual IOReturn getRATE_SET(apple80211_rate_set_data *) override;
    virtual IOReturn getDTIM_INT(apple80211_dtim_int_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSTATION_LIST(apple80211_sta_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRSN_IE(apple80211_rsn_ie_data *) override;
    virtual IOReturn getAP_IE_LIST(apple80211_ap_ie_data *) override;
    virtual IOReturn getSTATS(apple80211_stats_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getASSOCIATION_STATUS(apple80211_assoc_status_data *) override;
    virtual IOReturn getGUARD_INTERVAL(apple80211_guard_interval_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getMCS(apple80211_mcs_data *) override;
    virtual IOReturn getMCS_INDEX_SET(apple80211_mcs_index_set_data *) override;
    virtual IOReturn getWOW_PARAMETERS(apple80211_wow_parameter_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWOW_ENABLED(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getPID_LOCK(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSTA_IE_LIST(apple80211_sta_ie_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSTA_STATS(apple80211_sta_stats_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBT_COEX_FLAGS(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCURRENT_NETWORK(apple80211_scan_result *) override;
    virtual IOReturn getRSSI_BOUNDS(apple80211_rssi_bounds_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getPOWER_DEBUG_INFO(apple80211_power_debug_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHT_CAPABILITY(apple80211_ht_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn getLINK_CHANGED_EVENT_DATA(apple80211_link_changed_event_data *) override;
    virtual IOReturn getEXTENDED_STATS(apple80211_extended_stats *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBEACON_PERIOD(apple80211_beacon_period_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getVHT_MCS_INDEX_SET(apple80211_vht_mcs_index_set_data *) override;
    virtual IOReturn getMCS_VHT(apple80211_mcs_vht_data *) override;
    virtual IOReturn getGAS_RESULTS(apple80211_gas_result_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCHANNELS_INFO(apple80211_channels_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getVHT_CAPABILITY(apple80211_vht_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBGSCAN_CACHE_RESULTS(apple80211_bgscan_cached_network_data_list *) override { return kIOReturnUnsupported; }
    virtual IOReturn getROAM_PROFILE(apple80211_roam_profile_band_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_COUNTER_STATS(apple80211_chip_stats *) override { return kIOReturnUnsupported; }
    virtual IOReturn getDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn getLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_CHANNELS(apple80211_country_channel_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getPRIVATE_MAC(apple80211_private_mac_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_ENABLE(apple80211_ranging_enable_request_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_START(apple80211_ranging_start_request_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getAWDL_RSDB_CAPS(apple80211_rsdb_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTKO_PARAMS(apple80211_tko_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTKO_DUMP(apple80211_tko_dump *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBTCOEX_PROFILE(apple80211_btcoex_profile *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTRAP_INFO(apple80211_trap_info_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTHERMAL_INDEX(apple80211_thermal_index_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getMAX_NSS_FOR_AP(apple80211_btcoex_max_nss_for_ap_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable *) override { return kIOReturnUnsupported; }
    virtual IOReturn getPOWER_BUDGET(apple80211_power_budget_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRANGING_CAPS(apple80211_ranging_capabilities_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSUPPRESS_SCANS(apple80211_suppress_scans_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHOST_AP_MODE_HIDDEN(apple80211_host_ap_mode_hidden_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getLQM_CONFIG(apple80211_lqm_config_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTRAP_CRASHTRACER_MINI_DUMP(apple80211_trap_mini_dump_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHE_CAPABILITY(apple80211_he_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBEACON_INFO(apple80211_beacon_info_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSOFTAP_PARAMS(apple80211_softap_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_POWER_RANGE(apple80211_chip_power_limit *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSOFTAP_STATS(apple80211_softap_stats *) override { return kIOReturnUnsupported; }
    virtual IOReturn getNSS(apple80211_nss_data *) override;
    virtual IOReturn getHW_ADDR(apple80211_hw_mac_address *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHE_MCS_INDEX_SET(apple80211_he_mcs_index_set_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCHIP_DIAGS(appl80211_chip_diags_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getHP2P_CTRL(apple80211_hp2p_ctrl *) override { return kIOReturnUnsupported; }
    virtual IOReturn getREQUEST_BSS_BLACKLIST(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn getASSOC_READY_STATUS(apple80211_assoc_ready *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTXRX_CHAIN_INFO(apple80211_txrx_chain_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getMIMO_STATUS(apple80211_mimo_status *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCUR_PMK(apple80211_pmk *) override { return kIOReturnUnsupported; }
    virtual IOReturn getDYNSAR_DETAIL(apple80211_dynsar_detail *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRANDOMISATION_STATUS(apple80211_mac_randomisation_status *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_CHANNELS_INFO(apple80211_channels_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getLQM_SUMMARY(apple80211_lqm_summary *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *) override;
    virtual IOReturn getBEACON_SCAN_CACHE_REQ(apple80211_scan_result *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSLOW_WIFI_FEATURE_ENABLED(apple80211_slow_wifi_feature_enabled *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCCA(apple80211_interface_cca_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRX_RATE(apple80211_rate_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getTIMESYNC_INFO(apple80211_timesync_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSENSING_DATA(apple80211_sensing_data_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getCOUNTRY_BAND_SUPPORT(apple80211_country_band_support *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_BSS_INFO(apple80211_beacon_msg *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_GET_TX_BLANKING_STATUS(uint *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSSID_TRANSITION_SUPPORT(apple80211_ssid_transition_feature_enabled *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_VALID_CHANNEL_COUNT(unsigned long *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_P2P_STATUS_FOR_SCAN(p2pStatusForScan *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_CHANNELS_INFO(apple80211ChannelInfo *) override { return kIOReturnUnsupported; }
    virtual IOReturn getP2P_STEERING_METRIC(apple80211_p2p_steering_metrics *) override { return kIOReturnUnsupported; }
    virtual IOReturn getRSN_XE(apple80211_rsn_xe_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn getSIB_COEX_STATUS(apple80211_sib_coex_status *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_LOW_LATENCY_INFO_STATS(apple80211_wcl_low_latency_stats *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list *) override { return kIOReturnUnsupported; }
    virtual IOReturn getWIFI_NOISE_PER_ANT(apple80211_noise_per_ant_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn getBLOCKED_BANDS(apple80211_blocked_bands *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSSID(apple80211_ssid_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setAUTH_TYPE(apple80211_authtype_data *) override;
    virtual IOReturn setCIPHER_KEY(apple80211_key *) override;
    virtual IOReturn setCHANNEL(apple80211_channel_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setPOWERSAVE(apple80211_powersave_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setTXPOWER(apple80211_txpower_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRATE(apple80211_rate_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSCAN_REQ(apple80211_scan_data *) override;
    virtual IOReturn setASSOCIATE(apple80211_assoc_data *) override;
    virtual IOReturn setDISASSOCIATE(apple80211_disassoc_data *) override;
    virtual IOReturn setIBSS_MODE(apple80211_network_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setHOST_AP_MODE(apple80211_network_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setAP_MODE(apple80211_apmode_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setDEAUTH(apple80211_deauth_data *) override;
    virtual IOReturn setTX_ANTENNA(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setANTENNA_DIVERSITY(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_IE(apple80211_rsn_ie_data *) override;
    virtual IOReturn setBACKGROUND_SCAN(apple80211_bgscan_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_PARAMETERS(apple80211_wow_parameter_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_ENABLED(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setPID_LOCK(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_AUTHORIZE(apple80211_sta_authorize_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_DISASSOCIATE(apple80211_sta_disassoc_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSTA_DEAUTH(apple80211_sta_disassoc_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_CONF(apple80211_rsn_conf_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setIE(apple80211_ie_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWOW_TEST(apple80211_wow_test_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSCANCACHE_CLEAR(void *) override;
    virtual IOReturn setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBT_COEX_FLAGS(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setROAM(apple80211_sta_roam_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setHT_CAPABILITY(apple80211_ht_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn setAWDL_FORCED_ROAM_CONFIG(apple80211_awdl_forced_roam_config *) override { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_ARP(apple80211_offload_arp_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_NDP(apple80211_offload_ndp_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_SCAN(apple80211_offload_scan_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_REQ(apple80211_gas_query_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_START(apple80211_gas_query_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_SET_PEER(apple80211_gas_peer_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setVHT_CAPABILITY(apple80211_vht_capability *) override { return kIOReturnUnsupported; }
    virtual IOReturn setROAM_PROFILE(apple80211_roam_profile_band_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setAWDL_ENABLE_ROAMING(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting *) override { return kIOReturnUnsupported; }
    virtual IOReturn setPRIVATE_MAC(apple80211_private_mac_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRESET_CHIP(apple80211_reset_command *) override { return kIOReturnUnsupported; }
    virtual IOReturn setCRASH(apple80211_crash_command *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_ENABLE(apple80211_ranging_enable_request_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_START(apple80211_ranging_start_request_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRANGING_AUTHENTICATE(apple80211_ranging_authenticate_request_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setTKO_PARAMS(apple80211_tko_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_PROFILE(apple80211_btcoex_profile *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setTHERMAL_INDEX(apple80211_thermal_index_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable *) override { return kIOReturnUnsupported; }
    virtual IOReturn setPOWER_BUDGET(apple80211_power_budget_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSUPPRESS_SCANS(apple80211_suppress_scans_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setHOST_AP_MODE_HIDDEN(apple80211_host_ap_mode_hidden_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setLQM_CONFIG(apple80211_lqm_config_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_PARAMS(apple80211_softap_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_TRIGGER_CSA(apple80211_softap_csa_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_WIFI_NETWORK_INFO_IE(apple80211_softap_wifi_network_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBTCOEX_DISABLE_ULOFDMA(uint *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSCAN_CONTROL(apple80211_scan_control_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setUSB_HOST_NOTIFICATION(apple80211_usb_host_notification_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSET_MAC_ADDRESS(apple80211_set_mac_address *) override { return kIOReturnUnsupported; }
    virtual IOReturn setHP2P_CTRL(apple80211_hp2p_ctrl *) override { return kIOReturnUnsupported; }
    virtual IOReturn setABORT_SCAN(apple80211_abort_scan *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSET_PROPERTY(apple80211_set_property_unserialized_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setROAM_CACHE_UPDATE(apple80211_roam_cache_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setPM_MODE(apple80211_pm_mode *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSET_WIFI_ASSERTION_STATE(apple80211_wifi_assertion_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setREASSOCIATE_WITH_CORECAPTURE(apple80211_capture_debug_info_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setLINKDOWN_DEBOUNCE_STATUS(apple80211_linkdown_debounce_status *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSOFTAP_EXTENDED_CAPABILITIES_IE(apple80211_softap_extended_capabilities_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn setREALTIME_QOS_MSCS(apple80211_state_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSENSING_ENABLE(apple80211_sensing_enable_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSENSING_DISABLE(apple80211_sensing_disable_t *) override { return kIOReturnUnsupported; }
    virtual IOReturn setNANPHS_ASSOCIATION(apple80211_nan_link_association_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn setNANPHS_TERMINATED(apple80211_nan_link_association_info *) override { return kIOReturnUnsupported; }
    virtual IOReturn set6G_MODE(apple80211_6G_mode *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_LEAVE_NETWORK(apple80211_leave_network *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_REASSOC(apple80211_reassoc *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_PROFILE_CONFIG(apple80211_roam_profile_config *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_PROFILE_CONFIGV1(apple80211_roam_profile_configV1 *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ROAM_USER_CACHE(apple80211_user_roam_cache *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SET_MULTI_AP_ENV(apple80211_set_multi_ap_env *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SCAN_ABORT(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_REAL_TIME_MODE(apple80211_wcl_real_time_mode *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_GARP_MODE(apple80211_wcl_garp_mode *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_JOIN_ABORT(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_TRIGGER_CC(triggerCC *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SCAN_REQ(apple80211ScanRequest *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ASSOCIATE(apple80211_assoc_candidates *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_PROTECT_IP(apple80211_wcl_protect_ip_mode *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_LINK_UP_DONE(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_VOLUNTARY_NETWORK_DISCONNECT(apple80211_wcl_voluntary_network_disconnect *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *) override { return kIOReturnUnsupported; }
    virtual IOReturn setSLOW_WIFI_RECOVERY(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setRSN_XE(apple80211_rsn_xe_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ULOFDMA_STATE(apple80211_wcl_ulofdma_state *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_ACTION_FRAME(apple80211_wcl_action_frame *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_REAL_TIME_POLICY(apple80211_wcl_real_time_policy *) override { return kIOReturnUnsupported; }
    virtual IOReturn setGAS_ABORT(void *) override { return kIOReturnUnsupported; }
    virtual IOReturn setOS_FEATURE_FLAGS(apple80211_feature_flags *) override { return kIOReturnUnsupported; }
    virtual IOReturn setDHCP_RENEWAL_DATA(apple80211_dhcp_renewal_data *) override { return kIOReturnUnsupported; }
    virtual IOReturn setMOVING_NETWORK(apple80211_network_flags *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBATTERY_POWERSAVE_CONFIG(apple80211_battery_ps_config *) override { return kIOReturnUnsupported; }
    virtual IOReturn setMIMO_CONFIG(apple80211_mimo_config *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_MOTIONPROFILE(apple80211_bg_motion_profile *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_NETWORK(apple80211_bg_network *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BGSCAN(apple80211_bg_scan *) override { return kIOReturnUnsupported; }
    virtual IOReturn setWCL_CONFIG_BG_PARAMS(apple80211_bg_params *) override { return kIOReturnUnsupported; }
    virtual IOReturn setBLOCKED_BANDS(apple80211_blocked_bands *) override { return kIOReturnUnsupported; }
    
private:
    AirportItlwm *instance;
    ItlHalService *fHalService;
    
    //IO80211
    struct ieee80211_node *fNextNodeToSend;
    IOTimerEventSource *scanSource;
    bool fScanResultWrapping;
    
    u_int32_t current_authtype_lower;
    u_int32_t current_authtype_upper;
    bool disassocIsVoluntary;
};


#endif /* AirportItlwmSkywalkInterface_hpp */
