//
//  AirportVirtualIOCTL.cpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "AirportItlwm.hpp"


SInt32 AirportItlwm::
apple80211VirtualRequest(UInt request_type, int request_number, IO80211VirtualInterface *interface, void *data)
{
    if (request_type != SIOCGA80211 && request_type != SIOCSA80211)
        return kIOReturnError;
    IOReturn ret = kIOReturnError;
    
    switch (request_number) {
        case APPLE80211_IOC_CARD_CAPABILITIES:
            IOCTL_GET(request_type, CARD_CAPABILITIES, apple80211_capability_data);
            break;
        case APPLE80211_IOC_POWER:
            IOCTL_GET(request_type, POWER, apple80211_power_data);
            break;
        case APPLE80211_IOC_SUPPORTED_CHANNELS:
            IOCTL_GET(request_type, SUPPORTED_CHANNELS, apple80211_sup_channel_data);
            break;
        case APPLE80211_IOC_DRIVER_VERSION:
            IOCTL_GET(request_type, DRIVER_VERSION, apple80211_version_data);
            break;
        case APPLE80211_IOC_OP_MODE:
            IOCTL_GET(request_type, OP_MODE, apple80211_opmode_data);
            break;
        case APPLE80211_IOC_PHY_MODE:
            IOCTL_GET(request_type, PHY_MODE, apple80211_phymode_data);
            break;
        case APPLE80211_IOC_RSSI:
            IOCTL_GET(request_type, RSSI, apple80211_rssi_data);
            break;
        case APPLE80211_IOC_STATE:
            IOCTL_GET(request_type, STATE, apple80211_state_data);
            break;
        case APPLE80211_IOC_BSSID:
            IOCTL(request_type, BSSID, apple80211_bssid_data);
            break;
        case APPLE80211_IOC_RATE:
            IOCTL_GET(request_type, RATE, apple80211_rate_data);
            break;
        case APPLE80211_IOC_CHANNEL:
            IOCTL(request_type, CHANNEL, apple80211_channel_data);
            break;
        case APPLE80211_IOC_AUTH_TYPE:
            IOCTL(request_type, AUTH_TYPE, apple80211_authtype_data);
            break;
        case APPLE80211_IOC_ROAM_PROFILE:
            IOCTL(request_type, ROAM_PROFILE, apple80211_roam_profile_band_data);
            break;
        case APPLE80211_IOC_SSID:
            IOCTL(request_type, SSID, apple80211_ssid_data);
            break;
        case APPLE80211_IOC_AWDL_PEER_TRAFFIC_REGISTRATION:
            IOCTL(request_type, AWDL_PEER_TRAFFIC_REGISTRATION, apple80211_awdl_peer_traffic_registration);
            break;
        case APPLE80211_IOC_AWDL_SYNC_ENABLED:
            IOCTL(request_type, SYNC_ENABLED, apple80211_awdl_sync_enabled);
            break;
        case APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE:
            IOCTL(request_type, SYNC_FRAME_TEMPLATE, apple80211_awdl_sync_frame_template);
            break;
        case APPLE80211_IOC_HT_CAPABILITY:
            IOCTL_GET(request_type, AWDL_HT_CAPABILITY, apple80211_ht_capability);
            break;
        case APPLE80211_IOC_VHT_CAPABILITY:
            IOCTL_GET(request_type, AWDL_VHT_CAPABILITY, apple80211_vht_capability);
            break;
        case APPLE80211_IOC_AWDL_ELECTION_METRIC:
            IOCTL(request_type, AWDL_ELECTION_METRIC, apple80211_awdl_election_metric);
            break;
        case APPLE80211_IOC_AWDL_BSSID:
            IOCTL(request_type, AWDL_BSSID, apple80211_awdl_bssid);
            break;
        case APPLE80211_IOC_CHANNELS_INFO:
            IOCTL_GET(request_type, CHANNELS_INFO, apple80211_channels_info);
            break;
        case APPLE80211_IOC_PEER_CACHE_MAXIMUM_SIZE:
            IOCTL(request_type, PEER_CACHE_MAXIMUM_SIZE, apple80211_peer_cache_maximum_size);
            break;
        case APPLE80211_IOC_AWDL_ELECTION_ID:
            IOCTL(request_type, AWDL_ELECTION_ID, apple80211_awdl_election_id);            
            break;
        case APPLE80211_IOC_AWDL_MASTER_CHANNEL:
            IOCTL(request_type, AWDL_MASTER_CHANNEL, apple80211_awdl_master_channel);
            break;
        case APPLE80211_IOC_AWDL_SECONDARY_MASTER_CHANNEL:
            IOCTL(request_type, AWDL_SECONDARY_MASTER_CHANNEL, apple80211_awdl_secondary_master_channel);
            break;
        case APPLE80211_IOC_AWDL_MIN_RATE:
            IOCTL(request_type, AWDL_MIN_RATE, apple80211_awdl_min_rate);
            break;
        case APPLE80211_IOC_AWDL_ELECTION_RSSI_THRESHOLDS:
            IOCTL(request_type, AWDL_ELECTION_RSSI_THRESHOLDS, apple80211_awdl_election_rssi_thresholds);
            break;
        case APPLE80211_IOC_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE:
            IOCTL(request_type, AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE, apple80211_awdl_sync_channel_sequence);
            break;
        case APPLE80211_IOC_AWDL_PRESENCE_MODE:
            IOCTL(request_type, AWDL_PRESENCE_MODE, apple80211_awdl_presence_mode);
            break;
        case APPLE80211_IOC_AWDL_EXTENSION_STATE_MACHINE_PARAMETERS:
            IOCTL(request_type, AWDL_EXTENSION_STATE_MACHINE_PARAMETERS, apple80211_awdl_extension_state_machine_parameter);
            break;
        case APPLE80211_IOC_AWDL_SYNC_STATE:
            IOCTL(request_type, AWDL_SYNC_STATE, apple80211_awdl_sync_state);
            break;
        case APPLE80211_IOC_AWDL_SYNC_PARAMS:
            IOCTL(request_type, AWDL_SYNC_PARAMS, apple80211_awdl_sync_params);
            break;
        case APPLE80211_IOC_AWDL_CAPABILITIES:
            IOCTL_GET(request_type, AWDL_CAPABILITIES, apple80211_awdl_cap);
            break;
        case APPLE80211_IOC_AWDL_AF_TX_MODE:
            IOCTL(request_type, AWDL_AF_TX_MODE, apple80211_awdl_af_tx_mode);
            break;
        case APPLE80211_IOC_AWDL_OOB_AUTO_REQUEST:
            IOCTL_SET(request_type, AWDL_OOB_AUTO_REQUEST, apple80211_awdl_oob_request);
            break;
        case APPLE80211_IOC_IE:
            IOCTL(request_type, IE, apple80211_ie_data);
            break;
        case APPLE80211_IOC_P2P_LISTEN:
            IOCTL_SET(request_type, P2P_LISTEN, apple80211_p2p_listen_data);
            break;
        case APPLE80211_IOC_P2P_SCAN:
            IOCTL_SET(request_type, P2P_SCAN, apple80211_scan_data);
            break;
        case APPLE80211_IOC_P2P_GO_CONF:
            IOCTL_SET(request_type, P2P_GO_CONF, apple80211_p2p_go_conf_data);
            break;
        default:
        unhandled:
            if (!ml_at_interrupt_context())
                XYLog("%s Unhandled IOCTL %s (%d) %s\n", __FUNCTION__, IOCTL_NAMES[request_number >= ARRAY_SIZE(IOCTL_NAMES) ? 0: request_number],
                      request_number, request_type == SIOCGA80211 ? "get" : (request_type == SIOCSA80211 ? "set" : "other"));
            break;
    }
    
    return ret;
}

IOReturn AirportItlwm::
setAWDL_PEER_TRAFFIC_REGISTRATION(OSObject *object, struct apple80211_awdl_peer_traffic_registration *data)
{
    char name[255];
    if (data->name_len > 0 && data->name_len < 255) {
        bzero(name, 255);
        memcpy(name, data->name, data->name_len);
    }
    XYLog("%s name=%s, name_len=%d, active=%d\n", __FUNCTION__, name, data->name_len, data->active);
    if (!strncmp(data->name, "wifid-assisted-discovery", data->name_len)) {
        if (data->active) {
            
        } else {
            
        }
    } else if (!strncmp(data->name, "sidecar", data->name_len)) {
        
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_PEER_TRAFFIC_REGISTRATION(OSObject *object, struct apple80211_awdl_peer_traffic_registration *)
{
    XYLog("%s\n", __FUNCTION__);
    if (fAWDLInterface)
        return 45;
    return 22;
}

IOReturn AirportItlwm::
setAWDL_ELECTION_METRIC(OSObject *object, struct apple80211_awdl_election_metric *data)
{
    XYLog("%s metric=%d\n", __FUNCTION__, data->metric);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_ELECTION_METRIC(OSObject *object, struct apple80211_awdl_election_metric *data)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnError;
}

IOReturn AirportItlwm::
getSYNC_ENABLED(OSObject *object, struct apple80211_awdl_sync_enabled *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->enabled = this->awdlSyncEnable;
    data->unk1 = 0;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSYNC_ENABLED(OSObject *object, struct apple80211_awdl_sync_enabled *data)
{
    XYLog("%s sync_enabled=%d\n", __FUNCTION__, data->enabled);
    this->awdlSyncEnable = data->enabled;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getSYNC_FRAME_TEMPLATE(OSObject *object, struct apple80211_awdl_sync_frame_template *data)
{
    XYLog("%s\n", __FUNCTION__);
    if (syncFrameTemplate == NULL || syncFrameTemplateLength == 0)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->payload_len = syncFrameTemplateLength;
    memcpy(data->payload, syncFrameTemplate, syncFrameTemplateLength);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSYNC_FRAME_TEMPLATE(OSObject *object, struct apple80211_awdl_sync_frame_template *data)
{
    XYLog("%s payload_len=%d\n", __FUNCTION__, data->payload_len);
    if (data->payload_len <= 0)
        return kIOReturnError;
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    syncFrameTemplate = (uint8_t *)IOMalloc(data->payload_len);
    syncFrameTemplateLength = data->payload_len;
    memset(syncFrameTemplate, 0, data->payload_len);
    memcpy(syncFrameTemplate, data->payload, data->payload_len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_HT_CAPABILITY(OSObject *object, struct apple80211_ht_capability *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->hc_id = IEEE80211_ELEMID_HTCAPS;
    data->hc_cap = (IEEE80211_HTCAP_SGI20 | IEEE80211_HTCAP_CBW20_40 | IEEE80211_HTCAP_SGI40);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_VHT_CAPABILITY(OSObject *object, struct apple80211_vht_capability *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->cap = 3263;

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_BSSID(OSObject *object, struct apple80211_awdl_bssid *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    memcpy(data->bssid, awdlBSSID, 6);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_BSSID(OSObject *object, struct apple80211_awdl_bssid *data)
{
    XYLog("%s bssid=%s unk_mac=%s\n", __FUNCTION__, ether_sprintf(data->bssid), ether_sprintf(data->unk_mac));
    memcpy(awdlBSSID, data->bssid, 6);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCHANNELS_INFO(OSObject *object, struct apple80211_channels_info *data)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
        struct ieee80211_channel *channel = &ic->ic_channels[i];
        if (channel->ic_freq != 0) {
            int chanNum = ieee80211_chan2ieee(ic, channel);
            data->chan_num[data->num_chan_specs] = chanNum;
            data->support_80Mhz[data->num_chan_specs] = IEEE80211_IS_CHAN_VHT80(channel);
            data->support_40Mhz[data->num_chan_specs] = IEEE80211_IS_CHAN_HT40(channel) || IEEE80211_IS_CHAN_VHT40(channel);
            data->num_chan_specs++;
            if (data->num_chan_specs >= APPLE80211_MAX_CHANNELS)
                break;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_ELECTION_ID(OSObject *object, struct apple80211_awdl_election_id *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->election_id = awdlElectionId;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_ELECTION_ID(OSObject *object, struct apple80211_awdl_election_id *data)
{
    XYLog("%s election_id=%d\n", __FUNCTION__, data->election_id);
    awdlElectionId = data->election_id;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPEER_CACHE_MAXIMUM_SIZE(OSObject *object, struct apple80211_peer_cache_maximum_size *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->max_peers = 255;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setPEER_CACHE_MAXIMUM_SIZE(OSObject *object, struct apple80211_peer_cache_maximum_size *data)
{
    XYLog("%s max_peers=%d\n", __FUNCTION__, data->max_peers);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_MASTER_CHANNEL(OSObject *object, struct apple80211_awdl_master_channel *data)
{
    data->version = APPLE80211_VERSION;
    data->master_channel = awdlMasterChannel;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_MASTER_CHANNEL(OSObject *object, struct apple80211_awdl_master_channel *data)
{
    XYLog("%s master_channel=%d\n", __FUNCTION__, data->master_channel);
    awdlMasterChannel = data->master_channel;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_SECONDARY_MASTER_CHANNEL(OSObject *object, struct apple80211_awdl_secondary_master_channel *data)
{
    XYLog("%s temporary return channel 0\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->secondary_master_channel = awdlSecondaryMasterChannel;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_SECONDARY_MASTER_CHANNEL(OSObject *object, struct apple80211_awdl_secondary_master_channel *data)
{
    XYLog("%s secondary_master_channel=%d\n", __FUNCTION__, data->secondary_master_channel);
    awdlSecondaryMasterChannel = data->secondary_master_channel;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_MIN_RATE(OSObject *object, struct apple80211_awdl_min_rate *data)
{
    XYLog("%s min_rate=%d plus=%d\n", __FUNCTION__, data->min_rate, 2 *data->min_rate);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_MIN_RATE(OSObject *object, struct apple80211_awdl_min_rate *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_ELECTION_RSSI_THRESHOLDS(OSObject *object, struct apple80211_awdl_election_rssi_thresholds *data)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnError;
}

IOReturn AirportItlwm::
setAWDL_ELECTION_RSSI_THRESHOLDS(OSObject *object, struct apple80211_awdl_election_rssi_thresholds *data)
{
    XYLog("%s unk1=%d unk2=%d unk3=%d\n", __FUNCTION__, data->unk1, data->unk2, data->unk3);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(OSObject *object, struct apple80211_awdl_sync_channel_sequence *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    
    return kIOReturnSuccess;
}

#if 0
static void dumpAWDLChannelSeqs(struct apple80211_awdl_sync_channel_sequence *data)
{
    if (data == nullptr)
        return;
    XYLog("%s length %u step count %u duplicate %u fill %d encoding %u\n", __FUNCTION__, data->length, data->step_count, data->duplicate_count, data->fill_channel, data->encoding);
    for (int i = 0; i < data->length; i++) {
        struct apple80211_channel_sequence seq = data->seqs[i];
        uint16_t band = seq.flags & 0xC00;
        uint16_t channel = seq.flags & 0x300;

        XYLog("%s %d 0x%04x=%d%s%s%s\n", __FUNCTION__, i, seq.flags, (uint8_t)seq.flags, band != 0x800 ? (band == 0xC00 ? ",20MHz" : ",unknown") : ",20MHz", channel != 0x200 ? (channel == 0x100 ? ",-1" : ",none") : ",1", (seq.flags & 0xF000) == 4096 ? ",5GHz" : ",unknown");
    }
}
#endif

IOReturn AirportItlwm::
setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(OSObject *object, struct apple80211_awdl_sync_channel_sequence *data)
{
    XYLog("%s\n", __FUNCTION__);
#if 0
    dumpAWDLChannelSeqs(data);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_PRESENCE_MODE(OSObject *object, struct apple80211_awdl_presence_mode *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->mode = awdlPresenceMode;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_PRESENCE_MODE(OSObject *object, struct apple80211_awdl_presence_mode *data)
{
    XYLog("%s mode=%d\n", __FUNCTION__, data->mode);
    awdlPresenceMode = data->mode;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(OSObject *object, struct apple80211_awdl_extension_state_machine_parameter *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(OSObject *object, struct apple80211_awdl_extension_state_machine_parameter *data)
{
    XYLog("%s unk1=%d unk2=%d unk3=%d unk4=%d\n", __FUNCTION__, data->unk1, data->unk2, data->unk3, data->unk4);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_SYNC_STATE(OSObject *object, struct apple80211_awdl_sync_state *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->state = awdlSyncState;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_SYNC_STATE(OSObject *object, struct apple80211_awdl_sync_state *data)
{
    XYLog("%s state=%d\n", __FUNCTION__, data->state);
    awdlSyncState = data->state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_SYNC_PARAMS(OSObject *object, struct apple80211_awdl_sync_params *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_SYNC_PARAMS(OSObject *object, struct apple80211_awdl_sync_params *data)
{
    XYLog("%s availability_window_length=%d availability_window_period=%d extension_length=%d synchronization_frame_period=%d\n", __FUNCTION__, data->availability_window_length, data->availability_window_period, data->extension_length, data->synchronization_frame_period);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_CAPABILITIES(OSObject *object, struct apple80211_awdl_cap *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;
    data->cap = APPLE80211_AWDL_CAP_CCA_STATS;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAWDL_AF_TX_MODE(OSObject *object, struct apple80211_awdl_af_tx_mode *data)
{
    XYLog("%s\n", __FUNCTION__);
    data->version = APPLE80211_VERSION;

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_AF_TX_MODE(OSObject *object, struct apple80211_awdl_af_tx_mode *data)
{
    XYLog("%s mode=%llu\n", __FUNCTION__, data->mode);

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAWDL_OOB_AUTO_REQUEST(OSObject *object, struct apple80211_awdl_oob_request *data)
{
    XYLog("%s data_len=%d unk1=%d unk2=%d unk3=%d unk4=%d unk5=%d unk6=%d unk7=%d unk9=%d\n", __FUNCTION__, data->data_len, data->unk1, data->unk2, data->unk3, data->unk4, data->unk5, data->unk6, data->unk7, data->unk9);
    return kIOReturnSuccess;
}
