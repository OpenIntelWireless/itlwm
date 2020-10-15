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
    if (request_type != SIOCGA80211 && request_type != SIOCSA80211) {
        return kIOReturnError;
    }
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
            *(uint32_t*)data = 1;
            ret = kIOReturnSuccess;
            break;
        case APPLE80211_IOC_AWDL_ELECTION_METRIC:
            IOCTL(request_type, AWDL_ELECTION_METRIC, apple80211_awdl_election_metric);
            break;
        default:
        unhandled:
            if (!ml_at_interrupt_context()) {
                XYLog("%s Unhandled IOCTL %s (%d) %s\n", __FUNCTION__, IOCTL_NAMES[request_number],
                      request_number, request_type == SIOCGA80211 ? "get" : (request_type == SIOCSA80211 ? "set" : "other"));
            }
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
    if (fAWDLInterface) {
        return 45;
    }
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
    data->enabled = 1;
    data->unk1 = 0;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSYNC_ENABLED(OSObject *object, struct apple80211_awdl_sync_enabled *data)
{
    XYLog("%s sync_enabled=%d\n", __FUNCTION__, data->enabled);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getSYNC_FRAME_TEMPLATE(OSObject *object, struct apple80211_awdl_sync_frame_template *data)
{
    XYLog("%s\n", __FUNCTION__);
    if (syncFrameTemplate == NULL || syncFrameTemplateLength == 0) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    data->payload_len = syncFrameTemplateLength;
    memcpy(data->payload, syncFrameTemplate, syncFrameTemplateLength);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSYNC_FRAME_TEMPLATE(OSObject *object, struct apple80211_awdl_sync_frame_template *data)
{
    XYLog("%s payload_len=%d\n", __FUNCTION__, data->payload_len);
    if (data->payload_len <= 0) {
        return kIOReturnError;
    }
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
    return kIOReturnSuccess;
}
