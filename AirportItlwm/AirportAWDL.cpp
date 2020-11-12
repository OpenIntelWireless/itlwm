//
//  AirportAWDL.cpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "AirportItlwm.hpp"

#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_var.h>

#define INTERFACE_NAME(object) \
 OSDynamicCast(IO80211Interface, object) == nullptr ? (OSDynamicCast(IO80211P2PInterface, object) == nullptr ? "???" : OSDynamicCast(IO80211P2PInterface, object)->getBSDName()) : OSDynamicCast(IO80211Interface, object)->getBSDName()

IOReturn AirportItlwm::
getIE(OSObject *object, struct apple80211_ie_data *data)
{
    XYLog("%s %s Error\n", __FUNCTION__,  INTERFACE_NAME(object));
    return kIOReturnError;
}

IOReturn AirportItlwm::
setIE(OSObject *object, struct apple80211_ie_data *data)
{
    XYLog("%s %s frame_type_flags %x add %d signature_len %d ie_len %d\n", __FUNCTION__, INTERFACE_NAME(object), data->frame_type_flags, data->add, data->signature_len, data->ie_len);
    if (data->frame_type_flags == APPLE80211_IE_FLAG_ASSOC_REQ && data->add && data->ie_len && *(uint8_t*)data->ie == 68) {
        XYLog("%s setCustomAssocIE\n", __FUNCTION__);
        return kIOReturnSuccess;
    }

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setP2P_SCAN(OSObject *object, struct apple80211_scan_data *data)
{
    XYLog("%s %s ssid=%s bssid=%s channel=%d phy_mode=%d scan_type=%d\n", __FUNCTION__, INTERFACE_NAME(object), data->ssid, ether_sprintf(data->bssid.octet), data->num_channels, data->phy_mode, data->scan_type);

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setP2P_LISTEN(OSObject *object, struct apple80211_p2p_listen_data *data)
{
    XYLog("%s %s channel=%d pad1=%d flags=%d duration=%d\n", __FUNCTION__, INTERFACE_NAME(object), data->channel, data->pad1, data->flags, data->duration);

    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setP2P_GO_CONF(OSObject *object, struct apple80211_p2p_go_conf_data *data)
{
    XYLog("%s %s auth_upper=%d auth_lower=%d channel=%d bcn_len=%d ssid=%s suppress_beacon=%d\n", __FUNCTION__, INTERFACE_NAME(object), data->auth_upper, data->auth_lower, data->channel, data->bcn_len, data->ssid, data->suppress_beacon);

    return kIOReturnSuccess;
}
