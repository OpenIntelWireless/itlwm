//
//  AirportSTAIOCTL.cpp
//  AirportItlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "AirportItlwm.hpp"

extern IOCommandGate *_fCommandGate;

const char* hexdump(uint8_t *buf, size_t len);

SInt32 AirportItlwm::apple80211Request(unsigned int request_type,
                                       int request_number,
                                       IO80211Interface *interface,
                                       void *data)
{
    if (request_type != SIOCGA80211 && request_type != SIOCSA80211) {
        return kIOReturnError;
    }
    IOReturn ret = kIOReturnError;
    
    switch (request_number) {
        case APPLE80211_IOC_SSID:  // 1
            IOCTL(request_type, SSID, apple80211_ssid_data);
            break;
        case APPLE80211_IOC_AUTH_TYPE:  // 2
            IOCTL(request_type, AUTH_TYPE, apple80211_authtype_data);
            break;
        case APPLE80211_IOC_CHANNEL:  // 4
            IOCTL(request_type, CHANNEL, apple80211_channel_data);
            break;
        case APPLE80211_IOC_PROTMODE:
            IOCTL(request_type, PROTMODE, apple80211_protmode_data);
            break;
        case APPLE80211_IOC_TXPOWER:  // 7
            IOCTL_GET(request_type, TXPOWER, apple80211_txpower_data);
            break;
        case APPLE80211_IOC_RATE:  // 8
            IOCTL_GET(request_type, RATE, apple80211_rate_data);
            break;
        case APPLE80211_IOC_BSSID:  // 9
            IOCTL(request_type, BSSID, apple80211_bssid_data);
            break;
        case APPLE80211_IOC_SCAN_REQ:  // 10
            IOCTL_SET(request_type, SCAN_REQ, apple80211_scan_data);
            break;
        case APPLE80211_IOC_SCAN_REQ_MULTIPLE:
            IOCTL_SET(request_type, SCAN_REQ_MULTIPLE, apple80211_scan_multiple_data);
            break;
        case APPLE80211_IOC_SCAN_RESULT:  // 11
            IOCTL_GET(request_type, SCAN_RESULT, apple80211_scan_result*);
            break;
        case APPLE80211_IOC_CARD_CAPABILITIES:  // 12
            IOCTL_GET(request_type, CARD_CAPABILITIES, apple80211_capability_data);
            break;
        case APPLE80211_IOC_STATE:  // 13
            IOCTL_GET(request_type, STATE, apple80211_state_data);
            break;
        case APPLE80211_IOC_PHY_MODE:  // 14
            IOCTL_GET(request_type, PHY_MODE, apple80211_phymode_data);
            break;
        case APPLE80211_IOC_OP_MODE:  // 15
            IOCTL_GET(request_type, OP_MODE, apple80211_opmode_data);
            break;
        case APPLE80211_IOC_RSSI:  // 16
            IOCTL_GET(request_type, RSSI, apple80211_rssi_data);
            break;
        case APPLE80211_IOC_NOISE:  // 17
            IOCTL_GET(request_type, NOISE, apple80211_noise_data);
            break;
        case APPLE80211_IOC_INT_MIT:  // 18
            IOCTL_GET(request_type, INT_MIT, apple80211_intmit_data);
            break;
        case APPLE80211_IOC_POWER:  // 19
            IOCTL(request_type, POWER, apple80211_power_data);
            break;
        case APPLE80211_IOC_ASSOCIATE:  // 20
            IOCTL_SET(request_type, ASSOCIATE, apple80211_assoc_data);
            break;
        case APPLE80211_IOC_ASSOCIATE_RESULT: // 21
            IOCTL_GET(request_type, ASSOCIATE_RESULT, apple80211_assoc_result_data);
            break;
        case APPLE80211_IOC_DISASSOCIATE: // 22
            if (request_type == SIOCSA80211)
                setDISASSOCIATE(interface);
            break;
        case APPLE80211_IOC_RATE_SET:
            IOCTL_GET(request_type, RATE_SET, apple80211_rate_set_data);
            break;
        case APPLE80211_IOC_MCS_INDEX_SET:
            IOCTL_GET(request_type, MCS_INDEX_SET, apple80211_mcs_index_set_data);
            break;
        case APPLE80211_IOC_SUPPORTED_CHANNELS:  // 27
        case APPLE80211_IOC_HW_SUPPORTED_CHANNELS:
            IOCTL_GET(request_type, SUPPORTED_CHANNELS, apple80211_sup_channel_data);
            break;
        case APPLE80211_IOC_LOCALE:  // 28
            IOCTL_GET(request_type, LOCALE, apple80211_locale_data);
            break;
        case APPLE80211_IOC_DEAUTH:
            IOCTL(request_type, DEAUTH, apple80211_deauth_data);
            break;
        case APPLE80211_IOC_TX_ANTENNA:  // 37
            IOCTL_GET(request_type, TX_ANTENNA, apple80211_antenna_data);
            break;
        case APPLE80211_IOC_ANTENNA_DIVERSITY:  // 39
            IOCTL_GET(request_type, ANTENNA_DIVERSITY, apple80211_antenna_data);
            break;
        case APPLE80211_IOC_DRIVER_VERSION:  // 43
            IOCTL_GET(request_type, DRIVER_VERSION, apple80211_version_data);
            break;
        case APPLE80211_IOC_HARDWARE_VERSION:  // 44
            IOCTL_GET(request_type, HARDWARE_VERSION, apple80211_version_data);
            break;
        case APPLE80211_IOC_RSN_IE: // 46
            IOCTL(request_type, RSN_IE, apple80211_rsn_ie_data);
            break;
        case APPLE80211_IOC_AP_IE_LIST: // 48
            IOCTL_GET(request_type, AP_IE_LIST, apple80211_ap_ie_data);
            break;
        case APPLE80211_IOC_ASSOCIATION_STATUS:  // 50
            IOCTL_GET(request_type, ASSOCIATION_STATUS, apple80211_assoc_status_data);
            break;
        case APPLE80211_IOC_COUNTRY_CODE:  // 51
            IOCTL_GET(request_type, COUNTRY_CODE, apple80211_country_code_data);
            break;
        case APPLE80211_IOC_RADIO_INFO:
            IOCTL_GET(request_type, RADIO_INFO, apple80211_radio_info_data);
            break;
        case APPLE80211_IOC_MCS:  // 57
            IOCTL_GET(request_type, MCS, apple80211_mcs_data);
            break;
        case APPLE80211_IOC_VIRTUAL_IF_CREATE: // 94
            IOCTL_SET(request_type, VIRTUAL_IF_CREATE, apple80211_virt_if_create_data);
            break;
        case APPLE80211_IOC_VIRTUAL_IF_DELETE:
            IOCTL_SET(request_type, VIRTUAL_IF_DELETE, apple80211_virt_if_delete_data);
            break;
        case APPLE80211_IOC_ROAM_THRESH:
            IOCTL_GET(request_type, ROAM_THRESH, apple80211_roam_threshold_data);
            break;
        case APPLE80211_IOC_LINK_CHANGED_EVENT_DATA:
            IOCTL_GET(request_type, LINK_CHANGED_EVENT_DATA, apple80211_link_changed_event_data);
            break;
        case APPLE80211_IOC_POWERSAVE:
            IOCTL_GET(request_type, POWERSAVE, apple80211_powersave_data);
            break;
        case APPLE80211_IOC_CIPHER_KEY:
            IOCTL_SET(request_type, CIPHER_KEY, apple80211_key);
            break;
        case APPLE80211_IOC_SCANCACHE_CLEAR:
            IOCTL_SET(request_type, SCANCACHE_CLEAR, apple80211req);
            break;
        case APPLE80211_IOC_TX_NSS:
            IOCTL(request_type, TX_NSS, apple80211_tx_nss_data);
            break;
        case APPLE80211_IOC_NSS:
            IOCTL_GET(request_type, NSS, apple80211_nss_data);
            break;
        case APPLE80211_IOC_ROAM_PROFILE:
            IOCTL(request_type, ROAM_PROFILE, apple80211_roam_profile_band_data);
            break;
        case APPLE80211_IOC_WOW_PARAMETERS:
            IOCTL(request_type, WOW_PARAMETERS, apple80211_wow_parameter_data);
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
            if (!ml_at_interrupt_context()) {
                XYLog("%s Unhandled IOCTL %s (%d) %s\n", __FUNCTION__, IOCTL_NAMES[request_number >= ARRAY_SIZE(IOCTL_NAMES) ? 0: request_number],
                      request_number, request_type == SIOCGA80211 ? "get" : (request_type == SIOCSA80211 ? "set" : "other"));
            }
            break;
    }
    
    return ret;
}

IOReturn AirportItlwm::
getSSID(OSObject *object,
                        struct apple80211_ssid_data *sd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
        memcpy(sd->ssid_bytes, ic->ic_des_essid, strlen((const char*)ic->ic_des_essid));
        sd->ssid_len = (uint32_t)strlen((const char*)ic->ic_des_essid);
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
setSSID(OSObject *object, struct apple80211_ssid_data *sd)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAUTH_TYPE(OSObject *object, struct apple80211_authtype_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setAUTH_TYPE(OSObject *object, struct apple80211_authtype_data *ad)
{
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setCIPHER_KEY(OSObject *object, struct apple80211_key *key)
{
    XYLog("%s", __FUNCTION__);
    const char* keydump = hexdump(key->key, key->key_len);
    const char* rscdump = hexdump(key->key_rsc, key->key_rsc_len);
    const char* eadump = hexdump(key->key_ea.octet, APPLE80211_ADDR_LEN);
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");
    if (keydump && rscdump && eadump)
        XYLog("Set key request: len=%d cipher_type=%d flags=%d index=%d key=%s rsc_len=%d rsc=%s ea=%s\n",
              key->key_len, key->key_cipher_type, key->key_flags, key->key_index, keydump, key->key_rsc_len, rscdump, eadump);
    else
        XYLog("Set key request, but failed to allocate memory for hexdump\n");
    
    if (keydump)
        IOFree((void*)keydump, 3 * key->key_len + 1);
    if (rscdump)
        IOFree((void*)rscdump, 3 * key->key_rsc_len + 1);
    if (eadump)
        IOFree((void*)eadump, 3 * APPLE80211_ADDR_LEN + 1);
    
    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    getNetworkInterface()->postMessage(APPLE80211_M_RSN_HANDSHAKE_DONE);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    getNetworkInterface()->postMessage(APPLE80211_M_RSN_HANDSHAKE_DONE);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA is not supported\n");
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
}

static int ieeeChanFlag2apple(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)    ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)    ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))    ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_OFDM)    ret |= APPLE80211_C_FLAG_20MHZ; // XXX ??
    if (flags & IEEE80211_CHAN_CCK)        ret |= APPLE80211_C_FLAG_10MHZ; // XXX ??
    if (flags & IEEE80211_CHAN_VHT)     ret |= APPLE80211_C_FLAG_5GHZ;
    if (flags & IEEE80211_CHAN_HT)      ret |= 6;
    return ret;
}

IOReturn AirportItlwm::
getCHANNEL(OSObject *object,
                           struct apple80211_channel_data *cd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags);
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
setCHANNEL(OSObject *object, struct apple80211_channel_data *data)
{
    XYLog("%s channel=%d\n", __FUNCTION__, data->channel.channel);
    struct ieee80211_channel *channel;
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct _ifnet *ifp = &ic->ic_ac.ac_if;
    if (data->channel.channel >= IEEE80211_CHAN_MAX) {
        XYLog("%s channel set error, channel=%d IEEE80211_CHAN_MAX=%d\n", __FUNCTION__, data->channel.channel, IEEE80211_CHAN_MAX);
        return kIOReturnError;
    }
    channel = &ic->ic_channels[data->channel.channel];
    if (!ifp->if_ioctl(ifp, SIOCS80211CHANNEL, (caddr_t)channel)) {
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getPROTMODE(OSObject *object, struct apple80211_protmode_data *pd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(pd, 0, sizeof(*pd));
        pd->version = APPLE80211_VERSION;
        pd->threshold = 0;
        pd->protmode = 0;
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
setPROTMODE(OSObject *object, struct apple80211_protmode_data *pd)
{
    return kIOReturnError;
}

IOReturn AirportItlwm::
getTXPOWER(OSObject *object,
                           struct apple80211_txpower_data *txd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = 100;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getTX_NSS(OSObject *object, struct apple80211_tx_nss_data *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getNSS(OSObject *object, struct apple80211_nss_data *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setTX_NSS(OSObject *object, struct apple80211_tx_nss_data *data)
{
    return kIOReturnError;
}

IOReturn AirportItlwm::
getRATE(OSObject *object, struct apple80211_rate_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getROAM_PROFILE(OSObject *object, struct apple80211_roam_profile_band_data *data)
{
    if (roamProfile == NULL) {
        XYLog("%s no roam profile, return error\n", __FUNCTION__);
        return kIOReturnError;
    }
    memcpy(data, roamProfile, sizeof(struct apple80211_roam_profile_band_data));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setROAM_PROFILE(OSObject *object, struct apple80211_roam_profile_band_data *data)
{
    XYLog("%s cnt=%d flags=%d\n", __FUNCTION__, data->profile_cnt, data->flags);
    if (roamProfile != NULL) {
        IOFree(roamProfile, sizeof(struct apple80211_roam_profile_band_data));
    }
    roamProfile = (uint8_t *)IOMalloc(sizeof(struct apple80211_roam_profile_band_data));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getWOW_PARAMETERS(OSObject *object, struct apple80211_wow_parameter_data *data)
{
    return kIOReturnError;
}

IOReturn AirportItlwm::
setWOW_PARAMETERS(OSObject *object, struct apple80211_wow_parameter_data *data)
{
    XYLog("%s pattern_count=%d\n", __FUNCTION__, data->pattern_count);
    return kIOReturnError;
}

IOReturn AirportItlwm::
getBSSID(OSObject *object,
                         struct apple80211_bssid_data *bd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
setBSSID(OSObject *object, struct apple80211_bssid_data *data)
{
    XYLog("%s bssid=%s\n", __FUNCTION__, ether_sprintf(data->bssid.octet));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCARD_CAPABILITIES(OSObject *object,
                                     struct apple80211_capability_data *cd)
{
    uint32_t caps = fHalService->get80211Controller()->ic_caps;
    if (caps & IEEE80211_C_WEP)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_WEP;
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_TKIP | 1 << APPLE80211_CAP_AES_CCM;
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_PMGT)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_PMGT;
    // if (caps & IEEE80211_C_IBSS)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_IBSS;
    // if (caps & IEEE80211_C_HOSTAP)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_HOSTAP;
    // AES not enabled, like on Apple cards
    
    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHPREAMBLE - 8);
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_WPA1 - 8) | 1 << (APPLE80211_CAP_WPA2 - 8) | 1 << (APPLE80211_CAP_TKIPMIC - 8);
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_TXPMGT)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_TXPMGT - 8);
    // if (caps & IEEE80211_C_MONITOR)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_MONITOR - 8);
    // WPA not enabled, like on Apple cards

    cd->version = APPLE80211_VERSION;
    cd->capabilities[2] = 0xFF; // BURST, WME, SHORT_GI_40MHZ, SHORT_GI_20MHZ, WOW, TSN, ?, ?
    cd->capabilities[3] = 0x2B;
    cd->capabilities[4] = 0xAD;
    cd->capabilities[5] = 0x80;//isCntryDefaultSupported
    cd->capabilities[5] |= 0x0C;
    cd->capabilities[6] = 0x8D;
    cd->capabilities[7] = 0x84; // This byte contains Apple Watch unlock
    //cd->capabilities[8] = 0x40;
    //cd->capabilities[8] |= 8;//dfs white list
    //cd->capabilities[9] = 0x28;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getSTATE(OSObject *object,
                         struct apple80211_state_data *sd)
{
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    IO80211Interface *inf = OSDynamicCast(IO80211Interface, object);
    if (inf && inf->linkState() == kIO80211NetworkLinkUp) {
        sd->state = APPLE80211_S_RUN;
    }
    IO80211VirtualInterface *vif = OSDynamicCast(IO80211VirtualInterface, object);
    if (vif && vif->linkState() == kIO80211NetworkLinkUp) {
        sd->state = APPLE80211_S_RUN;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getMCS_INDEX_SET(OSObject *object, struct apple80211_mcs_index_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (int i = 0; i < size; i++) {
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        }
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getRATE_SET(OSObject *object, struct apple80211_rate_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        ad->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        for (int i=0; i < size; i++) {
            struct apple80211_rate apple_rate = ad->rates[i];
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getPHY_MODE(OSObject *object,
                            struct apple80211_phymode_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;
    if (fHalService->getDriverInfo()->is5GBandSupport()) {
        pd->phy_mode |= APPLE80211_MODE_11AC;
    }
    
    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
            
        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getOP_MODE(OSObject *object,
                           struct apple80211_opmode_data *od)
{
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getRSSI(OSObject *object,
                        struct apple80211_rssi_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getRSN_IE(OSObject *object, struct apple80211_rsn_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setRSN_IE(OSObject *object, struct apple80211_rsn_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getAP_IE_LIST(OSObject *object, struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len > data->len) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getNOISE(OSObject *object,
                         struct apple80211_noise_data *nd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = fHalService->getDriverInfo()->getBSSNoise();
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::
getINT_MIT(OSObject *object, struct apple80211_intmit_data *imd)
{
    imd->version = APPLE80211_VERSION;
    imd->int_mit = APPLE80211_INT_MIT_AUTO;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 1;
    pd->power_state[0] = power_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPOWERSAVE(OSObject *object, struct apple80211_powersave_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) ==
        (IFF_UP | IFF_RUNNING);
        if (pd->power_state[0] == 0) {
            if (isRunning) {
                disableAdapter(fNetIf);
            }
        } else {
            if (!isRunning) {
                enableAdapter(fNetIf);
            }
        }
        power_state = (pd->power_state[0]);
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setASSOCIATE(OSObject *object,
                             struct apple80211_assoc_data *ad)
{
    XYLog("%s [%s] mode=%d ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%d%s%s%s%s%s%s%s\n", __FUNCTION__, ad->ad_ssid, ad->ad_mode, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_rsn_ie_len,
          (ad->ad_flags & 2) ? ", Instant Hotspot" : "",
          (ad->ad_flags & 4) ? ", Auto Instant Hotspot" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 1) ? ", don't disassociate" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 2) ? ", don't blacklist" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 4) ? ", closed Network" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 8) ? ", 802.1X" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 0x20) ? ", force BSSID" : "");
    
    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_state <= IEEE80211_S_INIT) {
        return kIOReturnError;
    }

    if (ad->ad_mode != 1) {
        disassocIsVoluntary = false;
        auth_type_data.version = APPLE80211_VERSION;
        auth_type_data.authtype_upper = ad->ad_auth_upper;
        auth_type_data.authtype_lower = ad->ad_auth_lower;
        setAUTH_TYPE(object, &auth_type_data);
        rsn_ie_data.version = APPLE80211_VERSION;
        rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
        memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
        setRSN_IE(object, &rsn_ie_data);

        associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getASSOCIATE_RESULT(OSObject *object, struct apple80211_assoc_result_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(struct apple80211_assoc_result_data));
        ad->version = APPLE80211_VERSION;
        ad->result = APPLE80211_RESULT_SUCCESS;
        return kIOReturnSuccess;
    }
    return kIOReturnError;
}

IOReturn AirportItlwm::setDISASSOCIATE(OSObject *object)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    disassocIsVoluntary = true;

    if (ic->ic_state <= IEEE80211_S_ASSOC) {
        return kIOReturnSuccess;
    }

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
    ic->ic_rsn_ie_override[1] = 0;
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getSUPPORTED_CHANNELS(OSObject *object, struct apple80211_sup_channel_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 0;
    struct ieee80211com *ic = fHalService->get80211Controller();
    for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            ad->supported_channels[ad->num_channels++].channel    = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags    = ieeeChanFlag2apple(ic->ic_channels[i].ic_flags);
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getLOCALE(OSObject *object,
                          struct apple80211_locale_data *ld)
{
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getDEAUTH(OSObject *object,
                          struct apple80211_deauth_data *da) {
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getASSOCIATION_STATUS(OSObject *object, struct apple80211_assoc_status_data *hv) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    hv->status = APPLE80211_STATUS_SUCCESS;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSCANCACHE_CLEAR(OSObject *object, struct apple80211req *req)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN)) {
        return kIOReturnSuccess;
    }
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setDEAUTH(OSObject *object,
                          struct apple80211_deauth_data *da) {
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

void AirportItlwm::
eventHandler(struct ieee80211com *ic, int msgCode, void *data)
{
#define INTERFACE_POST_MESSAGE(code) \
    if (interface) { \
        interface->postMessage(code); \
    }
    IO80211Interface *interface = OSDynamicCast(IO80211Interface, ic->ic_ac.ac_if.iface);
    switch (msgCode) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            INTERFACE_POST_MESSAGE(APPLE80211_M_COUNTRY_CODE_CHANGED)
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            INTERFACE_POST_MESSAGE(APPLE80211_M_ASSOC_DONE)
            break;
        case IEEE80211_EVT_STA_DEAUTH:
            INTERFACE_POST_MESSAGE(APPLE80211_M_DEAUTH_RECEIVED)
            break;
        default:
            break;
    }
}

IOReturn AirportItlwm::
getTX_ANTENNA(OSObject *object,
                              apple80211_antenna_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL)
        return kIOReturnError;
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 1;
    ad->antenna_index[0] = 1;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getANTENNA_DIVERSITY(OSObject *object,
                                     apple80211_antenna_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 1;
    ad->antenna_index[0] = 1;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getDRIVER_VERSION(OSObject *object,
                                  struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    snprintf(hv->string, sizeof(hv->string), "itlwm: %s fw: %s", ITLWM_VERSION, fHalService->getDriverInfo()->getFirmwareVersion());
    hv->string_len = strlen(hv->string);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getHARDWARE_VERSION(OSObject *object,
                                    struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, fHalService->getDriverInfo()->getFirmwareVersion(), sizeof(hv->string));
    hv->string_len = strlen(fHalService->getDriverInfo()->getFirmwareVersion());
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCOUNTRY_CODE(OSObject *object,
                                struct apple80211_country_code_data *cd)
{
    char cc[3];
    cd->version = APPLE80211_VERSION;
    memset(cc, 0, sizeof(cc));
    PE_parse_boot_argn("itlwm_cc", cc, 3);
    strncpy((char*)cd->cc, cc[0] == 0 ? fHalService->getDriverInfo()->getFirmwareCountryCode() : cc, sizeof(cd->cc));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getMCS(OSObject *object, struct apple80211_mcs_data* md)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL)
        return kIOReturnError;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getROAM_THRESH(OSObject *object, struct apple80211_roam_threshold_data* md)
{
    md->threshold = 100;
    md->count = 0;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getRADIO_INFO(OSObject *object, struct apple80211_radio_info_data* md)
{
    md->version = APPLE80211_VERSION;
    md->count = 1;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSCAN_REQ(OSObject *object,
                            struct apple80211_scan_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (fScanResultWrapping) {
        return 22;
    }
    if (ic->ic_state <= IEEE80211_S_INIT) {
        return 22;
    }
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setSCAN_REQ_MULTIPLE(OSObject *object, struct apple80211_scan_multiple_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (fScanResultWrapping) {
        return 22;
    }
    if (ic->ic_state <= IEEE80211_S_INIT) {
        return 22;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getSCAN_RESULT(OSObject *object, struct apple80211_scan_result **sr)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    if (fNextNodeToSend == NULL) {
        if (fScanResultWrapping) {
            fScanResultWrapping = false;
            return 5;
        } else {
            fNextNodeToSend = RB_MIN(ieee80211_tree, &ic->ic_tree);
            if (fNextNodeToSend == NULL) {
                return 12;
            }
        }
    }
//    XYLog("%s ni_bssid=%s ni_essid=%s channel=%d flags=%d asr_cap=%d asr_nrates=%d asr_ssid_len=%d asr_ie_len=%d asr_rssi=%d\n", __FUNCTION__, ether_sprintf(fNextNodeToSend->ni_bssid), fNextNodeToSend->ni_essid, ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan), ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags), fNextNodeToSend->ni_capinfo, fNextNodeToSend->ni_rates.rs_nrates, fNextNodeToSend->ni_esslen, fNextNodeToSend->ni_rsnie_tlv == NULL ? 0 : fNextNodeToSend->ni_rsnie_tlv_len, fNextNodeToSend->ni_rssi);
    apple80211_scan_result* result = (apple80211_scan_result* )fNextNodeToSend->verb;
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv) {
        result->asr_ie_len = fNextNodeToSend->ni_rsnie_tlv_len;
        result->asr_ie_data = fNextNodeToSend->ni_rsnie_tlv;
    } else {
        result->asr_ie_len = 0;
        result->asr_ie_data = NULL;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
    for (int i = 0; i < result->asr_nrates; i++ )
        result->asr_rates[i] = fNextNodeToSend->ni_rates.rs_rates[i];
    result->asr_nrates = fNextNodeToSend->ni_rates.rs_nrates;
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = fHalService->getDriverInfo()->getBSSNoise();
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0) {
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len + 1);
    }

    *sr = result;
    
    fNextNodeToSend = RB_NEXT(ieee80211_tree, &ic->ic_tree, fNextNodeToSend);
    if (fNextNodeToSend == NULL)
        fScanResultWrapping = true;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setVIRTUAL_IF_CREATE(OSObject *object, struct apple80211_virt_if_create_data* data)
{
    struct ether_addr addr;
    struct apple80211_channel chann;
    IOLog("%s role=%d, bsd_name=%s, mac=%s, unk1=%d\n", __FUNCTION__, data->role, data->bsd_name,
          ether_sprintf(data->mac), data->unk1);
    if (data->role - 2 < 2) {
        //TODO check awdl coexist
    }
    if (data->role == APPLE80211_VIF_P2P_DEVICE) {
        IO80211P2PInterface *inf = new IO80211P2PInterface;
        if (inf == NULL) {
            return kIOReturnError;
        }
        memcpy(addr.octet, data->mac, 6);
        inf->init(this, &addr, data->role, "p2p");
        fP2PDISCInterface = inf;
        IOLog("啊啊啊啊 虚拟接口fP2PDISCInterface调用成功\n");
    } else if(data->role == APPLE80211_VIF_P2P_CLIENT) {
        
    } else if (data->role == APPLE80211_VIF_P2P_GO) {
        IO80211P2PInterface *inf = new IO80211P2PInterface;
        if (inf == NULL) {
            return kIOReturnError;
        }
        memcpy(addr.octet, data->mac, 6);
        inf->init(this, &addr, data->role, "p2p");
        fP2PGOInterface = inf;
        IOLog("啊啊啊啊 虚拟接口fP2PGOInterface调用成功\n");
    } else if (data->role == APPLE80211_VIF_AWDL) {
        if (fAWDLInterface != NULL && strncmp((const char *)data->bsd_name, "awdl", 4) == 0) {
            XYLog("%s awdl interface already exists!\n", __FUNCTION__);
            return kIOReturnSuccess;
        }
        IO80211P2PInterface *inf = new IO80211P2PInterface;
        if (inf == NULL) {
            return kIOReturnError;
        }
        memcpy(addr.octet, data->mac, 6);
        inf->init(this, &addr, data->role, "awdl");
        chann.channel = 149;
        chann.version = 1;
        chann.flags = APPLE80211_C_FLAG_5GHZ | APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_80MHZ;
        setInfraChannel(&chann);
        fAWDLInterface = inf;
        IOLog("啊啊啊啊 虚拟接口fAWDLInterface调用成功\n");
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setVIRTUAL_IF_DELETE(OSObject *object, struct apple80211_virt_if_delete_data *data)
{
    XYLog("%s bsd_name=%s\n", __FUNCTION__, data->bsd_name);
    //TODO find vif according to the bsd_name
    IO80211VirtualInterface *vif = OSDynamicCast(IO80211VirtualInterface, object);
    if (vif == NULL) {
        return kIOReturnError;
    }
    detachVirtualInterface(vif, false);
    vif->release();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getLINK_CHANGED_EVENT_DATA(OSObject *object, struct apple80211_link_changed_event_data *ed) {
    if (ed == nullptr)
        return 16;
    
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        ed->voluntary = disassocIsVoluntary;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
    }
    else {
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    }
    XYLog("Link %s, reason: %d, voluntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->voluntary);
    return kIOReturnSuccess;
}
