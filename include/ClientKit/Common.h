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

#ifndef Common_h
#define Common_h

#include "IoctlId.h"

#define IOCTL_MASK 0x800000
#define IOCTL_VERSION 1
#define NWID_LEN 32
#define WPA_KEY_LEN 128

#define kIONoScanResult 20008

struct ioctl_driver_info {
    unsigned int version;
    char fw_version[32];    //firmware version string
    char driver_version[32];    //driver version string
    char bsd_name[32];  //interface bsd name, eg. en1
};

enum itl_phy_mode {
    ITL80211_MODE_11A,
    ITL80211_MODE_11B,
    ITL80211_MODE_11G,
    ITL80211_MODE_11N,
    ITL80211_MODE_11AC,
    ITL80211_MODE_11AX
};

struct ioctl_sta_info {
    unsigned int version;
    enum itl_phy_mode op_mode;
    int max_mcs;
    int cur_mcs;
    uint channel;
    uint16_t band_width;//20 40 80 160
    int16_t rssi;
    int16_t noise;
    uint rate;
    unsigned char ssid[NWID_LEN];
    uint8_t bssid[ETHER_ADDR_LEN];
};

struct ioctl_power {
    unsigned int version;
    unsigned int enabled;    //1 == on, 0 == off
    unsigned int maxsleep;   //max sleep in ms
};

enum itl_80211_state {
    ITL80211_S_INIT    = 0,    /* default state */
    ITL80211_S_SCAN    = 1,    /* scanning */
    ITL80211_S_AUTH    = 2,    /* try to authenticate */
    ITL80211_S_ASSOC    = 3,    /* try to assoc */
    ITL80211_S_RUN        = 4    /* associated */
};

struct ioctl_state {
    unsigned int version;
    int state; //itl_80211_state
};

struct ioctl_nw_id {
    unsigned int version;
    unsigned int len;
    char nwid[NWID_LEN];
};

struct ioctl_nw_bssid {
    unsigned int version;
    char bssid[ETHER_ADDR_LEN];
};

struct ioctl_wpa_key {
    unsigned int version;
    unsigned int len;
    char key[WPA_KEY_LEN];
};

#define PMK_LEN 32

enum itl80211_eap_status {
    ITL_EAP_STATUS_IDLE    = 0,
    ITL_EAP_STATUS_SUCCESS = 1,    /* pmk[] is valid */
    ITL_EAP_STATUS_FAILED  = 2,    /* authenticator rejected the credentials */
    ITL_EAP_STATUS_TIMEOUT = 3,
    ITL_EAP_STATUS_ERROR   = 4
};

/*
 * IOCTL_80211_WPA_KEY (set): result of a userspace 802.1X/EAP exchange for
 * `ssid`. On success the PMK is added to the PMKSA cache for the 4-way
 * handshake; any other status makes the driver leave the network.
 */
#pragma pack(push, 1)
struct ioctl_eap_pmk {
    unsigned int version;
    unsigned char ssid[NWID_LEN];
    unsigned int ssid_len;
    enum itl80211_eap_status status;
    unsigned int pmk_len;
    unsigned char pmk[PMK_LEN];
};
#pragma pack(pop)

struct ioctl_associate {
    unsigned int version;
    struct ioctl_nw_id nwid;
    struct ioctl_wpa_key wpa_key;
};

struct ioctl_disassociate {
    unsigned int version;
    unsigned char ssid[NWID_LEN];
};

/*
 * IOCTL_80211_ASSOCIATE_ENTERPRISE (set): join `nwid` with RSN, AKM 802.1X and
 * no PSK. Send before starting EAP; WPA_KEY only accepts a result for this SSID.
 */
struct ioctl_associate_enterprise {
    unsigned int version;
    struct ioctl_nw_id nwid;
};

/*
 * IOCTL_80211_TX_EAPOL (set) / IOCTL_80211_RX_EAPOL (get): complete Ethernet II
 * EAPOL frames (EtherType 0x888E) between the driver and a userspace
 * supplicant. RX returns len == 0 when no frame is queued.
 */
#define EAPOL_MAX_FRAME 1600
struct ioctl_eapol_tx {
    unsigned int version;
    unsigned int len;
    unsigned char frame[EAPOL_MAX_FRAME];
};

struct ioctl_eapol_rx {
    unsigned int version;
    unsigned int len;
    unsigned char frame[EAPOL_MAX_FRAME];
};

struct ioctl_join {
    unsigned int version;
    struct ioctl_nw_id nwid;
    struct ioctl_wpa_key wpa_key;
};

struct ioctl_scan {
    unsigned int version;
};

struct ioctl_scan_result {
    unsigned int version;
};

struct ioctl_tx_power {
    unsigned int version;
};

/*
 * 802.11 ciphers.
 */
enum itl80211_cipher {
    ITL80211_CIPHER_NONE        = 0x00000000,
    ITL80211_CIPHER_USEGROUP    = 0x00000001,
    ITL80211_CIPHER_WEP40        = 0x00000002,
    ITL80211_CIPHER_TKIP        = 0x00000004,
    ITL80211_CIPHER_CCMP        = 0x00000008,
    ITL80211_CIPHER_WEP104        = 0x00000010,
    ITL80211_CIPHER_BIP        = 0x00000020    /* 11w */
};

enum itl80211_wpa_proto {
    ITL80211_WPA_PROTO_WPA1 = 0x01,
    ITL80211_WPA_PROTO_WPA2 = 0x02
};

enum itl80211_proto {
    ITL80211_PROTO_NONE = 0,
    ITL80211_PROTO_RSN = 1 << 0,
    ITL80211_PROTO_WPA = 1 << 1
};

/*
 * 802.11 Authentication and Key Management Protocols.
 */
enum itl80211_akm {
    ITL80211_AKM_NONE        = 0x00000000,
    ITL80211_AKM_8021X        = 0x00000001,
    ITL80211_AKM_PSK        = 0x00000002,
    ITL80211_AKM_SHA256_8021X    = 0x00000004,    /* 11w */
    ITL80211_AKM_SHA256_PSK    = 0x00000008    /* 11w */
};

struct ioctl_network_info {
    unsigned char ssid[NWID_LEN];
    int16_t noise;
    int16_t rssi;
    uint8_t bssid[ETHER_ADDR_LEN];
    uint32_t channel;
    unsigned int supported_rsnprotos;   //itl80211_proto
    unsigned int rsn_protos;    //itl80211_wpa_proto
    unsigned int supported_rsnakms; //itl80211_akm
    unsigned int rsn_akms;  //rsn_akms
    unsigned int rsn_ciphers;
    enum itl80211_cipher    rsn_groupcipher;
    enum itl80211_cipher    rsn_groupmgmtcipher;
    u_int16_t        ni_rsncaps;
    enum itl80211_cipher    ni_rsncipher;
    uint32_t recv_timestamp;
};

#endif /* Common_h */
