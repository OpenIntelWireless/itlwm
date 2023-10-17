/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _APPLE80211_VAR_H_
#define _APPLE80211_VAR_H_

#include <Availability.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <sys/param.h>

// This is necessary, because even the latest Xcode does not support properly targeting 11.0.
#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

// Sizes and limits
#define APPLE80211_ADDR_LEN            6
#define APPLE80211_MAX_RATES           15
#define APPLE80211_MAX_SSID_LEN        32
#define APPLE80211_MAX_ANTENNAE        4
#define APPLE80211_MAX_RADIO           4
#define APPLE80211_MAX_CHANNELS        128
#define APPLE80211_MAX_STATIONS        128
#define APPLE80211_MAX_VERSION_LEN     256
#define APPLE80211_MAX_ROM_SIZE        32768    // 32 KB
#define APPLE80211_MAX_RSN_IE_LEN      257      // 255 + type and length bytes
#define APPLE80211_MAX_CC_LEN          3
#define APPLE80211_MAX_MCS_INDEX       76
#define APPLE80211_MAX_MPDU_FACTOR     3
#define APPLE80211_MAX_MPDU_DENSITY    7
#define APPLE80211_MAX_WOW_PAT_LEN     1500    // Max wake on wireless pattern length
#define APPLE80211_MAX_WOW_PATTERNS    12      // Arbitrary..this can change

#define APPLE80211_MAP_SIZE( _bits ) (roundup( _bits, NBBY )/NBBY)

enum apple80211_phymode {
    APPLE80211_MODE_UNKNOWN            = 0,
    APPLE80211_MODE_AUTO            = 0x1,                  // autoselect
    APPLE80211_MODE_11A                = 2 << (1 - 1),      // 5GHz, OFDM
    APPLE80211_MODE_11B                = 2 << (2 - 1),      // 2GHz, CCK
    APPLE80211_MODE_11G                = 2 << (3 - 1),      // 2GHz, OFDM
    APPLE80211_MODE_11N                = 2 << (4 - 1),      // 2GHz/5GHz, OFDM
    APPLE80211_MODE_TURBO_A            = 2 << (5 - 1),      // 5GHz, OFDM, 2x clock
    APPLE80211_MODE_TURBO_G            = 2 << (6 - 1),      // 2GHz, OFDM, 2x clock
    APPLE80211_MODE_11AC               = 2 << (7 - 1),
    APPLE80211_MODE_11AX               = 2 << (8 - 1),
};

enum apple80211_physubmode {
    APPLE80211_SUBMODE_UNKNOWN           = 0x0,
    APPLE80211_SUBMODE_11N_AUTO          = 0x1,    // 11n mode determined by AP capabilities
    APPLE80211_SUBMODE_11N_LEGACY        = 0x2,    // legacy
    APPLE80211_SUBMODE_11N_LEGACY_DUP    = 0x4,    // legacy duplicate
    APPLE80211_SUBMODE_11N_HT            = 0x8,    // high throughput
    APPLE80211_SUBMODE_11N_HT_DUP        = 0x10,   // high throughput duplicate
    APPLE80211_SUBMODE_11N_GF            = 0x20,   // green field
};

// flags
enum apple80211_opmode {
    APPLE80211_M_NONE     = 0x0,
    APPLE80211_M_STA      = 0x1,        // infrastructure station
    APPLE80211_M_IBSS     = 0x2,        // IBSS (adhoc) station
    APPLE80211_M_AHDEMO   = 0x4,        // Old lucent compatible adhoc demo
    APPLE80211_M_HOSTAP   = 0x8,        // Software Access Point
    APPLE80211_M_MONITOR  = 0x10        // Monitor mode
};

enum apple80211_apmode    {
    APPLE80211_AP_MODE_UNKNOWN    = 0,
    APPLE80211_AP_MODE_IBSS       = 1,        // IBSS (adhoc) station
    APPLE80211_AP_MODE_INFRA      = 2,        // Access Point
    APPLE80211_AP_MODE_ANY        = 3,        // Any supported mode
};

enum apple80211_state {
    APPLE80211_S_INIT    = 0,            // default state
    APPLE80211_S_SCAN    = 1,            // scanning
    APPLE80211_S_AUTH    = 2,            // try to authenticate
    APPLE80211_S_ASSOC   = 3,            // try to assoc
    APPLE80211_S_RUN     = 4,            // associated
};

enum apple80211_protmode {
    APPLE80211_PROTMODE_OFF            = 0,    // no protection
    APPLE80211_PROTMODE_AUTO           = 1,    // auto
    APPLE80211_PROTMODE_CTS            = 2,    // CTS to self
    APPLE80211_PROTMODE_RTSCTS         = 3,    // RTS-CTS
    APPLE80211_PROTMODE_DUAL_CTS       = 4,    // dual CTS
};

enum apple80211_cipher_type {
    APPLE80211_CIPHER_NONE        = 0,        // open network
    APPLE80211_CIPHER_WEP_40      = 1,        // 40 bit WEP
    APPLE80211_CIPHER_WEP_104     = 2,        // 104 bit WEP
    APPLE80211_CIPHER_TKIP        = 3,        // TKIP (WPA)
    APPLE80211_CIPHER_AES_OCB     = 4,        // AES (OCB)
    APPLE80211_CIPHER_AES_CCM     = 5,        // AES (CCM)
    APPLE80211_CIPHER_PMK         = 6,        // PMK
    APPLE80211_CIPHER_PMKSA       = 7,        // PMK obtained from pre-authentication
    APPLE80211_CIPHER_SMS4        = 8,
    APPLE80211_CIPHER_MSK         = 9,
    APPLE80211_CIPHER_PWD         = 10,
    APPLE80211_CIPHER_AES_GCM     = 11,
    APPLE80211_CIPHER_AES_GCM256  = 12,
};

enum apple80211_cipher_key_type
{
    APPLE80211_CIPHER_KEY_TYPE_UNICAST   = 0,   // unicast cipher key
    APPLE80211_CIPHER_KEY_TYPE_MULTICAST = 1    // multicast cipher key
};

// Low level 802.11 authentication types

enum apple80211_authtype_lower
{
    APPLE80211_AUTHTYPE_OPEN          = 1,    // open
    APPLE80211_AUTHTYPE_SHARED        = 2,    // shared key
    APPLE80211_AUTHTYPE_CISCO         = 3,    // cisco net eap
};

// Higher level authentication used after 802.11 association complete

enum apple80211_authtype_upper
{
    APPLE80211_AUTHTYPE_NONE         = 0,         //    No upper auth
    APPLE80211_AUTHTYPE_WPA          = 1 << 0,    //    WPA
    APPLE80211_AUTHTYPE_WPA_PSK      = 1 << 1,    //    WPA PSK
    APPLE80211_AUTHTYPE_WPA2         = 1 << 2,    //    WPA2
    APPLE80211_AUTHTYPE_WPA2_PSK     = 1 << 3,    //    WPA2 PSK
    APPLE80211_AUTHTYPE_FT_PSK       = 1 << 4,    //
    APPLE80211_AUTHTYPE_LEAP         = 1 << 5,    //    LEAP
    APPLE80211_AUTHTYPE_WEP_8021X    = 1 << 6,    //    WEP 802.1x
    APPLE80211_AUTHTYPE_FT_8021X     = 1 << 7,    //    802.1x
    APPLE80211_AUTHTYPE_WPS          = 1 << 8,    //    WiFi Protected Setup
    APPLE80211_AUTHTYPE_WAPI         = 1 << 9,
    APPLE80211_AUTHTYPE_SHA256_PSK   = 1 << 10,
    APPLE80211_AUTHTYPE_SHA256_8021X = 1 << 11,
    APPLE80211_AUTHTYPE_WPA3_SAE     = 1 << 12,
    APPLE80211_AUTHTYPE_WPA3_FT_SAE  = 1 << 13,
    APPLE80211_AUTHTYPE_WPA3_ENTERPRISE = 1 << 14,
    APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE = 1 << 15,
};

// Unify association status code and deauth reason codes into a single enum describing
// common error conditions
enum apple80211_associate_result
{
    APPLE80211_RESULT_UNAVAILABLE                = 0,  // No association/authentication result ready
    APPLE80211_RESULT_SUCCESS                    = 1,  // APPLE80211_STATUS_SUCCESS and no deauth
    APPLE80211_RESULT_UNSPECIFIED_FAILURE        = 2,  // APPLE80211_STATUS_UNSPECIFIED_FAILURE
    APPLE80211_RESULT_UNSUPPORTED_CAPAPBILITIES  = 3,  // APPLE80211_STATUS_UNSUPPORTED_CAPABILITIES
    APPLE80211_RESULT_REASSOCIATION_DENIED       = 4,  // APPLE80211_STATUS_REASSOCIATION_DENIED
    APPLE80211_RESULT_ASSOCIATION_DENIED         = 5,  // APPLE80211_STATUS_ASSOCIATION_DENIED
    APPLE80211_RESULT_AUTH_ALG_UNSUPPORTED       = 6,  // APPLE80211_STATUS_AUTH_ALG_UNSUPPORTED
    APPLE80211_RESULT_INVALID_AUTH_SEQ_NUM       = 7,  // APPLE80211_STATUS_INVALID_AUTH_SEQ_NUM
    APPLE80211_RESULT_CHALLENGE_FAILURE          = 8,  // APPLE80211_STATUS_CHALLENGE_FAILURE
    APPLE80211_RESULT_TIMEOUT                    = 9,  // APPLE80211_STATUS_TIMEOUT
    APPLE80211_RESULT_AP_FULL                    = 10, // APPLE80211_STATUS_AP_FULL
    APPLE80211_RESULT_UNSUPPORTED_RATE_SET       = 11, // APPLE80211_STATUS_UNSUPPORTED_RATE_SET
    APPLE80211_RESULT_SHORT_SLOT_UNSUPPORTED     = 12, // APPLE80211_STATUS_SHORT_SLOT_UNSUPPORTED
    APPLE80211_RESULT_DSSS_OFDM_UNSUPPORTED      = 13, // APPLE80211_STATUS_DSSS_OFDM_UNSUPPORTED
    APPLE80211_RESULT_INVALID_IE                 = 14, // APPLE80211_STATUS_INVALID_IE
    APPLE80211_RESULT_INVALID_GROUP_CIPHER       = 15, // APPLE80211_STATUS_INVALID_GROUP_CIPHER
    APPLE80211_RESULT_INVALID_PAIRWISE_CIPHER    = 16, // APPLE80211_STATUS_INVALID_PAIRWISE_CIPHER
    APPLE80211_RESULT_INVALID_AKMP               = 17, // APPLE80211_STATUS_INVALID_AKMP
    APPLE80211_RESULT_UNSUPPORTED_RSN_VERSION    = 18, // APPLE80211_STATUS_UNSUPPORTED_RSN_VERSION
    APPLE80211_RESULT_INVALID_RSN_CAPABILITIES   = 19, // APPLE80211_STATUS_INVALID_RSN_CAPABILITIES
    APPLE80211_RESULT_CIPHER_SUITE_REJECTED      = 20, // APPLE80211_STATUS_CIPHER_SUIT_REJECTED
    APPLE80211_RESULT_INVALID_PMK                = 21, // APPLE80211_REASON_PREV_AUTH_EXPIRED received
    APPLE80211_RESULT_SUPPLICANT_TIMEOUT         = 22, // RSNSupplicant did not finish handshake
    APPLE80211_RESULT_UNKNOWN                    = 0xffff // Unrecognized error condition
};

enum apple80211_link_down_reason
{
   APPLE80211_LINK_DOWN_REASON_INTERNAL_ERROR   = 0,
   APPLE80211_LINK_DOWN_REASON_BEACONLOST       = 1,
   APPLE80211_LINK_DOWN_REASON_DEAUTH           = 2,
   APPLE80211_LINK_DOWN_REASON_INTERNAL_ERROR_2 = 3
};

enum apple80211_unit
{
    APPLE80211_UNIT_DBM        = 0,        // dBm
    APPLE80211_UNIT_MW         = 1,        // milliwatts
    APPLE80211_UNIT_PERCENT    = 2,        // value expressed as a percentage
};

enum apple80211_power_state
{
    APPLE80211_POWER_OFF       = 0,    //    Chain disabled
    APPLE80211_POWER_ON        = 1,    //    Chain powered on for tx and rx
    APPLE80211_POWER_TX        = 2,    //    Chain powered on for tx only
    APPLE80211_POWER_RX        = 3,    //    Chain powered on for rx only
};

enum apple80211_locale
{
    APPLE80211_LOCALE_UNKNOWN    = 0,
    APPLE80211_LOCALE_FCC        = 1,
    APPLE80211_LOCALE_ETSI       = 2,
    APPLE80211_LOCALE_JAPAN      = 3,
    APPLE80211_LOCALE_KOREA      = 4,
    APPLE80211_LOCALE_APAC       = 5,
    APPLE80211_LOCALE_ROW        = 6,
    APPLE80211_LOCALE_INDONESIA  = 7
};

enum apple80211_scan_type
{
    APPLE80211_SCAN_TYPE_NONE       = 0,
    APPLE80211_SCAN_TYPE_ACTIVE     = 1,
    APPLE80211_SCAN_TYPE_PASSIVE    = 2,
    APPLE80211_SCAN_TYPE_FAST       = 3,    // Ok to return cached scan results
    APPLE80211_SCAN_TYPE_BACKGROUND = 4,    // Initiate background scanning
};

enum apple80211_int_mit {
    APPLE80211_INT_MIT_OFF    = 0,
    APPLE80211_INT_MIT_AUTO   = 1,
};

enum apple80211_channel_flag
{
    APPLE80211_C_FLAG_NONE         = 0x0,   // no flags
    APPLE80211_C_FLAG_10MHZ        = 0x1,   // 10 MHz wide
    APPLE80211_C_FLAG_20MHZ        = 0x2,   // 20 MHz wide
    APPLE80211_C_FLAG_40MHZ        = 0x4,   // 40 MHz wide
    APPLE80211_C_FLAG_2GHZ         = 0x8,   // 2.4 GHz
    APPLE80211_C_FLAG_5GHZ         = 0x10,  // 5 GHz
    APPLE80211_C_FLAG_IBSS         = 0x20,  // IBSS supported
    APPLE80211_C_FLAG_HOST_AP      = 0x40,  // HOST AP mode supported
    APPLE80211_C_FLAG_ACTIVE       = 0x80,  // active scanning supported
    APPLE80211_C_FLAG_DFS          = 0x100, // DFS required
    APPLE80211_C_FLAG_EXT_ABV      = 0x200, // If 40 Mhz, extension channel above.
    // If this flag is not set, then the
    // extension channel is below.
    APPLE80211_C_FLAG_80MHZ        = 0x400,  // name made up - set if channelWidth == 80 && 5ghz && AC
    APPLE80211_C_FLAG_160MHZ       = 0x800,  // zxystd: Apple Broadcom not use it, but we can use!
};

enum apple80211_rate_flag
{
    APPLE80211_RATE_FLAG_NONE      = 0x0,   // no flags
    APPLE80211_RATE_FLAG_BASIC     = 0x1,   // basic rate
    APPLE80211_RATE_FLAG_HT        = 0x2,   // HT rate computed from MCS index
};

enum apple80211_short_slot_mode
{
    APPLE80211_SHORT_SLOT_MODE_AUTO     = 1,    // Default behavior
    APPLE80211_SHORT_SLOT_MODE_LONG     = 2,    // long - short slot timing mode
    APPLE80211_SHORT_SLOT_MODE_SHORT    = 3,    // short - short slot timing mode
};

enum apple80211_powersave_mode
{
    // Standard modes
    APPLE80211_POWERSAVE_MODE_DISABLED       = 0,
    APPLE80211_POWERSAVE_MODE_80211          = 1,
    APPLE80211_POWERSAVE_MODE_VENDOR         = 2,    //    Vendor specific mode, there should be
    //  more general apple modes in the future.
    //  Vendor modes also likely require more info.
    // Mimo modes
    APPLE80211_POWERSAVE_MODE_MIMO_STATIC     = 3,
    APPLE80211_POWERSAVE_MODE_MIMO_DYNAMIC    = 4,
    APPLE80211_POWERSAVE_MODE_MIMO_MIMO       = 5,

    // WOW
    APPLE80211_POWERSAVE_MODE_WOW             = 6,

    // Vendor specific powersave mode, throughput is maximized
    APPLE80211_POWERSAVE_MODE_MAX_THROUGHPUT  = 7,

    // Vendor specific powersave mode, power savings are maximized, possibly
    // at the expense of throughput/latency.
    APPLE80211_POWERSAVE_MODE_MAX_POWERSAVE   = 8,
};

enum apple80211_debug_flag
{
    APPLE80211_DEBUG_FLAG_NONE           = 0x0,    // No logging
    APPLE80211_DEBUG_FLAG_INFORMATIVE    = 0x1,    // Log "interesting" events
    APPLE80211_DEBUG_FLAG_ERROR          = 0x2,    // Log errors
    APPLE80211_DEBUG_FLAG_RSN            = 0x4,    // Full RSN supplicant logging
    APPLE80211_DEBUG_FLAG_SCAN           = 0x8,    // Scan events and information
};

enum apple80211_guard_interval
{
    APPLE80211_GI_SHORT    = 400,    // ns
    APPLE80211_GI_LONG     = 800,    // ns
};

#define APPLE80211_RSC_LEN                 8
#define APPLE80211_KEY_BUFF_LEN           32

#define APPLE80211_KEY_FLAG_UNICAST       0x1
#define APPLE80211_KEY_FLAG_MULTICAST     0x2
#define APPLE80211_KEY_FLAG_TX            0x4
#define APPLE80211_KEY_FLAG_RX            0x8

struct apple80211_key
{
    u_int32_t           version;
    u_int32_t           key_len;
    u_int32_t           key_cipher_type;                    // apple80211_cipher_type
    u_int16_t           key_flags;
    u_int16_t           key_index;
    u_int8_t            key[ APPLE80211_KEY_BUFF_LEN ];
    u_int8_t            pad[30];
    u_int32_t           key_rsc_len;
    u_int8_t            key_rsc[ APPLE80211_RSC_LEN ];    // receive sequence counter
    struct ether_addr   key_ea;                           // key applies to this bssid
    uint                wowl_kck_len;
    uint8_t             wowl_kck_key[16];
    uint                wowl_kek_len;
    u_int8_t            wowl_kek_key[24];
};

// Changing this affects any structure that contains a channel
struct apple80211_channel
{
    u_int32_t    version;
    u_int32_t    channel;    //    channel number
    u_int32_t    flags;      //    apple80211_channel_flag vector
};

struct apple80211_rate
{
    u_int32_t    version;
    u_int32_t    rate;     // rate mbps
    u_int32_t    flags;    // apple80211_rate_flag vector
};

// Probe response capability flags, IEEE 7.3.1.4
#define APPLE80211_CAPINFO_ESS               0x0001
#define APPLE80211_CAPINFO_IBSS              0x0002
#define APPLE80211_CAPINFO_CF_POLLABLE       0x0004
#define APPLE80211_CAPINFO_CF_POLLREQ        0x0008
#define APPLE80211_CAPINFO_PRIVACY           0x0010
#define APPLE80211_CAPINFO_SHORT_PREAMBLE    0x0020
#define APPLE80211_CAPINFO_PBCC              0x0040
#define APPLE80211_CAPINFO_AGILITY           0x0080
// 0x0100, 0x0200 reserved
#define APPLE80211_CAPINFO_SHORT_SLOT_TIME   0x0400
// 0x0800, 0x1000 reserved
#define APPLE80211_CAPINFO_DSSS_OFDM         0x2000
// 0x4000, 0x8000 reserved

// Reason codes IEEE 7.3.1.7
#define APPLE80211_REASON_UNSPECIFIED                1
#define APPLE80211_REASON_PREV_AUTH_EXPIRED          2
#define APPLE80211_REASON_AUTH_LEAVING               3
#define APPLE80211_REASON_INACTIVE                   4
#define APPLE80211_REASON_AP_OVERLOAD                5
#define APPLE80211_REASON_NOT_AUTHED                 6
#define APPLE80211_REASON_NOT_ASSOCED                7
#define APPLE80211_REASON_ASSOC_LEAVING              8
#define APPLE80211_REASON_ASSOC_NOT_AUTHED           9
#define APPLE80211_REASON_POWER_CAP                  10
#define APPLE80211_REASON_SUPPORTED_CHANS            11

#define APPLE80211_REASON_INVALID_IE                 13
#define APPLE80211_REASON_MIC_FAILURE                14
#define APPLE80211_REASON_4_WAY_TIMEOUT              15
#define APPLE80211_REASON_GROUP_KEY_TIMEOUT          16
#define APPLE80211_REASON_DIFF_IE                    17
#define APPLE80211_REASON_INVALID_GROUP_KEY          18
#define APPLE80211_REASON_INVALID_PAIR_KEY           19
#define APPLE80211_REASON_INVALID_AKMP               20
#define APPLE80211_REASON_UNSUPP_RSN_VER             21
#define APPLE80211_REASON_INVALID_RSN_CAPS           22
#define APPLE80211_REASON_8021X_AUTH_FAILED          23

// Status codes IEEE 7.3.1.9
#define APPLE80211_STATUS_SUCCESS                     0
#define APPLE80211_STATUS_UNSPECIFIED_FAILURE         1
// 2-9 reserved
#define APPLE80211_STATUS_UNSUPPORTED_CAPABILITIES   10
#define APPLE80211_STATUS_REASSOCIATION_DENIED       11
#define APPLE80211_STATUS_ASSOCIATION_DENIED         12
#define APPLE80211_STATUS_AUTH_ALG_UNSUPPORTED       13
#define APPLE80211_STATUS_INVALID_AUTH_SEQ_NUM       14
#define APPLE80211_STATUS_CHALLENGE_FAILURE          15
#define APPLE80211_STATUS_TIMEOUT                    16
#define APPLE80211_STATUS_AP_FULL                    17
#define APPLE80211_STATUS_UNSUPPORTED_RATE_SET       18
// 22-24 reserved
#define APPLE80211_STATUS_SHORT_SLOT_UNSUPPORTED     25
#define APPLE80211_STATUS_DSSS_OFDM_UNSUPPORTED      26
// 27-39 reserved
#define APPLE80211_STATUS_INVALID_IE                 40
#define APPLE80211_STATUS_INVALID_GROUP_CIPHER       41
#define APPLE80211_STATUS_INVALID_PAIRWISE_CIPHER    42
#define APPLE80211_STATUS_INVALID_AKMP               43
#define APPLE80211_STATUS_UNSUPPORTED_RSN_VERSION    44
#define APPLE80211_STATUS_INVALID_RSN_CAPABILITIES   45
#define APPLE80211_STATUS_CIPHER_SUITE_REJECTED      46
// 47 - 65535 reserved
#define APPLE80211_STATUS_UNAVAILABLE                0xffff

// If mcs index is set to APPLE80211_MCS_INDEX_AUTO, the interface
// should go to auto rate selection, and abandon any previously
// configured static MCS indices
#define APPLE80211_MCS_INDEX_AUTO    0xffffffff

/*
 DSCP TOS/Traffic class values for WME access categories taken from
 WiFi WMM Test Plan v 1.3.1 Appendix C.
 
 TOS/Traffic class field looks like:
 
 0   1   2   3   4   5   6   7
 +---+---+---+---+---+---+---+---+
 |          DSCP         |  ECN  |
 +---+---+---+---+---+---+---+---+
 
 These bits are numbered according to rfc 2474, but might be misleading.
 It looks like bit 0 is actually the high order bit.
 */

#define APPLE80211_DSCP_WME_BE    0x00
#define APPLE80211_DSCP_WME_BK    0x08
#define APPLE80211_DSCP_WME_VI    0x28
#define APPLE80211_DSCP_WME_VO    0x38

// Access category values set in the mbuf
#define APPLE80211_WME_AC_BE    0
#define APPLE80211_WME_AC_BK    1
#define APPLE80211_WME_AC_VI    2
#define APPLE80211_WME_AC_VO    3

// Working within the limitations of the kpi mbuf routines, the receive interface pointer
// is the best place to put this for now since it is not used on the output path. The mbuf
// kpi doesn't allow us to access unused flags, or I would put the WME AC in there like
// everyone else.

#define APPLE80211_MBUF_SET_WME_AC( m, ac ) mbuf_pkthdr_setrcvif( m, (ifnet_t)ac )
#define APPLE80211_MBUF_WME_AC( m ) (int)mbuf_pkthdr_rcvif( m )

// FIXME: seems that rates array starts at 0x24, immediately after
struct apple80211_scan_result
{
    u_int32_t             version;        // 0x00 - 0x03
    apple80211_channel    asr_channel;    // 0x04 - 0x0f

    int16_t               asr_unk;        // 0x10 - 0x11

    int16_t               asr_noise;      // 0x12 - 0x13
    int16_t               asr_snr;        // 0x14 - 0x15
    int16_t               asr_rssi;       // 0x16 - 0x17
    int16_t               asr_beacon_int; // 0x18 - 0x19

    int16_t               asr_cap;        // 0x1a - 0x1b (capabilities)

    u_int8_t              asr_bssid[ APPLE80211_ADDR_LEN ]; // 0x1c 0x1d 0x1e 0x1f 0x20 0x21
    u_int8_t              asr_nrates;     // 0x22
    u_int8_t              asr_nr_unk;     // 0x23
    u_int32_t             asr_rates[ APPLE80211_MAX_RATES ]; // 0x24 - 0x5f
    u_int8_t              asr_ssid_len;   // 0x60
    u_int8_t              asr_ssid[ APPLE80211_MAX_SSID_LEN ]; // 0x61 - 0x80
    int16_t               unk;
    uint8_t               unk2;
    u_int32_t             asr_age;        // (ms) non-zero for cached scan result // 0x84

    u_int16_t             unk3;             // 0x88
    int16_t               asr_ie_len;       // 0x8A
#if __IO80211_TARGET < __MAC_12_0
    uint32_t              asr_unk3;         // 0x8C
    void*                 asr_ie_data;      // 90
#else
    uint8_t               asr_ie_data[1024];    // 0x8C
#endif
} __attribute__((packed));

struct apple80211_network_data
{
    u_int32_t                   version;
    u_int16_t                   nd_mode;              // apple80211_apmode
    u_int16_t                   nd_auth_lower;        // apple80211_authtype_lower
    u_int16_t                   nd_auth_upper;        // apple80211_authtype_upper
    struct apple80211_channel   nd_channel;
    u_int32_t                   nd_ssid_len;
    u_int8_t                    nd_ssid[ APPLE80211_MAX_SSID_LEN ];
    struct apple80211_key       nd_key;
    u_int32_t                   nd_ie_len;
    void                        *nd_ie_data;
};

#define APPLE80211_NETWORK_DATA_MAX_IE_LEN 1024

// As hostap support improves, this will grow
struct apple80211_station
{
    u_int32_t            version;
    struct ether_addr    sta_mac;
    int32_t              sta_rssi;
};

// WOW structures and defines

struct apple80211_wow_pattern
{
    size_t      len;
    u_int8_t    *pattern;
};

enum apple80211_wake_condition
{
    APPLE80211_WAKE_COND_MAGIC_PATTERN  = 0,
    APPLE80211_WAKE_COND_NET_PATTERN    = 1,
    APPLE80211_WAKE_COND_DISASSOCIATED  = 2,
    APPLE80211_WAKE_COND_DEAUTHED       = 3,
    APPLE80211_WAKE_COND_RETROGRADE_TSF = 4,
    APPLE80211_WAKE_COND_BEACON_LOSS    = 5,
};

#define APPLE80211_MAX_WAKE_COND 5

enum apple80211_card_capability
{
    APPLE80211_CAP_WEP             = 0,    // CAPABILITY: WEP available
    APPLE80211_CAP_TKIP            = 1,    // CAPABILITY: TKIP available
    APPLE80211_CAP_AES             = 2,    // CAPABILITY: AES OCB avail
    APPLE80211_CAP_AES_CCM         = 3,    // CAPABILITY: AES CCM avail
    APPLE80211_CAP_CKIP            = 4,    // CAPABILITY: CKIP available
    APPLE80211_CAP_IBSS            = 5,    // CAPABILITY: IBSS available
    APPLE80211_CAP_PMGT            = 6,    // CAPABILITY: Power mgmt
    APPLE80211_CAP_HOSTAP          = 7,    // CAPABILITY: HOSTAP avail
    APPLE80211_CAP_TXPMGT          = 8,    // CAPABILITY: tx power mgmt
    APPLE80211_CAP_SHSLOT          = 9,    // CAPABILITY: short slottime
    APPLE80211_CAP_SHPREAMBLE      = 10,   // CAPABILITY: short preamble
    APPLE80211_CAP_MONITOR         = 11,   // CAPABILITY: monitor mode
    APPLE80211_CAP_TKIPMIC         = 12,   // CAPABILITY: TKIP MIC avail
    APPLE80211_CAP_WPA1            = 13,   // CAPABILITY: WPA1 avail
    APPLE80211_CAP_WPA2            = 14,   // CAPABILITY: WPA2 avail
    APPLE80211_CAP_WPA             = 15,   // CAPABILITY: WPA1+WPA2 avail
    APPLE80211_CAP_BURST           = 16,   // CAPABILITY: frame bursting
    APPLE80211_CAP_WME             = 17,   // CAPABILITY: WME avail
    APPLE80211_CAP_SHORT_GI_40MHZ  = 18,   // CAPABILITY: Short guard interval in 40 MHz
    APPLE80211_CAP_SHORT_GI_20MHZ  = 19,   // CAPABILITY: Short guard interval in 20 MHz
    APPLE80211_CAP_WOW             = 20,   // CAPABILITY: Wake on wireless
    APPLE80211_CAP_TSN             = 21,   // CAPABILITY: WPA with WEP group key
};
#define APPLE80211_CAP_MAX    63

enum apple80211_virtual_interface_type
{
#if __IO80211_TARGET < __MAC_13_0
    APPLE80211_VIF_P2P_DEVICE   = 1,
#else
    APPLE80211_VIF_P2P_DEVICE   = 3,
#endif
    APPLE80211_VIF_P2P_CLIENT,
    APPLE80211_VIF_P2P_GO,
    APPLE80211_VIF_AWDL,
    APPLE80211_VIF_SOFT_AP,
    
    APPLE80211_VIF_MAX
};

enum apple80211_ie_type
{
    APPLE80211_IE_FLAG_PROBE_REQ     = (1 << 0),
    APPLE80211_IE_FLAG_PROBE_RESP    = (1 << 1),
    APPLE80211_IE_FLAG_ASSOC_REQ     = (1 << 2),
    APPLE80211_IE_FLAG_ASSOC_RESP    = (1 << 3),
    APPLE80211_IE_FLAG_BEACON        = (1 << 4),
};

enum apple80211_assoc_flags {
    APPLE80211_ASSOC_F_CLOSED    = 1,    // flag: scan was directed, needed to remember closed networks
};

enum IO80211LinkState
{
    kIO80211NetworkLinkUndefined,            // Starting link state when an interface is created
    kIO80211NetworkLinkDown,                // Interface not capable of transmitting packets
    kIO80211NetworkLinkUp,                    // Interface capable of transmitting packets
};
typedef enum IO80211LinkState IO80211LinkState;

// Kernel messages

struct apple80211_status_msg_hdr
{
    u_int32_t    msg_type;        //    type of message
    u_int32_t    msg_len;         //  length of data (not including msg_type and msg_len)
    
    // data follows
};

#define APPLE80211_M_MAX_LEN                2048

#define APPLE80211_M_POWER_CHANGED           1
#define APPLE80211_M_SSID_CHANGED            2
#define APPLE80211_M_BSSID_CHANGED           3
#define APPLE80211_M_LINK_CHANGED            4
#define APPLE80211_M_MIC_ERROR_UCAST         5
#define APPLE80211_M_MIC_ERROR_MCAST         6
#define APPLE80211_M_INT_MIT_CHANGED         7
#define APPLE80211_M_MODE_CHANGED            8
#define APPLE80211_M_ASSOC_DONE              9
#define APPLE80211_M_SCAN_DONE               10
#define APPLE80211_M_COUNTRY_CODE_CHANGED    11
#define APPLE80211_M_STA_ARRIVE              12
#define APPLE80211_M_STA_LEAVE               13
#define APPLE80211_M_DECRYPTION_FAILURE      14
#define APPLE80211_M_SCAN_CACHE_UPDATED      15
#define APPLE80211_M_INTERNAL_SCAN_DONE      16
#define APPLE80211_M_LINK_QUALITY            17
#define APPLE80211_M_IBSS_PEER_ARRIVED       18
#define APPLE80211_M_IBSS_PEER_LEFT          19
#define APPLE80211_M_RSN_HANDSHAKE_DONE      20
#define APPLE80211_M_BT_COEX_CHANGED         21
#define APPLE80211_M_P2P_PEER_DETECTED       22
#define APPLE80211_M_P2P_LISTEN_COMPLETE     23
#define APPLE80211_M_P2P_SCAN_COMPLETE       24
#define APPLE80211_M_P2P_LISTEN_STARTED      25
#define APPLE80211_M_P2P_SCAN_STARTED        26
#define APPLE80211_M_P2P_INTERFACE_CREATED   27
#define APPLE80211_M_P2P_GROUP_STARTED       28
#define APPLE80211_M_BGSCAN_NET_DISCOVERED   29
#define APPLE80211_M_ROAMED                  30
#define APPLE80211_M_ACT_FRM_TX_COMPLETE     31
#define APPLE80211_M_DEAUTH_RECEIVED         32
#define APPLE80211_M_RSSI_CHANGED            39
#define APPLE80211_M_PEER_STATE              40
#define APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START 42
#define APPLE80211_M_AWDL_AVAILABILITY_WINDOW_EXTENSIONS_END    43
#define APPLE80211_M_AWDL_SYNC_STATE_CHANGED 46
#define APPLE80211_M_AWDL_PEER_PRESENCE      47
#define APPLE80211_M_RESET_INTERFACE         49
#define APPLE80211_M_PEER_CREDIT_GRANT       50
#define APPLE80211_M_CHANNEL_SWITCH          54
#define APPLE80211_M_DRIVER_AVAILABLE        55
#define APPLE80211_M_INTERFACE_STATE         58
#define APPLE80211_M_LINK_ADDRESS_CHANGED    59
#define APPLE80211_M_BGSCAN_CACHED_NETWORK_AVAILABLE    63
#define APPLE80211_M_AWDL_STATISTICS         65
#define APPLE80211_M_AWDL_REALTIME_MODE_START   67
#define APPLE80211_M_AWDL_REALTIME_MODE_END  68
#define APPLE80211_M_ROAM_START              70
#define APPLE80211_M_ROAM_END                71
#define APPLE80211_M_DUMP_LOGS               79
#define APPLE80211_M_LEAKY_AP_STATISTICS     81
#define APPLE80211_M_RANGING_MEASUREMENT_DONE   83
#define APPLE80211_M_AWDL_DFS_CSA            88
#define APPLE80211_M_TCPKA_TIMEOUT           91
#define APPLE80211_M_AWDL_DFS_CSA_COMPLETE   94
#define APPLE80211_M_BSS_STEERING_REQUEST_EVENT 140
#define APPLE80211_M_AWDL_HPP_STATISTICS     142
#define APPLE80211_M_ACTION_FRAME            143
#define APPLE80211_M_AWDL_APP_SPECIFIC_INFO  144
#define APPLE80211_M_WSEC_NOTIFICATION       146


#define APPLE80211_M_MAX                     170
#define APPLE80211_M_BUFF_SIZE               APPLE80211_MAP_SIZE( APPLE80211_M_MAX )

// Registry Information
#define APPLE80211_REGKEY_HARDWARE_VERSION    "IO80211HardwareVersion"
// #define APPLE80211_REG_FIRMWARE_VERSION    "IO80211FirmwareVersion"
#define APPLE80211_REGKEY_DRIVER_VERSION      "IO80211DriverVersion"
#define APPLE80211_REGKEY_LOCALE              "IO80211Locale"
#define APPLE80211_REGKEY_SSID                "IO80211SSID"
#define APPLE80211_REGKEY_CHANNEL             "IO80211Channel"
#define APPLE80211_REGKEY_EXT_CHANNEL         "IO80211ExtensionChannel"
#define APPLE80211_REGKEY_BAND                "IO80211Band"
#define APPLE80211_BAND_2GHZ                  "2 GHz"
#define APPLE80211_BAND_5GHZ                  "5 GHz"
#define APPLE80211_REGKEY_COUNTRY_CODE        "IO80211CountryCode"

// Userland messages
#define APPLE80211_M_RSN_AUTH_SUCCESS            254
#define APPLE80211_M_RSN_AUTH_SUCCESS_TEMPLATE   "com.apple.rsn.%s.auth.success"    // string is interface name

#define APPLE80211_M_RSN_AUTH_TIMEOUT            255
#define APPLE80211_M_RSN_AUTH_TIMEOUT_TEMPLATE   "com.apple.rsn.%s.auth.timeout"    // string is interface name

#define APPLE80211_M_RSN_MSG_MAX                 2

#endif // _APPLE80211_VAR_H_

