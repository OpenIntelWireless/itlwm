//
//  rs.hpp
//  itlwm
//
//  Created by zxystd on 2021/8/27.
//  Copyright © 2021 钟先耀. All rights reserved.
//

#ifndef rs_hpp
#define rs_hpp

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kpi_mbuf.h>

#include <linux/types.h>
#include <sys/pcireg.h>

#include <net80211/ieee80211_var.h>

#define IWL_DEBUG_RATE(sc, fmt, x...)
//#define IWL_DEBUG_RATE(sc, fmt, x...)\
//do\
//{\
//XYLog("%s: " fmt, "RATE", ##x);\
//}while(0)

#define IWL_ERR(sc, fmt, x...)\
do\
{\
XYLog("RS %s: " fmt, "ERR", ##x);\
}while(0)

/**
 * enum nl80211_band - Frequency band
 * @NL80211_BAND_2GHZ: 2.4 GHz ISM band
 * @NL80211_BAND_5GHZ: around 5 GHz band (4.9 - 5.7 GHz)
 * @NUM_NL80211_BANDS: number of bands, avoid using this in userspace
 *    since newer kernel versions may support more bands
 */
enum nl80211_band {
    NL80211_BAND_2GHZ,
    NL80211_BAND_5GHZ,

    NUM_NL80211_BANDS,
};

/**
 * enum mac80211_tx_info_flags - flags to describe transmission information/status
 *
 * These flags are used with the @flags member of &ieee80211_tx_info.
 *
 * @IEEE80211_TX_CTL_REQ_TX_STATUS: require TX status callback for this frame.
 * @IEEE80211_TX_CTL_ASSIGN_SEQ: The driver has to assign a sequence
 *    number to this frame, taking care of not overwriting the fragment
 *    number and increasing the sequence number only when the
 *    IEEE80211_TX_CTL_FIRST_FRAGMENT flag is set. mac80211 will properly
 *    assign sequence numbers to QoS-data frames but cannot do so correctly
 *    for non-QoS-data and management frames because beacons need them from
 *    that counter as well and mac80211 cannot guarantee proper sequencing.
 *    If this flag is set, the driver should instruct the hardware to
 *    assign a sequence number to the frame or assign one itself. Cf. IEEE
 *    802.11-2007 7.1.3.4.1 paragraph 3. This flag will always be set for
 *    beacons and always be clear for frames without a sequence number field.
 * @IEEE80211_TX_CTL_NO_ACK: tell the low level not to wait for an ack
 * @IEEE80211_TX_CTL_CLEAR_PS_FILT: clear powersave filter for destination
 *    station
 * @IEEE80211_TX_CTL_FIRST_FRAGMENT: this is a first fragment of the frame
 * @IEEE80211_TX_CTL_SEND_AFTER_DTIM: send this frame after DTIM beacon
 * @IEEE80211_TX_CTL_AMPDU: this frame should be sent as part of an A-MPDU
 * @IEEE80211_TX_CTL_INJECTED: Frame was injected, internal to mac80211.
 * @IEEE80211_TX_STAT_TX_FILTERED: The frame was not transmitted
 *    because the destination STA was in powersave mode. Note that to
 *    avoid race conditions, the filter must be set by the hardware or
 *    firmware upon receiving a frame that indicates that the station
 *    went to sleep (must be done on device to filter frames already on
 *    the queue) and may only be unset after mac80211 gives the OK for
 *    that by setting the IEEE80211_TX_CTL_CLEAR_PS_FILT (see above),
 *    since only then is it guaranteed that no more frames are in the
 *    hardware queue.
 * @IEEE80211_TX_STAT_ACK: Frame was acknowledged
 * @IEEE80211_TX_STAT_AMPDU: The frame was aggregated, so status
 *     is for the whole aggregation.
 * @IEEE80211_TX_STAT_AMPDU_NO_BACK: no block ack was returned,
 *     so consider using block ack request (BAR).
 * @IEEE80211_TX_CTL_RATE_CTRL_PROBE: internal to mac80211, can be
 *    set by rate control algorithms to indicate probe rate, will
 *    be cleared for fragmented frames (except on the last fragment)
 * @IEEE80211_TX_INTFL_OFFCHAN_TX_OK: Internal to mac80211. Used to indicate
 *    that a frame can be transmitted while the queues are stopped for
 *    off-channel operation.
 * @IEEE80211_TX_CTL_HW_80211_ENCAP: This frame uses hardware encapsulation
 *    (header conversion)
 * @IEEE80211_TX_INTFL_RETRIED: completely internal to mac80211,
 *    used to indicate that a frame was already retried due to PS
 * @IEEE80211_TX_INTFL_DONT_ENCRYPT: completely internal to mac80211,
 *    used to indicate frame should not be encrypted
 * @IEEE80211_TX_CTL_NO_PS_BUFFER: This frame is a response to a poll
 *    frame (PS-Poll or uAPSD) or a non-bufferable MMPDU and must
 *    be sent although the station is in powersave mode.
 * @IEEE80211_TX_CTL_MORE_FRAMES: More frames will be passed to the
 *    transmit function after the current frame, this can be used
 *    by drivers to kick the DMA queue only if unset or when the
 *    queue gets full.
 * @IEEE80211_TX_INTFL_RETRANSMISSION: This frame is being retransmitted
 *    after TX status because the destination was asleep, it must not
 *    be modified again (no seqno assignment, crypto, etc.)
 * @IEEE80211_TX_INTFL_MLME_CONN_TX: This frame was transmitted by the MLME
 *    code for connection establishment, this indicates that its status
 *    should kick the MLME state machine.
 * @IEEE80211_TX_INTFL_NL80211_FRAME_TX: Frame was requested through nl80211
 *    MLME command (internal to mac80211 to figure out whether to send TX
 *    status to user space)
 * @IEEE80211_TX_CTL_LDPC: tells the driver to use LDPC for this frame
 * @IEEE80211_TX_CTL_STBC: Enables Space-Time Block Coding (STBC) for this
 *    frame and selects the maximum number of streams that it can use.
 * @IEEE80211_TX_CTL_TX_OFFCHAN: Marks this packet to be transmitted on
 *    the off-channel channel when a remain-on-channel offload is done
 *    in hardware -- normal packets still flow and are expected to be
 *    handled properly by the device.
 * @IEEE80211_TX_INTFL_TKIP_MIC_FAILURE: Marks this packet to be used for TKIP
 *    testing. It will be sent out with incorrect Michael MIC key to allow
 *    TKIP countermeasures to be tested.
 * @IEEE80211_TX_CTL_NO_CCK_RATE: This frame will be sent at non CCK rate.
 *    This flag is actually used for management frame especially for P2P
 *    frames not being sent at CCK rate in 2GHz band.
 * @IEEE80211_TX_STATUS_EOSP: This packet marks the end of service period,
 *    when its status is reported the service period ends. For frames in
 *    an SP that mac80211 transmits, it is already set; for driver frames
 *    the driver may set this flag. It is also used to do the same for
 *    PS-Poll responses.
 * @IEEE80211_TX_CTL_USE_MINRATE: This frame will be sent at lowest rate.
 *    This flag is used to send nullfunc frame at minimum rate when
 *    the nullfunc is used for connection monitoring purpose.
 * @IEEE80211_TX_CTL_DONTFRAG: Don't fragment this packet even if it
 *    would be fragmented by size (this is optional, only used for
 *    monitor injection).
 * @IEEE80211_TX_STAT_NOACK_TRANSMITTED: A frame that was marked with
 *    IEEE80211_TX_CTL_NO_ACK has been successfully transmitted without
 *    any errors (like issues specific to the driver/HW).
 *    This flag must not be set for frames that don't request no-ack
 *    behaviour with IEEE80211_TX_CTL_NO_ACK.
 *
 * Note: If you have to add new flags to the enumeration, then don't
 *     forget to update %IEEE80211_TX_TEMPORARY_FLAGS when necessary.
 */
enum mac80211_tx_info_flags {
    IEEE80211_TX_CTL_REQ_TX_STATUS        = BIT(0),
    IEEE80211_TX_CTL_ASSIGN_SEQ        = BIT(1),
    IEEE80211_TX_CTL_NO_ACK            = BIT(2),
    IEEE80211_TX_CTL_CLEAR_PS_FILT        = BIT(3),
    IEEE80211_TX_CTL_FIRST_FRAGMENT        = BIT(4),
    IEEE80211_TX_CTL_SEND_AFTER_DTIM    = BIT(5),
    IEEE80211_TX_CTL_AMPDU            = BIT(6),
    IEEE80211_TX_CTL_INJECTED        = BIT(7),
    IEEE80211_TX_STAT_TX_FILTERED        = BIT(8),
    IEEE80211_TX_STAT_ACK            = BIT(9),
    IEEE80211_TX_STAT_AMPDU            = BIT(10),
    IEEE80211_TX_STAT_AMPDU_NO_BACK        = BIT(11),
    IEEE80211_TX_CTL_RATE_CTRL_PROBE    = BIT(12),
    IEEE80211_TX_INTFL_OFFCHAN_TX_OK    = BIT(13),
    IEEE80211_TX_CTL_HW_80211_ENCAP        = BIT(14),
    IEEE80211_TX_INTFL_RETRIED        = BIT(15),
    IEEE80211_TX_INTFL_DONT_ENCRYPT        = BIT(16),
    IEEE80211_TX_CTL_NO_PS_BUFFER        = BIT(17),
    IEEE80211_TX_CTL_MORE_FRAMES        = BIT(18),
    IEEE80211_TX_INTFL_RETRANSMISSION    = BIT(19),
    IEEE80211_TX_INTFL_MLME_CONN_TX        = BIT(20),
    IEEE80211_TX_INTFL_NL80211_FRAME_TX    = BIT(21),
    IEEE80211_TX_CTL_LDPC            = BIT(22),
    IEEE80211_TX_CTL_STBC            = BIT(23) | BIT(24),
    IEEE80211_TX_CTL_TX_OFFCHAN        = BIT(25),
    IEEE80211_TX_INTFL_TKIP_MIC_FAILURE    = BIT(26),
    IEEE80211_TX_CTL_NO_CCK_RATE        = BIT(27),
    IEEE80211_TX_STATUS_EOSP        = BIT(28),
    IEEE80211_TX_CTL_USE_MINRATE        = BIT(29),
    IEEE80211_TX_CTL_DONTFRAG        = BIT(30),
    IEEE80211_TX_STAT_NOACK_TRANSMITTED    = BIT(31),
};

/**
 * enum mac80211_rate_control_flags - per-rate flags set by the
 *    Rate Control algorithm.
 *
 * These flags are set by the Rate control algorithm for each rate during tx,
 * in the @flags member of struct ieee80211_tx_rate.
 *
 * @IEEE80211_TX_RC_USE_RTS_CTS: Use RTS/CTS exchange for this rate.
 * @IEEE80211_TX_RC_USE_CTS_PROTECT: CTS-to-self protection is required.
 *    This is set if the current BSS requires ERP protection.
 * @IEEE80211_TX_RC_USE_SHORT_PREAMBLE: Use short preamble.
 * @IEEE80211_TX_RC_MCS: HT rate.
 * @IEEE80211_TX_RC_VHT_MCS: VHT MCS rate, in this case the idx field is split
 *    into a higher 4 bits (Nss) and lower 4 bits (MCS number)
 * @IEEE80211_TX_RC_GREEN_FIELD: Indicates whether this rate should be used in
 *    Greenfield mode.
 * @IEEE80211_TX_RC_40_MHZ_WIDTH: Indicates if the Channel Width should be 40 MHz.
 * @IEEE80211_TX_RC_80_MHZ_WIDTH: Indicates 80 MHz transmission
 * @IEEE80211_TX_RC_160_MHZ_WIDTH: Indicates 160 MHz transmission
 *    (80+80 isn't supported yet)
 * @IEEE80211_TX_RC_DUP_DATA: The frame should be transmitted on both of the
 *    adjacent 20 MHz channels, if the current channel type is
 *    NL80211_CHAN_HT40MINUS or NL80211_CHAN_HT40PLUS.
 * @IEEE80211_TX_RC_SHORT_GI: Short Guard interval should be used for this rate.
 */
enum mac80211_rate_control_flags {
    IEEE80211_TX_RC_USE_RTS_CTS        = BIT(0),
    IEEE80211_TX_RC_USE_CTS_PROTECT        = BIT(1),
    IEEE80211_TX_RC_USE_SHORT_PREAMBLE    = BIT(2),

    /* rate index is an HT/VHT MCS instead of an index */
    IEEE80211_TX_RC_MCS            = BIT(3),
    IEEE80211_TX_RC_GREEN_FIELD        = BIT(4),
    IEEE80211_TX_RC_40_MHZ_WIDTH        = BIT(5),
    IEEE80211_TX_RC_DUP_DATA        = BIT(6),
    IEEE80211_TX_RC_SHORT_GI        = BIT(7),
    IEEE80211_TX_RC_VHT_MCS            = BIT(8),
    IEEE80211_TX_RC_80_MHZ_WIDTH        = BIT(9),
    IEEE80211_TX_RC_160_MHZ_WIDTH        = BIT(10),
};

/**
 * struct ieee80211_rx_status - receive status
 *
 * The low-level driver should provide this information (the subset
 * supported by hardware) to the 802.11 code with each received
 * frame, in the skb's control buffer (cb).
 *
 * @mactime: value in microseconds of the 64-bit Time Synchronization Function
 *     (TSF) timer when the first data symbol (MPDU) arrived at the hardware.
 * @boottime_ns: CLOCK_BOOTTIME timestamp the frame was received at, this is
 *    needed only for beacons and probe responses that update the scan cache.
 * @device_timestamp: arbitrary timestamp for the device, mac80211 doesn't use
 *    it but can store it and pass it back to the driver for synchronisation
 * @band: the active band when this frame was received
 * @freq: frequency the radio was tuned to when receiving this frame, in MHz
 *    This field must be set for management frames, but isn't strictly needed
 *    for data (other) frames - for those it only affects radiotap reporting.
 * @freq_offset: @freq has a positive offset of 500Khz.
 * @signal: signal strength when receiving this frame, either in dBm, in dB or
 *    unspecified depending on the hardware capabilities flags
 *    @IEEE80211_HW_SIGNAL_*
 * @chains: bitmask of receive chains for which separate signal strength
 *    values were filled.
 * @chain_signal: per-chain signal strength, in dBm (unlike @signal, doesn't
 *    support dB or unspecified units)
 * @antenna: antenna used
 * @rate_idx: index of data rate into band's supported rates or MCS index if
 *    HT or VHT is used (%RX_FLAG_HT/%RX_FLAG_VHT)
 * @nss: number of streams (VHT and HE only)
 * @flag: %RX_FLAG_\*
 * @encoding: &enum mac80211_rx_encoding
 * @bw: &enum rate_info_bw
 * @enc_flags: uses bits from &enum mac80211_rx_encoding_flags
 * @he_ru: HE RU, from &enum nl80211_he_ru_alloc
 * @he_gi: HE GI, from &enum nl80211_he_gi
 * @he_dcm: HE DCM value
 * @rx_flags: internal RX flags for mac80211
 * @ampdu_reference: A-MPDU reference number, must be a different value for
 *    each A-MPDU but the same for each subframe within one A-MPDU
 * @ampdu_delimiter_crc: A-MPDU delimiter CRC
 * @zero_length_psdu_type: radiotap type of the 0-length PSDU
 */
struct ieee80211_rx_status {
//    u64 mactime;
//    u64 boottime_ns;
//    u32 device_timestamp;
//    u32 ampdu_reference;
//    u32 flag;
//    u16 freq: 13, freq_offset: 1;
//    u8 enc_flags;
//    u8 encoding:2, bw:3, he_ru:3;
//    u8 he_gi:2, he_dcm:1;
//    u8 rate_idx;
//    u8 nss;
//    u8 rx_flags;
//    u8 band;
//    u8 antenna;
    s8 signal;
    u8 chains;
    s8 chain_signal[4];
//    u8 ampdu_delimiter_crc;
//    u8 zero_length_psdu_type;
};

/**
 * struct ieee80211_tx_rate - rate selection/status
 *
 * @idx: rate index to attempt to send with
 * @flags: rate control flags (&enum mac80211_rate_control_flags)
 * @count: number of tries in this rate before going to the next rate
 *
 * A value of -1 for @idx indicates an invalid rate and, if used
 * in an array of retry rates, that no more rates should be tried.
 *
 * When used for transmit status reporting, the driver should
 * always report the rate along with the flags it used.
 *
 * &struct ieee80211_tx_info contains an array of these structs
 * in the control information, and it will be filled by the rate
 * control algorithm according to what should be sent. For example,
 * if this array contains, in the format { <idx>, <count> } the
 * information::
 *
 *    { 3, 2 }, { 2, 2 }, { 1, 4 }, { -1, 0 }, { -1, 0 }
 *
 * then this means that the frame should be transmitted
 * up to twice at rate 3, up to twice at rate 2, and up to four
 * times at rate 1 if it doesn't get acknowledged. Say it gets
 * acknowledged by the peer after the fifth attempt, the status
 * information should then contain::
 *
 *   { 3, 2 }, { 2, 2 }, { 1, 1 }, { -1, 0 } ...
 *
 * since it was transmitted twice at rate 3, twice at rate 2
 * and once at rate 1 after which we received an acknowledgement.
 */
struct ieee80211_tx_rate {
    s8 idx;
    u16 count:5,
        flags:11;
} __packed;

struct ieee80211_tx_info {
    /* common information */
    u32 flags;
    u32 band:3,
        ack_frame_id:13,
        hw_queue:4,
        tx_time_est:10;
    /* 2 free bits */

    union {
        struct {
            struct ieee80211_tx_rate rates[4];
            s32 ack_signal;
            u8 ampdu_ack_len;
            u8 ampdu_len;
            u8 antenna;
            u16 tx_time;
            bool is_valid_ack_signal;
            void *status_driver_data[19 / sizeof(void *)];
        } status;
    };
};

/**
 * struct ieee80211_mcs_info - MCS information
 * @rx_mask: RX mask
 * @rx_highest: highest supported RX rate. If set represents
 *    the highest supported RX data rate in units of 1 Mbps.
 *    If this field is 0 this value should not be used to
 *    consider the highest RX data rate supported.
 * @tx_params: TX parameters
 */
struct ieee80211_mcs_info {
    u8 rx_mask[10];
    __le16 rx_highest;
    u8 tx_params;
    u8 reserved[3];
} __packed;

/**
 * struct ieee80211_sta_ht_cap - STA's HT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11n HT capabilities for an STA.
 *
 * @ht_supported: is HT supported by the STA
 * @cap: HT capabilities map as described in 802.11n spec
 * @ampdu_factor: Maximum A-MPDU length factor
 * @ampdu_density: Minimum A-MPDU spacing
 * @mcs: Supported MCS rates
 */
struct ieee80211_sta_ht_cap {
    u16 cap; /* use IEEE80211_HT_CAP_ */
    bool ht_supported;
    u8 ampdu_factor;
    u8 ampdu_density;
    struct ieee80211_mcs_info mcs;
};

/**
 * struct ieee80211_sta_vht_cap - STA's VHT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11ac VHT capabilities for an STA.
 *
 * @vht_supported: is VHT supported by the STA
 * @cap: VHT capabilities map as described in 802.11ac spec
 * @vht_mcs: Supported VHT MCS rates
 */
struct ieee80211_sta_vht_cap {
    bool vht_supported;
    u32 cap; /* use IEEE80211_VHT_CAP_ */
    struct ieee80211_vht_mcs_info vht_mcs;
};

/**
 * struct ieee80211_vht_cap - VHT capabilities
 *
 * This structure is the "VHT capabilities element" as
 * described in 802.11ac D3.0 8.4.2.160
 * @vht_cap_info: VHT capability info
 * @supp_mcs: VHT MCS supported rates
 */
struct ieee80211_vht_cap {
    __le32 vht_cap_info;
    struct ieee80211_vht_mcs_info supp_mcs;
} __packed;

static inline int ieee80211_get_vht_max_nss(struct ieee80211_vht_cap *cap,
                  int bw,
                  int mcs, bool ext_nss_bw_capable,
                  unsigned int max_vht_nss)
{
    u16 map = le16_to_cpu(cap->supp_mcs.rx_mcs_map);
    int ext_nss_bw;
    int supp_width;
    int i, mcs_encoding;

    if (map == 0xffff)
        return 0;

    if (WARN_ON(mcs > 9 || max_vht_nss > 8))
        return 0;
    if (mcs <= 7)
        mcs_encoding = 0;
    else if (mcs == 8)
        mcs_encoding = 1;
    else
        mcs_encoding = 2;

    if (!max_vht_nss) {
        /* find max_vht_nss for the given MCS */
        for (i = 7; i >= 0; i--) {
            int supp = (map >> (2 * i)) & 3;

            if (supp == 3)
                continue;

            if (supp >= mcs_encoding) {
                max_vht_nss = i + 1;
                break;
            }
        }
    }

    if (!(cap->supp_mcs.tx_mcs_map &
            cpu_to_le16(IEEE80211_VHT_EXT_NSS_BW_CAPABLE)))
        return max_vht_nss;

    ext_nss_bw = le32_get_bits(cap->vht_cap_info,
                   IEEE80211_VHTCAP_EXT_NSS_BW_MASK);
    supp_width = le32_get_bits(cap->vht_cap_info,
                   IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK);

    /* if not capable, treat ext_nss_bw as 0 */
    if (!ext_nss_bw_capable)
        ext_nss_bw = 0;

    /* This is invalid */
    if (supp_width == 3)
        return 0;

    /* This is an invalid combination so pretend nothing is supported */
    if (supp_width == 2 && (ext_nss_bw == 1 || ext_nss_bw == 2))
        return 0;

    /*
     * Cover all the special cases according to IEEE 802.11-2016
     * Table 9-250. All other cases are either factor of 1 or not
     * valid/supported.
     */
    switch (bw) {
    case IEEE80211_VHT_CHANWIDTH_USE_HT:
    case IEEE80211_VHT_CHANWIDTH_80MHZ:
        if ((supp_width == 1 || supp_width == 2) &&
            ext_nss_bw == 3)
            return 2 * max_vht_nss;
        break;
    case IEEE80211_VHT_CHANWIDTH_160MHZ:
        if (supp_width == 0 &&
            (ext_nss_bw == 1 || ext_nss_bw == 2))
            return max_vht_nss / 2;
        if (supp_width == 0 &&
            ext_nss_bw == 3)
            return (3 * max_vht_nss) / 4;
        if (supp_width == 1 &&
            ext_nss_bw == 3)
            return 2 * max_vht_nss;
        break;
    case IEEE80211_VHT_CHANWIDTH_80P80MHZ:
        if (supp_width == 0 && ext_nss_bw == 1)
            return 0; /* not possible */
        if (supp_width == 0 &&
            ext_nss_bw == 2)
            return max_vht_nss / 2;
        if (supp_width == 0 &&
            ext_nss_bw == 3)
            return (3 * max_vht_nss) / 4;
        if (supp_width == 1 &&
            ext_nss_bw == 0)
            return 0; /* not possible */
        if (supp_width == 1 &&
            ext_nss_bw == 1)
            return max_vht_nss / 2;
        if (supp_width == 1 &&
            ext_nss_bw == 2)
            return (3 * max_vht_nss) / 4;
        break;
    }

    /* not covered or invalid combination received */
    return max_vht_nss;
}

#define IWL_MVM_UAPSD_NOAGG_BSSIDS_NUM        20

#define IWL_MVM_DEFAULT_PS_TX_DATA_TIMEOUT    (100 * USEC_PER_MSEC)
#define IWL_MVM_DEFAULT_PS_RX_DATA_TIMEOUT    (100 * USEC_PER_MSEC)
#define IWL_MVM_WOWLAN_PS_TX_DATA_TIMEOUT    (10 * USEC_PER_MSEC)
#define IWL_MVM_WOWLAN_PS_RX_DATA_TIMEOUT    (10 * USEC_PER_MSEC)
#define IWL_MVM_SHORT_PS_TX_DATA_TIMEOUT    (2 * 1024) /* defined in TU */
#define IWL_MVM_SHORT_PS_RX_DATA_TIMEOUT    (40 * 1024) /* defined in TU */
#define IWL_MVM_P2P_LOWLATENCY_PS_ENABLE    0
#define IWL_MVM_UAPSD_RX_DATA_TIMEOUT        (50 * USEC_PER_MSEC)
#define IWL_MVM_UAPSD_TX_DATA_TIMEOUT        (50 * USEC_PER_MSEC)
#define IWL_MVM_UAPSD_QUEUES        (IEEE80211_WMM_IE_STA_QOSINFO_AC_VO |\
                     IEEE80211_WMM_IE_STA_QOSINFO_AC_VI |\
                     IEEE80211_WMM_IE_STA_QOSINFO_AC_BK |\
                     IEEE80211_WMM_IE_STA_QOSINFO_AC_BE)
#define IWL_MVM_PS_HEAVY_TX_THLD_PACKETS    20
#define IWL_MVM_PS_HEAVY_RX_THLD_PACKETS    8
#define IWL_MVM_PS_SNOOZE_HEAVY_TX_THLD_PACKETS    30
#define IWL_MVM_PS_SNOOZE_HEAVY_RX_THLD_PACKETS    20
#define IWL_MVM_PS_HEAVY_TX_THLD_PERCENT    50
#define IWL_MVM_PS_HEAVY_RX_THLD_PERCENT    50
#define IWL_MVM_PS_SNOOZE_INTERVAL        25
#define IWL_MVM_PS_SNOOZE_WINDOW        50
#define IWL_MVM_WOWLAN_PS_SNOOZE_WINDOW        25
#define IWL_MVM_LOWLAT_QUOTA_MIN_PERCENT    64
#define IWL_MVM_BT_COEX_EN_RED_TXP_THRESH    62
#define IWL_MVM_BT_COEX_DIS_RED_TXP_THRESH    65
#define IWL_MVM_BT_COEX_SYNC2SCO        1
#define IWL_MVM_BT_COEX_MPLUT            1
#define IWL_MVM_BT_COEX_RRC            1
#define IWL_MVM_BT_COEX_TTC            1
#define IWL_MVM_BT_COEX_MPLUT_REG0        0x22002200
#define IWL_MVM_BT_COEX_MPLUT_REG1        0x11118451
#define IWL_MVM_BT_COEX_ANTENNA_COUPLING_THRS    30
#define IWL_MVM_FW_MCAST_FILTER_PASS_ALL    0
#define IWL_MVM_FW_BCAST_FILTER_PASS_ALL    0
#define IWL_MVM_QUOTA_THRESHOLD            4
#define IWL_MVM_RS_RSSI_BASED_INIT_RATE         0
#define IWL_MVM_RS_80_20_FAR_RANGE_TWEAK    1
#define IWL_MVM_TOF_IS_RESPONDER        0
#define IWL_MVM_HW_CSUM_DISABLE            0
#define IWL_MVM_PARSE_NVM            0
#define IWL_MVM_ADWELL_ENABLE            1
#define IWL_MVM_ADWELL_MAX_BUDGET        0
#define IWL_MVM_TCM_LOAD_MEDIUM_THRESH        10 /* percentage */
#define IWL_MVM_TCM_LOAD_HIGH_THRESH        50 /* percentage */
#define IWL_MVM_TCM_LOWLAT_ENABLE_THRESH    100 /* packets/10 seconds */
#define IWL_MVM_UAPSD_NONAGG_PERIOD        5000 /* msecs */
#define IWL_MVM_UAPSD_NOAGG_LIST_LEN        IWL_MVM_UAPSD_NOAGG_BSSIDS_NUM
#define IWL_MVM_NON_TRANSMITTING_AP        0
#define IWL_MVM_RS_NUM_TRY_BEFORE_ANT_TOGGLE    1
#define IWL_MVM_RS_HT_VHT_RETRIES_PER_RATE      2
#define IWL_MVM_RS_HT_VHT_RETRIES_PER_RATE_TW   1
#define IWL_MVM_RS_INITIAL_MIMO_NUM_RATES       3
#define IWL_MVM_RS_INITIAL_SISO_NUM_RATES       3
#define IWL_MVM_RS_INITIAL_LEGACY_NUM_RATES     2
#define IWL_MVM_RS_INITIAL_LEGACY_RETRIES       2
#define IWL_MVM_RS_SECONDARY_LEGACY_RETRIES    1
#define IWL_MVM_RS_SECONDARY_LEGACY_NUM_RATES   16
#define IWL_MVM_RS_SECONDARY_SISO_NUM_RATES     3
#define IWL_MVM_RS_SECONDARY_SISO_RETRIES       1
#define IWL_MVM_RS_RATE_MIN_FAILURE_TH        3
#define IWL_MVM_RS_RATE_MIN_SUCCESS_TH        8
#define IWL_MVM_RS_STAY_IN_COLUMN_TIMEOUT    5    /* Seconds */
#define IWL_MVM_RS_IDLE_TIMEOUT            5    /* Seconds */
#define IWL_MVM_RS_MISSED_RATE_MAX        15
#define IWL_MVM_RS_LEGACY_FAILURE_LIMIT        160
#define IWL_MVM_RS_LEGACY_SUCCESS_LIMIT        480
#define IWL_MVM_RS_LEGACY_TABLE_COUNT        160
#define IWL_MVM_RS_NON_LEGACY_FAILURE_LIMIT    400
#define IWL_MVM_RS_NON_LEGACY_SUCCESS_LIMIT    4500
#define IWL_MVM_RS_NON_LEGACY_TABLE_COUNT    1500
#define IWL_MVM_RS_SR_FORCE_DECREASE        15    /* percent */
#define IWL_MVM_RS_SR_NO_DECREASE        85    /* percent */
#define IWL_MVM_RS_AGG_TIME_LIMIT            4000    /* 4 msecs. valid 100-8000 */
#define IWL_MVM_RS_AGG_DISABLE_START            3
#define IWL_MVM_RS_AGG_START_THRESHOLD            10    /* num frames per second */
#define IWL_MVM_RS_TPC_SR_FORCE_INCREASE    75    /* percent */
#define IWL_MVM_RS_TPC_SR_NO_INCREASE        85    /* percent */
#define IWL_MVM_RS_TPC_TX_POWER_STEP        3
#define IWL_MVM_ENABLE_EBS            1
#define IWL_MVM_FTM_INITIATOR_ALGO        IWL_TOF_ALGO_TYPE_MAX_LIKE
#define IWL_MVM_FTM_INITIATOR_DYNACK        true
#define IWL_MVM_FTM_R2I_MAX_REP            7
#define IWL_MVM_FTM_I2R_MAX_REP            7
#define IWL_MVM_FTM_R2I_MAX_STS            1
#define IWL_MVM_FTM_I2R_MAX_STS            1
#define IWL_MVM_FTM_R2I_MAX_TOTAL_LTF        3
#define IWL_MVM_FTM_I2R_MAX_TOTAL_LTF        3
#define IWL_MVM_FTM_INITIATOR_SECURE_LTF    false
#define IWL_MVM_FTM_RESP_NDP_SUPPORT        true
#define IWL_MVM_FTM_RESP_LMR_FEEDBACK_SUPPORT    true
#define IWL_MVM_D3_DEBUG            false
#define IWL_MVM_USE_TWT                true
#define IWL_MVM_AMPDU_CONSEC_DROPS_DELBA    10
#define IWL_MVM_USE_NSSN_SYNC            0
#define IWL_MVM_PHY_FILTER_CHAIN_A        0
#define IWL_MVM_PHY_FILTER_CHAIN_B        0
#define IWL_MVM_PHY_FILTER_CHAIN_C        0
#define IWL_MVM_PHY_FILTER_CHAIN_D        0
#define IWL_MVM_FTM_INITIATOR_ENABLE_SMOOTH     false
#define IWL_MVM_FTM_INITIATOR_SMOOTH_ALPHA      40
/*  20016 pSec is 6 meter RTT, meaning 3 meter range */
#define IWL_MVM_FTM_INITIATOR_SMOOTH_UNDERSHOOT 20016
#define IWL_MVM_FTM_INITIATOR_SMOOTH_OVERSHOOT  20016
#define IWL_MVM_FTM_INITIATOR_SMOOTH_AGE_SEC    2
#define IWL_MVM_DISABLE_AP_FILS            false
#define IWL_MVM_6GHZ_PASSIVE_SCAN_TIMEOUT       3000 /* in seconds */
#define IWL_MVM_6GHZ_PASSIVE_SCAN_ASSOC_TIMEOUT 60   /* in seconds */

#define IWL_MAX_TID_COUNT    8
#define IWL_MGMT_TID        15
#define IWL_FRAME_LIMIT    64
#define IWL_MAX_RX_HW_QUEUES    16
#define IWL_9000_MAX_RX_HW_QUEUES    6

/* Antenna presence definitions */
#define    ANT_NONE    0x0
#define    ANT_INVALID    0xff
#define    ANT_A        BIT(0)
#define    ANT_B        BIT(1)
#define ANT_C        BIT(2)
#define    ANT_AB        (ANT_A | ANT_B)
#define    ANT_AC        (ANT_A | ANT_C)
#define ANT_BC        (ANT_B | ANT_C)
#define ANT_ABC        (ANT_A | ANT_B | ANT_C)
#define MAX_ANT_NUM 3

#define IWL_RATE_BIT_MSK(r) BIT(IWL_RATE_##r##M_INDEX)

/* fw API values for legacy bit rates, both OFDM and CCK */
enum {
    IWL_RATE_6M_PLCP  = 13,
    IWL_RATE_9M_PLCP  = 15,
    IWL_RATE_12M_PLCP = 5,
    IWL_RATE_18M_PLCP = 7,
    IWL_RATE_24M_PLCP = 9,
    IWL_RATE_36M_PLCP = 11,
    IWL_RATE_48M_PLCP = 1,
    IWL_RATE_54M_PLCP = 3,
    IWL_RATE_1M_PLCP  = 10,
    IWL_RATE_2M_PLCP  = 20,
    IWL_RATE_5M_PLCP  = 55,
    IWL_RATE_11M_PLCP = 110,
    IWL_RATE_INVM_PLCP = 0xff,
};

/*
 * Returns the first antenna as ANT_[ABC], as defined in iwl-config.h.
 * The parameter should also be a combination of ANT_[ABC].
 */
static inline u8 first_antenna(u8 mask)
{
    BUILD_BUG_ON(ANT_A != BIT(0)); /* using ffs is wrong if not */
    if (WARN_ON_ONCE(!mask)) /* ffs will return 0 if mask is zeroed */
        return BIT(0);
    return BIT(ffs(mask) - 1);
}

/*
 * These serve as indexes into
 * struct iwl_rate_info fw_rate_idx_to_plcp[IWL_RATE_COUNT];
 * TODO: avoid overlap between legacy and HT rates
 */
enum {
    IWL_RATE_1M_INDEX = 0,
    IWL_FIRST_CCK_RATE = IWL_RATE_1M_INDEX,
    IWL_RATE_2M_INDEX,
    IWL_RATE_5M_INDEX,
    IWL_RATE_11M_INDEX,
    IWL_LAST_CCK_RATE = IWL_RATE_11M_INDEX,
    IWL_RATE_6M_INDEX,
    IWL_FIRST_OFDM_RATE = IWL_RATE_6M_INDEX,
    IWL_RATE_MCS_0_INDEX = IWL_RATE_6M_INDEX,
    IWL_FIRST_HT_RATE = IWL_RATE_MCS_0_INDEX,
    IWL_FIRST_VHT_RATE = IWL_RATE_MCS_0_INDEX,
    IWL_RATE_9M_INDEX,
    IWL_RATE_12M_INDEX,
    IWL_RATE_MCS_1_INDEX = IWL_RATE_12M_INDEX,
    IWL_RATE_18M_INDEX,
    IWL_RATE_MCS_2_INDEX = IWL_RATE_18M_INDEX,
    IWL_RATE_24M_INDEX,
    IWL_RATE_MCS_3_INDEX = IWL_RATE_24M_INDEX,
    IWL_RATE_36M_INDEX,
    IWL_RATE_MCS_4_INDEX = IWL_RATE_36M_INDEX,
    IWL_RATE_48M_INDEX,
    IWL_RATE_MCS_5_INDEX = IWL_RATE_48M_INDEX,
    IWL_RATE_54M_INDEX,
    IWL_RATE_MCS_6_INDEX = IWL_RATE_54M_INDEX,
    IWL_LAST_NON_HT_RATE = IWL_RATE_54M_INDEX,
    IWL_RATE_60M_INDEX,
    IWL_RATE_MCS_7_INDEX = IWL_RATE_60M_INDEX,
    IWL_LAST_HT_RATE = IWL_RATE_MCS_7_INDEX,
    IWL_RATE_MCS_8_INDEX,
    IWL_RATE_MCS_9_INDEX,
    IWL_LAST_VHT_RATE = IWL_RATE_MCS_9_INDEX,
    IWL_RATE_MCS_10_INDEX,
    IWL_RATE_MCS_11_INDEX,
    IWL_LAST_HE_RATE = IWL_RATE_MCS_11_INDEX,
    IWL_RATE_COUNT_LEGACY = IWL_LAST_NON_HT_RATE + 1,
    IWL_RATE_COUNT = IWL_LAST_HE_RATE + 1,
};

/*
 * rate_n_flags bit fields
 *
 * The 32-bit value has different layouts in the low 8 bites depending on the
 * format. There are three formats, HT, VHT and legacy (11abg, with subformats
 * for CCK and OFDM).
 *
 * High-throughput (HT) rate format
 *    bit 8 is 1, bit 26 is 0, bit 9 is 0 (OFDM)
 * Very High-throughput (VHT) rate format
 *    bit 8 is 0, bit 26 is 1, bit 9 is 0 (OFDM)
 * Legacy OFDM rate format for bits 7:0
 *    bit 8 is 0, bit 26 is 0, bit 9 is 0 (OFDM)
 * Legacy CCK rate format for bits 7:0:
 *    bit 8 is 0, bit 26 is 0, bit 9 is 1 (CCK)
 */

/* Bit 8: (1) HT format, (0) legacy or VHT format */
#define RATE_MCS_HT_POS 8
#define RATE_MCS_HT_MSK (1 << RATE_MCS_HT_POS)

/* Bit 9: (1) CCK, (0) OFDM.  HT (bit 8) must be "0" for this bit to be valid */
#define RATE_MCS_CCK_POS 9
#define RATE_MCS_CCK_MSK (1 << RATE_MCS_CCK_POS)

/* Bit 26: (1) VHT format, (0) legacy format in bits 8:0 */
#define RATE_MCS_VHT_POS 26
#define RATE_MCS_VHT_MSK (1 << RATE_MCS_VHT_POS)


/*
 * High-throughput (HT) rate format for bits 7:0
 *
 *  2-0:  MCS rate base
 *        0)   6 Mbps
 *        1)  12 Mbps
 *        2)  18 Mbps
 *        3)  24 Mbps
 *        4)  36 Mbps
 *        5)  48 Mbps
 *        6)  54 Mbps
 *        7)  60 Mbps
 *  4-3:  0)  Single stream (SISO)
 *        1)  Dual stream (MIMO)
 *        2)  Triple stream (MIMO)
 *    5:  Value of 0x20 in bits 7:0 indicates 6 Mbps HT40 duplicate data
 *  (bits 7-6 are zero)
 *
 * Together the low 5 bits work out to the MCS index because we don't
 * support MCSes above 15/23, and 0-7 have one stream, 8-15 have two
 * streams and 16-23 have three streams. We could also support MCS 32
 * which is the duplicate 20 MHz MCS (bit 5 set, all others zero.)
 */
#define RATE_HT_MCS_RATE_CODE_MSK    0x7
#define RATE_HT_MCS_NSS_POS             3
#define RATE_HT_MCS_NSS_MSK             (3 << RATE_HT_MCS_NSS_POS)

/* Bit 10: (1) Use Green Field preamble */
#define RATE_HT_MCS_GF_POS        10
#define RATE_HT_MCS_GF_MSK        (1 << RATE_HT_MCS_GF_POS)

#define RATE_HT_MCS_INDEX_MSK        0x3f

/*
 * Very High-throughput (VHT) rate format for bits 7:0
 *
 *  3-0:  VHT MCS (0-9)
 *  5-4:  number of streams - 1:
 *        0)  Single stream (SISO)
 *        1)  Dual stream (MIMO)
 *        2)  Triple stream (MIMO)
 */

/* Bit 4-5: (0) SISO, (1) MIMO2 (2) MIMO3 */
#define RATE_VHT_MCS_RATE_CODE_MSK    0xf
#define RATE_VHT_MCS_NSS_POS        4
#define RATE_VHT_MCS_NSS_MSK        (3 << RATE_VHT_MCS_NSS_POS)

/*
 * Legacy OFDM rate format for bits 7:0
 *
 *  3-0:  0xD)   6 Mbps
 *        0xF)   9 Mbps
 *        0x5)  12 Mbps
 *        0x7)  18 Mbps
 *        0x9)  24 Mbps
 *        0xB)  36 Mbps
 *        0x1)  48 Mbps
 *        0x3)  54 Mbps
 * (bits 7-4 are 0)
 *
 * Legacy CCK rate format for bits 7:0:
 * bit 8 is 0, bit 26 is 0, bit 9 is 1 (CCK):
 *
 *  6-0:   10)  1 Mbps
 *         20)  2 Mbps
 *         55)  5.5 Mbps
 *        110)  11 Mbps
 * (bit 7 is 0)
 */
#define RATE_LEGACY_RATE_MSK 0xff

/* Bit 10 - OFDM HE */
#define RATE_MCS_HE_POS        10
#define RATE_MCS_HE_MSK        BIT(RATE_MCS_HE_POS)

/*
 * Bit 11-12: (0) 20MHz, (1) 40MHz, (2) 80MHz, (3) 160MHz
 * 0 and 1 are valid for HT and VHT, 2 and 3 only for VHT
 */
#define RATE_MCS_CHAN_WIDTH_POS        11
#define RATE_MCS_CHAN_WIDTH_MSK        (3 << RATE_MCS_CHAN_WIDTH_POS)
#define RATE_MCS_CHAN_WIDTH_20        (0 << RATE_MCS_CHAN_WIDTH_POS)
#define RATE_MCS_CHAN_WIDTH_40        (1 << RATE_MCS_CHAN_WIDTH_POS)
#define RATE_MCS_CHAN_WIDTH_80        (2 << RATE_MCS_CHAN_WIDTH_POS)
#define RATE_MCS_CHAN_WIDTH_160        (3 << RATE_MCS_CHAN_WIDTH_POS)

/* Bit 13: (1) Short guard interval (0.4 usec), (0) normal GI (0.8 usec) */
#define RATE_MCS_SGI_POS        13
#define RATE_MCS_SGI_MSK        (1 << RATE_MCS_SGI_POS)

/* Bit 14-16: Antenna selection (1) Ant A, (2) Ant B, (4) Ant C */
#define RATE_MCS_ANT_POS        14
#define RATE_MCS_ANT_A_MSK        (1 << RATE_MCS_ANT_POS)
#define RATE_MCS_ANT_B_MSK        (2 << RATE_MCS_ANT_POS)
#define RATE_MCS_ANT_C_MSK        (4 << RATE_MCS_ANT_POS)
#define RATE_MCS_ANT_AB_MSK        (RATE_MCS_ANT_A_MSK | \
                     RATE_MCS_ANT_B_MSK)
#define RATE_MCS_ANT_ABC_MSK        (RATE_MCS_ANT_AB_MSK | \
                     RATE_MCS_ANT_C_MSK)
#define RATE_MCS_ANT_MSK        RATE_MCS_ANT_ABC_MSK

/* Bit 17: (0) SS, (1) SS*2 */
#define RATE_MCS_STBC_POS        17
#define RATE_MCS_STBC_MSK        BIT(RATE_MCS_STBC_POS)

/* Bit 18: OFDM-HE dual carrier mode */
#define RATE_HE_DUAL_CARRIER_MODE    18
#define RATE_HE_DUAL_CARRIER_MODE_MSK    BIT(RATE_HE_DUAL_CARRIER_MODE)

/* Bit 19: (0) Beamforming is off, (1) Beamforming is on */
#define RATE_MCS_BF_POS            19
#define RATE_MCS_BF_MSK            (1 << RATE_MCS_BF_POS)

/*
 * Bit 20-21: HE LTF type and guard interval
 * HE (ext) SU:
 *    0            1xLTF+0.8us
 *    1            2xLTF+0.8us
 *    2            2xLTF+1.6us
 *    3 & SGI (bit 13) clear    4xLTF+3.2us
 *    3 & SGI (bit 13) set    4xLTF+0.8us
 * HE MU:
 *    0            4xLTF+0.8us
 *    1            2xLTF+0.8us
 *    2            2xLTF+1.6us
 *    3            4xLTF+3.2us
 * HE TRIG:
 *    0            1xLTF+1.6us
 *    1            2xLTF+1.6us
 *    2            4xLTF+3.2us
 *    3            (does not occur)
 */
#define RATE_MCS_HE_GI_LTF_POS        20
#define RATE_MCS_HE_GI_LTF_MSK        (3 << RATE_MCS_HE_GI_LTF_POS)

/* Bit 22-23: HE type. (0) SU, (1) SU_EXT, (2) MU, (3) trigger based */
#define RATE_MCS_HE_TYPE_POS        22
#define RATE_MCS_HE_TYPE_SU        (0 << RATE_MCS_HE_TYPE_POS)
#define RATE_MCS_HE_TYPE_EXT_SU        (1 << RATE_MCS_HE_TYPE_POS)
#define RATE_MCS_HE_TYPE_MU        (2 << RATE_MCS_HE_TYPE_POS)
#define RATE_MCS_HE_TYPE_TRIG        (3 << RATE_MCS_HE_TYPE_POS)
#define RATE_MCS_HE_TYPE_MSK        (3 << RATE_MCS_HE_TYPE_POS)

/* Bit 24-25: (0) 20MHz (no dup), (1) 2x20MHz, (2) 4x20MHz, 3 8x20MHz */
#define RATE_MCS_DUP_POS        24
#define RATE_MCS_DUP_MSK        (3 << RATE_MCS_DUP_POS)

/* Bit 27: (1) LDPC enabled, (0) LDPC disabled */
#define RATE_MCS_LDPC_POS        27
#define RATE_MCS_LDPC_MSK        (1 << RATE_MCS_LDPC_POS)

/* Bit 28: (1) 106-tone RX (8 MHz RU), (0) normal bandwidth */
#define RATE_MCS_HE_106T_POS        28
#define RATE_MCS_HE_106T_MSK        (1 << RATE_MCS_HE_106T_POS)

/* Bit 30-31: (1) RTS, (2) CTS */
#define RATE_MCS_RTS_REQUIRED_POS  (30)
#define RATE_MCS_RTS_REQUIRED_MSK  (0x1 << RATE_MCS_RTS_REQUIRED_POS)

#define RATE_MCS_CTS_REQUIRED_POS  (31)
#define RATE_MCS_CTS_REQUIRED_MSK  (0x1 << RATE_MCS_CTS_REQUIRED_POS)

/* Link Quality definitions */

/* Link quality command flags bit fields */

/* Bit 0: (0) Don't use RTS (1) Use RTS */
#define LQ_FLAG_USE_RTS_POS             0
#define LQ_FLAG_USE_RTS_MSK            (1 << LQ_FLAG_USE_RTS_POS)

/* Bit 1-3: LQ command color. Used to match responses to LQ commands */
#define LQ_FLAG_COLOR_POS               1
#define LQ_FLAG_COLOR_MSK               (7 << LQ_FLAG_COLOR_POS)
#define LQ_FLAG_COLOR_GET(_f)        (((_f) & LQ_FLAG_COLOR_MSK) >>\
                     LQ_FLAG_COLOR_POS)
#define LQ_FLAGS_COLOR_INC(_c)        ((((_c) + 1) << LQ_FLAG_COLOR_POS) &\
                     LQ_FLAG_COLOR_MSK)
#define LQ_FLAG_COLOR_SET(_f, _c)    ((_c) | ((_f) & ~LQ_FLAG_COLOR_MSK))

/* Bit 4-5: Tx RTS BW Signalling
 * (0) No RTS BW signalling
 * (1) Static BW signalling
 * (2) Dynamic BW signalling
 */
#define LQ_FLAG_RTS_BW_SIG_POS          4
#define LQ_FLAG_RTS_BW_SIG_NONE         (0 << LQ_FLAG_RTS_BW_SIG_POS)
#define LQ_FLAG_RTS_BW_SIG_STATIC       (1 << LQ_FLAG_RTS_BW_SIG_POS)
#define LQ_FLAG_RTS_BW_SIG_DYNAMIC      (2 << LQ_FLAG_RTS_BW_SIG_POS)

/* Bit 6: (0) No dynamic BW selection (1) Allow dynamic BW selection
 * Dyanmic BW selection allows Tx with narrower BW then requested in rates
 */
#define LQ_FLAG_DYNAMIC_BW_POS          6
#define LQ_FLAG_DYNAMIC_BW_MSK          (1 << LQ_FLAG_DYNAMIC_BW_POS)

/* Single Stream Tx Parameters (lq_cmd->ss_params)
 * Flags to control a smart FW decision about whether BFER/STBC/SISO will be
 * used for single stream Tx.
 */

/* Bit 0-1: Max STBC streams allowed. Can be 0-3.
 * (0) - No STBC allowed
 * (1) - 2x1 STBC allowed (HT/VHT)
 * (2) - 4x2 STBC allowed (HT/VHT)
 * (3) - 3x2 STBC allowed (HT only)
 * All our chips are at most 2 antennas so only (1) is valid for now.
 */
#define LQ_SS_STBC_ALLOWED_POS          0
#define LQ_SS_STBC_ALLOWED_MSK        (3 << LQ_SS_STBC_ALLOWED_MSK)

/* 2x1 STBC is allowed */
#define LQ_SS_STBC_1SS_ALLOWED        (1 << LQ_SS_STBC_ALLOWED_POS)

/* Bit 2: Beamformer (VHT only) is allowed */
#define LQ_SS_BFER_ALLOWED_POS        2
#define LQ_SS_BFER_ALLOWED        (1 << LQ_SS_BFER_ALLOWED_POS)

/* Bit 3: Force BFER or STBC for testing
 * If this is set:
 * If BFER is allowed then force the ucode to choose BFER else
 * If STBC is allowed then force the ucode to choose STBC over SISO
 */
#define LQ_SS_FORCE_POS            3
#define LQ_SS_FORCE            (1 << LQ_SS_FORCE_POS)

/* Bit 31: ss_params field is valid. Used for FW backward compatibility
 * with other drivers which don't support the ss_params API yet
 */
#define LQ_SS_PARAMS_VALID_POS        31
#define LQ_SS_PARAMS_VALID        (1 << LQ_SS_PARAMS_VALID_POS)

struct iwl_rs_rate_info {
    u8 plcp;      /* uCode API:  IWL_RATE_6M_PLCP, etc. */
    u8 plcp_ht_siso;  /* uCode API:  IWL_RATE_SISO_6M_PLCP, etc. */
    u8 plcp_ht_mimo2; /* uCode API:  IWL_RATE_MIMO2_6M_PLCP, etc. */
    u8 plcp_vht_siso;
    u8 plcp_vht_mimo2;
    u8 prev_rs;      /* previous rate used in rs algo */
    u8 next_rs;      /* next rate used in rs algo */
};

extern struct iwl_rs_rate_info iwl_rates[IWL_RATE_COUNT];

#define IWL_RATE_60M_PLCP 3

enum {
    IWL_RATE_INVM_INDEX = IWL_RATE_COUNT,
    IWL_RATE_INVALID = IWL_RATE_COUNT,
};

#define LINK_QUAL_MAX_RETRY_NUM 16

enum {
    IWL_RATE_6M_INDEX_TABLE = 0,
    IWL_RATE_9M_INDEX_TABLE,
    IWL_RATE_12M_INDEX_TABLE,
    IWL_RATE_18M_INDEX_TABLE,
    IWL_RATE_24M_INDEX_TABLE,
    IWL_RATE_36M_INDEX_TABLE,
    IWL_RATE_48M_INDEX_TABLE,
    IWL_RATE_54M_INDEX_TABLE,
    IWL_RATE_1M_INDEX_TABLE,
    IWL_RATE_2M_INDEX_TABLE,
    IWL_RATE_5M_INDEX_TABLE,
    IWL_RATE_11M_INDEX_TABLE,
    IWL_RATE_INVM_INDEX_TABLE = IWL_RATE_INVM_INDEX - 1,
};

/* #define vs. enum to keep from defaulting to 'large integer' */
#define    IWL_RATE_6M_MASK   (1 << IWL_RATE_6M_INDEX)
#define    IWL_RATE_9M_MASK   (1 << IWL_RATE_9M_INDEX)
#define    IWL_RATE_12M_MASK  (1 << IWL_RATE_12M_INDEX)
#define    IWL_RATE_18M_MASK  (1 << IWL_RATE_18M_INDEX)
#define    IWL_RATE_24M_MASK  (1 << IWL_RATE_24M_INDEX)
#define    IWL_RATE_36M_MASK  (1 << IWL_RATE_36M_INDEX)
#define    IWL_RATE_48M_MASK  (1 << IWL_RATE_48M_INDEX)
#define    IWL_RATE_54M_MASK  (1 << IWL_RATE_54M_INDEX)
#define IWL_RATE_60M_MASK  (1 << IWL_RATE_60M_INDEX)
#define    IWL_RATE_1M_MASK   (1 << IWL_RATE_1M_INDEX)
#define    IWL_RATE_2M_MASK   (1 << IWL_RATE_2M_INDEX)
#define    IWL_RATE_5M_MASK   (1 << IWL_RATE_5M_INDEX)
#define    IWL_RATE_11M_MASK  (1 << IWL_RATE_11M_INDEX)


/* uCode API values for HT/VHT bit rates */
enum {
    IWL_RATE_HT_SISO_MCS_0_PLCP = 0,
    IWL_RATE_HT_SISO_MCS_1_PLCP = 1,
    IWL_RATE_HT_SISO_MCS_2_PLCP = 2,
    IWL_RATE_HT_SISO_MCS_3_PLCP = 3,
    IWL_RATE_HT_SISO_MCS_4_PLCP = 4,
    IWL_RATE_HT_SISO_MCS_5_PLCP = 5,
    IWL_RATE_HT_SISO_MCS_6_PLCP = 6,
    IWL_RATE_HT_SISO_MCS_7_PLCP = 7,
    IWL_RATE_HT_MIMO2_MCS_0_PLCP = 0x8,
    IWL_RATE_HT_MIMO2_MCS_1_PLCP = 0x9,
    IWL_RATE_HT_MIMO2_MCS_2_PLCP = 0xA,
    IWL_RATE_HT_MIMO2_MCS_3_PLCP = 0xB,
    IWL_RATE_HT_MIMO2_MCS_4_PLCP = 0xC,
    IWL_RATE_HT_MIMO2_MCS_5_PLCP = 0xD,
    IWL_RATE_HT_MIMO2_MCS_6_PLCP = 0xE,
    IWL_RATE_HT_MIMO2_MCS_7_PLCP = 0xF,
    IWL_RATE_VHT_SISO_MCS_0_PLCP = 0,
    IWL_RATE_VHT_SISO_MCS_1_PLCP = 1,
    IWL_RATE_VHT_SISO_MCS_2_PLCP = 2,
    IWL_RATE_VHT_SISO_MCS_3_PLCP = 3,
    IWL_RATE_VHT_SISO_MCS_4_PLCP = 4,
    IWL_RATE_VHT_SISO_MCS_5_PLCP = 5,
    IWL_RATE_VHT_SISO_MCS_6_PLCP = 6,
    IWL_RATE_VHT_SISO_MCS_7_PLCP = 7,
    IWL_RATE_VHT_SISO_MCS_8_PLCP = 8,
    IWL_RATE_VHT_SISO_MCS_9_PLCP = 9,
    IWL_RATE_VHT_MIMO2_MCS_0_PLCP = 0x10,
    IWL_RATE_VHT_MIMO2_MCS_1_PLCP = 0x11,
    IWL_RATE_VHT_MIMO2_MCS_2_PLCP = 0x12,
    IWL_RATE_VHT_MIMO2_MCS_3_PLCP = 0x13,
    IWL_RATE_VHT_MIMO2_MCS_4_PLCP = 0x14,
    IWL_RATE_VHT_MIMO2_MCS_5_PLCP = 0x15,
    IWL_RATE_VHT_MIMO2_MCS_6_PLCP = 0x16,
    IWL_RATE_VHT_MIMO2_MCS_7_PLCP = 0x17,
    IWL_RATE_VHT_MIMO2_MCS_8_PLCP = 0x18,
    IWL_RATE_VHT_MIMO2_MCS_9_PLCP = 0x19,
    IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_HT_MIMO2_MCS_INV_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_VHT_SISO_MCS_INV_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_VHT_MIMO2_MCS_INV_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_HT_SISO_MCS_8_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_HT_SISO_MCS_9_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_HT_MIMO2_MCS_8_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
    IWL_RATE_HT_MIMO2_MCS_9_PLCP = IWL_RATE_HT_SISO_MCS_INV_PLCP,
};

#define IWL_RATES_MASK ((1 << IWL_RATE_COUNT) - 1)

#define IWL_INVALID_VALUE    0xff

#define TPC_MAX_REDUCTION        15
#define TPC_NO_REDUCTION        0
#define TPC_INVALID            0xff

#define LINK_QUAL_AGG_FRAME_LIMIT_DEF    (63)
#define LINK_QUAL_AGG_FRAME_LIMIT_MAX    (63)
/*
 * FIXME - various places in firmware API still use u8,
 * e.g. LQ command and SCD config command.
 * This should be 256 instead.
 */
#define LINK_QUAL_AGG_FRAME_LIMIT_GEN2_DEF    (255)
#define LINK_QUAL_AGG_FRAME_LIMIT_GEN2_MAX    (255)
#define LINK_QUAL_AGG_FRAME_LIMIT_MIN    (0)

#define LQ_SIZE        2    /* 2 mode tables:  "Active" and "Search" */

/* load per tid defines for A-MPDU activation */
#define IWL_AGG_TPT_THREHOLD    0
#define IWL_AGG_ALL_TID        0xff

enum iwl_table_type {
    LQ_NONE,
    LQ_LEGACY_G,    /* legacy types */
    LQ_LEGACY_A,
    LQ_HT_SISO,    /* HT types */
    LQ_HT_MIMO2,
    LQ_VHT_SISO,    /* VHT types */
    LQ_VHT_MIMO2,
    LQ_HE_SISO,     /* HE types */
    LQ_HE_MIMO2,
    LQ_MAX,
};

struct rs_rate {
    int index;
    enum iwl_table_type type;
    u8 ant;
    u32 bw;
    bool sgi;
    bool ldpc;
    bool stbc;
    bool bfer;
};

#define is_type_legacy(type) (((type) == LQ_LEGACY_G) || \
                  ((type) == LQ_LEGACY_A))
#define is_type_ht_siso(type) ((type) == LQ_HT_SISO)
#define is_type_ht_mimo2(type) ((type) == LQ_HT_MIMO2)
#define is_type_vht_siso(type) ((type) == LQ_VHT_SISO)
#define is_type_vht_mimo2(type) ((type) == LQ_VHT_MIMO2)
#define is_type_he_siso(type) ((type) == LQ_HE_SISO)
#define is_type_he_mimo2(type) ((type) == LQ_HE_MIMO2)
#define is_type_siso(type) (is_type_ht_siso(type) || is_type_vht_siso(type) || \
                is_type_he_siso(type))
#define is_type_mimo2(type) (is_type_ht_mimo2(type) || \
                 is_type_vht_mimo2(type) || is_type_he_mimo2(type))
#define is_type_mimo(type) (is_type_mimo2(type))
#define is_type_ht(type) (is_type_ht_siso(type) || is_type_ht_mimo2(type))
#define is_type_vht(type) (is_type_vht_siso(type) || is_type_vht_mimo2(type))
#define is_type_he(type) (is_type_he_siso(type) || is_type_he_mimo2(type))
#define is_type_a_band(type) ((type) == LQ_LEGACY_A)
#define is_type_g_band(type) ((type) == LQ_LEGACY_G)

#define is_legacy(rate)       is_type_legacy((rate)->type)
#define is_ht_siso(rate)      is_type_ht_siso((rate)->type)
#define is_ht_mimo2(rate)     is_type_ht_mimo2((rate)->type)
#define is_vht_siso(rate)     is_type_vht_siso((rate)->type)
#define is_vht_mimo2(rate)    is_type_vht_mimo2((rate)->type)
#define is_siso(rate)         is_type_siso((rate)->type)
#define is_mimo2(rate)        is_type_mimo2((rate)->type)
#define is_mimo(rate)         is_type_mimo((rate)->type)
#define is_ht(rate)           is_type_ht((rate)->type)
#define is_vht(rate)          is_type_vht((rate)->type)
#define is_he(rate)           is_type_he((rate)->type)
#define is_a_band(rate)       is_type_a_band((rate)->type)
#define is_g_band(rate)       is_type_g_band((rate)->type)

#define is_ht20(rate)         ((rate)->bw == RATE_MCS_CHAN_WIDTH_20)
#define is_ht40(rate)         ((rate)->bw == RATE_MCS_CHAN_WIDTH_40)
#define is_ht80(rate)         ((rate)->bw == RATE_MCS_CHAN_WIDTH_80)
#define is_ht160(rate)        ((rate)->bw == RATE_MCS_CHAN_WIDTH_160)

#define IWL_MAX_MCS_DISPLAY_SIZE    12

struct iwl_rate_mcs_info {
    char    mbps[IWL_MAX_MCS_DISPLAY_SIZE];
    char    mcs[IWL_MAX_MCS_DISPLAY_SIZE];
};

/**
 * struct iwl_lq_sta_rs_fw - rate and related statistics for RS in FW
 * @last_rate_n_flags: last rate reported by FW
 * @sta_id: the id of the station
#ifdef CONFIG_MAC80211_DEBUGFS
 * @dbg_fixed_rate: for debug, use fixed rate if not 0
 * @dbg_agg_frame_count_lim: for debug, max number of frames in A-MPDU
#endif
 * @chains: bitmask of chains reported in %chain_signal
 * @chain_signal: per chain signal strength
 * @last_rssi: last rssi reported
 * @drv: pointer back to the driver data
 */

struct iwl_lq_sta_rs_fw {
    /* last tx rate_n_flags */
    u32 last_rate_n_flags;

    /* persistent fields - initialized only once - keep last! */
    struct lq_sta_pers_rs_fw {
        u32 sta_id;
        u8 chains;
        s8 chain_signal[4];
        s8 last_rssi;
        struct iwm_softc *drv;
    } pers;
};

/**
 * struct iwl_rate_scale_data -- tx success history for one rate
 */
struct iwl_rate_scale_data {
    u64 data;        /* bitmap of successful frames */
    s32 success_counter;    /* number of frames successful */
    s32 success_ratio;    /* per-cent * 128  */
    s32 counter;        /* number of frames attempted */
    s32 average_tpt;    /* success ratio * expected throughput */
};

/* Possible Tx columns
 * Tx Column = a combo of legacy/siso/mimo x antenna x SGI
 */
enum rs_column {
    RS_COLUMN_LEGACY_ANT_A = 0,
    RS_COLUMN_LEGACY_ANT_B,
    RS_COLUMN_SISO_ANT_A,
    RS_COLUMN_SISO_ANT_B,
    RS_COLUMN_SISO_ANT_A_SGI,
    RS_COLUMN_SISO_ANT_B_SGI,
    RS_COLUMN_MIMO2,
    RS_COLUMN_MIMO2_SGI,

    RS_COLUMN_LAST = RS_COLUMN_MIMO2_SGI,
    RS_COLUMN_COUNT = RS_COLUMN_LAST + 1,
    RS_COLUMN_INVALID,
};

enum rs_ss_force_opt {
    RS_SS_FORCE_NONE = 0,
    RS_SS_FORCE_STBC,
    RS_SS_FORCE_BFER,
    RS_SS_FORCE_SISO,
};

/* Packet stats per rate */
struct rs_rate_stats {
    u64 success;
    u64 total;
};

/**
 * struct iwl_scale_tbl_info -- tx params and success history for all rates
 *
 * There are two of these in struct iwl_lq_sta,
 * one for "active", and one for "search".
 */
struct iwl_scale_tbl_info {
    struct rs_rate rate;
    enum rs_column column;
    const u16 *expected_tpt;    /* throughput metrics; expected_tpt_G, etc. */
    struct iwl_rate_scale_data win[IWL_RATE_COUNT]; /* rate histories */
    /* per txpower-reduction history */
    struct iwl_rate_scale_data tpc_win[TPC_MAX_REDUCTION + 1];
};

enum {
    RS_STATE_SEARCH_CYCLE_STARTED,
    RS_STATE_SEARCH_CYCLE_ENDED,
    RS_STATE_STAY_IN_COLUMN,
};

struct lq_sta_pers {
    u8 chains;
    s8 chain_signal[4];
    s8 last_rssi;
    struct rs_rate_stats tx_stats[RS_COLUMN_COUNT][IWL_RATE_COUNT];
    struct iwm_softc *drv;
    IOSimpleLock *lock; /* for races in reinit/update table */
};

/**
 * struct iwl_lq_sta -- driver's rate scaling private structure
 *
 * Pointer to this gets passed back and forth between driver and mac80211.
 */
struct iwl_lq_sta {
    u8 active_tbl;        /* index of active table, range 0-1 */
    u8 rs_state;            /* RS_STATE_* */
    u8 search_better_tbl;    /* 1: currently trying alternate mode */
    s32 last_tpt;

    /* The following determine when to search for a new mode */
    u32 table_count_limit;
    u32 max_failure_limit;    /* # failed frames before new search */
    u32 max_success_limit;    /* # successful frames before new search */
    u32 table_count;
    u32 total_failed;    /* total failed frames, any/all rates */
    u32 total_success;    /* total successful frames, any/all rates */
    u64 flush_timer;    /* time staying in mode before new search */

    u32 visited_columns;    /* Bitmask marking which Tx columns were
                 * explored during a search cycle
                 */
    u64 last_tx;
    bool is_vht;
    bool ldpc;              /* LDPC Rx is supported by the STA */
    bool stbc_capable;      /* Tx STBC is supported by chip and Rx by STA */
    bool bfer_capable;      /* Remote supports beamformee and we BFer */

    enum nl80211_band band;

    /* The following are bitmaps of rates; IWL_RATE_6M_MASK, etc. */
    unsigned long active_legacy_rate;
    unsigned long active_siso_rate;
    unsigned long active_mimo2_rate;

    /* Highest rate per Tx mode */
    u8 max_legacy_rate_idx;
    u8 max_siso_rate_idx;
    u8 max_mimo2_rate_idx;

    /* Optimal rate based on RSSI and STA caps.
     * Used only to reflect link speed to userspace.
     */
    struct rs_rate optimal_rate;
    unsigned long optimal_rate_mask;
    const struct rs_init_rate_info *optimal_rates;
    int optimal_nentries;

    u8 missed_rate_counter;

    struct iwm_lq_cmd lq;
    struct iwl_scale_tbl_info lq_info[LQ_SIZE]; /* "active", "search" */
    u8 tx_agg_tid_en;

    /* last tx rate_n_flags */
    u32 last_rate_n_flags;
    /* packets destined for this STA are aggregated */
    u8 is_agg;

    /* tx power reduce for this sta */
    int tpc_reduce;

    /* persistent fields - initialized only once - keep last! */
    struct lq_sta_pers pers;
};

/* ieee80211_tx_info's status_driver_data[0] is packed with lq color and txp
 * Note, it's iwlmvm <-> mac80211 interface.
 * bits 0-7: reduced tx power
 * bits 8-10: LQ command's color
 */
#define RS_DRV_DATA_TXP_MSK 0xff
#define RS_DRV_DATA_LQ_COLOR_POS 8
#define RS_DRV_DATA_LQ_COLOR_MSK (7 << RS_DRV_DATA_LQ_COLOR_POS)
#define RS_DRV_DATA_LQ_COLOR_GET(_f) (((_f) & RS_DRV_DATA_LQ_COLOR_MSK) >>\
                      RS_DRV_DATA_LQ_COLOR_POS)
#define RS_DRV_DATA_PACK(_c, _p) ((void *)(uintptr_t)\
                  (((uintptr_t)_p) |\
                   ((_c) << RS_DRV_DATA_LQ_COLOR_POS)))

#define IWL_DECLARE_RATE_INFO(r) \
    [IWL_RATE_##r##M_INDEX] = IWL_RATE_##r##M_PLCP

/*
 * Translate from fw_rate_index (IWL_RATE_XXM_INDEX) to PLCP
 */
static const u8 fw_rate_idx_to_plcp[IWL_RATE_COUNT] = {
    IWL_DECLARE_RATE_INFO(1),
    IWL_DECLARE_RATE_INFO(2),
    IWL_DECLARE_RATE_INFO(5),
    IWL_DECLARE_RATE_INFO(11),
    IWL_DECLARE_RATE_INFO(6),
    IWL_DECLARE_RATE_INFO(9),
    IWL_DECLARE_RATE_INFO(12),
    IWL_DECLARE_RATE_INFO(18),
    IWL_DECLARE_RATE_INFO(24),
    IWL_DECLARE_RATE_INFO(36),
    IWL_DECLARE_RATE_INFO(48),
    IWL_DECLARE_RATE_INFO(54),
};

#undef IWL_DECLARE_RATE_INFO

/* Convert an MCS index into an iwm_rates[] index. */
const int iwm_mcs2ridx[] = {
    IWL_RATE_6M_INDEX,
    IWL_RATE_12M_INDEX,
    IWL_RATE_12M_INDEX,
    IWL_RATE_18M_INDEX,
    IWL_RATE_24M_INDEX,
    IWL_RATE_36M_INDEX,
    IWL_RATE_48M_INDEX,
    IWL_RATE_54M_INDEX,
    IWL_RATE_54M_INDEX,
    IWL_RATE_54M_INDEX,
};

static inline int iwl_mvm_legacy_rate_to_mac80211_idx(u32 rate_n_flags,
                    enum nl80211_band band)
{
    int rate = rate_n_flags & RATE_LEGACY_RATE_MSK;
    int idx;
    int band_offset = 0;

    /* Legacy rate format, search for match in table */
    if (band != NL80211_BAND_2GHZ)
        band_offset = IWL_FIRST_OFDM_RATE;
    for (idx = band_offset; idx < IWL_RATE_COUNT_LEGACY; idx++)
        if (fw_rate_idx_to_plcp[idx] == rate)
            return idx - band_offset;

    return -1;
}

static inline u8 iwl_mvm_mac80211_idx_to_hwrate(int rate_idx)
{
    /* Get PLCP rate for tx_cmd->rate_n_flags */
    return fw_rate_idx_to_plcp[rate_idx];
}

static inline void ieee80211_rate_set_vht(struct ieee80211_tx_rate *rate,
                      u8 mcs, u8 nss)
{
    WARN_ON(mcs & ~0xF);
    WARN_ON((nss - 1) & ~0x7);
    rate->idx = ((nss - 1) << 4) | mcs;
}

static inline void iwl_mvm_hwrate_to_tx_rate(u32 rate_n_flags,
                   enum nl80211_band band,
                   struct ieee80211_tx_rate *r)
{
    if (rate_n_flags & RATE_HT_MCS_GF_MSK)
        r->flags |= IEEE80211_TX_RC_GREEN_FIELD;
    switch (rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) {
    case RATE_MCS_CHAN_WIDTH_20:
        break;
    case RATE_MCS_CHAN_WIDTH_40:
        r->flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;
        break;
    case RATE_MCS_CHAN_WIDTH_80:
        r->flags |= IEEE80211_TX_RC_80_MHZ_WIDTH;
        break;
    case RATE_MCS_CHAN_WIDTH_160:
        r->flags |= IEEE80211_TX_RC_160_MHZ_WIDTH;
        break;
    }
    if (rate_n_flags & RATE_MCS_SGI_MSK)
        r->flags |= IEEE80211_TX_RC_SHORT_GI;
    if (rate_n_flags & RATE_MCS_HT_MSK) {
        r->flags |= IEEE80211_TX_RC_MCS;
        r->idx = rate_n_flags & RATE_HT_MCS_INDEX_MSK;
    } else if (rate_n_flags & RATE_MCS_VHT_MSK) {
        ieee80211_rate_set_vht(
            r, rate_n_flags & RATE_VHT_MCS_RATE_CODE_MSK,
            ((rate_n_flags & RATE_VHT_MCS_NSS_MSK) >>
                        RATE_VHT_MCS_NSS_POS) + 1);
        r->flags |= IEEE80211_TX_RC_VHT_MCS;
    } else {
        r->idx = iwl_mvm_legacy_rate_to_mac80211_idx(rate_n_flags,
                                 band);
    }
}

/*
 * translate ucode response to mac80211 tx status control values
 */
static inline void iwl_mvm_hwrate_to_tx_status(u32 rate_n_flags,
                    struct ieee80211_tx_info *info)
{
    struct ieee80211_tx_rate *r = &info->status.rates[0];

    info->status.antenna =
        ((rate_n_flags & RATE_MCS_ANT_ABC_MSK) >> RATE_MCS_ANT_POS);
    iwl_mvm_hwrate_to_tx_rate(rate_n_flags, (enum nl80211_band)info->band, r);
}

int iwl_mvm_send_lq_cmd(struct iwm_softc *sc, struct iwm_lq_cmd *lq);

/* Initialize station's rate scaling information after adding station */
void iwl_mvm_rs_rate_init(struct iwm_softc *mvm, struct ieee80211_node *sta,
              enum nl80211_band band, bool init);

/* Notify RS about Tx status */
void iwl_mvm_rs_tx_status(struct iwm_softc *mvm, struct ieee80211_node *sta,
              int tid, struct ieee80211_tx_info *info, bool ndp);

void rs_drv_mac80211_tx_status(struct iwm_softc *sc,
                struct ieee80211_node *sta,
                               struct ieee80211_tx_info *info, int tid, uint16_t fc, int ssn);

void rs_update_last_rssi(struct iwm_softc *mvm,
                         struct ieee80211_rx_status *rx_status);

int rs_pretty_print_rate(char *buf, int bufsz, const u32 rate);

void rs_drv_rate_update(struct iwm_softc *mvm,
                        struct ieee80211_node *sta,
                        enum nl80211_band band, u32 changed);

void *rs_drv_alloc_sta(iwm_softc *sc, struct ieee80211_node *ni);

void rs_drv_free_sta(iwm_softc *sc, struct ieee80211_node *ni);

void iwm_rs_alloc(struct iwm_softc *sc);

void iwm_rs_free(struct iwm_softc *sc);

#endif /* rs_hpp */
