//
//  _netstat.h
//  itlwm
//
//  Created by qcwap on 2021/4/22.
//  Copyright © 2021 钟先耀. All rights reserved.
//

#ifndef _netstat_h
#define _netstat_h

#include <linux/types.h>

static inline const char *
openbsd_plural(u_int64_t n)
{
    return (n != 1 ? "s" : "");
}

/*
 * Dump IEEE802.11 per-interface statistics
 */
static inline void
net80211_ifstats(struct ieee80211com *ic)
{
    struct ieee80211_stats *stats = &ic->ic_stats;

#define    p(f, m)    XYLog(m, (unsigned long)stats->f, openbsd_plural(stats->f))
    p(is_rx_badversion, "\t%lu input packet%s with bad version\n");
    p(is_rx_tooshort, "\t%lu input packet%s too short\n");
    p(is_rx_wrongbss, "\t%lu input packet%s from wrong bssid\n");
    p(is_rx_dup, "\t%lu input packet duplicate%s discarded\n");
    p(is_rx_wrongdir, "\t%lu input packet%s with wrong direction\n");
    p(is_rx_mcastecho, "\t%lu input multicast echo packet%s discarded\n");
    p(is_rx_notassoc, "\t%lu input packet%s from unassociated station discarded\n");
    p(is_rx_nowep, "\t%lu input encrypted packet%s without wep/wpa config discarded\n");
    p(is_rx_unencrypted, "\t%lu input unencrypted packet%s with wep/wpa config discarded\n");
    p(is_rx_wepfail, "\t%lu input wep/wpa packet%s processing failed\n");
    p(is_rx_decap, "\t%lu input packet decapsulation%s failed\n");
    p(is_rx_mgtdiscard, "\t%lu input management packet%s discarded\n");
    p(is_rx_ctl, "\t%lu input control packet%s discarded\n");
    p(is_rx_rstoobig, "\t%lu input packet%s with truncated rate set\n");
    p(is_rx_elem_missing, "\t%lu input packet%s with missing elements\n");
    p(is_rx_elem_toobig, "\t%lu input packet%s with elements too big\n");
    p(is_rx_elem_toosmall, "\t%lu input packet%s with elements too small\n");
    p(is_rx_badchan, "\t%lu input packet%s with invalid channel\n");
    p(is_rx_chanmismatch, "\t%lu input packet%s with mismatched channel\n");
    p(is_rx_nodealloc, "\t%lu node allocation%s failed\n");
    p(is_rx_ssidmismatch, "\t%lu input packet%s with mismatched ssid\n");
    p(is_rx_auth_unsupported, "\t%lu input packet%s with unsupported auth algorithm\n");
    p(is_rx_auth_fail, "\t%lu input authentication%s failed\n");
    p(is_rx_assoc_bss, "\t%lu input association%s from wrong bssid\n");
    p(is_rx_assoc_notauth, "\t%lu input association%s without authentication\n");
    p(is_rx_assoc_capmismatch, "\t%lu input association%s with mismatched capabilities\n");
    p(is_rx_assoc_norate, "\t%lu input association%s without matching rates\n");
    p(is_rx_assoc_badrsnie, "\t%lu input association%s with bad rsn ie\n");
    p(is_rx_deauth, "\t%lu input deauthentication packet%s\n");
    p(is_rx_disassoc, "\t%lu input disassociation packet%s\n");
    p(is_rx_badsubtype, "\t%lu input packet%s with unknown subtype\n");
    p(is_rx_nombuf, "\t%lu input packet%s failed for lack of mbufs\n");
    p(is_rx_decryptcrc, "\t%lu input decryption%s failed on crc\n");
    p(is_rx_ahdemo_mgt, "\t%lu input ahdemo management packet%s discarded\n");
    p(is_rx_bad_auth, "\t%lu input packet%s with bad auth request\n");
    p(is_rx_eapol_key, "\t%lu input eapol-key packet%s\n");
    p(is_rx_eapol_badmic, "\t%lu input eapol-key packet%s with bad mic\n");
    p(is_rx_eapol_replay, "\t%lu input eapol-key packet%s replayed\n");
    p(is_rx_locmicfail, "\t%lu input packet%s with bad tkip mic\n");
    p(is_rx_remmicfail, "\t%lu input tkip mic failure notification%s\n");
    p(is_rx_unauth, "\t%lu input packet%s on unauthenticated port\n");
    p(is_tx_nombuf, "\t%lu output packet%s failed for lack of mbufs\n");
    p(is_tx_nonode, "\t%lu output packet%s failed for no nodes\n");
    p(is_tx_unknownmgt, "\t%lu output packet%s of unknown management type\n");
    p(is_tx_noauth, "\t%lu output packet%s on unauthenticated port\n");
    p(is_scan_active, "\t%lu active scan%s started\n");
    p(is_scan_passive, "\t%lu passive scan%s started\n");
    p(is_node_timeout, "\t%lu node%s timed out\n");
    p(is_crypto_nomem, "\t%lu failure%s with no memory for crypto ctx\n");
    p(is_ccmp_dec_errs, "\t%lu ccmp decryption error%s\n");
    p(is_ccmp_replays, "\t%lu ccmp replayed frame%s \n");
    p(is_cmac_icv_errs, "\t%lu cmac icv error%s\n");
    p(is_cmac_replays, "\t%lu cmac replayed frame%s\n");
    p(is_tkip_icv_errs, "\t%lu tkip icv error%s\n");
    p(is_tkip_replays, "\t%lu tkip replay%s\n");
    p(is_pbac_errs, "\t%lu pbac error%s\n");
    p(is_ht_nego_no_mandatory_mcs, "\t%lu HT negotiation failure%s because "
        "peer does not support MCS 0-7\n");
    p(is_ht_nego_no_basic_mcs, "\t%lu HT negotiation failure%s because "
        "we do not support basic MCS set\n");
    p(is_ht_nego_bad_crypto,
        "\t%lu HT negotiation failure%s because peer uses bad crypto\n");
    p(is_ht_prot_change, "\t%lu HT protection change%s\n");
    p(is_ht_rx_ba_agreements, "\t%lu new input block ack agreement%s\n");
    p(is_ht_tx_ba_agreements, "\t%lu new output block ack agreement%s\n");
    p(is_ht_rx_frame_below_ba_winstart,
        "\t%lu input frame%s below block ack window start\n");
    p(is_ht_rx_frame_above_ba_winend,
        "\t%lu input frame%s above block ack window end\n");
    p(is_ht_rx_ba_window_slide, "\t%lu input block ack window slide%s\n");
    p(is_ht_rx_ba_window_jump, "\t%lu input block ack window jump%s\n");
    p(is_ht_rx_ba_no_buf, "\t%lu duplicate input block ack frame%s\n");
    p(is_ht_rx_ba_frame_lost,
        "\t%lu expected input block ack frame%s never arrived\n");
    p(is_ht_rx_ba_window_gap_timeout,
        "\t%lu input block ack window gap%s timed out\n");
    p(is_ht_rx_ba_timeout,
        "\t%lu input block ack agreement%s timed out\n");
    p(is_ht_tx_ba_timeout,
        "\t%lu output block ack agreement%s timed out\n");
    p(is_vht_nego_no_mandatory_mcs, "\t%lu VHT negotiation failure%s because "
        "peer does not support MCS 0-9\n");
    p(is_vht_nego_bad_crypto,
        "\t%lu VHT negotiation failure%s because peer uses bad crypto\n");

#undef p
}

#endif /* _netstat_h */
