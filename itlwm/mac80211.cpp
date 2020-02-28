//
//  mac80211.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

int itlwm::
iwm_is_valid_channel(uint16_t ch_id)
{
    if (ch_id <= 14 ||
        (36 <= ch_id && ch_id <= 64 && ch_id % 4 == 0) ||
        (100 <= ch_id && ch_id <= 140 && ch_id % 4 == 0) ||
        (145 <= ch_id && ch_id <= 165 && ch_id % 4 == 1))
        return 1;
    return 0;
}

uint8_t itlwm::
iwm_ch_id_to_ch_index(uint16_t ch_id)
{
    if (!iwm_is_valid_channel(ch_id))
        return 0xff;

    if (ch_id <= 14)
        return ch_id - 1;
    if (ch_id <= 64)
        return (ch_id + 20) / 4;
    if (ch_id <= 140)
        return (ch_id - 12) / 4;
    return (ch_id - 13) / 4;
}


uint16_t itlwm::
iwm_channel_id_to_papd(uint16_t ch_id)
{
    if (!iwm_is_valid_channel(ch_id))
        return 0xff;

    if (1 <= ch_id && ch_id <= 14)
        return 0;
    if (36 <= ch_id && ch_id <= 64)
        return 1;
    if (100 <= ch_id && ch_id <= 140)
        return 2;
    return 3;
}

uint16_t itlwm::
iwm_channel_id_to_txp(struct iwm_softc *sc, uint16_t ch_id)
{
    struct iwm_phy_db *phy_db = &sc->sc_phy_db;
    struct iwm_phy_db_chg_txp *txp_chg;
    int i;
    uint8_t ch_index = iwm_ch_id_to_ch_index(ch_id);

    if (ch_index == 0xff)
        return 0xff;

    for (i = 0; i < IWM_NUM_TXP_CH_GROUPS; i++) {
        txp_chg = (struct iwm_phy_db_chg_txp *)phy_db->calib_ch_group_txp[i].data;
        if (!txp_chg)
            return 0xff;
        /*
         * Looking for the first channel group the max channel
         * of which is higher than the requested channel.
         */
        if (le16toh(txp_chg->max_channel_idx) >= ch_index)
            return i;
    }
    return 0xff;
}

void itlwm::
iwm_init_channel_map(struct iwm_softc *sc, const uint16_t * const nvm_ch_flags,
    const uint8_t *nvm_channels, size_t nchan)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_nvm_data *data = &sc->sc_nvm;
    int ch_idx;
    struct ieee80211_channel *channel;
    uint16_t ch_flags;
    int is_5ghz;
    int flags, hw_value;

    for (ch_idx = 0; ch_idx < nchan; ch_idx++) {
        ch_flags = le16_to_cpup(nvm_ch_flags + ch_idx);

        if (ch_idx >= IWM_NUM_2GHZ_CHANNELS &&
            !data->sku_cap_band_52GHz_enable)
            ch_flags &= ~IWM_NVM_CHANNEL_VALID;

        if (!(ch_flags & IWM_NVM_CHANNEL_VALID))
            continue;

        hw_value = nvm_channels[ch_idx];
        channel = &ic->ic_channels[hw_value];

        is_5ghz = ch_idx >= IWM_NUM_2GHZ_CHANNELS;
        if (!is_5ghz) {
            flags = IEEE80211_CHAN_2GHZ;
            channel->ic_flags
                = IEEE80211_CHAN_CCK
                | IEEE80211_CHAN_OFDM
                | IEEE80211_CHAN_DYN
                | IEEE80211_CHAN_2GHZ;
        } else {
            flags = IEEE80211_CHAN_5GHZ;
            channel->ic_flags =
                IEEE80211_CHAN_A;
        }
        channel->ic_freq = ieee80211_ieee2mhz(hw_value, flags);

        if (!(ch_flags & IWM_NVM_CHANNEL_ACTIVE))
            channel->ic_flags |= IEEE80211_CHAN_PASSIVE;

        if (data->sku_cap_11n_enable)
            channel->ic_flags |= IEEE80211_CHAN_HT;
    }
}

void itlwm::
iwm_setup_ht_rates(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rx_ant;

    /* TX is supported with the same MCS as RX. */
    ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;

    ic->ic_sup_mcs[0] = 0xff;        /* MCS 0-7 */

    if (sc->sc_nvm.sku_cap_mimo_disable)
        return;

    rx_ant = iwm_fw_valid_rx_ant(sc);
    if ((rx_ant & IWM_ANT_AB) == IWM_ANT_AB ||
        (rx_ant & IWM_ANT_BC) == IWM_ANT_BC)
        ic->ic_sup_mcs[1] = 0xff;    /* MCS 8-15 */
}

#define IWM_MAX_RX_BA_SESSIONS 16

void itlwm::
iwm_sta_rx_agg(struct iwm_softc *sc, struct ieee80211_node *ni, uint8_t tid,
    uint16_t ssn, int start)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_add_sta_cmd_v7 cmd;
    struct iwm_node *in = (struct iwm_node *)ni;
    int err, s;
    uint32_t status;

    if (start && sc->sc_rx_ba_sessions >= IWM_MAX_RX_BA_SESSIONS) {
        ieee80211_addba_req_refuse(ic, ni, tid);
        return;
    }

    memset(&cmd, 0, sizeof(cmd));

    cmd.sta_id = IWM_STATION_ID;
    cmd.mac_id_n_color
        = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.add_modify = IWM_STA_MODE_MODIFY;

    if (start) {
        cmd.add_immediate_ba_tid = (uint8_t)tid;
        cmd.add_immediate_ba_ssn = ssn;
    } else {
        cmd.remove_immediate_ba_tid = (uint8_t)tid;
    }
    cmd.modify_mask = start ? IWM_STA_MODIFY_ADD_BA_TID :
        IWM_STA_MODIFY_REMOVE_BA_TID;

    status = IWM_ADD_STA_SUCCESS;
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, sizeof(cmd), &cmd,
        &status);

    s = splnet();
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) == IWM_ADD_STA_SUCCESS) {
        if (start) {
            sc->sc_rx_ba_sessions++;
            ieee80211_addba_req_accept(ic, ni, tid);
        } else if (sc->sc_rx_ba_sessions > 0)
            sc->sc_rx_ba_sessions--;
    } else if (start)
        ieee80211_addba_req_refuse(ic, ni, tid);

    splx(s);
}

void itlwm::
iwm_set_hw_address_8000(struct iwm_softc *sc, struct iwm_nvm_data *data,
    const uint16_t *mac_override, const uint16_t *nvm_hw)
{
    const uint8_t *hw_addr;

    if (mac_override) {
        static const uint8_t reserved_mac[] = {
            0x02, 0xcc, 0xaa, 0xff, 0xee, 0x00
        };

        hw_addr = (const uint8_t *)(mac_override +
                 IWM_MAC_ADDRESS_OVERRIDE_8000);

        /*
         * Store the MAC address from MAO section.
         * No byte swapping is required in MAO section
         */
        memcpy(data->hw_addr, hw_addr, ETHER_ADDR_LEN);

        /*
         * Force the use of the OTP MAC address in case of reserved MAC
         * address in the NVM, or if address is given but invalid.
         */
        if (memcmp(reserved_mac, hw_addr, ETHER_ADDR_LEN) != 0 &&
            (memcmp(etherbroadcastaddr, data->hw_addr,
            sizeof(etherbroadcastaddr)) != 0) &&
            (memcmp(etheranyaddr, data->hw_addr,
            sizeof(etheranyaddr)) != 0) &&
            !ETHER_IS_MULTICAST(data->hw_addr))
            return;
    }

    if (nvm_hw) {
        /* Read the mac address from WFMP registers. */
        uint32_t mac_addr0, mac_addr1;

        if (!iwm_nic_lock(sc))
            goto out;
        mac_addr0 = htole32(iwm_read_prph(sc, IWM_WFMP_MAC_ADDR_0));
        mac_addr1 = htole32(iwm_read_prph(sc, IWM_WFMP_MAC_ADDR_1));
        iwm_nic_unlock(sc);

        hw_addr = (const uint8_t *)&mac_addr0;
        data->hw_addr[0] = hw_addr[3];
        data->hw_addr[1] = hw_addr[2];
        data->hw_addr[2] = hw_addr[1];
        data->hw_addr[3] = hw_addr[0];

        hw_addr = (const uint8_t *)&mac_addr1;
        data->hw_addr[4] = hw_addr[1];
        data->hw_addr[5] = hw_addr[0];

        return;
    }
out:
    XYLog("%s: mac address not found\n", DEVNAME(sc));
    memset(data->hw_addr, 0, sizeof(data->hw_addr));
}

#define IWM_RSSI_OFFSET 50
int itlwm::
iwm_calc_rssi(struct iwm_softc *sc, struct iwm_rx_phy_info *phy_info)
{
    int rssi_a, rssi_b, rssi_a_dbm, rssi_b_dbm, max_rssi_dbm;
    uint32_t agc_a, agc_b;
    uint32_t val;

    val = le32toh(phy_info->non_cfg_phy[IWM_RX_INFO_AGC_IDX]);
    agc_a = (val & IWM_OFDM_AGC_A_MSK) >> IWM_OFDM_AGC_A_POS;
    agc_b = (val & IWM_OFDM_AGC_B_MSK) >> IWM_OFDM_AGC_B_POS;

    val = le32toh(phy_info->non_cfg_phy[IWM_RX_INFO_RSSI_AB_IDX]);
    rssi_a = (val & IWM_OFDM_RSSI_INBAND_A_MSK) >> IWM_OFDM_RSSI_A_POS;
    rssi_b = (val & IWM_OFDM_RSSI_INBAND_B_MSK) >> IWM_OFDM_RSSI_B_POS;

    /*
     * dBm = rssi dB - agc dB - constant.
     * Higher AGC (higher radio gain) means lower signal.
     */
    rssi_a_dbm = rssi_a - IWM_RSSI_OFFSET - agc_a;
    rssi_b_dbm = rssi_b - IWM_RSSI_OFFSET - agc_b;
    max_rssi_dbm = MAX(rssi_a_dbm, rssi_b_dbm);

    return max_rssi_dbm;
}

/*
 * RSSI values are reported by the FW as positive values - need to negate
 * to obtain their dBM.  Account for missing antennas by replacing 0
 * values by -256dBm: practically 0 power and a non-feasible 8 bit value.
 */
int itlwm::
iwm_get_signal_strength(struct iwm_softc *sc, struct iwm_rx_phy_info *phy_info)
{
    int energy_a, energy_b, energy_c, max_energy;
    uint32_t val;

    val = le32toh(phy_info->non_cfg_phy[IWM_RX_INFO_ENERGY_ANT_ABC_IDX]);
    energy_a = (val & IWM_RX_INFO_ENERGY_ANT_A_MSK) >>
        IWM_RX_INFO_ENERGY_ANT_A_POS;
    energy_a = energy_a ? -energy_a : -256;
    energy_b = (val & IWM_RX_INFO_ENERGY_ANT_B_MSK) >>
        IWM_RX_INFO_ENERGY_ANT_B_POS;
    energy_b = energy_b ? -energy_b : -256;
    energy_c = (val & IWM_RX_INFO_ENERGY_ANT_C_MSK) >>
        IWM_RX_INFO_ENERGY_ANT_C_POS;
    energy_c = energy_c ? -energy_c : -256;
    max_energy = MAX(energy_a, energy_b);
    max_energy = MAX(max_energy, energy_c);

    return max_energy;
}

/*
 * Retrieve the average noise (in dBm) among receivers.
 */
int itlwm::
iwm_get_noise(const struct iwm_statistics_rx_non_phy *stats)
{
    int i, total, nbant, noise;

    total = nbant = noise = 0;
    for (i = 0; i < 3; i++) {
        noise = letoh32(stats->beacon_silence_rssi[i]) & 0xff;
        if (noise) {
            total += noise;
            nbant++;
        }
    }

    /* There should be at least one antenna but check anyway. */
    return (nbant == 0) ? -127 : (total / nbant) - 107;
}

void itlwm::
iwm_rx_rx_mpdu(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
    struct iwm_rx_data *data, struct mbuf_list *ml)
{
//    struct ieee80211com *ic = &sc->sc_ic;
//    struct ieee80211_frame *wh;
//    struct ieee80211_node *ni;
//    struct ieee80211_rxinfo rxi;
//    struct ieee80211_channel *bss_chan;
//    mbuf_t m;
//    struct iwm_rx_phy_info *phy_info;
//    struct iwm_rx_mpdu_res_start *rx_res;
//    int device_timestamp;
//    uint32_t len;
//    uint32_t rx_pkt_status;
//    int rssi, chanidx;
//    uint8_t saved_bssid[IEEE80211_ADDR_LEN] = { 0 };
//
//    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWM_RBUF_SIZE,
//        BUS_DMASYNC_POSTREAD);
//
//    phy_info = &sc->sc_last_phy_info;
//    rx_res = (struct iwm_rx_mpdu_res_start *)pkt->data;
//    wh = (struct ieee80211_frame *)(pkt->data + sizeof(*rx_res));
//    len = le16toh(rx_res->byte_count);
//    if (len < IEEE80211_MIN_LEN) {
//        ic->ic_stats.is_rx_tooshort++;
//        IC2IFP(ic)->if_ierrors++;
//        return;
//    }
//    if (len > IWM_RBUF_SIZE - sizeof(*rx_res)) {
//        IC2IFP(ic)->if_ierrors++;
//        return;
//    }
//    rx_pkt_status = le32toh(*(uint32_t *)(pkt->data +
//        sizeof(*rx_res) + len));
//
//    if (phy_info->cfg_phy_cnt > 20)
//        return;
//
//    if (!(rx_pkt_status & IWM_RX_MPDU_RES_STATUS_CRC_OK) ||
//        !(rx_pkt_status & IWM_RX_MPDU_RES_STATUS_OVERRUN_OK))
//        return; /* drop */
//
//    m = data->m;
//    if (iwm_rx_addbuf(sc, IWM_RBUF_SIZE, sc->rxq.cur) != 0)
//        return;
//    mbuf_setdata(m, pkt->data + sizeof(*rx_res), );
//    m->m_data = pkt->data + sizeof(*rx_res);
//    m->m_pkthdr.len = m->m_len = len;
//
//    device_timestamp = le32toh(phy_info->system_timestamp);
//
//    if (sc->sc_capaflags & IWM_UCODE_TLV_FLAGS_RX_ENERGY_API) {
//        rssi = iwm_get_signal_strength(sc, phy_info);
//    } else {
//        rssi = iwm_calc_rssi(sc, phy_info);
//    }
//    rssi = (0 - IWM_MIN_DBM) + rssi;    /* normalize */
//    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */
//
//    chanidx = letoh32(phy_info->channel);
//    if (chanidx < 0 || chanidx >= nitems(ic->ic_channels))
//        chanidx = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
//
//    ni = ieee80211_find_rxnode(ic, wh);
//    if (ni == ic->ic_bss) {
//        /*
//         * We may switch ic_bss's channel during scans.
//         * Record the current channel so we can restore it later.
//         */
//        bss_chan = ni->ni_chan;
//        IEEE80211_ADDR_COPY(&saved_bssid, ni->ni_macaddr);
//    }
//    ni->ni_chan = &ic->ic_channels[chanidx];
//
//    memset(&rxi, 0, sizeof(rxi));
//    rxi.rxi_rssi = rssi;
//    rxi.rxi_tstamp = device_timestamp;
//
//#if NBPFILTER > 0
//    if (sc->sc_drvbpf != NULL) {
//        struct iwm_rx_radiotap_header *tap = &sc->sc_rxtap;
//        uint16_t chan_flags;
//
//        tap->wr_flags = 0;
//        if (phy_info->phy_flags & htole16(IWM_PHY_INFO_FLAG_SHPREAMBLE))
//            tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;
//        tap->wr_chan_freq =
//            htole16(ic->ic_channels[chanidx].ic_freq);
//        chan_flags = ic->ic_channels[chanidx].ic_flags;
//        if (ic->ic_curmode != IEEE80211_MODE_11N)
//            chan_flags &= ~IEEE80211_CHAN_HT;
//        tap->wr_chan_flags = htole16(chan_flags);
//        tap->wr_dbm_antsignal = (int8_t)rssi;
//        tap->wr_dbm_antnoise = (int8_t)sc->sc_noise;
//        tap->wr_tsft = phy_info->system_timestamp;
//        if (phy_info->phy_flags &
//            htole16(IWM_RX_RES_PHY_FLAGS_OFDM_HT)) {
//            uint8_t mcs = (phy_info->rate_n_flags &
//                htole32(IWM_RATE_HT_MCS_RATE_CODE_MSK |
//                    IWM_RATE_HT_MCS_NSS_MSK));
//            tap->wr_rate = (0x80 | mcs);
//        } else {
//            uint8_t rate = (phy_info->rate_n_flags &
//                htole32(IWM_RATE_LEGACY_RATE_MSK));
//            switch (rate) {
//            /* CCK rates. */
//            case  10: tap->wr_rate =   2; break;
//            case  20: tap->wr_rate =   4; break;
//            case  55: tap->wr_rate =  11; break;
//            case 110: tap->wr_rate =  22; break;
//            /* OFDM rates. */
//            case 0xd: tap->wr_rate =  12; break;
//            case 0xf: tap->wr_rate =  18; break;
//            case 0x5: tap->wr_rate =  24; break;
//            case 0x7: tap->wr_rate =  36; break;
//            case 0x9: tap->wr_rate =  48; break;
//            case 0xb: tap->wr_rate =  72; break;
//            case 0x1: tap->wr_rate =  96; break;
//            case 0x3: tap->wr_rate = 108; break;
//            /* Unknown rate: should not happen. */
//            default:  tap->wr_rate =   0;
//            }
//        }
//
//        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_rxtap_len,
//            m, BPF_DIRECTION_IN);
//    }
//#endif
//    ieee80211_inputm(IC2IFP(ic), m, ni, &rxi, ml);
//    /*
//     * ieee80211_inputm() might have changed our BSS.
//     * Restore ic_bss's channel if we are still in the same BSS.
//     */
//    if (ni == ic->ic_bss && IEEE80211_ADDR_EQ(saved_bssid, ni->ni_macaddr))
//        ni->ni_chan = bss_chan;
//    ieee80211_release_node(ic, ni);
}

void itlwm::
iwm_enable_ht_cck_fallback(struct iwm_softc *sc, struct iwm_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    uint8_t rval = (rs->rs_rates[ni->ni_txrate] & IEEE80211_RATE_VAL);
    uint8_t min_rval = ieee80211_min_basic_rate(ic);
    int i;

    /* Are CCK frames forbidden in our BSS? */
    if (IWM_RVAL_IS_OFDM(min_rval))
        return;

    in->ht_force_cck = 1;

    ieee80211_mira_cancel_timeouts(&in->in_mn);
    ieee80211_mira_node_init(&in->in_mn);
    ieee80211_amrr_node_init(&sc->sc_amrr, &in->in_amn);

    /* Choose initial CCK Tx rate. */
    ni->ni_txrate = 0;
    for (i = 0; i < rs->rs_nrates; i++) {
        rval = (rs->rs_rates[i] & IEEE80211_RATE_VAL);
        if (rval == min_rval) {
            ni->ni_txrate = i;
            break;
        }
    }
}

void itlwm::
iwm_rx_tx_cmd_single(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
    struct iwm_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct ifnet *ifp = IC2IFP(ic);
    struct iwm_tx_resp *tx_resp = (struct iwm_tx_resp *)pkt->data;
    int status = le16toh(tx_resp->status.status) & IWM_TX_STATUS_MSK;
    int txfail;
    
    _KASSERT(tx_resp->frame_count == 1);

    txfail = (status != IWM_TX_STATUS_SUCCESS &&
        status != IWM_TX_STATUS_DIRECT_DONE);

    /* Update rate control statistics. */
    if ((ni->ni_flags & IEEE80211_NODE_HT) == 0 || in->ht_force_cck) {
        in->in_amn.amn_txcnt++;
        if (in->ht_force_cck) {
            /*
             * We want to move back to OFDM quickly if possible.
             * Only show actual Tx failures to AMRR, not retries.
             */
            if (txfail)
                in->in_amn.amn_retrycnt++;
        } else if (tx_resp->failure_frame > 0)
            in->in_amn.amn_retrycnt++;
    } else if (ic->ic_fixed_mcs == -1) {
        in->in_mn.frames += tx_resp->frame_count;
        in->in_mn.ampdu_size = le16toh(tx_resp->byte_cnt);
        in->in_mn.agglen = tx_resp->frame_count;
        if (tx_resp->failure_frame > 0)
            in->in_mn.retries += tx_resp->failure_frame;
        if (txfail)
            in->in_mn.txfail += tx_resp->frame_count;
        if (ic->ic_state == IEEE80211_S_RUN && !in->ht_force_cck) {
            int otxmcs = ni->ni_txmcs;

            ieee80211_mira_choose(&in->in_mn, ic, &in->in_ni);

            /* Fall back to CCK rates if MCS 0 is failing. */
            if (txfail && IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) &&
                otxmcs == 0 && ni->ni_txmcs == 0)
                iwm_enable_ht_cck_fallback(sc, in);
        }
    }

    if (txfail)
        ifp->if_oerrors++;
}

void itlwm::
iwm_rx_tx_cmd(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
    struct iwm_rx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ifnet *ifp = IC2IFP(ic);
    struct iwm_cmd_header *cmd_hdr = &pkt->hdr;
    int idx = cmd_hdr->idx;
    int qid = cmd_hdr->qid;
    struct iwm_tx_ring *ring = &sc->txq[qid];
    struct iwm_tx_data *txd = &ring->data[idx];
    struct iwm_node *in = txd->in;

    if (txd->done)
        return;

    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWM_RBUF_SIZE,
        BUS_DMASYNC_POSTREAD);

    sc->sc_tx_timer = 0;

    iwm_rx_tx_cmd_single(sc, pkt, in);

//    bus_dmamap_sync(sc->sc_dmat, txd->map, 0, txd->map->dm_mapsize,
//        BUS_DMASYNC_POSTWRITE);
//    bus_dmamap_unload(sc->sc_dmat, txd->map);
    mbuf_freem(txd->m);

    _KASSERT(txd->done == 0);
    txd->done = 1;
    _KASSERT(txd->in);

    txd->m = NULL;
    txd->in = NULL;
    ieee80211_release_node(ic, &in->in_ni);

    if (--ring->queued < IWM_TX_RING_LOMARK) {
        sc->qfullmsk &= ~(1 << ring->qid);
        //TODO fix
//        if (sc->qfullmsk == 0 && ifq_is_oactive(&ifp->if_snd)) {
//            ifq_clr_oactive(&ifp->if_snd);
//            /*
//             * Well, we're in interrupt context, but then again
//             * I guess net80211 does all sorts of stunts in
//             * interrupt context, so maybe this is no biggie.
//             */
//            (*ifp->if_start)(ifp);
//        }
    }
}

void itlwm::
iwm_rx_bmiss(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
    struct iwm_rx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_missed_beacons_notif *mbn = (struct iwm_missed_beacons_notif *)pkt->data;
    uint32_t missed;

    if ((ic->ic_opmode != IEEE80211_M_STA) ||
        (ic->ic_state != IEEE80211_S_RUN))
        return;

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
        sizeof(*mbn), BUS_DMASYNC_POSTREAD);

    missed = le32toh(mbn->consec_missed_beacons_since_last_rx);
    if (missed > ic->ic_bmissthres && ic->ic_mgt_timer == 0) {
        /*
         * Rather than go directly to scan state, try to send a
         * directed probe request first. If that fails then the
         * state machine will drop us into scanning after timing
         * out waiting for a probe response.
         */
        IEEE80211_SEND_MGMT(ic, ic->ic_bss,
            IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
    }

}

/*
 * Fill in various bit for management frames, and leave them
 * unfilled for data frames (firmware takes care of that).
 * Return the selected TX rate.
 */
const struct iwm_rate * itlwm::
iwm_tx_fill_cmd(struct iwm_softc *sc, struct iwm_node *in,
    struct ieee80211_frame *wh, struct iwm_tx_cmd *tx)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    const struct iwm_rate *rinfo;
    int type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    int min_ridx = iwm_rval2ridx(ieee80211_min_basic_rate(ic));
    int ridx, rate_flags;

    tx->rts_retry_limit = IWM_RTS_DFAULT_RETRY_LIMIT;
    tx->data_retry_limit = IWM_LOW_RETRY_LIMIT;

    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA) {
        /* for non-data, use the lowest supported rate */
        ridx = min_ridx;
        tx->data_retry_limit = IWM_MGMT_DFAULT_RETRY_LIMIT;
    } else if (ic->ic_fixed_mcs != -1) {
        ridx = sc->sc_fixed_ridx;
    } else if (ic->ic_fixed_rate != -1) {
        ridx = sc->sc_fixed_ridx;
    } else if ((ni->ni_flags & IEEE80211_NODE_HT) && !in->ht_force_cck) {
        ridx = iwm_mcs2ridx[ni->ni_txmcs];
    } else {
        uint8_t rval;
        rval = (rs->rs_rates[ni->ni_txrate] & IEEE80211_RATE_VAL);
        ridx = iwm_rval2ridx(rval);
        if (ridx < min_ridx)
            ridx = min_ridx;
    }

    rinfo = &iwm_rates[ridx];
    if (iwm_is_mimo_ht_plcp(rinfo->ht_plcp))
        rate_flags = IWM_RATE_MCS_ANT_AB_MSK;
    else
        rate_flags = IWM_RATE_MCS_ANT_A_MSK;
    if (IWM_RIDX_IS_CCK(ridx))
        rate_flags |= IWM_RATE_MCS_CCK_MSK;
    if ((ni->ni_flags & IEEE80211_NODE_HT) &&
        rinfo->ht_plcp != IWM_RATE_HT_SISO_MCS_INV_PLCP) {
        rate_flags |= IWM_RATE_MCS_HT_MSK;
        tx->rate_n_flags = htole32(rate_flags | rinfo->ht_plcp);
    } else
        tx->rate_n_flags = htole32(rate_flags | rinfo->plcp);

    return rinfo;
}

#define TB0_SIZE 16
int itlwm::
iwm_tx(struct iwm_softc *sc, mbuf_t m, struct ieee80211_node *ni, int ac)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ni;
    struct iwm_tx_ring *ring;
    struct iwm_tx_data *data;
    struct iwm_tfd *desc;
    struct iwm_device_cmd *cmd;
    struct iwm_tx_cmd *tx;
    struct ieee80211_frame *wh;
    struct ieee80211_key *k = NULL;
    const struct iwm_rate *rinfo;
    uint32_t flags;
    u_int hdrlen;
    IOPhysicalSegment *seg;
    uint8_t tid, type;
    int i, totlen, err, pad;
    int hdrlen2, rtsthres = ic->ic_rtsthreshold;

    wh = mtod(m, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

    hdrlen2 = (ieee80211_has_qos(wh)) ?
        sizeof (struct ieee80211_qosframe) :
        sizeof (struct ieee80211_frame);

    tid = 0;

    ring = &sc->txq[ac];
    desc = &ring->desc[ring->cur];
    memset(desc, 0, sizeof(*desc));
    data = &ring->data[ring->cur];

    cmd = &ring->cmd[ring->cur];
    cmd->hdr.code = IWM_TX_CMD;
    cmd->hdr.flags = 0;
    cmd->hdr.qid = ring->qid;
    cmd->hdr.idx = ring->cur;

    tx = (struct iwm_tx_cmd *)cmd->data;
    memset(tx, 0, sizeof(*tx));

    rinfo = iwm_tx_fill_cmd(sc, in, wh, tx);

#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwm_tx_radiotap_header *tap = &sc->sc_txtap;
        uint16_t chan_flags;

        tap->wt_flags = 0;
        tap->wt_chan_freq = htole16(ni->ni_chan->ic_freq);
        chan_flags = ni->ni_chan->ic_flags;
        if (ic->ic_curmode != IEEE80211_MODE_11N)
            chan_flags &= ~IEEE80211_CHAN_HT;
        tap->wt_chan_flags = htole16(chan_flags);
        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
            !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
            type == IEEE80211_FC0_TYPE_DATA &&
            rinfo->ht_plcp != IWM_RATE_HT_SISO_MCS_INV_PLCP) {
            tap->wt_rate = (0x80 | rinfo->ht_plcp);
        } else
            tap->wt_rate = rinfo->rate;
        tap->wt_hwqueue = ac;
        if ((ic->ic_flags & IEEE80211_F_WEPON) &&
            (wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
            tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_txtap_len,
            m, BPF_DIRECTION_OUT);
    }
#endif

    if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
                k = ieee80211_get_txkey(ic, wh, ni);
        if ((m = ieee80211_encrypt(ic, m, k)) == NULL)
            return ENOBUFS;
        /* 802.11 header may have moved. */
        wh = mtod(m, struct ieee80211_frame *);
    }
    totlen = mbuf_pkthdr_len(m);

    flags = 0;
    if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
        flags |= IWM_TX_CMD_FLG_ACK;
    }

    if (ni->ni_flags & IEEE80211_NODE_HT)
        rtsthres = ieee80211_mira_get_rts_threshold(&in->in_mn, ic, ni,
            totlen + IEEE80211_CRC_LEN);

    if (type == IEEE80211_FC0_TYPE_DATA &&
        !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
        (totlen + IEEE80211_CRC_LEN > rtsthres ||
        (ic->ic_flags & IEEE80211_F_USEPROT)))
        flags |= IWM_TX_CMD_FLG_PROT_REQUIRE;

    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA)
        tx->sta_id = IWM_AUX_STA_ID;
    else
        tx->sta_id = IWM_STATION_ID;

    if (type == IEEE80211_FC0_TYPE_MGT) {
        uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

        if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
            subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
            tx->pm_frame_timeout = htole16(3);
        else
            tx->pm_frame_timeout = htole16(2);
    } else {
        tx->pm_frame_timeout = htole16(0);
    }

    if (hdrlen & 3) {
        /* First segment length must be a multiple of 4. */
        flags |= IWM_TX_CMD_FLG_MH_PAD;
        pad = 4 - (hdrlen & 3);
    } else
        pad = 0;

    tx->driver_txop = 0;
    tx->next_frame_len = 0;

    tx->len = htole16(totlen);
    tx->tid_tspec = tid;
    tx->life_time = htole32(IWM_TX_CMD_LIFE_TIME_INFINITE);

    /* Set physical address of "scratch area". */
    tx->dram_lsb_ptr = htole32(data->scratch_paddr);
    tx->dram_msb_ptr = iwm_get_dma_hi_addr(data->scratch_paddr);

    /* Copy 802.11 header in TX command. */
    memcpy(((uint8_t *)tx) + sizeof(*tx), wh, hdrlen);

    flags |= IWM_TX_CMD_FLG_BT_DIS | IWM_TX_CMD_FLG_SEQ_CTL;

    tx->sec_ctl = 0;
    tx->tx_flags |= htole32(flags);

    /* Trim 802.11 header. */
    mbuf_adj(m, hdrlen);

    err = bus_dmamap_load_mbuf(data->map, m);
    if (err && err != EFBIG) {
        XYLog("%s: can't map mbuf (error %d)\n", DEVNAME(sc), err);
        mbuf_freem(m);
        return err;
    }
    if (err) {
        /* Too many DMA segments, linearize mbuf. */
        IOLog("%s: Too many DMA segments, linearize mbuf. but do noting.\n");
//        if (m_defrag(m, M_DONTWAIT)) {
//            mbuf_freem(m);
//            return ENOBUFS;
//        }
        err = bus_dmamap_load_mbuf(data->map, m);
        if (err) {
            XYLog("%s: can't map mbuf (error %d)\n", DEVNAME(sc),
                err);
            mbuf_freem(m);
            return err;
        }
    }
    data->m = m;
    data->in = in;
    data->done = 0;

    /* Fill TX descriptor. */
    desc->num_tbs = 2 + data->map->dm_nsegs;

    desc->tbs[0].lo = htole32(data->cmd_paddr);
    desc->tbs[0].hi_n_len = htole16(iwm_get_dma_hi_addr(data->cmd_paddr)) |
        (TB0_SIZE << 4);
    desc->tbs[1].lo = htole32(data->cmd_paddr + TB0_SIZE);
    desc->tbs[1].hi_n_len = htole16(iwm_get_dma_hi_addr(data->cmd_paddr)) |
        ((sizeof(struct iwm_cmd_header) + sizeof(*tx)
          + hdrlen + pad - TB0_SIZE) << 4);

    /* Other DMA segments are for data payload. */
    seg = data->map->dm_segs;
    for (i = 0; i < data->map->dm_nsegs; i++, seg++) {
        desc->tbs[i+2].lo = htole32(seg->location);
        desc->tbs[i+2].hi_n_len = \
            htole16(iwm_get_dma_hi_addr(seg->location))
            | ((seg->length) << 4);
    }

//    bus_dmamap_sync(sc->sc_dmat, data->map, 0, data->map->dm_mapsize,
//        BUS_DMASYNC_PREWRITE);
//    bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
//        (char *)(void *)cmd - (char *)(void *)ring->cmd_dma.vaddr,
//        sizeof (*cmd), BUS_DMASYNC_PREWRITE);
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//        (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
//        sizeof (*desc), BUS_DMASYNC_PREWRITE);

#if 0
    iwm_update_sched(sc, ring->qid, ring->cur, tx->sta_id, le16toh(tx->len));
#endif

    /* Kick TX ring. */
    ring->cur = (ring->cur + 1) % IWM_TX_RING_COUNT;
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

    /* Mark TX ring as full if we reach a certain threshold. */
    if (++ring->queued > IWM_TX_RING_HIMARK) {
        sc->qfullmsk |= 1 << ring->qid;
    }

    return 0;
}

int itlwm::
iwm_flush_tx_path(struct iwm_softc *sc, int tfd_msk)
{
    struct iwm_tx_path_flush_cmd flush_cmd = {
        .queues_ctl = htole32(tfd_msk),
        .flush_ctl = htole16(IWM_DUMP_TX_FIFO_FLUSH),
    };
    int err;

    err = iwm_send_cmd_pdu(sc, IWM_TXPATH_FLUSH, 0,
        sizeof(flush_cmd), &flush_cmd);
    if (err)
                XYLog("%s: Flushing tx queue failed: %d\n", DEVNAME(sc), err);
    return err;
}

void itlwm::
iwm_mac_ctxt_cmd_common(struct iwm_softc *sc, struct iwm_node *in,
    struct iwm_mac_ctx_cmd *cmd, uint32_t action, int assoc)
{
#define IWM_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int cck_ack_rates, ofdm_ack_rates;
    int i;

    cmd->id_and_color = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id,
        in->in_color));
    cmd->action = htole32(action);

    cmd->mac_type = htole32(IWM_FW_MAC_TYPE_BSS_STA);
    cmd->tsf_id = htole32(IWM_TSF_ID_A);

    IEEE80211_ADDR_COPY(cmd->node_addr, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(cmd->bssid_addr, ni->ni_bssid);

    iwm_ack_rates(sc, in, &cck_ack_rates, &ofdm_ack_rates);
    cmd->cck_rates = htole32(cck_ack_rates);
    cmd->ofdm_rates = htole32(ofdm_ack_rates);

    cmd->cck_short_preamble
        = htole32((ic->ic_flags & IEEE80211_F_SHPREAMBLE)
          ? IWM_MAC_FLG_SHORT_PREAMBLE : 0);
    cmd->short_slot
        = htole32((ic->ic_flags & IEEE80211_F_SHSLOT)
          ? IWM_MAC_FLG_SHORT_SLOT : 0);

    for (i = 0; i < EDCA_NUM_AC; i++) {
        struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[i];
        int txf = iwm_ac_to_tx_fifo[i];

        cmd->ac[txf].cw_min = htole16(IWM_EXP2(ac->ac_ecwmin));
        cmd->ac[txf].cw_max = htole16(IWM_EXP2(ac->ac_ecwmax));
        cmd->ac[txf].aifsn = ac->ac_aifsn;
        cmd->ac[txf].fifos_mask = (1 << txf);
        cmd->ac[txf].edca_txop = htole16(ac->ac_txoplimit * 32);
    }
    if (ni->ni_flags & IEEE80211_NODE_QOS)
        cmd->qos_flags |= htole32(IWM_MAC_QOS_FLG_UPDATE_EDCA);

    if (ni->ni_flags & IEEE80211_NODE_HT) {
        enum ieee80211_htprot htprot =
            (enum ieee80211_htprot)(ni->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
        switch (htprot) {
        case IEEE80211_HTPROT_NONE:
            break;
        case IEEE80211_HTPROT_NONMEMBER:
        case IEEE80211_HTPROT_NONHT_MIXED:
            cmd->protection_flags |=
                htole32(IWM_MAC_PROT_FLG_HT_PROT);
            if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
                cmd->protection_flags |=
                    htole32(IWM_MAC_PROT_FLG_SELF_CTS_EN);
            break;
        case IEEE80211_HTPROT_20MHZ:
            if (ic->ic_htcaps & IEEE80211_HTCAP_CBW20_40) {
                /* XXX ... and if our channel is 40 MHz ... */
                cmd->protection_flags |=
                    htole32(IWM_MAC_PROT_FLG_HT_PROT |
                    IWM_MAC_PROT_FLG_FAT_PROT);
                if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
                    cmd->protection_flags |= htole32(
                        IWM_MAC_PROT_FLG_SELF_CTS_EN);
            }
            break;
        default:
            break;
        }

        cmd->qos_flags |= htole32(IWM_MAC_QOS_FLG_TGN);
    }
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        cmd->protection_flags |= htole32(IWM_MAC_PROT_FLG_TGG_PROTECT);

    cmd->filter_flags = htole32(IWM_MAC_FILTER_ACCEPT_GRP);
#undef IWM_EXP2
}

void itlwm::
iwm_mac_ctxt_cmd_fill_sta(struct iwm_softc *sc, struct iwm_node *in,
    struct iwm_mac_data_sta *sta, int assoc)
{
    struct ieee80211_node *ni = &in->in_ni;
    uint32_t dtim_off;
    uint64_t tsf;

    dtim_off = ni->ni_dtimcount * ni->ni_intval * IEEE80211_DUR_TU;
    memcpy(&tsf, ni->ni_tstamp, sizeof(tsf));
    tsf = letoh64(tsf);

    sta->is_assoc = htole32(assoc);
    sta->dtim_time = htole32(ni->ni_rstamp + dtim_off);
    sta->dtim_tsf = htole64(tsf + dtim_off);
    sta->bi = htole32(ni->ni_intval);
    sta->bi_reciprocal = htole32(iwm_reciprocal(ni->ni_intval));
    sta->dtim_interval = htole32(ni->ni_intval * ni->ni_dtimperiod);
    sta->dtim_reciprocal = htole32(iwm_reciprocal(sta->dtim_interval));
    sta->listen_interval = htole32(10);
    sta->assoc_id = htole32(ni->ni_associd);
    sta->assoc_beacon_arrive_time = htole32(ni->ni_rstamp);
}

int itlwm::
iwm_mac_ctxt_cmd(struct iwm_softc *sc, struct iwm_node *in, uint32_t action,
    int assoc)
{
    struct ieee80211_node *ni = &in->in_ni;
    struct iwm_mac_ctx_cmd cmd;
    int active = (sc->sc_flags & IWM_FLAG_MAC_ACTIVE);

    if (action == IWM_FW_CTXT_ACTION_ADD && active)
        panic("MAC already added");
    if (action == IWM_FW_CTXT_ACTION_REMOVE && !active)
        panic("MAC already removed");

    memset(&cmd, 0, sizeof(cmd));

    iwm_mac_ctxt_cmd_common(sc, in, &cmd, action, assoc);

    /* Allow beacons to pass through as long as we are not associated or we
     * do not have dtim period information */
    if (!assoc || !ni->ni_associd || !ni->ni_dtimperiod)
        cmd.filter_flags |= htole32(IWM_MAC_FILTER_IN_BEACON);
    else
        iwm_mac_ctxt_cmd_fill_sta(sc, in, &cmd.sta, assoc);

    return iwm_send_cmd_pdu(sc, IWM_MAC_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int itlwm::
iwm_update_quotas(struct iwm_softc *sc, struct iwm_node *in, int running)
{
    struct iwm_time_quota_cmd cmd;
    int i, idx, num_active_macs, quota, quota_rem;
    int colors[IWM_MAX_BINDINGS] = { -1, -1, -1, -1, };
    int n_ifs[IWM_MAX_BINDINGS] = {0, };
    uint16_t id;

    memset(&cmd, 0, sizeof(cmd));

    /* currently, PHY ID == binding ID */
    if (in && in->in_phyctxt) {
        id = in->in_phyctxt->id;
        _KASSERT(id < IWM_MAX_BINDINGS);
        colors[id] = in->in_phyctxt->color;
        if (running)
            n_ifs[id] = 1;
    }

    /*
     * The FW's scheduling session consists of
     * IWM_MAX_QUOTA fragments. Divide these fragments
     * equally between all the bindings that require quota
     */
    num_active_macs = 0;
    for (i = 0; i < IWM_MAX_BINDINGS; i++) {
        cmd.quotas[i].id_and_color = htole32(IWM_FW_CTXT_INVALID);
        num_active_macs += n_ifs[i];
    }

    quota = 0;
    quota_rem = 0;
    if (num_active_macs) {
        quota = IWM_MAX_QUOTA / num_active_macs;
        quota_rem = IWM_MAX_QUOTA % num_active_macs;
    }

    for (idx = 0, i = 0; i < IWM_MAX_BINDINGS; i++) {
        if (colors[i] < 0)
            continue;

        cmd.quotas[idx].id_and_color =
            htole32(IWM_FW_CMD_ID_AND_COLOR(i, colors[i]));

        if (n_ifs[i] <= 0) {
            cmd.quotas[idx].quota = htole32(0);
            cmd.quotas[idx].max_duration = htole32(0);
        } else {
            cmd.quotas[idx].quota = htole32(quota * n_ifs[i]);
            cmd.quotas[idx].max_duration = htole32(0);
        }
        idx++;
    }

    /* Give the remainder of the session to the first binding */
    cmd.quotas[0].quota = htole32(le32toh(cmd.quotas[0].quota) + quota_rem);

    return iwm_send_cmd_pdu(sc, IWM_TIME_QUOTA_CMD, 0,
        sizeof(cmd), &cmd);
}

int itlwm::
iwm_auth(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    uint32_t duration;
    int generation = sc->sc_generation, err;

    splassert(IPL_NET);

    sc->sc_phyctxt[0].channel = in->in_ni.ni_chan;
    err = iwm_phy_ctxt_cmd(sc, &sc->sc_phyctxt[0], 1, 1,
        IWM_FW_CTXT_ACTION_MODIFY, 0);
    if (err) {
        XYLog("%s: could not update PHY context (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }
    in->in_phyctxt = &sc->sc_phyctxt[0];

    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_ADD, 0);
    if (err) {
        XYLog("%s: could not add MAC context (error %d)\n",
            DEVNAME(sc), err);
        return err;
     }
    sc->sc_flags |= IWM_FLAG_MAC_ACTIVE;

    err = iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_ADD);
    if (err) {
        XYLog("%s: could not add binding (error %d)\n",
            DEVNAME(sc), err);
        goto rm_mac_ctxt;
    }
    sc->sc_flags |= IWM_FLAG_BINDING_ACTIVE;

    err = iwm_add_sta_cmd(sc, in, 0);
    if (err) {
        XYLog("%s: could not add sta (error %d)\n",
            DEVNAME(sc), err);
        goto rm_binding;
    }
    sc->sc_flags |= IWM_FLAG_STA_ACTIVE;

    /*
     * Prevent the FW from wandering off channel during association
     * by "protecting" the session with a time event.
     */
    if (in->in_ni.ni_intval)
        duration = in->in_ni.ni_intval * 2;
    else
        duration = IEEE80211_DUR_TU;
    iwm_protect_session(sc, in, duration, in->in_ni.ni_intval / 2);

    return 0;

rm_binding:
    if (generation == sc->sc_generation) {
        iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE);
        sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    }
rm_mac_ctxt:
    if (generation == sc->sc_generation) {
        iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE, 0);
        sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    }
    return err;
}

int itlwm::
iwm_deauth(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int ac, tfd_msk, err;

    splassert(IPL_NET);

    iwm_unprotect_session(sc, in);

    if (sc->sc_flags & IWM_FLAG_STA_ACTIVE) {
        err = iwm_rm_sta_cmd(sc, in);
        if (err) {
            XYLog("%s: could not remove STA (error %d)\n",
                DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_STA_ACTIVE;
    }

    tfd_msk = 0;
    for (ac = 0; ac < EDCA_NUM_AC; ac++)
        tfd_msk |= htole32(1 << iwm_ac_to_tx_fifo[ac]);
    err = iwm_flush_tx_path(sc, tfd_msk);
    if (err) {
        XYLog("%s: could not flush Tx path (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    if (sc->sc_flags & IWM_FLAG_BINDING_ACTIVE) {
        err = iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE);
        if (err) {
            XYLog("%s: could not remove binding (error %d)\n",
                DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    }

    if (sc->sc_flags & IWM_FLAG_MAC_ACTIVE) {
        err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE, 0);
        if (err) {
            XYLog("%s: could not remove MAC context (error %d)\n",
                DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    }

    return 0;
}

int itlwm::
iwm_assoc(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int update_sta = (sc->sc_flags & IWM_FLAG_STA_ACTIVE);
    int err;

    splassert(IPL_NET);

    err = iwm_add_sta_cmd(sc, in, update_sta);
    if (err) {
        XYLog("%s: could not %s STA (error %d)\n",
            DEVNAME(sc), update_sta ? "update" : "add", err);
        return err;
    }

    return 0;
}

int itlwm::
iwm_disassoc(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err;

    splassert(IPL_NET);

    if (sc->sc_flags & IWM_FLAG_STA_ACTIVE) {
        err = iwm_rm_sta_cmd(sc, in);
        if (err) {
            XYLog("%s: could not remove STA (error %d)\n",
                DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_STA_ACTIVE;
    }

    return 0;
}

int itlwm::
iwm_run(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err;

    splassert(IPL_NET);

    /* Configure Rx chains for MIMO. */
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) &&
        !sc->sc_nvm.sku_cap_mimo_disable) {
        err = iwm_phy_ctxt_cmd(sc, &sc->sc_phyctxt[0],
            2, 2, IWM_FW_CTXT_ACTION_MODIFY, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n",
                DEVNAME(sc));
            return err;
        }
    }

    /* We have now been assigned an associd by the AP. */
    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_MODIFY, 1);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }

    err = iwm_sf_config(sc, IWM_SF_FULL_ON);
    if (err) {
        XYLog("%s: could not set sf full on (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    err = iwm_allow_mcast(sc);
    if (err) {
        XYLog("%s: could not allow mcast (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    err = iwm_power_update_device(sc);
    if (err) {
        XYLog("%s: could not send power command (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }
#ifdef notyet
    /*
     * Disabled for now. Default beacon filter settings
     * prevent net80211 from getting ERP and HT protection
     * updates from beacons.
     */
    err = iwm_enable_beacon_filter(sc, in);
    if (err) {
        XYLog("%s: could not enable beacon filter\n",
            DEVNAME(sc));
        return err;
    }
#endif
    err = iwm_power_mac_update_mode(sc, in);
    if (err) {
        XYLog("%s: could not update MAC power (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    err = iwm_update_quotas(sc, in, 1);
    if (err) {
        XYLog("%s: could not update quotas (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    ieee80211_amrr_node_init(&sc->sc_amrr, &in->in_amn);
    ieee80211_mira_node_init(&in->in_mn);

    /* Start at lowest available bit-rate, AMRR will raise. */
    in->in_ni.ni_txrate = 0;
    in->in_ni.ni_txmcs = 0;

    timeout_add_msec(&sc->sc_calib_to, 500);
    iwm_led_enable(sc);

    return 0;
}

int itlwm::
iwm_run_stop(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err;

    splassert(IPL_NET);

    err = iwm_sf_config(sc, IWM_SF_INIT_OFF);
    if (err)
        return err;

    iwm_disable_beacon_filter(sc);

    err = iwm_update_quotas(sc, in, 0);
    if (err) {
        XYLog("%s: could not update quotas (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_MODIFY, 0);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }

    /* Reset Tx chains in case MIMO was enabled. */
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) &&
        !sc->sc_nvm.sku_cap_mimo_disable) {
        err = iwm_phy_ctxt_cmd(sc, &sc->sc_phyctxt[0], 1, 1,
            IWM_FW_CTXT_ACTION_MODIFY, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n", DEVNAME(sc));
            return err;
        }
    }

    return 0;
}

struct ieee80211_node *itlwm::
iwm_node_alloc(struct ieee80211com *ic)
{
    void *buf = malloc(sizeof (struct iwm_node), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (buf) {
        bzero(buf, sizeof (struct iwm_node));
    }
    return (struct ieee80211_node *)buf;
}

void itlwm::
iwm_calib_timeout(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    struct ieee80211_node *ni = &in->in_ni;
    int s;

    s = splnet();
    if ((ic->ic_fixed_rate == -1 || ic->ic_fixed_mcs == -1) &&
        ((ni->ni_flags & IEEE80211_NODE_HT) == 0 || in->ht_force_cck) &&
        ic->ic_opmode == IEEE80211_M_STA && ic->ic_bss) {
        ieee80211_amrr_choose(&sc->sc_amrr, &in->in_ni, &in->in_amn);
        if (in->ht_force_cck) {
            struct ieee80211_rateset *rs = &ni->ni_rates;
            uint8_t rv;
            rv = (rs->rs_rates[ni->ni_txrate] & IEEE80211_RATE_VAL);
            if (IWM_RVAL_IS_OFDM(rv))
                in->ht_force_cck = 0;
        }
    }

    splx(s);

    timeout_add_msec(&sc->sc_calib_to, 500);
}

/* Allow multicast from our BSSID. */
int itlwm::
iwm_allow_mcast(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    struct iwm_mcast_filter_cmd *cmd;
    size_t size;
    int err;

    size = roundup(sizeof(*cmd), 4);
    cmd = (struct iwm_mcast_filter_cmd*)malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
    if (cmd == NULL)
        return ENOMEM;
    bzero(cmd, size);
    cmd->filter_own = 1;
    cmd->port_id = 0;
    cmd->count = 0;
    cmd->pass_all = 1;
    IEEE80211_ADDR_COPY(cmd->bssid, ni->ni_bssid);

    err = iwm_send_cmd_pdu(sc, IWM_MCAST_FILTER_CMD,
        0, size, cmd);
    free(cmd);
    return err;
}

/*
 * This function is called by upper layer when an ADDBA request is received
 * from another STA and before the ADDBA response is sent.
 */
int itlwm::
iwm_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    struct iwm_softc *sc = (struct iwm_softc *)IC2IFP(ic)->if_softc;

    if (sc->sc_rx_ba_sessions >= IWM_MAX_RX_BA_SESSIONS)
        return ENOSPC;

    sc->ba_start = 1;
    sc->ba_tid = tid;
    sc->ba_ssn = htole16(ba->ba_winstart);
//    iwm_add_task(sc, systq, &sc->ba_task);

    return EBUSY;
}

/*
 * This function is called by upper layer on teardown of an HT-immediate
 * Block Ack agreement (eg. upon receipt of a DELBA frame).
 */
void itlwm::
iwm_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
    struct iwm_softc *sc = (struct iwm_softc *)IC2IFP(ic)->if_softc;

    sc->ba_start = 0;
    sc->ba_tid = tid;
//    iwm_add_task(sc, systq, &sc->ba_task);
}

/*
 * This function is called by upper layer when HT protection settings in
 * beacons have changed.
 */
void itlwm::
iwm_update_htprot(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;

    /* assumes that ni == ic->ic_bss */
//    iwm_add_task(sc, systq, &sc->htprot_task);
}
